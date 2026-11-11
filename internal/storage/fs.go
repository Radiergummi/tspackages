package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Sidecar, lock and temp file names contain "#", which ValidKey never
// accepts, so they cannot collide with a key.
const (
	etagSuffix = "#etag"
	tmpSuffix  = "#tmp"
	lockDir    = "#locks"
)

// lockStripes is the number of lock files. Keys share them by hash; a lock is
// held only within one driver call and never nested, so sharing costs at most
// a short wait.
const lockStripes = 256

// staleTemp is the age after which a temp file is a crash leftover: no write
// takes that long.
const staleTemp = time.Hour

type fsDriver struct{ root string }

// NewFS returns a driver storing objects as files below root. Next to each
// object it keeps a "<key>#etag" sidecar (temp files end in "#tmp"), and it
// locks through a fixed set of files in "#locks"; keys cannot contain "#", so
// these never collide. A key cannot also be a prefix of another key (a file
// cannot be a directory); such writes fail with ErrInvalidKey or ErrExists.
// Temp files older than staleTemp are removed.
func NewFS(root string) (Driver, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(abs, lockDir), 0o700); err != nil {
		return nil, err
	}
	if err := removeStaleTemps(abs); err != nil {
		return nil, fmt.Errorf("remove stale temp files: %w", err)
	}
	return &fsDriver{root: abs}, nil
}

func removeStaleTemps(root string) error {
	cutoff := time.Now().Add(-staleTemp)
	return filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
		switch {
		case err != nil:
			if isMissing(err) {
				return nil
			}
			return err
		case de.IsDir() && de.Name() == lockDir:
			return filepath.SkipDir
		case de.IsDir() || !strings.HasSuffix(de.Name(), tmpSuffix):
			return nil
		}
		fi, err := de.Info()
		if isMissing(err) {
			return nil // gone meanwhile
		}
		if err != nil {
			return err
		}
		if fi.ModTime().After(cutoff) {
			return nil // possibly another instance's write in progress
		}
		if err := os.Remove(p); err != nil && !isMissing(err) {
			return err
		}
		return nil
	})
}

func (d *fsDriver) path(key string) (string, error) {
	if err := ValidKey(key); err != nil {
		return "", err
	}
	return filepath.Join(d.root, filepath.FromSlash(key)), nil
}

// lock takes an flock on the lock stripe of the object at p, polling so that
// ctx can abort the wait, and returns the release function.
func (d *fsDriver) lock(ctx context.Context, p string, how int) (func(), error) {
	h := sha256.Sum256([]byte(strings.TrimPrefix(p, d.root)))
	stripe := strconv.Itoa(int(h[0]) % lockStripes)
	f, err := os.OpenFile(filepath.Join(d.root, lockDir, stripe), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(f.Fd()), how|unix.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil // closing releases the flock
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// etagOf returns the object's ETag. The sidecar records "<etag> <size>
// <mtime-ns>" of the object it was computed for; if the object no longer
// matches (a crash between publishing the object and its sidecar) or the
// sidecar is missing, the content is hashed instead.
func etagOf(p string, fi fs.FileInfo) (string, error) {
	if b, err := os.ReadFile(p + etagSuffix); err == nil {
		var etag string
		var size, mtime int64
		if n, _ := fmt.Sscanf(string(b), "%s %d %d", &etag, &size, &mtime); n == 3 &&
			size == fi.Size() && mtime == fi.ModTime().UnixNano() {
			return etag, nil
		}
	}
	return hashFile(p)
}

func (d *fsDriver) info(key, p string, fi fs.FileInfo) (Info, error) {
	etag, err := etagOf(p, fi)
	if err != nil {
		return Info{}, err
	}
	return Info{Key: key, Size: fi.Size(), ETag: etag, ModTime: fi.ModTime()}, nil
}

func isMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOTDIR)
}

// regular stats p and reports whether a regular file lives there.
func regular(p string) (fs.FileInfo, bool, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		if isMissing(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return fi, fi.Mode().IsRegular(), nil
}

func (d *fsDriver) Get(ctx context.Context, key string) (io.ReadCloser, Info, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, Info{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, Info{}, err
	}
	// Reads never create anything for a missing object.
	if _, ok, err := regular(p); err != nil {
		return nil, Info{}, err
	} else if !ok {
		return nil, Info{}, ErrNotFound
	}
	// The shared lock is held only while opening; the open file stays valid
	// across a concurrent rename.
	unlock, err := d.lock(ctx, p, unix.LOCK_SH)
	if err != nil {
		return nil, Info{}, err
	}
	defer unlock()
	f, err := os.Open(p)
	if err != nil {
		if isMissing(err) {
			return nil, Info{}, ErrNotFound
		}
		return nil, Info{}, err
	}
	fi, err := f.Stat()
	var info Info
	if err == nil {
		info, err = d.info(key, p, fi)
	}
	if err != nil {
		f.Close()
		if isMissing(err) {
			return nil, Info{}, ErrNotFound
		}
		return nil, Info{}, err
	}
	return f, info, nil
}

func (d *fsDriver) GetRange(ctx context.Context, key string, off, n int64) (io.ReadCloser, error) {
	rc, _, err := d.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	f := rc.(*os.File)
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	if n < 0 {
		return f, nil
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(f, n), f}, nil
}

func (d *fsDriver) Stat(ctx context.Context, key string) (Info, error) {
	rc, info, err := d.Get(ctx, key)
	if err != nil {
		return Info{}, err
	}
	rc.Close()
	return info, nil
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// stage streams r into a synced 0600 temp file next to p and returns its path
// and content hash.
func stage(p string, r io.Reader) (tmp, etag string, err error) {
	f, err := os.CreateTemp(filepath.Dir(p), "*"+tmpSuffix)
	if err != nil {
		return "", "", err
	}
	tmp = f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	h := sha256.New()
	if _, err = io.Copy(io.MultiWriter(f, h), r); err != nil {
		return "", "", err
	}
	if err = f.Chmod(0o600); err != nil {
		return "", "", err
	}
	if err = f.Sync(); err != nil {
		return "", "", err
	}
	if err = f.Close(); err != nil {
		return "", "", err
	}
	return tmp, hex.EncodeToString(h.Sum(nil)), nil
}

func writeSidecar(p string, etag string, fi fs.FileInfo) error {
	f, err := os.CreateTemp(filepath.Dir(p), "*"+tmpSuffix)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%s %d %d", etag, fi.Size(), fi.ModTime().UnixNano())
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), p+etagSuffix)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

type commitMode int

const (
	modeReplace commitMode = iota
	modeCreate
)

func conflictErr(err error) error {
	if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENOTEMPTY) {
		return fmt.Errorf("%w: key conflicts with another key's prefix", ErrInvalidKey)
	}
	return err
}

// write stores r at key under the key's exclusive lock. check, if non-nil,
// runs under the lock before anything is published.
//
// Guarantees: readers see either the old or the new object, never a partial
// one (temp file, fsync, atomic rename/link, directory fsync). The sidecar is
// written after the object and records the object's size and mtime, so a crash
// between the two leaves a sidecar that etagOf recognises as stale and ignores.
func (d *fsDriver) write(ctx context.Context, key string, r io.Reader, mode commitMode, check func(p string) error) (Info, error) {
	p, err := d.path(key)
	if err != nil {
		return Info{}, err
	}
	if err := ctx.Err(); err != nil {
		return Info{}, err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Info{}, conflictErr(err)
	}
	unlock, err := d.lock(ctx, p, unix.LOCK_EX)
	if err != nil {
		return Info{}, err
	}
	defer unlock()
	if check != nil {
		if err := check(p); err != nil {
			return Info{}, err
		}
	}
	tmp, etag, err := stage(p, r)
	if err != nil {
		return Info{}, err
	}
	defer os.Remove(tmp) // no-op once renamed
	if mode == modeCreate {
		if err := os.Link(tmp, p); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return Info{}, ErrExists
			}
			return Info{}, conflictErr(err)
		}
	} else if err := os.Rename(tmp, p); err != nil {
		if errors.Is(err, fs.ErrExist) { // a directory is in the way (macOS)
			err = unix.EISDIR
		}
		return Info{}, conflictErr(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return Info{}, err
	}
	if err := writeSidecar(p, etag, fi); err != nil {
		return Info{}, err
	}
	if err := syncDir(dir); err != nil {
		return Info{}, err
	}
	return Info{Key: key, Size: fi.Size(), ETag: etag, ModTime: fi.ModTime()}, nil
}

func (d *fsDriver) Put(ctx context.Context, key string, r io.Reader) (Info, error) {
	return d.write(ctx, key, r, modeReplace, nil)
}

func (d *fsDriver) PutIfAbsent(ctx context.Context, key string, r io.Reader) (Info, error) {
	return d.write(ctx, key, r, modeCreate, func(p string) error {
		if _, err := os.Lstat(p); err == nil {
			return ErrExists
		} else if !isMissing(err) {
			return err
		}
		return nil
	})
}

func (d *fsDriver) PutIfMatch(ctx context.Context, key string, r io.Reader, etag string) (Info, error) {
	mode := modeReplace
	if etag == "" {
		mode = modeCreate
	}
	return d.write(ctx, key, r, mode, func(p string) error {
		fi, ok, err := regular(p)
		if err != nil {
			return err
		}
		if etag == "" {
			if _, err := os.Lstat(p); err == nil {
				return ErrPrecondition
			}
			return nil
		}
		if !ok {
			return ErrPrecondition
		}
		cur, err := etagOf(p, fi)
		if err != nil {
			return err
		}
		if cur != etag {
			return ErrPrecondition
		}
		return nil
	})
}

func (d *fsDriver) Delete(ctx context.Context, key string) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok, err := regular(p); err != nil || !ok {
		return err
	}
	unlock, err := d.lock(ctx, p, unix.LOCK_EX)
	if err != nil {
		return err
	}
	defer unlock()
	if err := os.Remove(p); err != nil && !isMissing(err) {
		return err
	}
	if err := os.Remove(p + etagSuffix); err != nil && !isMissing(err) {
		return err
	}
	return nil
}

// isSidecar reports whether a name is a sidecar, temp file or the lock directory.
func isSidecar(name string) bool { return strings.Contains(name, "#") }

func (d *fsDriver) List(ctx context.Context, prefix string) iter.Seq2[Info, error] {
	return func(yield func(Info, error) bool) {
		if err := validPrefix(prefix); err != nil {
			yield(Info{}, err)
			return
		}
		start := d.root
		if before, _, ok := strings.CutLast(prefix, "/"); ok {
			start = filepath.Join(d.root, filepath.FromSlash(before))
		}
		// Collect keys first and sort them byte-wise: directory walk order
		// differs from key order ("a.b" sorts before "a/b").
		var keys []string
		err := filepath.WalkDir(start, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				if isMissing(err) {
					return nil
				}
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if de.IsDir() && isSidecar(de.Name()) {
				return filepath.SkipDir // the lock files
			}
			if de.IsDir() || isSidecar(de.Name()) {
				return nil
			}
			rel, err := filepath.Rel(d.root, p)
			if err != nil {
				return err
			}
			if key := filepath.ToSlash(rel); strings.HasPrefix(key, prefix) {
				keys = append(keys, key)
			}
			return nil
		})
		if err != nil {
			yield(Info{}, err)
			return
		}
		slices.Sort(keys)
		for _, key := range keys {
			if err := ctx.Err(); err != nil {
				yield(Info{}, err)
				return
			}
			fi, ok, err := regular(filepath.Join(d.root, filepath.FromSlash(key)))
			if err != nil {
				yield(Info{}, err)
				return
			}
			if !ok {
				continue // deleted meanwhile
			}
			if !yield(Info{Key: key, Size: fi.Size(), ModTime: fi.ModTime()}, nil) {
				return
			}
		}
	}
}
