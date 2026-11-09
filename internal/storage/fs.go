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
	"strings"

	"golang.org/x/sys/unix"
)

const (
	etagSuffix = ".etag"
	lockSuffix = ".lock"
	tmpSuffix  = ".tmp"
)

type fsDriver struct{ root string }

// NewFS returns a driver storing objects as files below root. Next to each
// object it keeps a "<key>.etag" sidecar and a "<key>.lock" file; keys ending
// in .etag, .lock or .tmp are therefore rejected.
func NewFS(root string) (Driver, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	return &fsDriver{root: abs}, nil
}

func (d *fsDriver) path(key string) (string, error) {
	if err := ValidKey(key); err != nil {
		return "", err
	}
	for _, s := range []string{etagSuffix, lockSuffix, tmpSuffix} {
		if strings.HasSuffix(key, s) {
			return "", fmt.Errorf("%w: reserved suffix %q", ErrInvalidKey, s)
		}
	}
	return filepath.Join(d.root, filepath.FromSlash(key)), nil
}

// lock takes an flock on "<p>.lock" and returns its release function. All
// writers and Get/Stat use it, so an object and its sidecar are always seen
// together.
func lock(p string, how int) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p+lockSuffix, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(f.Fd()), how)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil // closing releases the flock
}

// etagOf reads the sidecar, falling back to hashing the object when it is
// missing (e.g. after a crash between writing the object and its sidecar).
func etagOf(p string) (string, error) {
	if b, err := os.ReadFile(p + etagSuffix); err == nil {
		return string(b), nil
	}
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

func (d *fsDriver) info(key, p string, fi fs.FileInfo) (Info, error) {
	etag, err := etagOf(p)
	if err != nil {
		return Info{}, err
	}
	return Info{Key: key, Size: fi.Size(), ETag: etag, ModTime: fi.ModTime()}, nil
}

func mapNotExist(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

func (d *fsDriver) Get(ctx context.Context, key string) (io.ReadCloser, Info, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, Info{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, Info{}, err
	}
	// The shared lock is held only while opening; the open file stays valid
	// across a concurrent rename.
	if _, err := os.Stat(filepath.Dir(p)); err != nil {
		return nil, Info{}, mapNotExist(err)
	}
	unlock, err := lock(p, unix.LOCK_SH)
	if err != nil {
		return nil, Info{}, err
	}
	defer unlock()
	f, err := os.Open(p)
	if err != nil {
		return nil, Info{}, mapNotExist(err)
	}
	fi, err := f.Stat()
	if err == nil && fi.IsDir() {
		err = fs.ErrNotExist
	}
	var info Info
	if err == nil {
		info, err = d.info(key, p, fi)
	}
	if err != nil {
		f.Close()
		return nil, Info{}, mapNotExist(err)
	}
	return f, info, nil
}

func (d *fsDriver) Stat(ctx context.Context, key string) (Info, error) {
	rc, info, err := d.Get(ctx, key)
	if err != nil {
		return Info{}, err
	}
	rc.Close()
	return info, nil
}

// stage streams r into a synced temp file next to p and returns its path and
// content hash.
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
	if err = f.Sync(); err != nil {
		return "", "", err
	}
	if err = f.Close(); err != nil {
		return "", "", err
	}
	return tmp, hex.EncodeToString(h.Sum(nil)), nil
}

func writeSidecar(p, etag string) error {
	f, err := os.CreateTemp(filepath.Dir(p), "*"+tmpSuffix)
	if err != nil {
		return err
	}
	_, err = f.WriteString(etag)
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

// write stores r at key under the key's exclusive lock. check, if non-nil,
// runs under the lock before anything is published.
func (d *fsDriver) write(ctx context.Context, key string, r io.Reader, mode commitMode, check func(p string) error) (Info, error) {
	p, err := d.path(key)
	if err != nil {
		return Info{}, err
	}
	if err := ctx.Err(); err != nil {
		return Info{}, err
	}
	unlock, err := lock(p, unix.LOCK_EX)
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
	// The sidecar goes first; for a create the object does not exist yet, so
	// a leftover sidecar is harmless.
	if err := writeSidecar(p, etag); err != nil {
		return Info{}, err
	}
	if mode == modeCreate {
		if err := os.Link(tmp, p); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return Info{}, ErrExists
			}
			return Info{}, err
		}
	} else if err := os.Rename(tmp, p); err != nil {
		return Info{}, err
	}
	fi, err := os.Stat(p)
	if err != nil {
		return Info{}, err
	}
	return Info{Key: key, Size: fi.Size(), ETag: etag, ModTime: fi.ModTime()}, nil
}

func exists(p string) (bool, error) {
	_, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (d *fsDriver) Put(ctx context.Context, key string, r io.Reader) (Info, error) {
	return d.write(ctx, key, r, modeReplace, nil)
}

func (d *fsDriver) PutIfAbsent(ctx context.Context, key string, r io.Reader) (Info, error) {
	return d.write(ctx, key, r, modeCreate, func(p string) error {
		if ok, err := exists(p); err != nil {
			return err
		} else if ok {
			return ErrExists
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
		ok, err := exists(p)
		if err != nil {
			return err
		}
		if etag == "" {
			if ok {
				return ErrPrecondition
			}
			return nil
		}
		if !ok {
			return ErrPrecondition
		}
		cur, err := etagOf(p)
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
	if ok, _ := exists(filepath.Dir(p)); !ok {
		return nil
	}
	unlock, err := lock(p, unix.LOCK_EX)
	if err != nil {
		return err
	}
	defer unlock()
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Remove(p + etagSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func isSidecar(name string) bool {
	return strings.HasSuffix(name, etagSuffix) || strings.HasSuffix(name, lockSuffix) || strings.HasSuffix(name, tmpSuffix)
}

func (d *fsDriver) List(ctx context.Context, prefix string) iter.Seq2[Info, error] {
	return func(yield func(Info, error) bool) {
		if err := validPrefix(prefix); err != nil {
			yield(Info{}, err)
			return
		}
		start := d.root
		if i := strings.LastIndexByte(prefix, '/'); i >= 0 {
			start = filepath.Join(d.root, filepath.FromSlash(prefix[:i]))
		}
		stop := errors.New("stop")
		err := filepath.WalkDir(start, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if de.IsDir() || isSidecar(de.Name()) {
				return nil
			}
			rel, err := filepath.Rel(d.root, p)
			if err != nil {
				return err
			}
			key := filepath.ToSlash(rel)
			if !strings.HasPrefix(key, prefix) {
				return nil
			}
			fi, err := de.Info()
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			info, err := d.info(key, p, fi)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if !yield(info, nil) {
				return stop
			}
			return nil
		})
		if err != nil && !errors.Is(err, stop) {
			yield(Info{}, err)
		}
	}
}
