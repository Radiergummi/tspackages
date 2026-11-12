package goproxy

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	modzip "golang.org/x/mod/zip"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/resolve"
)

const (
	// MaxArchiveBytes caps the git archive a module zip is built from
	// (cmd/go's codehost.MaxZipFile).
	MaxArchiveBytes = 500 << 20
	// GoZipFormat is the version of the zip algorithm below, recorded with
	// every stored zip.
	GoZipFormat = 1
)

// ZipResult describes a built module zip.
type ZipResult struct {
	ZipHash, ModHash string // "h1:…", as go.sum records them
	SHA256           string // hex sha256 of the zip bytes
	Size             int64
}

// BuildInput is what BuildZip needs to build one module version.
type BuildInput struct {
	Version module.Version
	Subdir  string // Found.Dir: the module's directory in the repository
	GoMod   []byte
	// Archive writes `git archive --format=zip -0 --prefix=prefix/ <commit>
	// [-- Subdir]` to w (gitmirror.Mirror.ArchiveModuleZip).
	Archive func(ctx context.Context, w io.Writer) error
	// License returns the repository root's LICENSE at the commit
	// (ReadFileMax with MaxLICENSE): resolve.ErrNotFound when it is missing or
	// not a blob, gitmirror.ErrTooLarge over the cap.
	License  func(ctx context.Context) ([]byte, error)
	TmpDir   string // <work_dir>/go-build
	MaxBytes int64  // min(MaxArchiveBytes, max_artifact_bytes)

	// wrapZipWriter wraps the module zip's file; tests use it to fail writes.
	wrapZipWriter func(io.Writer) io.Writer
}

// BuildZip builds a module zip as cmd/go's codeRepo.Zip does from a git
// archive, writes it to a temp file in TmpDir and returns its path (the
// caller removes it) and hashes. Nothing is held in memory.
//
// A *RefusalError is derived from the commit's content: the archive over
// MaxBytes, a root LICENSE over MaxLICENSE, or a zip that modzip.Create
// rejects. Every other error (I/O, context, Archive's own, git archive
// failing with gitmirror.ErrArchiveFailed) is returned as is; the caller
// decides whether to retry.
func BuildZip(ctx context.Context, in BuildInput) (path string, res ZipResult, err error) {
	archive, err := spoolArchive(ctx, in)
	if err != nil {
		return "", ZipResult{}, err
	}
	defer os.Remove(archive)

	zr, err := zip.OpenReader(archive)
	if err != nil {
		return "", ZipResult{}, fmt.Errorf("goproxy: read git archive: %w", err)
	}
	defer zr.Close()

	rec := &ioRecorder{ctx: ctx}
	files, err := moduleFiles(ctx, in, zr.File, rec)
	if err != nil {
		return "", ZipResult{}, err
	}

	out, err := os.CreateTemp(in.TmpDir, "module-*.zip")
	if err != nil {
		return "", ZipResult{}, err
	}
	defer func() {
		if err != nil {
			out.Close()
			os.Remove(out.Name())
		}
	}()
	h := sha256.New()
	var w io.Writer = out
	if in.wrapZipWriter != nil {
		w = in.wrapZipWriter(w)
	}
	cw := &countWriter{w: io.MultiWriter(w, h), rec: rec}
	cerr := modzip.Create(cw, in.Version, files)
	switch {
	case rec.err != nil:
		// Also after a successful Create: modzip reads the root go.mod's go
		// line ignoring errors, and a failed read changes the vendoring rules.
		return "", ZipResult{}, fmt.Errorf("goproxy: build module zip: %w", rec.err)
	case cerr != nil:
		return "", ZipResult{}, &RefusalError{Reason: "zip: " + cerr.Error()}
	}
	if err := out.Close(); err != nil {
		return "", ZipResult{}, err
	}
	zipHash, err := dirhash.HashZip(out.Name(), dirhash.Hash1)
	if err != nil {
		return "", ZipResult{}, err
	}
	modHash, err := modHash(in.GoMod)
	if err != nil {
		return "", ZipResult{}, err
	}
	return out.Name(), ZipResult{
		ZipHash: zipHash,
		ModHash: modHash,
		SHA256:  hex.EncodeToString(h.Sum(nil)),
		Size:    cw.n,
	}, nil
}

// spoolArchive writes the git archive to a temp file in TmpDir, capped at
// MaxBytes, and returns its path.
//
// The archive is stored (-0), so the cap bounds the inflated bytes and a
// zero-filled blob can't become a decompression bomb. It counts every file
// git archives, including the ones modzip later drops (nested modules,
// vendored packages, symlinks): stricter than cmd/go, whose MaxZipFile
// applies to deflated output.
func spoolArchive(ctx context.Context, in BuildInput) (path string, err error) {
	f, err := os.CreateTemp(in.TmpDir, "archive-*.zip")
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = cerr
		}
		if err != nil {
			os.Remove(f.Name())
		}
	}()
	cw := &capWriter{w: f, max: in.MaxBytes}
	aerr := in.Archive(ctx, cw)
	if cw.over {
		return "", &RefusalError{Reason: fmt.Sprintf("archive over %d bytes", in.MaxBytes)}
	}
	if aerr != nil {
		return "", aerr
	}
	return f.Name(), nil
}

var errArchiveCap = errors.New("goproxy: archive over the size cap")

// capWriter fails once more than max bytes are written.
type capWriter struct {
	w    io.Writer
	max  int64
	n    int64
	over bool
}

func (c *capWriter) Write(b []byte) (int, error) {
	if c.n+int64(len(b)) > c.max {
		c.over = true
		return 0, errArchiveCap
	}
	n, err := c.w.Write(b)
	c.n += int64(n)
	return n, err
}

// moduleFiles turns the archive's entries into modzip files as codeRepo.Zip
// does: names lose "prefix/" and Subdir+"/", directory entries are dropped,
// and a subdirectory module without an entry named LICENSE (of any kind: a
// symlink counts, though modzip drops it) gets the root's LICENSE.
func moduleFiles(ctx context.Context, in BuildInput, entries []*zip.File, rec *ioRecorder) ([]modzip.File, error) {
	subdir := ""
	if in.Subdir != "" {
		subdir = in.Subdir + "/"
	}
	var files []modzip.File
	haveLICENSE := false
	for _, zf := range entries {
		name, ok := strings.CutPrefix(zf.Name, "prefix/")
		if !ok {
			continue
		}
		if name, ok = strings.CutPrefix(name, subdir); !ok {
			continue
		}
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		files = append(files, archiveFile{name: name, f: zf, rec: rec})
		if name == "LICENSE" {
			haveLICENSE = true
		}
	}
	// codeRepo.Zip adds the root LICENSE to subdirectory modules only; for
	// the root module the archive already holds it if it is a blob.
	if haveLICENSE || subdir == "" {
		return files, nil
	}
	// Archive succeeded for this commit, so resolve.ErrNotFound here means
	// the path is missing or not a blob, never a missing commit (mirrors keep
	// their objects: gc.auto=0, fetch --prune drops only refs).
	data, err := in.License(ctx)
	switch {
	case err == nil:
		return append(files, dataFile{name: "LICENSE", data: data}), nil
	case errors.Is(err, resolve.ErrNotFound):
		return files, nil
	case errors.Is(err, gitmirror.ErrTooLarge):
		return nil, &RefusalError{Reason: "LICENSE over 16 MiB"}
	default:
		return nil, err
	}
}

// ioRecorder keeps the first I/O error seen by the module zip's readers or
// writer, so that a modzip.Create failure caused by I/O (or cancellation)
// isn't mistaken for a content refusal.
type ioRecorder struct {
	ctx context.Context
	err error
}

func (r *ioRecorder) record(err error) error {
	if err != nil && !errors.Is(err, io.EOF) && r.err == nil {
		r.err = err
	}
	return err
}

// archiveFile is codeRepo.Zip's zipFile with recorded read errors.
type archiveFile struct {
	name string
	f    *zip.File
	rec  *ioRecorder
}

func (f archiveFile) Path() string                { return f.name }
func (f archiveFile) Lstat() (fs.FileInfo, error) { return f.f.FileInfo(), nil }
func (f archiveFile) Open() (io.ReadCloser, error) {
	rc, err := f.f.Open()
	if err != nil {
		return nil, f.rec.record(err)
	}
	return &recordingReader{rc: rc, rec: f.rec}, nil
}

type recordingReader struct {
	rc  io.ReadCloser
	rec *ioRecorder
}

func (r *recordingReader) Read(b []byte) (int, error) {
	if err := r.rec.ctx.Err(); err != nil {
		return 0, r.rec.record(err)
	}
	n, err := r.rc.Read(b)
	return n, r.rec.record(err)
}

func (r *recordingReader) Close() error { return r.rc.Close() }

// countWriter counts the bytes written and records write errors.
type countWriter struct {
	w   io.Writer
	rec *ioRecorder
	n   int64
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n += int64(n)
	return n, c.rec.record(err)
}

// dataFile is codeRepo.Zip's dataFile: an in-memory regular file.
type dataFile struct {
	name string
	data []byte
}

func (f dataFile) Path() string                 { return f.name }
func (f dataFile) Lstat() (fs.FileInfo, error)  { return dataFileInfo{f}, nil }
func (f dataFile) Open() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(f.data)), nil }

type dataFileInfo struct{ f dataFile }

func (fi dataFileInfo) Name() string       { return fi.f.name }
func (fi dataFileInfo) Size() int64        { return int64(len(fi.f.data)) }
func (fi dataFileInfo) Mode() fs.FileMode  { return 0o644 }
func (fi dataFileInfo) ModTime() time.Time { return time.Time{} }
func (fi dataFileInfo) IsDir() bool        { return false }
func (fi dataFileInfo) Sys() any           { return nil }
