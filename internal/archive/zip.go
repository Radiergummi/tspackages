// Package archive inspects untrusted zip uploads before anything is read from
// or stored for them.
package archive

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
)

// Limits caps what an upload may contain.
type Limits struct {
	MaxBytes        int64 // size of the zip itself
	MaxDecompressed int64 // total declared uncompressed size
	MaxEntries      int
}

// Error is a rejected archive. Reason is safe to show to clients.
type Error struct{ Reason string }

func (e *Error) Error() string { return e.Reason }

func reject(format string, a ...any) error { return &Error{Reason: fmt.Sprintf(format, a...)} }

// ErrNotFound means a wanted file is not in the archive.
var ErrNotFound = errors.New("archive: file not found")

// InspectZip opens data as a zip and rejects it when it is larger than
// l.MaxBytes, has more than l.MaxEntries entries, has an entry whose name is
// absolute, contains a ".." segment or a backslash, has a symlink, declares more
// than l.MaxDecompressed bytes in total, or has an entry that inflates to more
// than it declares. Names must be canonical (path.Clean, a directory keeps its
// trailing "/"), have no drive prefix and be unique ignoring case; modes must
// be regular files or directories without setuid/setgid. Every entry is inflated once (bounded by its declared size)
// so a lying header cannot be used to bypass the cap later.
func InspectZip(data []byte, l Limits) (*zip.Reader, error) {
	if int64(len(data)) > l.MaxBytes {
		return nil, reject("archive exceeds %d bytes", l.MaxBytes)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, reject("not a valid zip archive")
	}
	if len(zr.File) > l.MaxEntries {
		return nil, reject("archive has more than %d entries", l.MaxEntries)
	}
	var total uint64
	seen := make(map[string]struct{}, len(zr.File))
	for _, f := range zr.File {
		if err := checkName(f.Name); err != nil {
			return nil, err
		}
		lower := strings.ToLower(f.Name)
		if _, dup := seen[lower]; dup {
			return nil, reject("archive has duplicate entry %q", f.Name)
		}
		seen[lower] = struct{}{}
		mode := f.Mode()
		if mode&fs.ModeSymlink != 0 {
			return nil, reject("archive entry %q is a symlink", f.Name)
		}
		if mode&(fs.ModeNamedPipe|fs.ModeSocket|fs.ModeDevice|fs.ModeCharDevice|fs.ModeIrregular|fs.ModeSetuid|fs.ModeSetgid) != 0 {
			return nil, reject("archive entry %q has a special file mode", f.Name)
		}
		if f.UncompressedSize64 > uint64(l.MaxDecompressed) {
			return nil, reject("archive entry %q declares more than %d uncompressed bytes", f.Name, l.MaxDecompressed)
		}
		total += f.UncompressedSize64 // each term <= MaxInt64, total checked every step: cannot overflow
		if total > uint64(l.MaxDecompressed) {
			return nil, reject("archive declares more than %d uncompressed bytes in total", l.MaxDecompressed)
		}
	}
	for _, f := range zr.File {
		if err := checkInflates(f); err != nil {
			return nil, err
		}
	}
	return zr, nil
}

func checkName(name string) error {
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\\x00") {
		return reject("archive entry name %q is not allowed", name)
	}
	if len(name) >= 2 && name[1] == ':' && (name[0]|0x20 >= 'a' && name[0]|0x20 <= 'z') {
		return reject("archive entry name %q is not allowed", name)
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || trimmed == "." || path.Clean(trimmed) != trimmed {
		return reject("archive entry name %q is not canonical", name)
	}
	for seg := range strings.SplitSeq(trimmed, "/") {
		if seg == ".." {
			return reject("archive entry name %q is not allowed", name)
		}
	}
	return nil
}

func checkInflates(f *zip.File) error {
	rc, err := f.Open()
	if err != nil {
		return reject("archive entry %q is unreadable", f.Name)
	}
	defer rc.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(rc, int64(f.UncompressedSize64)+1))
	if err != nil {
		return reject("archive entry %q is corrupt", f.Name)
	}
	if uint64(n) > f.UncompressedSize64 {
		return reject("archive entry %q is larger than it declares", f.Name)
	}
	return nil
}

// FindFile returns the file called name at the archive root, or, if every
// entry shares a single top-level directory, inside that directory.
func FindFile(zr *zip.Reader, name string) (*zip.File, error) {
	for _, f := range zr.File {
		if f.Name == name {
			return f, nil
		}
	}
	top := ""
	for _, f := range zr.File {
		first, _, hasDir := strings.Cut(f.Name, "/")
		if !hasDir {
			return nil, ErrNotFound // a root-level file other than name: no single top dir
		}
		if top == "" {
			top = first
		} else if first != top {
			return nil, ErrNotFound
		}
	}
	if top == "" {
		return nil, ErrNotFound
	}
	want := top + "/" + name
	for _, f := range zr.File {
		if f.Name == want {
			return f, nil
		}
	}
	return nil, ErrNotFound
}

// DropSymlinks returns data without its symlink entries and the names it
// dropped. Data without symlinks is returned as is; otherwise the other
// entries are copied unchanged (still compressed) in their order, with the
// archive comment, so the result is deterministic. An archive naming a path
// twice, or as a file and as a directory, is refused: it has no single
// content for that path.
func DropSymlinks(data []byte) ([]byte, []string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, reject("not a valid zip archive")
	}
	files := make(map[string]bool, len(zr.File))
	for _, f := range zr.File {
		name := strings.TrimSuffix(f.Name, "/")
		if files[name] {
			return nil, nil, reject("archive has duplicate entry %q", f.Name)
		}
		files[name] = !strings.HasSuffix(f.Name, "/")
	}
	for _, f := range zr.File {
		for d := path.Dir(f.Name); d != "." && d != "/"; d = path.Dir(d) {
			if files[d] {
				return nil, nil, reject("archive has %q as a file and a directory", d)
			}
		}
	}
	var dropped []string
	for _, f := range zr.File {
		if f.Mode()&fs.ModeSymlink != 0 {
			dropped = append(dropped, f.Name)
		}
	}
	if len(dropped) == 0 {
		return data, nil, nil
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		if f.Mode()&fs.ModeSymlink != 0 {
			continue
		}
		if err := zw.Copy(f); err != nil {
			return nil, nil, err
		}
	}
	if err := zw.SetComment(zr.Comment); err != nil {
		return nil, nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), dropped, nil
}
