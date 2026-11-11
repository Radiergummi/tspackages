package pypi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/gitmirror"
)

// SdistFormat versions the generated sdist bytes. Identity includes it, and
// a change to BuildSdist's output must bump it (the golden test enforces
// that), so a release built by one format is never mistaken for another.
const SdistFormat = 1

// lfsPointer is how a Git LFS pointer file starts.
const lfsPointer = "version https://git-lfs.github.com/spec/v1\n"

// RefusedError is a release that cannot be served as an sdist.
type RefusedError struct{ Reason string }

// MaxGitSdistBytes caps the archive of a package directory the git source
// reads to build an sdist; sdists are built in memory.
const MaxGitSdistBytes = 512 << 20

func (e *RefusedError) Error() string { return e.Reason }

// Identity is a release's identity: a digest over the sdist format, the tree
// entries of the package directory (without excluded member directories)
// and the .gitattributes files that decide its export-ignore rules.
func Identity(entries []gitmirror.TreeEntry, exclude []string, attributes []gitmirror.TreeEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "tspackages-sdist-format %d\n", SdistFormat)
	line := func(e gitmirror.TreeEntry) string {
		return e.Mode + " " + e.Type + " " + e.Object + " " + e.Path + "\n"
	}
	var lines []string
	for _, e := range entries {
		if !excluded(e.Path, exclude) {
			lines = append(lines, line(e))
		}
	}
	slices.Sort(lines)
	for _, l := range lines {
		h.Write([]byte(l))
	}
	h.Write([]byte("attributes\n"))
	lines = lines[:0]
	for _, e := range attributes {
		lines = append(lines, line(e))
	}
	slices.Sort(lines)
	for _, l := range lines {
		h.Write([]byte(l))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func excluded(p string, exclude []string) bool {
	for _, d := range exclude {
		d = strings.TrimSuffix(d, "/")
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// RefuseTree returns why a package directory cannot become an sdist, or "".
func RefuseTree(entries []gitmirror.TreeEntry) string {
	if slices.ContainsFunc(entries, func(e gitmirror.TreeEntry) bool { return e.Type == "commit" }) {
		return "contains submodules, which an sdist cannot include"
	}
	if i := slices.IndexFunc(entries, func(e gitmirror.TreeEntry) bool { return !cleanTreePath(e.Path) }); i >= 0 {
		return fmt.Sprintf("contains an invalid path (%q), which git fsck rejects", entries[i].Path)
	}
	return ""
}

// cleanTreePath reports whether p is a path git fsck accepts: relative,
// without empty, "." or ".." segments.
func cleanTreePath(p string) bool {
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// BuildSdist turns `git archive --format=tar` output of the package's
// directory (the whole tree for a root package) into a deterministic sdist:
// paths moved under <name>-<version>/, excluded member directories and
// symlinks dropped, PKG-INFO added, entries sorted, owner and modes
// normalised, mtimes set to mtime, gzip without name or timestamp. A Git LFS
// pointer file makes it a *RefusedError.
func BuildSdist(gitTar io.Reader, p Package, pkgInfo []byte, mtime time.Time) ([]byte, error) {
	top := strings.TrimSuffix(SdistFilename(p.Name, p.Version), ".tar.gz") + "/"
	prefix := ""
	if p.Dir != "" {
		prefix = p.Dir + "/"
	}
	type file struct {
		name string
		mode int64
		body []byte
	}
	files := []file{{name: top + "PKG-INFO", mode: 0o644, body: pkgInfo}}
	tr := tar.NewReader(gitTar)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read git archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue // directories are implied; symlinks are left out
		}
		rel, ok := strings.CutPrefix(h.Name, prefix)
		if !ok || excluded(h.Name, p.Exclude) || rel == "PKG-INFO" {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read git archive: %w", err)
		}
		if bytes.HasPrefix(body, []byte(lfsPointer)) && len(body) < 1024 {
			return nil, &RefusedError{Reason: "contains Git LFS pointer files (" + h.Name + "), which an sdist cannot resolve"}
		}
		mode := int64(0o644)
		if h.Mode&0o111 != 0 {
			mode = 0o755
		}
		files = append(files, file{name: top + rel, mode: mode, body: body})
	}
	slices.SortFunc(files, func(a, b file) int { return strings.Compare(a.name, b.name) })

	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	gz.OS = 255 // unknown, so the bytes do not depend on the host
	tw := tar.NewWriter(gz)
	mt := time.Unix(mtime.Unix(), 0)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: f.name, Mode: f.mode, Size: int64(len(f.body)),
			ModTime: mt, Format: tar.FormatPAX,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
