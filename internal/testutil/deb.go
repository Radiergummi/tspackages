package testutil

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// DebOptions tunes Deb.
type DebOptions struct {
	// Compression of control.tar: "gz" (default), "xz", "zst" or "none".
	Compression string
}

// Deb builds a .deb whose control file is the given text: an ar archive with
// debian-binary, control.tar.<ext> holding ./control, and a data.tar.gz with
// one file.
func Deb(t testing.TB, control string, opts DebOptions) []byte {
	t.Helper()
	comp := opts.Compression
	if comp == "" {
		comp = "gz"
	}
	ctl := Tar(t, map[string]string{"./control": control})
	ext := map[string]string{"gz": ".gz", "xz": ".xz", "zst": ".zst", "none": ""}[comp]
	var cb []byte
	switch comp {
	case "none":
		cb = ctl
	case "gz", "xz", "zst":
		cb = compress(t, comp, ctl)
	default:
		t.Fatalf("testutil.Deb: unknown compression %q", comp)
	}
	data := compress(t, "gz", Tar(t, map[string]string{"./usr/share/doc/x": "x\n"}))
	return Ar(t, [][2]string{
		{"debian-binary", "2.0\n"},
		{"control.tar" + ext, string(cb)},
		{"data.tar.gz", string(data)},
	})
}

// Ar writes an ar archive of the members (name, content) in order.
func Ar(t testing.TB, members [][2]string) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, m := range members {
		fmt.Fprintf(&b, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", m[0], 0, 0, 0, "100644", len(m[1]))
		b.WriteString(m[1])
		if len(m[1])%2 == 1 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// Tar writes a tar archive of regular files; map order is not significant to
// callers with one file.
func Tar(t testing.TB, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for name, body := range files {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func compress(t testing.TB, kind string, in []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	var w interface {
		Write([]byte) (int, error)
		Close() error
	}
	var err error
	switch kind {
	case "gz":
		w = gzip.NewWriter(&b)
	case "xz":
		w, err = xz.NewWriter(&b)
	case "zst":
		w, err = zstd.NewWriter(&b)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(in); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Gzip compresses in; exported so tests can build bombs and odd members.
func Gzip(t testing.TB, in []byte) []byte { return compress(t, "gz", in) }
