package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"strconv"
	"strings"
	"testing"
)

type tarEntry struct {
	name, body string
	typ        byte
	link       string
}

func makeTarGz(t testing.TB, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o644, Size: int64(len(e.body)), Linkname: e.link}
		if typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func wantPKGINFO(name string) bool {
	return strings.HasSuffix(name, "/PKG-INFO") && strings.Count(name, "/") == 1
}

func TestInspectTarGz(t *testing.T) {
	ok := makeTarGz(t, tarEntry{name: "pkg-1.0/", typ: tar.TypeDir}, tarEntry{name: "pkg-1.0/PKG-INFO", body: "Name: pkg"}, tarEntry{name: "pkg-1.0/src/a.py", body: "x"})
	got, err := InspectTarGz(bytes.NewReader(ok), testLimits, wantPKGINFO)
	if err != nil || string(got["pkg-1.0/PKG-INFO"]) != "Name: pkg" || len(got) != 1 {
		t.Fatalf("normal sdist: %v %v", got, err)
	}
	many := make([]tarEntry, 0, 20001)
	for i := range 20001 {
		many = append(many, tarEntry{name: "p/f" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + "/" + strconv.Itoa(i), body: ""})
	}
	bomb := makeTarGz(t, tarEntry{name: "p/big", body: strings.Repeat("0", 20<<20)})
	for name, data := range map[string][]byte{
		"dotdot":    makeTarGz(t, tarEntry{name: "p/../x", body: "x"}),
		"absolute":  makeTarGz(t, tarEntry{name: "/abs", body: "x"}),
		"backslash": makeTarGz(t, tarEntry{name: `p\x`, body: "x"}),
		"symlink":   makeTarGz(t, tarEntry{name: "p/l", typ: tar.TypeSymlink, link: "/etc/passwd"}),
		"hardlink":  makeTarGz(t, tarEntry{name: "p/h", typ: tar.TypeLink, link: "p/x"}),
		"device":    makeTarGz(t, tarEntry{name: "p/d", typ: tar.TypeChar}),
		"fifo":      makeTarGz(t, tarEntry{name: "p/f", typ: tar.TypeFifo}),
		"duplicate": makeTarGz(t, tarEntry{name: "p/a", body: "1"}, tarEntry{name: "p/A", body: "2"}),
		"too many":  makeTarGz(t, many...),
		"gzip bomb": bomb,
		"not gzip":  []byte("plain text"),
		"not tar":   gzipOf(t, []byte(strings.Repeat("garbage", 200))),
	} {
		if _, err := InspectTarGz(bytes.NewReader(data), Limits{MaxBytes: 64 << 20, MaxDecompressed: 16 << 20, MaxEntries: 20000}, wantPKGINFO); !errors.As(err, new(*Error)) {
			t.Errorf("%s: err = %v, want *archive.Error", name, err)
		}
	}
	if _, err := InspectTarGz(bytes.NewReader(ok), Limits{MaxBytes: 10, MaxDecompressed: 1 << 20, MaxEntries: 10}, wantPKGINFO); !errors.As(err, new(*Error)) {
		t.Errorf("compressed size over MaxBytes: %v", err)
	}
}

func gzipOf(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(b)
	gz.Close()
	return buf.Bytes()
}
