package archive

import (
	"archive/zip"
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

var testLimits = Limits{MaxBytes: 1 << 20, MaxDecompressed: 16 << 20, MaxEntries: 20000}

type entry struct {
	name string
	body string
	mode fs.FileMode
}

func makeZip(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// lyingZip builds a zip whose single entry declares 1 KiB but inflates to
// 10 MiB by patching the declared sizes in the local and central headers.
func lyingZip(t *testing.T) []byte {
	t.Helper()
	const real = 10 << 20
	data := makeZip(t, entry{name: "big.bin", body: strings.Repeat("a", real)})
	patch := func(sig []byte, off int) {
		i := bytes.Index(data, sig)
		if i < 0 {
			t.Fatal("signature not found")
		}
		// uncompressed size field
		data[i+off] = 0x00
		data[i+off+1] = 0x04
		data[i+off+2] = 0
		data[i+off+3] = 0
	}
	patch([]byte("PK\x03\x04"), 22)
	patch([]byte("PK\x01\x02"), 24)
	return data
}

func TestInspectZip(t *testing.T) {
	many := make([]entry, 20001)
	for i := range many {
		many[i] = entry{name: "f" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + "/" + itoa(i)}
	}
	tests := []struct {
		name    string
		data    []byte
		limits  Limits
		wantErr bool
	}{
		{"normal", makeZip(t, entry{name: "composer.json", body: "{}"}, entry{name: "src/a.php", body: "<?php"}), testLimits, false},
		{"dotdot", makeZip(t, entry{name: "../evil", body: "x"}), testLimits, true},
		{"dotdot nested", makeZip(t, entry{name: "a/../../evil", body: "x"}), testLimits, true},
		{"absolute", makeZip(t, entry{name: "/abs", body: "x"}), testLimits, true},
		{"backslash", makeZip(t, entry{name: `a\b`, body: "x"}), testLimits, true},
		{"symlink", makeZip(t, entry{name: "link", body: "/etc/passwd", mode: fs.ModeSymlink | 0o777}), testLimits, true},
		{"too many entries", makeZip(t, many...), testLimits, true},
		{"declared total too big", makeZip(t, entry{name: "a", body: strings.Repeat("a", 2048)}), Limits{MaxBytes: 1 << 20, MaxDecompressed: 1024, MaxEntries: 10}, true},
		{"lying size", lyingZip(t), Limits{MaxBytes: 1 << 20, MaxDecompressed: 64 << 20, MaxEntries: 10}, true},
		{"too large archive", makeZip(t, entry{name: "a", body: "x"}), Limits{MaxBytes: 10, MaxDecompressed: 1 << 20, MaxEntries: 10}, true},
		{"not a zip", []byte("hello"), testLimits, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zr, err := InspectZip(tc.data, tc.limits)
			if !tc.wantErr {
				if err != nil || zr == nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var ae *Error
			if !errors.As(err, &ae) {
				t.Fatalf("want *Error, got %T %v", err, err)
			}
		})
	}
}

func itoa(i int) string {
	const d = "0123456789"
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(d[i%10]) + s
	}
	return s
}

func TestFindFile(t *testing.T) {
	open := func(entries ...entry) *zip.Reader {
		zr, err := InspectZip(makeZip(t, entries...), testLimits)
		if err != nil {
			t.Fatal(err)
		}
		return zr
	}
	t.Run("root", func(t *testing.T) {
		f, err := FindFile(open(entry{name: "composer.json", body: "{}"}, entry{name: "src/a", body: "x"}), "composer.json")
		if err != nil || f.Name != "composer.json" {
			t.Fatalf("%v %v", f, err)
		}
	})
	t.Run("single top dir", func(t *testing.T) {
		f, err := FindFile(open(entry{name: "pkg-1.0/", body: ""}, entry{name: "pkg-1.0/composer.json", body: "{}"}, entry{name: "pkg-1.0/src/a", body: "x"}), "composer.json")
		if err != nil || f.Name != "pkg-1.0/composer.json" {
			t.Fatalf("%v %v", f, err)
		}
	})
	t.Run("two top dirs", func(t *testing.T) {
		_, err := FindFile(open(entry{name: "a/composer.json", body: "{}"}, entry{name: "b/x", body: "x"}), "composer.json")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("deeper nesting is not found", func(t *testing.T) {
		_, err := FindFile(open(entry{name: "a/b/composer.json", body: "{}"}), "composer.json")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	})
}
