package archive

import (
	"archive/zip"
	"bytes"
	"errors"
	"io/fs"
	"strconv"
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
		many[i] = entry{name: "d" + strconv.Itoa(i) + "/f"}
	}
	big := Limits{MaxBytes: 1 << 30, MaxDecompressed: 1 << 30, MaxEntries: 20000}
	dupJSON := makeZip(t, entry{name: "composer.json", body: "{}"}, entry{name: "composer.json", body: "{\"x\":1}"})
	tests := []struct {
		name   string
		data   []byte
		limits Limits
		reason string // "" = accepted; otherwise a substring of Error.Reason
	}{
		{"normal", makeZip(t, entry{name: "composer.json", body: "{}"}, entry{name: "src/", body: ""}, entry{name: "src/a.php", body: "<?php", mode: 0o755}), testLimits, ""},
		{"dotdot", makeZip(t, entry{name: "../evil", body: "x"}), testLimits, "not allowed"},
		{"dotdot nested", makeZip(t, entry{name: "a/../../evil", body: "x"}), testLimits, "not canonical"},
		{"absolute", makeZip(t, entry{name: "/abs", body: "x"}), testLimits, "not allowed"},
		{"backslash", makeZip(t, entry{name: `a\b`, body: "x"}), testLimits, "not allowed"},
		{"drive prefix", makeZip(t, entry{name: "C:evil", body: "x"}), testLimits, "not allowed"},
		{"dot slash", makeZip(t, entry{name: "./composer.json", body: "{}"}), testLimits, "not canonical"},
		{"double slash", makeZip(t, entry{name: "a//b", body: "x"}), testLimits, "not canonical"},
		{"dot", makeZip(t, entry{name: ".", body: ""}), testLimits, "not canonical"},
		{"duplicate", dupJSON, testLimits, "duplicate"},
		{"case duplicate", makeZip(t, entry{name: "composer.json", body: "{}"}, entry{name: "COMPOSER.JSON", body: "{}"}), testLimits, "duplicate"},
		{"symlink", makeZip(t, entry{name: "link", body: "/etc/passwd", mode: fs.ModeSymlink | 0o777}), testLimits, "symlink"},
		{"fifo", makeZip(t, entry{name: "p", body: "", mode: fs.ModeNamedPipe | 0o644}), testLimits, "special"},
		{"device", makeZip(t, entry{name: "d", body: "", mode: fs.ModeDevice | 0o644}), testLimits, "special"},
		{"setuid", makeZip(t, entry{name: "s", body: "x", mode: fs.ModeSetuid | 0o755}), testLimits, "special"},
		{"setgid", makeZip(t, entry{name: "s", body: "x", mode: fs.ModeSetgid | 0o755}), testLimits, "special"},
		{"too many entries", makeZip(t, many...), big, "more than 20000 entries"},
		{"entry declares too much", makeZip(t, entry{name: "a", body: strings.Repeat("a", 2048)}), Limits{MaxBytes: 1 << 20, MaxDecompressed: 1024, MaxEntries: 10}, "entry \"a\" declares"},
		{"declared total too big", makeZip(t, entry{name: "a", body: strings.Repeat("a", 600)}, entry{name: "b", body: strings.Repeat("b", 600)}), Limits{MaxBytes: 1 << 20, MaxDecompressed: 1024, MaxEntries: 10}, "in total"},
		{"lying size", lyingZip(t), Limits{MaxBytes: 1 << 30, MaxDecompressed: 64 << 20, MaxEntries: 10}, "corrupt"},
		{"too large archive", makeZip(t, entry{name: "a", body: "x"}), Limits{MaxBytes: 10, MaxDecompressed: 1 << 20, MaxEntries: 10}, "exceeds 10 bytes"},
		{"not a zip", []byte("hello"), testLimits, "not a valid zip"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zr, err := InspectZip(tc.data, tc.limits)
			if tc.reason == "" {
				if err != nil || zr == nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var ae *Error
			if !errors.As(err, &ae) {
				t.Fatalf("want *Error, got %T %v", err, err)
			}
			if !strings.Contains(ae.Reason, tc.reason) {
				t.Fatalf("reason %q does not contain %q", ae.Reason, tc.reason)
			}
		})
	}
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
