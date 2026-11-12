package goproxy

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// manyEntryZip returns a zip of n empty stored files named by name, as
// archive/zip writes it (with zip64 end records from 65,535 entries on).
func manyEntryZip(t testing.TB, n int, name func(int) string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := range n {
		if _, err := w.CreateRaw(&zip.FileHeader{Name: name(i), Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// plainEnd replaces z's end records (zip64 included) with one classic end
// record that declares count entries, truncated to 16 bits, and a central
// directory of dirSize bytes; archive/zip can't write that itself.
func plainEnd(t testing.TB, z []byte, count int, dirSize uint32) []byte {
	t.Helper()
	end := z[len(z)-22:]
	if binary.LittleEndian.Uint32(end) != 0x06054b50 {
		t.Fatal("no end record at the end")
	}
	size := binary.LittleEndian.Uint32(end[12:])
	offset := binary.LittleEndian.Uint32(end[16:])
	dirSize = min(size, dirSize)
	out := bytes.Clone(z[:offset+dirSize])
	rec := make([]byte, 22)
	binary.LittleEndian.PutUint32(rec, 0x06054b50)
	binary.LittleEndian.PutUint16(rec[8:], uint16(count))  //nolint:gosec // the wrap is the point
	binary.LittleEndian.PutUint16(rec[10:], uint16(count)) //nolint:gosec // the wrap is the point
	binary.LittleEndian.PutUint32(rec[12:], dirSize)
	binary.LittleEndian.PutUint32(rec[16:], offset)
	return append(out, rec...)
}

func writeTemp(t testing.TB, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "m.zip")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCountZipEntries(t *testing.T) {
	short := func(i int) string { return fmt.Sprintf("f%d", i) }

	// 70,000 entries, end record count 70,000 mod 65,536 = 4,464.
	wrapped := plainEnd(t, manyEntryZip(t, 70_000, short), 70_000, ^uint32(0))
	if c := binary.LittleEndian.Uint16(wrapped[len(wrapped)-12:]); c != 4464 {
		t.Fatalf("fixture count %d", c)
	}
	// archive/zip reads all of them despite the declared 4,464.
	if zr, err := zip.NewReader(bytes.NewReader(wrapped), int64(len(wrapped))); err != nil || len(zr.File) != 70_000 {
		t.Fatalf("archive/zip: %v", err)
	}
	if n, err := countZipEntries(writeTemp(t, wrapped)); err != nil || n != 70_000 {
		t.Fatalf("wrapped: %d, %v", n, err)
	}

	// Over the cap, written with zip64 end records.
	if n, err := countZipEntries(writeTemp(t, manyEntryZip(t, maxZipEntries+1, short))); err == nil {
		t.Fatalf("over the cap: %d entries accepted", n)
	}
	if n, err := countZipEntries(writeTemp(t, manyEntryZip(t, maxZipEntries, short))); err != nil || n != maxZipEntries {
		t.Fatalf("at the cap: %d, %v", n, err)
	}

	// Three entries, the last directory header cut off: two found, three declared.
	three := manyEntryZip(t, 3, short)
	hdr := uint32(46 + len("f2"))
	end := three[len(three)-22:]
	full := binary.LittleEndian.Uint32(end[12:])
	if n, err := countZipEntries(writeTemp(t, plainEnd(t, three, 3, full-hdr))); err == nil {
		t.Fatalf("truncated directory: %d entries accepted", n)
	}
	if n, err := countZipEntries(writeTemp(t, plainEnd(t, three, 3, full))); err != nil || n != 3 {
		t.Fatalf("intact: %d, %v", n, err)
	}

	// No end record.
	if _, err := countZipEntries(writeTemp(t, three[:len(three)-22])); err == nil {
		t.Fatal("no end record accepted")
	}
}
