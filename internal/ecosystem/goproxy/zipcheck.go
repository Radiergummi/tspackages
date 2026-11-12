package goproxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	modzip "golang.org/x/mod/zip"
)

// maxZipEntries caps the central directory of a registry zip, as the tree
// cap does for git sources.
const maxZipEntries = 100_000

// Zip record layout (APPNOTE 4.3), as archive/zip reads it.
const (
	zipEndSig        = 0x06054b50
	zipEndLen        = 22
	zip64LocatorSig  = 0x07064b50
	zip64LocatorLen  = 20
	zip64EndSig      = 0x06064b50
	zip64EndLen      = 56
	zipDirHeaderSig  = 0x02014b50
	zipDirHeaderLen  = 46
	zipEndSearchSize = 65 * 1024 // archive/zip's largest search window
)

// countZipEntries walks the central directory of the zip at path in
// constant memory and fails once it has seen limit+1 headers.
//
// archive/zip reads directory headers until one fails to parse, past the
// declared count, and compares only the low 16 bits of the two; it loads
// every header it reads. So this pass finds the directory as archive/zip
// does and reads headers the same way, keeping only a count. A directory
// that isn't where the end record puts it (archive/zip would guess a base
// offset) is refused; module zips never have one.
func countZipEntries(path string, limit int) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := fi.Size()
	endOff, records, dirSize, dirOff, err := zipDirectoryEnd(f, size)
	if err != nil {
		return 0, err
	}
	if dirOff > uint64(endOff) || dirSize != uint64(endOff)-dirOff {
		return 0, errors.New("zip central directory is not where the end record says")
	}

	br := bufio.NewReader(io.NewSectionReader(f, int64(dirOff), size-int64(dirOff))) //nolint:gosec // dirOff <= endOff < size
	hdr := make([]byte, zipDirHeaderLen)
	n := 0
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return n, err
		}
		if binary.LittleEndian.Uint32(hdr) != zipDirHeaderSig {
			break
		}
		rest := int(binary.LittleEndian.Uint16(hdr[28:])) + int(binary.LittleEndian.Uint16(hdr[30:])) + int(binary.LittleEndian.Uint16(hdr[32:]))
		if _, err := br.Discard(rest); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return n, err
		}
		n++
		if n > limit {
			return n, fmt.Errorf("zip has more than %d entries", limit)
		}
	}
	if uint16(n) != uint16(records) { //nolint:gosec // archive/zip compares 16 bits
		return n, fmt.Errorf("zip central directory has %d entries, its end record %d", n, records)
	}
	return n, nil
}

// zipDirectoryEnd reads the end of central directory record, and the zip64
// one it points to, as archive/zip's readDirectoryEnd does. endOff is the
// offset of the record that ends the directory.
func zipDirectoryEnd(r io.ReaderAt, size int64) (endOff int64, records, dirSize, dirOff uint64, err error) {
	n := min(size, zipEndSearchSize)
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, size-n); err != nil && !errors.Is(err, io.EOF) {
		return 0, 0, 0, 0, err
	}
	// archive/zip takes the last signature and gives up if its comment
	// runs past the end.
	p := -1
	for i := len(buf) - zipEndLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:]) == zipEndSig {
			if i+zipEndLen+int(binary.LittleEndian.Uint16(buf[i+20:])) <= len(buf) {
				p = i
			}
			break
		}
	}
	if p < 0 {
		return 0, 0, 0, 0, errors.New("zip has no end of central directory record")
	}
	end := buf[p:]
	endOff = size - n + int64(p)
	records = uint64(binary.LittleEndian.Uint16(end[10:]))
	dirSize = uint64(binary.LittleEndian.Uint32(end[12:]))
	dirOff = uint64(binary.LittleEndian.Uint32(end[16:]))
	if records == 0xffff || dirSize == 0xffffffff || dirOff == 0xffffffff {
		if loc := endOff - zip64LocatorLen; loc >= 0 {
			l := make([]byte, zip64LocatorLen)
			if _, err := r.ReadAt(l, loc); err != nil {
				return 0, 0, 0, 0, err
			}
			if binary.LittleEndian.Uint32(l) == zip64LocatorSig && binary.LittleEndian.Uint32(l[4:]) == 0 && binary.LittleEndian.Uint32(l[16:]) == 1 {
				off := binary.LittleEndian.Uint64(l[8:])
				if off > uint64(size) {
					return 0, 0, 0, 0, errors.New("zip64 end record outside the file")
				}
				e := make([]byte, zip64EndLen)
				if _, err := r.ReadAt(e, int64(off)); err != nil {
					return 0, 0, 0, 0, err
				}
				if binary.LittleEndian.Uint32(e) != zip64EndSig {
					return 0, 0, 0, 0, errors.New("zip64 end record has no signature")
				}
				endOff = int64(off)
				records = binary.LittleEndian.Uint64(e[32:])
				dirSize = binary.LittleEndian.Uint64(e[40:])
				dirOff = binary.LittleEndian.Uint64(e[48:])
			}
		}
	}
	return endOff, records, dirSize, dirOff, nil
}

// verifyZip runs countZipEntries, modzip.CheckZip and dirhash.HashZip, and
// fails unless the hash equals want.
func verifyZip(path string, mv module.Version, want string) error {
	if _, err := countZipEntries(path, maxZipEntries); err != nil {
		return err
	}
	if _, err := modzip.CheckZip(mv, path); err != nil {
		return err
	}
	got, err := dirhash.HashZip(path, dirhash.Hash1)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("zip of %s %s hashes to %s, the checksum database says %s", mv.Path, mv.Version, got, want)
	}
	return nil
}

// modHash is the go.sum hash of a go.mod: dirhash.Hash1 over one file named
// "go.mod", as cmd/go's goModSum computes it.
func modHash(gomod []byte) (string, error) {
	return dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(gomod)), nil
	})
}
