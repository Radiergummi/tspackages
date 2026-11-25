package apt

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math/rand/v2"
	"runtime"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"

	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/testutil"
)

// xzBytes compresses b, in blocks of blockSize bytes when it is not 0.
func xzBytes(t *testing.T, b []byte, blockSize int64) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := xz.WriterConfig{BlockSize: blockSize}.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// xzBomb is b compressed, its first block header claiming a 1GiB LZMA2
// dictionary (with a valid CRC32).
func xzBomb(t *testing.T, b []byte) []byte {
	t.Helper()
	out := bytes.Clone(xzBytes(t, b, 0))
	size := (int(out[12]) + 1) * 4
	h := out[12 : 12+size]
	i := bytes.Index(h[2:], []byte{0x21, 0x01})
	if i < 0 {
		t.Fatal("no LZMA2 filter in the block header")
	}
	h[2+i+2] = 36 // 2 << (36/2 + 11) = 1GiB
	binary.LittleEndian.PutUint32(h[size-4:], crc32.ChecksumIEEE(h[:size-4]))
	return out
}

// allocated returns the bytes f allocates.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestXZGuardPasses(t *testing.T) {
	data := []byte(strings.Repeat("Package: acme\nVersion: 1.0\n\n", 2000))
	one := xzBytes(t, data, 0)
	multi := xzBytes(t, data, 4096)
	for name, in := range map[string][]byte{
		"one block":            one,
		"several blocks":       multi,
		"two streams, padding": append(append(bytes.Clone(one), 0, 0, 0, 0), multi...),
		"empty":                xzBytes(t, nil, 0),
	} {
		t.Run(name, func(t *testing.T) {
			want := data
			switch name {
			case "two streams, padding":
				want = append(bytes.Clone(data), data...)
			case "empty":
				want = nil
			}
			r, err := newXZReader(bytes.NewReader(in), maxControlDict)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("read %d bytes, %v; want %d", len(got), err, len(want))
			}
		})
	}
	// Uncompressed LZMA2 chunks: random data does not compress.
	rnd := make([]byte, 200<<10)
	rand.NewChaCha8([32]byte{}).Read(rnd)
	r, err := newXZReader(bytes.NewReader(xzBytes(t, rnd, 0)), maxControlDict)
	if err == nil {
		var got []byte
		got, err = io.ReadAll(r)
		if !bytes.Equal(got, rnd) {
			err = errors.Join(err, errors.New("bytes differ"))
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestXZGuardRejectsLargeDictionary(t *testing.T) {
	data := []byte("Package: acme\n")
	for name, in := range map[string][]byte{
		"first stream":  xzBomb(t, data),
		"second stream": append(xzBytes(t, data, 0), xzBomb(t, data)...),
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			n := allocated(func() {
				var r io.Reader
				if r, err = newXZReader(bytes.NewReader(in), maxIndexDict); err == nil {
					_, err = io.ReadAll(r)
				}
			})
			if err == nil || !strings.Contains(err.Error(), "dictionary") {
				t.Errorf("err = %v, want a dictionary error", err)
			}
			if n > 16<<20 {
				t.Errorf("allocated %d bytes", n)
			}
		})
	}
}

func TestInspectXZBomb(t *testing.T) {
	ctl := xzBomb(t, testutil.Tar(t, map[string]string{"./control": "Package: acme\nVersion: 1.0\nArchitecture: amd64\n"}))
	data := string(testutil.Gzip(t, testutil.Tar(t, map[string]string{"./x": "x"})))
	b := testutil.Ar(t, [][2]string{{"debian-binary", "2.0\n"}, {"control.tar.xz", string(ctl)}, {"data.tar.gz", data}})
	var err error
	n := allocated(func() { _, err = inspect(t, b) })
	var re *RequestError
	if !errors.As(err, &re) || re.Status != 400 || !strings.Contains(err.Error(), "dictionary") {
		t.Errorf("err = %v, want a 400 naming the dictionary", err)
	}
	if n > 16<<20 {
		t.Errorf("allocated %d bytes", n)
	}
}

func TestLookupXZBomb(t *testing.T) {
	e := newRegEnv(t)
	idx := []byte("Package: curl\nVersion: 8.0-1\nArchitecture: amd64\nFilename: " + curlPool + "\nSize: 1\nSHA256: " + strings.Repeat("ab", 32) + "\n")
	bomb := xzBomb(t, idx)
	e.publishIndexAs(t, "main/binary-amd64/Packages.xz", bomb)
	var err error
	n := allocated(func() { _, err = readBlob(e.src.Pool(context.Background(), anyAcc, poolPath(t, curlPool))) })
	if err == nil || errors.Is(err, resolve.ErrNotFound) || !strings.Contains(err.Error(), "dictionary") {
		t.Errorf("err = %v, want a dictionary error", err)
	}
	if n > 16<<20 {
		t.Errorf("allocated %d bytes", n)
	}
}
