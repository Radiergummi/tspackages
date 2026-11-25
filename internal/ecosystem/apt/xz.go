package apt

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ulikunitz/xz"
)

const (
	// maxControlDict caps the LZMA2 dictionary of an uploaded control
	// tarball; xz -9 uses 64MiB, dpkg-deb's default 8MiB.
	maxControlDict = 8 << 20
	// maxIndexDict caps the LZMA2 dictionary of an upstream Packages.xz.
	maxIndexDict = 64 << 20
)

// newXZReader decompresses r, failing before the decoder allocates a
// dictionary larger than maxDict: the decoder allocates whatever a block
// header asks for, up to 4GiB, before it reads any data.
func newXZReader(r io.Reader, maxDict int64) (io.Reader, error) {
	return xz.NewReader(&xzGuard{r: bufio.NewReader(r), maxDict: maxDict, next: (*xzGuard).streamHeader})
}

// xzGuard passes an xz file through unchanged while it walks the container
// format: stream headers, block headers, LZMA2 chunk headers (whose sizes
// let it skip the compressed data), block padding and checks, indexes,
// footers and stream padding. It fails on a block whose LZMA2 dictionary
// exceeds maxDict, before passing that block's header on.
type xzGuard struct {
	r        *bufio.Reader
	maxDict  int64
	out      []byte // structure read and checked, not yet passed on
	pass     int64  // opaque bytes to pass on before the next structure
	next     func(*xzGuard) error
	err      error
	check    int   // the stream's check size
	blockLen int64 // bytes of the current block so far, header included
}

func (g *xzGuard) Read(p []byte) (int, error) {
	for len(g.out) == 0 && g.pass == 0 {
		if g.err != nil {
			return 0, g.err
		}
		if g.err = g.next(g); g.err != nil {
			// Nothing of a rejected structure reaches the decoder.
			g.out, g.pass = nil, 0
		}
	}
	if len(g.out) > 0 {
		n := copy(p, g.out)
		g.out = g.out[n:]
		return n, nil
	}
	n, err := g.r.Read(p[:min(int64(len(p)), g.pass)])
	g.pass -= int64(n)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

// take reads n bytes of structure and queues them for the decoder.
func (g *xzGuard) take(n int) ([]byte, error) {
	start := len(g.out)
	g.out = append(g.out, make([]byte, n)...)
	if _, err := io.ReadFull(g.r, g.out[start:]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return g.out[start:], nil
}

// uvarint reads a multibyte integer of the xz format (at most 9 bytes).
func (g *xzGuard) uvarint() (uint64, int, error) {
	var x uint64
	for i := range 9 {
		b, err := g.take(1)
		if err != nil {
			return 0, 0, err
		}
		x |= uint64(b[0]&0x7f) << (7 * i)
		if b[0]&0x80 == 0 {
			return x, i + 1, nil
		}
	}
	return 0, 0, errors.New("xz: integer too long")
}

func (g *xzGuard) streamHeader() error {
	h, err := g.take(12)
	if err != nil {
		return err
	}
	if !bytes.Equal(h[:6], []byte("\xfd7zXZ\x00")) || h[6] != 0 || h[7] > 0x0f {
		return errors.New("xz: bad stream header")
	}
	g.check = [16]int{0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64}[h[7]]
	g.next = (*xzGuard).blockOrIndex
	return nil
}

func (g *xzGuard) blockOrIndex() error {
	b, err := g.take(1)
	if err != nil {
		return err
	}
	if b[0] == 0 {
		return g.index()
	}
	size := (int(b[0]) + 1) * 4
	h, err := g.take(size - 1)
	if err != nil {
		return err
	}
	flags, h := h[0], h[1:len(h)-4] // without the CRC32
	if flags&0x3c != 0 {
		return errors.New("xz: bad block flags")
	}
	r := bytes.NewReader(h)
	for _, present := range []bool{flags&0x40 != 0, flags&0x80 != 0} { // compressed, uncompressed size
		if present {
			if _, err := binary.ReadUvarint(r); err != nil {
				return errors.New("xz: bad block header")
			}
		}
	}
	// Filters: only one, LZMA2, as the decoder supports.
	id, err1 := binary.ReadUvarint(r)
	n, err2 := binary.ReadUvarint(r)
	props, err3 := r.ReadByte()
	if flags&0x03 != 0 || err1 != nil || err2 != nil || err3 != nil || id != 0x21 || n != 1 {
		return errors.New("xz: unsupported block filters")
	}
	if props > 40 {
		return errors.New("xz: bad LZMA2 dictionary size")
	}
	dict := int64(0xffffffff)
	if props < 40 {
		dict = int64(2|props&1) << (props/2 + 11)
	}
	if dict > g.maxDict {
		return fmt.Errorf("xz: LZMA2 dictionary of %d bytes exceeds %d", dict, g.maxDict)
	}
	g.blockLen = int64(size)
	g.next = (*xzGuard).chunk
	return nil
}

func (g *xzGuard) chunk() error {
	c, err := g.take(1)
	if err != nil {
		return err
	}
	g.blockLen++
	switch ctl := c[0]; {
	case ctl == 0: // end of block
		if _, err := g.take(int((4-g.blockLen%4)%4) + g.check); err != nil {
			return err
		}
		g.next = (*xzGuard).blockOrIndex
	case ctl == 1 || ctl == 2: // uncompressed chunk
		s, err := g.take(2)
		if err != nil {
			return err
		}
		g.pass = int64(binary.BigEndian.Uint16(s)) + 1
		g.blockLen += 2 + g.pass
	case ctl >= 0x80: // LZMA chunk
		n := 4
		if ctl >= 0xc0 {
			n = 5 // with properties
		}
		s, err := g.take(n)
		if err != nil {
			return err
		}
		g.pass = int64(binary.BigEndian.Uint16(s[2:4])) + 1
		g.blockLen += int64(n) + g.pass
	default:
		return errors.New("xz: bad LZMA2 chunk")
	}
	return nil
}

// index reads the index, whose indicator byte take has read, and the
// stream footer.
func (g *xzGuard) index() error {
	size := int64(1)
	records, n, err := g.uvarint()
	if err != nil {
		return err
	}
	size += int64(n)
	for range 2 * records {
		if _, n, err = g.uvarint(); err != nil {
			return err
		}
		size += int64(n)
	}
	if _, err := g.take(int((4-size%4)%4) + 4 + 12); err != nil { // padding, CRC32, footer
		return err
	}
	g.next = (*xzGuard).streamPadding
	return nil
}

// streamPadding reads zero padding in groups of four, then another stream
// or the end.
func (g *xzGuard) streamPadding() error {
	b, err := g.r.Peek(4)
	if len(b) == 0 && errors.Is(err, io.EOF) {
		return io.EOF
	}
	if bytes.Equal(b, []byte{0, 0, 0, 0}) {
		_, err := g.take(4)
		return err
	}
	return g.streamHeader()
}
