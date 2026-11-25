package apt

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

const (
	maxArMembers    = 16
	maxControlTar   = 4 << 20   // decompressed control.tar
	maxControlFile  = 256 << 10 // ./control
	arHeaderLen     = 60
	debianBinaryVer = "2.0\n"
)

// PublishableFields are the control fields the index keeps, in index order.
// Everything else in an uploaded control file, including any field the server
// sets itself (Filename, Size, SHA256), is dropped.
var PublishableFields = []string{
	"Package", "Source", "Version", "Architecture", "Maintainer", "Installed-Size",
	"Depends", "Pre-Depends", "Recommends", "Suggests", "Enhances", "Breaks",
	"Conflicts", "Replaces", "Provides", "Built-Using", "Static-Built-Using",
	"Multi-Arch", "Section", "Priority", "Homepage", "Description", "Essential",
	"Protected",
}

// Control is what an uploaded .deb declares about itself.
type Control struct {
	Deb    Deb
	Fields Stanza // PublishableFields only, in PublishableFields order
}

func badDeb(format string, a ...any) error {
	return &RequestError{Status: 400, Detail: "invalid .deb: " + fmt.Sprintf(format, a...)}
}

type arMember struct {
	name      string
	off, size int64
}

// Inspect reads the control file of a .deb: the ar container, its control
// tarball and ./control. It never decompresses data.tar. Errors are
// *RequestError with status 400.
func Inspect(r io.ReaderAt, size int64) (Control, error) {
	members, err := arMembers(r, size)
	if err != nil {
		return Control{}, err
	}
	if len(members) < 3 || members[0].name != "debian-binary" {
		return Control{}, badDeb("the first member must be debian-binary")
	}
	if members[0].size != int64(len(debianBinaryVer)) {
		return Control{}, badDeb("unsupported debian-binary")
	}
	ver := make([]byte, len(debianBinaryVer))
	if _, err := r.ReadAt(ver, members[0].off); err != nil || string(ver) != debianBinaryVer {
		return Control{}, badDeb("unsupported debian-binary (want 2.0)")
	}
	ctl := members[1]
	if ctl.name != "control.tar" && !strings.HasPrefix(ctl.name, "control.tar.") {
		return Control{}, badDeb("the second member must be control.tar")
	}
	i := 2
	for i < len(members) && strings.HasPrefix(members[i].name, "_") {
		i++
	}
	if i == len(members) || (members[i].name != "data.tar" && !strings.HasPrefix(members[i].name, "data.tar.")) {
		return Control{}, badDeb("the control.tar must be followed by data.tar")
	}
	for _, m := range members[i+1:] {
		if !strings.HasPrefix(m.name, "_") {
			return Control{}, badDeb("unexpected member %q after data.tar", m.name)
		}
	}
	raw, err := controlFile(io.NewSectionReader(r, ctl.off, ctl.size), strings.TrimPrefix(ctl.name, "control.tar"))
	if err != nil {
		return Control{}, err
	}
	st, err := ParseStanza(raw, maxControlFile)
	if err != nil {
		return Control{}, badDeb("control: %v", err)
	}
	var c Control
	for _, f := range []struct {
		name string
		ok   func(string) bool
		dst  *string
	}{
		{"Package", ValidName, &c.Deb.Name},
		{"Version", ValidVersion, &c.Deb.Version},
		{"Architecture", ValidArch, &c.Deb.Arch},
	} {
		v, ok := st.Get(f.name)
		if !ok || !f.ok(v) {
			return Control{}, badDeb("missing or invalid %s in control", f.name)
		}
		*f.dst = v
	}
	for _, n := range PublishableFields {
		if v, ok := st.Get(n); ok {
			c.Fields = append(c.Fields, Field{n, v})
		}
	}
	return c, nil
}

// arMembers lists the members of an ar archive, checking every header and
// that each member lies within the archive.
func arMembers(r io.ReaderAt, size int64) ([]arMember, error) {
	magic := make([]byte, 8)
	if _, err := r.ReadAt(magic, 0); err != nil || string(magic) != "!<arch>\n" {
		return nil, badDeb("not an ar archive")
	}
	var ms []arMember
	hdr := make([]byte, arHeaderLen)
	for off := int64(8); off < size; {
		if len(ms) == maxArMembers {
			return nil, badDeb("more than %d ar members", maxArMembers)
		}
		if _, err := r.ReadAt(hdr, off); err != nil || string(hdr[58:]) != "`\n" {
			return nil, badDeb("bad ar member header")
		}
		name := strings.TrimRight(string(hdr[:16]), " ")
		if name == "" || strings.Contains(name, "/") {
			return nil, badDeb("bad ar member name %q", name)
		}
		n, err := strconv.ParseInt(strings.TrimRight(string(hdr[48:58]), " "), 10, 64)
		if err != nil || n < 0 {
			return nil, badDeb("bad ar member size")
		}
		off += arHeaderLen
		if n > size-off {
			return nil, badDeb("ar member %q is truncated", name)
		}
		ms = append(ms, arMember{name, off, n})
		off += n + n%2
	}
	return ms, nil
}

// controlFile returns ./control from a control tarball with the given
// compression suffix, reading at most maxControlTar decompressed bytes.
func controlFile(r io.Reader, ext string) ([]byte, error) {
	var dec io.Reader
	switch ext {
	case "":
		dec = r
	case ".gz":
		z, err := gzip.NewReader(r)
		if err != nil {
			return nil, badDeb("control.tar.gz: %v", err)
		}
		defer z.Close()
		dec = z
	case ".xz":
		z, err := xz.NewReader(r)
		if err != nil {
			return nil, badDeb("control.tar.xz: %v", err)
		}
		dec = z
	case ".zst":
		z, err := zstd.NewReader(r, zstd.WithDecoderMaxMemory(maxControlTar), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, badDeb("control.tar.zst: %v", err)
		}
		defer z.Close()
		dec = z
	default:
		return nil, badDeb("unsupported control.tar compression %q", ext)
	}
	lr := &io.LimitedReader{R: dec, N: maxControlTar + 1}
	tr := tar.NewReader(lr)
	for {
		h, err := tr.Next()
		if lr.N <= 0 {
			return nil, badDeb("control.tar exceeds %d bytes decompressed", maxControlTar)
		}
		if errors.Is(err, io.EOF) {
			return nil, badDeb("control.tar has no control file")
		}
		if err != nil {
			return nil, badDeb("control.tar: %v", err)
		}
		if h.Typeflag != tar.TypeReg || (h.Name != "./control" && h.Name != "control") {
			continue
		}
		if h.Size > maxControlFile {
			return nil, badDeb("control exceeds %d bytes", maxControlFile)
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			if lr.N <= 0 {
				return nil, badDeb("control.tar exceeds %d bytes decompressed", maxControlTar)
			}
			return nil, badDeb("control.tar: %v", err)
		}
		return b, nil
	}
}
