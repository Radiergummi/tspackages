package maven

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// XMLLimits cap an XML document: its size in bytes, element nesting depth
// and element count. ASCIILabels accepts any declared encoding for a
// document whose every byte is ASCII, which reads the same in it.
type XMLLimits struct {
	MaxBytes    int64
	MaxDepth    int
	MaxElements int
	ASCIILabels bool
}

var (
	// UploadXML caps uploaded POMs and maven-metadata.xml.
	UploadXML = XMLLimits{MaxBytes: 1 << 20, MaxDepth: 32, MaxElements: 10000}
	// UpstreamXML caps maven-metadata.xml read from upstreams.
	UpstreamXML = XMLLimits{MaxBytes: 4 << 20, MaxDepth: 32, MaxElements: 10000, ASCIILabels: true}
)

// XMLError is why an XML document was refused.
type XMLError struct{ Reason string }

func (e *XMLError) Error() string { return "invalid XML: " + e.Reason }

func xmlErrorf(format string, args ...any) *XMLError {
	return &XMLError{Reason: fmt.Sprintf(format, args...)}
}

var (
	utf8BOM    = []byte{0xef, 0xbb, 0xbf}
	utf16BEBOM = []byte{0xfe, 0xff}
	utf16LEBOM = []byte{0xff, 0xfe}
)

// DecodeXML decodes r into v after rejecting <!DOCTYPE, <!ENTITY and any
// processing instruction other than the leading <?xml?> declaration, and
// enforcing l. The document is UTF-8, with or without a BOM; another
// declared encoding is an error naming it, unless l.ASCIILabels allows it
// for an ASCII document. Errors are *XMLError.
func DecodeXML(r io.Reader, l XMLLimits, v any) error {
	doc, err := scanXML(r, l, "")
	if err != nil {
		return err
	}
	if err := newXMLDecoder(doc, l).Decode(v); err != nil {
		return xmlErrorf("%v", err)
	}
	return nil
}

// CheckXML checks what DecodeXML checks, and that the root element's local
// name is root, without decoding the document.
func CheckXML(r io.Reader, l XMLLimits, root string) error {
	_, err := scanXML(r, l, root)
	return err
}

func newXMLDecoder(doc []byte, l XMLLimits) *xml.Decoder {
	d := xml.NewDecoder(bytes.NewReader(doc))
	d.CharsetReader = func(label string, r io.Reader) (io.Reader, error) {
		if l.ASCIILabels && isASCII(doc) {
			return r, nil
		}
		return nil, fmt.Errorf("encoding %s is not supported, only UTF-8", label)
	}
	return d
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

// scanXML reads at most l.MaxBytes of r, checks the document and returns
// it without a UTF-8 BOM. A non-empty root must be the root element's local
// name.
func scanXML(r io.Reader, l XMLLimits, root string) ([]byte, error) {
	doc, err := io.ReadAll(io.LimitReader(r, l.MaxBytes+1))
	if err != nil {
		return nil, xmlErrorf("reading: %v", err)
	}
	if int64(len(doc)) > l.MaxBytes {
		return nil, xmlErrorf("larger than %d bytes", l.MaxBytes)
	}
	if bytes.HasPrefix(doc, utf16BEBOM) || bytes.HasPrefix(doc, utf16LEBOM) {
		return nil, xmlErrorf("encoding UTF-16 is not supported, only UTF-8")
	}
	doc = bytes.TrimPrefix(doc, utf8BOM)

	d := newXMLDecoder(doc, l)
	depth, elements := 0, 0
	sawRoot := false
	for first := true; ; first = false {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, xmlErrorf("%v", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				if sawRoot {
					return nil, xmlErrorf("more than one root element")
				}
				sawRoot = true
				if root != "" && t.Name.Local != root {
					return nil, xmlErrorf("root element is <%s>, want <%s>", t.Name.Local, root)
				}
			}
			depth++
			elements++
			if depth > l.MaxDepth {
				return nil, xmlErrorf("nested deeper than %d elements", l.MaxDepth)
			}
			if elements > l.MaxElements {
				return nil, xmlErrorf("more than %d elements", l.MaxElements)
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				return nil, xmlErrorf("text outside the root element")
			}
		case xml.ProcInst:
			if !first || t.Target != "xml" {
				return nil, xmlErrorf("processing instruction <?%s?>", t.Target)
			}
		case xml.Directive:
			return nil, xmlErrorf("directive <!%s>", firstWord(t))
		case xml.Comment:
		}
	}
	if !sawRoot {
		return nil, xmlErrorf("no root element")
	}
	return doc, nil
}

// firstWord is the start of a directive, such as DOCTYPE or ENTITY.
func firstWord(b []byte) string {
	w, _, _ := strings.Cut(string(b), " ")
	if len(w) > 16 {
		w = w[:16]
	}
	return w
}
