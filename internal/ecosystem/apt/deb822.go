package apt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"
	"unicode/utf8"
)

// ErrStanzaTooLarge reports a stanza longer than the reader's cap.
var ErrStanzaTooLarge = errors.New("deb822 stanza too large")

// Field is one deb822 field. Value is the first line (without the space after
// the colon), then "\n" and each continuation line verbatim, leading space or
// tab kept.
type Field struct{ Name, Value string }

// Stanza is the fields of one paragraph in source order.
type Stanza []Field

// Get returns the value of the first field called name, compared
// case-insensitively.
func (s Stanza) Get(name string) (string, bool) {
	for _, f := range s {
		if strings.EqualFold(f.Name, name) {
			return f.Value, true
		}
	}
	return "", false
}

// checkField is the hygiene shared by ParseStanza and WriteStanza: after it
// passes, "Name: value\n" with the continuation lines as stored is a single
// field that no reader can split into more fields or paragraphs. maxField <= 0
// means no size limit.
func checkField(f Field, maxField int) error {
	if !validFieldName(f.Name) {
		return fmt.Errorf("deb822: invalid field name %q", f.Name)
	}
	if maxField > 0 && len(f.Value) > maxField {
		return fmt.Errorf("deb822: field %s exceeds %d bytes", f.Name, maxField)
	}
	if !utf8.ValidString(f.Value) {
		return fmt.Errorf("deb822: field %s is not valid UTF-8", f.Name)
	}
	if strings.ContainsAny(f.Value, "\x00\r") {
		return fmt.Errorf("deb822: field %s contains NUL or CR", f.Name)
	}
	first, rest, multi := strings.Cut(f.Value, "\n")
	if first != "" && (first[0] == ' ' || first[0] == '\t') {
		return fmt.Errorf("deb822: field %s starts with whitespace", f.Name)
	}
	for multi {
		var line string
		line, rest, multi = strings.Cut(rest, "\n")
		if line == "" || (line[0] != ' ' && line[0] != '\t') || strings.TrimLeft(line, " \t") == "" {
			return fmt.Errorf("deb822: field %s has an empty or unindented continuation line", f.Name)
		}
	}
	return nil
}

func validFieldName(n string) bool {
	if n == "" || n[0] == '-' {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// ParseStanza parses exactly one stanza strictly (upload hygiene): it rejects
// empty lines, comments, CR, NUL, invalid UTF-8, malformed or duplicate field
// names and any field of more than maxField bytes. One final newline is
// optional.
func ParseStanza(b []byte, maxField int) (Stanza, error) {
	if len(b) == 0 {
		return nil, errors.New("deb822: empty stanza")
	}
	if bytes.IndexByte(b, 0) >= 0 || bytes.IndexByte(b, '\r') >= 0 {
		return nil, errors.New("deb822: NUL or CR in stanza")
	}
	if !utf8.Valid(b) {
		return nil, errors.New("deb822: stanza is not valid UTF-8")
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	var s Stanza
	for line := range strings.SplitSeq(string(b), "\n") {
		if line == "" {
			return nil, errors.New("deb822: empty line in stanza")
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(s) == 0 {
				return nil, errors.New("deb822: continuation line before any field")
			}
			s[len(s)-1].Value += "\n" + line
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("deb822: line %q has no colon", line)
		}
		s = append(s, Field{name, strings.TrimLeft(value, " \t")})
	}
	for i, f := range s {
		if err := checkField(f, maxField); err != nil {
			return nil, err
		}
		for _, g := range s[:i] {
			if strings.EqualFold(g.Name, f.Name) {
				return nil, fmt.Errorf("deb822: duplicate field %s", f.Name)
			}
		}
	}
	return s, nil
}

// WriteStanza writes s as "Name: value\n" with continuation lines as stored,
// without a trailing blank line. It writes nothing and errors if any field
// fails the hygiene ParseStanza applies, so a field value can never add a
// field or end the paragraph.
func WriteStanza(w io.Writer, s Stanza) error {
	var buf bytes.Buffer
	for _, f := range s {
		if err := checkField(f, 0); err != nil {
			return err
		}
		first, rest, multi := strings.Cut(f.Value, "\n")
		buf.WriteString(f.Name + ":")
		if first != "" {
			buf.WriteString(" " + first)
		}
		buf.WriteByte('\n')
		if multi {
			buf.WriteString(rest + "\n")
		}
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// Stanzas streams the stanzas of an index or Release file. It is lenient about
// what real archives contain (duplicate fields, any bytes but NUL, "#" comment
// lines, runs of blank lines between stanzas) and strict about CR, a line
// without a colon outside a continuation, and a stanza longer than maxStanza
// bytes, which ends the sequence with ErrStanzaTooLarge.
func Stanzas(r io.Reader, maxStanza int) iter.Seq2[Stanza, error] {
	return func(yield func(Stanza, error) bool) {
		br := bufio.NewReaderSize(r, 64<<10)
		var cur Stanza
		size := 0
		flush := func() bool {
			if len(cur) == 0 {
				return true
			}
			s := cur
			cur, size = nil, 0
			return yield(s, nil)
		}
		for {
			line, err := readLine(br, maxStanza-size)
			eof := errors.Is(err, io.EOF)
			if err != nil && (!eof || line == nil) {
				if eof {
					flush()
					return
				}
				yield(nil, err)
				return
			}
			size += len(line) + 1
			text := string(line)
			switch {
			case strings.ContainsAny(text, "\r\x00"):
				yield(nil, errors.New("deb822: CR or NUL in index"))
				return
			case text == "":
				if !flush() {
					return
				}
			case text[0] == '#':
			case text[0] == ' ' || text[0] == '\t':
				if len(cur) == 0 {
					yield(nil, errors.New("deb822: continuation line before any field"))
					return
				}
				cur[len(cur)-1].Value += "\n" + text
			default:
				name, value, ok := strings.Cut(text, ":")
				if !ok || !validFieldName(name) {
					yield(nil, fmt.Errorf("deb822: malformed line %q", truncate(text, 80)))
					return
				}
				cur = append(cur, Field{name, strings.TrimLeft(value, " \t")})
			}
			if eof {
				flush()
				return
			}
		}
	}
}

// readLine returns the next line without its newline, reading at most budget
// bytes of it before failing with ErrStanzaTooLarge. At the end of input it
// returns io.EOF, along with the final unterminated line if there was one.
func readLine(br *bufio.Reader, budget int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > budget {
			return nil, ErrStanzaTooLarge
		}
		switch {
		case err == nil:
			return line[:len(line)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
		case errors.Is(err, io.EOF):
			if len(line) == 0 {
				return nil, io.EOF
			}
			return line, io.EOF
		default:
			return nil, err
		}
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
