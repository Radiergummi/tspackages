package npm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/radiergummi/tspackages/internal/resolve"
)

// walked is what walkPackument collected besides the versions.
type walked struct {
	name     string
	top      map[string]json.RawMessage // kept top-level fields
	tags     map[string]string
	times    map[string]string
	versions int // entries of "versions"
}

var (
	errMalformed = errors.New("malformed JSON")
	errTooDeep   = fmt.Errorf("nesting exceeds %d", maxDepth)
)

// walkPackument scans an upstream packument without decoding it whole. It
// calls onVersion for every entry of "versions" with its raw object, or nil
// when that exceeds MaxVersionBytes, and buffers the kept top-level fields,
// "dist-tags" and "time".
func walkPackument(r io.Reader, onVersion func(key string, raw []byte) error) (walked, error) {
	sc := &scanner{r: bufio.NewReaderSize(r, 64<<10)}
	w := walked{top: map[string]json.RawMessage{}}
	err := sc.object(nil, 0, func(key string) error {
		switch {
		case key == "versions":
			c := &capture{limit: MaxVersionBytes}
			return sc.object(nil, 1, func(v string) error {
				if w.versions++; w.versions > maxVersions {
					return fmt.Errorf("more than %d versions", maxVersions)
				}
				c.buf, c.over = c.buf[:0], false
				if err := sc.value(c, 2); err != nil {
					return err
				}
				var raw []byte
				if !c.over {
					raw = c.buf
				}
				return onVersion(v, raw)
			})
		case key == "dist-tags":
			m, err := sc.stringMap(maxDistTagsBytes, maxDistTags)
			w.tags = m
			return err
		case key == "time":
			m, err := sc.stringMap(maxTimeBytes, maxVersions+2)
			w.times = m
			return err
		case slices.Contains(fullTopFields, key):
			c := &capture{limit: maxTopBytes}
			if err := sc.value(c, 1); err != nil {
				return err
			}
			if c.over {
				return fmt.Errorf("top-level field %s exceeds %d bytes", key, maxTopBytes)
			}
			w.top[key] = c.buf
			if key == "name" {
				_ = json.Unmarshal(c.buf, &w.name) // a non-string name matches no package
			}
			return nil
		default:
			return sc.value(nil, 1)
		}
	})
	if err != nil {
		return w, err
	}
	if _, err := sc.next(); !errors.Is(err, io.EOF) {
		return w, fmt.Errorf("%w: data after the document", errMalformed)
	}
	return w, nil
}

// stringMap reads an object value of at most limit bytes and n entries and
// keeps its string members.
func (sc *scanner) stringMap(limit, n int) (map[string]string, error) {
	c := &capture{limit: limit}
	if err := sc.value(c, 1); err != nil {
		return nil, err
	}
	if c.over {
		return nil, fmt.Errorf("object exceeds %d bytes", limit)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(c.buf, &raw); err != nil {
		return nil, err
	}
	if len(raw) > n {
		return nil, fmt.Errorf("object has more than %d entries", n)
	}
	m := make(map[string]string, len(raw))
	for k, v := range raw {
		var str string
		if json.Unmarshal(v, &str) == nil {
			m[k] = str
		}
	}
	return m, nil
}

// findVersion scans a cached full document (as DocWriter writes it,
// "versions" first) for version v.
func findVersion(r io.Reader, v string) ([]byte, error) {
	sc := &scanner{r: bufio.NewReaderSize(r, 64<<10)}
	var obj []byte
	found := false
	errStop := errors.New("stop")
	err := sc.object(nil, 0, func(key string) error {
		if key != "versions" {
			return fmt.Errorf("%w: cached document does not start with versions", errMalformed)
		}
		err := sc.object(nil, 1, func(k string) error {
			if k != v {
				return sc.value(nil, 2)
			}
			c := &capture{limit: MaxVersionBytes}
			if err := sc.value(c, 2); err != nil {
				return err
			}
			obj, found = c.buf, true
			return errStop
		})
		if err == nil {
			err = errStop
		}
		return err
	})
	switch {
	case errors.Is(err, errStop) && found:
		return obj, nil
	case errors.Is(err, errStop):
		return nil, fmt.Errorf("%w: version %s", resolve.ErrNotFound, v)
	}
	return nil, fmt.Errorf("%w: %v", errCacheGone, err) //nolint:errorlint // an unreadable cached document is rebuilt, whatever the cause
}

// capture collects the raw bytes of a value up to limit; past it, it drops
// them and sets over.
type capture struct {
	buf   []byte
	limit int
	over  bool
}

func (c *capture) add(b []byte) {
	if c == nil || c.over {
		return
	}
	if len(c.buf)+len(b) > c.limit {
		c.over, c.buf = true, c.buf[:0]
		return
	}
	c.buf = append(c.buf, b...)
}

func (c *capture) addByte(b byte) {
	if c == nil || c.over {
		return
	}
	if len(c.buf) >= c.limit {
		c.over, c.buf = true, c.buf[:0]
		return
	}
	c.buf = append(c.buf, b)
}

// scanner is a JSON tokenizer that skips or copies values without
// buffering them. It checks structure, nesting and key length; captured
// values are validated again by whoever decodes them.
type scanner struct{ r *bufio.Reader }

// next consumes and returns the next byte after whitespace.
func (sc *scanner) next() (byte, error) {
	for {
		b, err := sc.r.ReadByte()
		if err != nil {
			return 0, err
		}
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return b, nil
	}
}

func (sc *scanner) peek() (byte, error) {
	b, err := sc.next()
	if err == nil {
		_ = sc.r.UnreadByte() // undoes the ReadByte above
	}
	return b, err
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// object reads an object at the given depth (containers already open),
// calling member for each key with the scanner positioned at its value,
// which member must consume.
func (sc *scanner) object(c *capture, depth int, member func(key string) error) error {
	b, err := sc.next()
	if err != nil {
		return unexpected(err)
	}
	if b != '{' {
		return fmt.Errorf("%w: want an object", errMalformed)
	}
	if depth >= maxDepth {
		return errTooDeep
	}
	c.addByte('{')
	if p, err := sc.peek(); err != nil {
		return unexpected(err)
	} else if p == '}' {
		_, _ = sc.r.ReadByte()
		c.addByte('}')
		return nil
	}
	for {
		key, err := sc.key(c)
		if err != nil {
			return err
		}
		if b, err := sc.next(); err != nil {
			return unexpected(err)
		} else if b != ':' {
			return fmt.Errorf("%w: want ':'", errMalformed)
		}
		c.addByte(':')
		if err := member(key); err != nil {
			return err
		}
		b, err := sc.next()
		if err != nil {
			return unexpected(err)
		}
		c.addByte(b)
		switch b {
		case '}':
			return nil
		case ',':
		default:
			return fmt.Errorf("%w: want ',' or '}'", errMalformed)
		}
	}
}

// key reads an object key of at most maxKeyBytes.
func (sc *scanner) key(c *capture) (string, error) {
	b, err := sc.next()
	if err != nil {
		return "", unexpected(err)
	}
	if b != '"' {
		return "", fmt.Errorf("%w: want a key", errMalformed)
	}
	c.addByte('"')
	raw := []byte{'"'}
	if err := sc.stringRest(c, &raw); err != nil {
		return "", err
	}
	var k string
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", fmt.Errorf("%w: key: %w", errMalformed, err)
	}
	return k, nil
}

// stringRest reads a string after its opening quote. keep, when not nil,
// collects it and caps it at maxKeyBytes.
func (sc *scanner) stringRest(c *capture, keep *[]byte) error {
	for {
		if _, err := sc.r.Peek(1); err != nil {
			return unexpected(err)
		}
		buf, _ := sc.r.Peek(sc.r.Buffered())
		i := bytes.IndexByte(buf, '"')
		chunk := buf
		if i >= 0 {
			chunk = buf[:i]
		}
		if j := bytes.IndexByte(chunk, '\\'); j >= 0 {
			chunk, i = chunk[:j], j
		}
		if keep != nil {
			if len(*keep)+len(chunk) > maxKeyBytes {
				return fmt.Errorf("key exceeds %d bytes", maxKeyBytes)
			}
			*keep = append(*keep, chunk...)
		}
		c.add(chunk)
		_, _ = sc.r.Discard(len(chunk)) // buffered
		if i < 0 {
			continue
		}
		b, _ := sc.r.ReadByte() // buffered
		c.addByte(b)
		if keep != nil {
			*keep = append(*keep, b)
		}
		if b == '"' {
			return nil
		}
		esc, err := sc.r.ReadByte()
		if err != nil {
			return unexpected(err)
		}
		c.addByte(esc)
		if keep != nil {
			*keep = append(*keep, esc)
		}
	}
}

// value reads one value at the given depth.
func (sc *scanner) value(c *capture, depth int) error {
	b, err := sc.peek()
	if err != nil {
		return unexpected(err)
	}
	switch {
	case b == '{':
		return sc.object(c, depth, func(string) error { return sc.value(c, depth+1) })
	case b == '[':
		_, _ = sc.r.ReadByte()
		if depth >= maxDepth {
			return errTooDeep
		}
		c.addByte('[')
		if p, err := sc.peek(); err != nil {
			return unexpected(err)
		} else if p == ']' {
			_, _ = sc.r.ReadByte()
			c.addByte(']')
			return nil
		}
		for {
			if err := sc.value(c, depth+1); err != nil {
				return err
			}
			b, err := sc.next()
			if err != nil {
				return unexpected(err)
			}
			c.addByte(b)
			switch b {
			case ']':
				return nil
			case ',':
			default:
				return fmt.Errorf("%w: want ',' or ']'", errMalformed)
			}
		}
	case b == '"':
		_, _ = sc.r.ReadByte()
		c.addByte('"')
		return sc.stringRest(c, nil)
	case b == 't' || b == 'f' || b == 'n':
		lit := map[byte]string{'t': "true", 'f': "false", 'n': "null"}[b]
		got := make([]byte, len(lit))
		if _, err := io.ReadFull(sc.r, got); err != nil {
			return unexpected(err)
		}
		if string(got) != lit {
			return fmt.Errorf("%w: bad literal", errMalformed)
		}
		c.add(got)
		return nil
	case b == '-' || b >= '0' && b <= '9':
		for {
			b, err := sc.r.ReadByte()
			if err != nil {
				return unexpected(err) // a number never ends the document
			}
			if b != '+' && b != '-' && b != '.' && b != 'e' && b != 'E' && (b < '0' || b > '9') {
				_ = sc.r.UnreadByte()
				return nil
			}
			c.addByte(b)
		}
	}
	return fmt.Errorf("%w: unexpected %q", errMalformed, b)
}
