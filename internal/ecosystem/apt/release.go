package apt

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaxRelease caps a Release file (and an InRelease).
const MaxRelease = 4 << 20

// releaseDate is how Render writes Date and Valid-Until.
const releaseDate = "Mon, 02 Jan 2006 15:04:05 UTC"

// FileHash is one entry of a Release file's SHA256 list. SHA256 is lowercase
// hex.
type FileHash struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ReleaseDoc is a Release file.
type ReleaseDoc struct {
	Fields     Stanza    // all fields except the hash lists, in order
	Date       time.Time // UTC
	ValidUntil time.Time // UTC; zero = none
	ByHash     bool      // Acquire-By-Hash: yes
	SHA256     []FileHash
}

// ParseRelease parses a Release file (or the signed text of an InRelease) of
// at most MaxRelease bytes: exactly one paragraph with a Date and no field
// twice. Date and Valid-Until are RFC 2822 dates in UTC (zone UTC, GMT, Z or
// +0000). SHA256 lines are "<hex> <size> <path>" with a clean relative path,
// each path once. The MD5Sum, SHA1 and SHA512 lists are dropped.
func ParseRelease(b []byte) (ReleaseDoc, error) {
	if len(b) > MaxRelease {
		return ReleaseDoc{}, fmt.Errorf("apt: Release exceeds %d bytes", MaxRelease)
	}
	var d ReleaseDoc
	paragraphs := 0
	seen := map[string]bool{}
	for s, err := range Stanzas(bytes.NewReader(b), MaxRelease) {
		if err != nil {
			return ReleaseDoc{}, fmt.Errorf("apt: Release: %w", err)
		}
		if paragraphs++; paragraphs > 1 {
			return ReleaseDoc{}, errors.New("apt: Release holds more than one paragraph")
		}
		for _, f := range s {
			key := strings.ToLower(f.Name)
			if seen[key] {
				return ReleaseDoc{}, fmt.Errorf("apt: Release holds %s twice", truncate(f.Name, 80))
			}
			seen[key] = true
			var err error
			switch key {
			case "md5sum", "sha1", "sha512":
				continue
			case "sha256":
				if d.SHA256, err = parseHashList(f.Value); err != nil {
					return ReleaseDoc{}, err
				}
				continue
			case "date":
				d.Date, err = parseReleaseDate(f.Value)
			case "valid-until":
				d.ValidUntil, err = parseReleaseDate(f.Value)
			case "acquire-by-hash":
				d.ByHash = f.Value == "yes"
			}
			if err != nil {
				return ReleaseDoc{}, fmt.Errorf("apt: Release %s: %w", f.Name, err)
			}
			d.Fields = append(d.Fields, f)
		}
	}
	if !seen["date"] {
		return ReleaseDoc{}, errors.New("apt: Release has no Date")
	}
	return d, nil
}

// parseReleaseDate parses the RFC 2822 form apt accepts in a Release:
// "Sat, 09 Nov 2026 10:12:43 UTC", the day of month with one or two digits.
func parseReleaseDate(v string) (time.Time, error) {
	stamp, zone, ok := strings.CutLast(v, " ")
	if !ok {
		return time.Time{}, fmt.Errorf("malformed date %q", truncate(v, 80))
	}
	switch zone {
	case "UTC", "GMT", "Z", "+0000":
	default:
		return time.Time{}, fmt.Errorf("date %q is not in UTC", truncate(v, 80))
	}
	t, err := time.ParseInLocation("Mon, _2 Jan 2006 15:04:05", stamp, time.UTC)
	if err != nil {
		return time.Time{}, fmt.Errorf("malformed date %q", truncate(v, 80))
	}
	return t, nil
}

func parseHashList(v string) ([]FileHash, error) {
	var out []FileHash
	paths := map[string]bool{}
	for line := range strings.SplitSeq(v, "\n") {
		cols := strings.Fields(line)
		if len(cols) == 0 {
			continue
		}
		if len(cols) != 3 {
			return nil, fmt.Errorf("apt: Release SHA256: malformed line %q", truncate(line, 120))
		}
		h, size, p := strings.ToLower(cols[0]), cols[1], cols[2]
		if !isHex64(h) {
			return nil, fmt.Errorf("apt: Release SHA256: malformed hash %q", truncate(cols[0], 80))
		}
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil || strings.TrimLeft(size, "0123456789") != "" {
			return nil, fmt.Errorf("apt: Release SHA256: malformed size %q", truncate(size, 80))
		}
		if p != path.Clean(p) || p == "." || p == ".." || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "../") {
			return nil, fmt.Errorf("apt: Release SHA256: path %q is not clean and relative", truncate(p, 120))
		}
		if paths[p] {
			return nil, fmt.Errorf("apt: Release SHA256: %s listed twice", truncate(p, 120))
		}
		paths[p] = true
		out = append(out, FileHash{Path: p, Size: n, SHA256: h})
	}
	return out, nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// Render writes the Release file: Fields in their order, then the SHA256
// list sorted by path. The Date, Valid-Until and Acquire-By-Hash fields take
// their values from Date, ValidUntil and ByHash (dates in UTC as
// "Mon, 02 Jan 2006 15:04:05 UTC"; a Valid-Until field is left out while
// ValidUntil is zero); fields not in Fields are not written. Field values
// must be deb822-clean, as ParseRelease returns them.
func (d ReleaseDoc) Render() []byte {
	var b bytes.Buffer
	for _, f := range d.Fields {
		v := f.Value
		switch strings.ToLower(f.Name) {
		case "date":
			v = d.Date.UTC().Format(releaseDate)
		case "valid-until":
			if d.ValidUntil.IsZero() {
				continue
			}
			v = d.ValidUntil.UTC().Format(releaseDate)
		case "acquire-by-hash":
			v = "no"
			if d.ByHash {
				v = "yes"
			}
		}
		first, rest, multi := strings.Cut(v, "\n")
		b.WriteString(f.Name + ":")
		if first != "" {
			b.WriteString(" " + first)
		}
		b.WriteByte('\n')
		if multi {
			b.WriteString(rest + "\n")
		}
	}
	hashes := slices.SortedFunc(slices.Values(d.SHA256), func(a, b FileHash) int { return cmp.Compare(a.Path, b.Path) })
	b.WriteString("SHA256:\n")
	for _, h := range hashes {
		fmt.Fprintf(&b, " %s %d %s\n", h.SHA256, h.Size, h.Path)
	}
	return b.Bytes()
}

// Lookup returns the SHA256 entry for path.
func (d ReleaseDoc) Lookup(path string) (FileHash, bool) {
	for _, h := range d.SHA256 {
		if h.Path == path {
			return h, true
		}
	}
	return FileHash{}, false
}
