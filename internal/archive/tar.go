package archive

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"strings"
)

// InspectTarGz reads a gzipped tar archive (an sdist) and rejects it as
// InspectZip rejects a zip: more than l.MaxBytes compressed, more than
// l.MaxEntries entries, more than l.MaxDecompressed bytes in total, a name
// that is absolute, contains "..", a backslash or a drive prefix, is not
// canonical or repeats another ignoring case, and any entry other than a
// regular file or directory (symlinks, hard links, devices, FIFOs). It
// returns the contents of the regular files want accepts.
func InspectTarGz(r io.Reader, l Limits, want func(name string) bool) (map[string][]byte, error) {
	compressed := &countingReader{r: r, max: l.MaxBytes}
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, archiveError(err, "not a gzip archive")
	}
	defer gz.Close()
	// One budget for everything the gzip stream inflates to, headers included.
	inflated := &countingReader{r: gz, max: l.MaxDecompressed}
	tr := tar.NewReader(inflated)
	out := map[string][]byte{}
	seen := map[string]struct{}{}
	for entries := 0; ; entries++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			if entries == 0 {
				return nil, reject("archive is empty")
			}
			return out, nil
		}
		if err != nil {
			return nil, archiveError(err, "not a valid tar archive")
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			entries-- // git archive writes one; it carries no file
			continue
		}
		if entries >= l.MaxEntries {
			return nil, reject("archive has more than %d entries", l.MaxEntries)
		}
		if err := checkName(h.Name); err != nil {
			return nil, err
		}
		lower := strings.ToLower(h.Name)
		if _, dup := seen[lower]; dup {
			return nil, reject("archive has duplicate entry %q", h.Name)
		}
		seen[lower] = struct{}{}
		switch h.Typeflag {
		case tar.TypeDir:
		case tar.TypeReg:
			if !want(h.Name) {
				continue // its bytes are read (and counted) by the next Next
			}
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, archiveError(err, "archive entry is corrupt")
			}
			out[h.Name] = b
		case tar.TypeSymlink:
			return nil, reject("archive entry %q is a symlink", h.Name)
		default:
			return nil, reject("archive entry %q is not a regular file or directory", h.Name)
		}
	}
}

var errOverLimit = errors.New("over limit")

// countingReader passes on at most max bytes and then fails, so a buffering
// reader on top cannot finish from bytes beyond the limit.
type countingReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.n >= c.max {
		// One byte more tells "exactly max" from "over max". Nothing past the
		// limit is passed on: an empty probe returns its own result.
		var one [1]byte
		n, err := c.r.Read(one[:])
		if n > 0 {
			return 0, errOverLimit
		}
		return 0, err
	}
	if int64(len(p)) > c.max-c.n {
		p = p[:c.max-c.n]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// archiveError turns a read failure into an *Error, naming a limit when one
// was hit.
func archiveError(err error, reason string) error {
	if errors.Is(err, errOverLimit) {
		return reject("archive exceeds the size limit")
	}
	return reject("%s", reason)
}
