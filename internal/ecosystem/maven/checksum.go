package maven

import (
	"crypto/md5" //nolint:gosec // MD5 is one of the checksums Maven clients request, not a security digest
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strings"
)

// maxChecksumFile is the largest checksum file read, in bytes.
const maxChecksumFile = 1 << 10

// Digests are a file's checksums as lowercase hex; "" is unknown.
type Digests struct {
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
	MD5    string `json:"md5"`
}

// Get returns the digest for alg ("sha1", "sha256", "sha512" or "md5"), or ""
// for any other alg.
func (d Digests) Get(alg string) string {
	switch alg {
	case "sha1":
		return d.SHA1
	case "sha256":
		return d.SHA256
	case "sha512":
		return d.SHA512
	case "md5":
		return d.MD5
	}
	return ""
}

// Hasher computes all four Digests of what is written to it.
type Hasher struct {
	sha1, sha256, sha512, md5 hash.Hash
	w                         io.Writer
}

// NewHasher returns an empty Hasher.
func NewHasher() *Hasher {
	h := &Hasher{sha1: sha1.New(), sha256: sha256.New(), sha512: sha512.New(), md5: md5.New()} //nolint:gosec // see the md5 import
	h.w = io.MultiWriter(h.sha1, h.sha256, h.sha512, h.md5)
	return h
}

// Write adds p to every digest; it never fails.
func (h *Hasher) Write(p []byte) (int, error) { return h.w.Write(p) }

// Digests returns the digests of everything written so far.
func (h *Hasher) Digests() Digests {
	return Digests{
		SHA1:   hex.EncodeToString(h.sha1.Sum(nil)),
		SHA256: hex.EncodeToString(h.sha256.Sum(nil)),
		SHA512: hex.EncodeToString(h.sha512.Sum(nil)),
		MD5:    hex.EncodeToString(h.md5.Sum(nil)),
	}
}

var (
	hexLen = map[string]int{"sha1": 40, "sha256": 64, "sha512": 128, "md5": 32}
	// bsdStyleRE is the "ALGO (name) = <hex>" form, as Maven's resolver
	// recognises it.
	bsdStyleRE = regexp.MustCompile(`^.+= [0-9A-Fa-f]+$`)
)

// ParseChecksumFile reads a checksum file of at most 1 KiB the way Maven's
// DefaultChecksumProcessor.readChecksum does: the first non-blank line,
// either "ALGO (name) = <hex>" or "<hex>" up to the first space. It returns
// the hex lowercased, which must be as long as alg requires.
func ParseChecksumFile(r io.Reader, alg string) (string, error) {
	want, ok := hexLen[alg]
	if !ok {
		return "", fmt.Errorf("unknown checksum algorithm %q", alg)
	}
	b, err := io.ReadAll(io.LimitReader(r, maxChecksumFile+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxChecksumFile {
		return "", errors.New("checksum file larger than 1 KiB")
	}
	var line string
	// BufferedReader.readLine ends lines at "\n", "\r" or "\r\n"; blank
	// lines are skipped, so splitting at either character is the same.
	for l := range strings.FieldsFuncSeq(string(b), func(r rune) bool { return r == '\n' || r == '\r' }) {
		if line = strings.TrimFunc(l, isJavaSpace); line != "" {
			break
		}
	}
	if line == "" {
		return "", errors.New("empty checksum file")
	}
	if bsdStyleRE.MatchString(line) {
		line = line[strings.LastIndexByte(line, ' ')+1:]
	} else if i := strings.IndexByte(line, ' '); i >= 0 {
		line = line[:i]
	}
	if len(line) != want {
		return "", fmt.Errorf("%s checksum has %d characters, want %d", alg, len(line), want)
	}
	if _, err := hex.DecodeString(line); err != nil {
		return "", fmt.Errorf("%s checksum is not hex", alg)
	}
	return strings.ToLower(line), nil
}

// isJavaSpace is what String.trim removes: every character up to U+0020.
func isJavaSpace(r rune) bool { return r <= ' ' }
