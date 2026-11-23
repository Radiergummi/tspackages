// Package digest computes and checks the hex digests tspackages records.
package digest

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
)

// Of returns the lowercase hex SHA-1 and SHA-256 of b.
func Of(b []byte) (sha1Hex, sha256Hex string) {
	s1, s256 := sha1.Sum(b), sha256.Sum256(b)
	return hex.EncodeToString(s1[:]), hex.EncodeToString(s256[:])
}

// IsHex reports whether s is lowercase hex of one of the given lengths.
func IsHex(s string, lens ...int) bool {
	if !slices.Contains(lens, len(s)) {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ParseIntegrity picks the strongest supported digest of a Subresource
// Integrity string (npm's "integrity"): a space-separated list of
// "<algo>-<base64>" entries with optional "?options". It prefers sha512 over
// sha1 and ignores other algorithms and malformed entries. The digest is
// returned as lowercase hex.
func ParseIntegrity(s string) (algo, hexDigest string, ok bool) {
	if len(s) > 1024 {
		return "", "", false
	}
	for entry := range strings.FieldsSeq(s) {
		a, b64, found := strings.Cut(entry, "-")
		if !found {
			continue
		}
		b64, _, _ = strings.Cut(b64, "?")
		var size int
		switch a {
		case "sha512":
			size = 64
		case "sha1":
			size = 20
		default:
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) != size {
			continue
		}
		if a == "sha512" {
			return a, hex.EncodeToString(raw), true
		}
		algo, hexDigest, ok = a, hex.EncodeToString(raw), true
	}
	return algo, hexDigest, ok
}
