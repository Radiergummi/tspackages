// Package digest computes and checks the hex digests tspackages records.
package digest

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"slices"
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
