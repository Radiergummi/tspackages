package digest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestOf(t *testing.T) {
	s1, s256 := Of([]byte("abc"))
	if s1 != "a9993e364706816aba3e25717850c26c9cd0d89d" ||
		s256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("Of = %s %s", s1, s256)
	}
}

func TestIsHex(t *testing.T) {
	for _, tc := range []struct {
		s    string
		lens []int
		want bool
	}{
		{"0123456789abcdef", []int{16}, true},
		{"0123456789abcdef", []int{40, 64}, false},
		{"0123456789ABCDEF", []int{16}, false},
		{"0123456789abcdeg", []int{16}, false},
		{"", []int{0}, true},
	} {
		if got := IsHex(tc.s, tc.lens...); got != tc.want {
			t.Errorf("IsHex(%q, %v) = %v", tc.s, tc.lens, got)
		}
	}
}

func TestParseIntegrity(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	s512, s1, s256 := bytes.Repeat([]byte{0xab}, 64), bytes.Repeat([]byte{0xcd}, 20), bytes.Repeat([]byte{0xef}, 32)
	hex512, hex1 := hex.EncodeToString(s512), hex.EncodeToString(s1)
	for _, c := range []struct {
		name, in, algo, hex string
		ok                  bool
	}{
		{"sha512", "sha512-" + b64(s512), "sha512", hex512, true},
		{"sha1 and sha512", "sha1-" + b64(s1) + " sha512-" + b64(s512), "sha512", hex512, true},
		{"sha512 first", "sha512-" + b64(s512) + " sha1-" + b64(s1), "sha512", hex512, true},
		{"sha1 with options", "sha1-" + b64(s1) + "?foo", "sha1", hex1, true},
		{"sha256 ignored", "sha256-" + b64(s256), "", "", false},
		{"sha256 skipped", "sha256-" + b64(s256) + " sha1-" + b64(s1), "sha1", hex1, true},
		{"bad base64", "sha512-!!", "", "", false},
		{"short sha512", "sha512-" + b64(s1), "", "", false},
		{"too long", "sha512-" + strings.Repeat("A", 1025), "", "", false},
		{"empty", "", "", "", false},
	} {
		algo, h, ok := ParseIntegrity(c.in)
		if algo != c.algo || h != c.hex || ok != c.ok {
			t.Errorf("%s: ParseIntegrity = %q, %q, %v", c.name, algo, h, ok)
		}
	}
}
