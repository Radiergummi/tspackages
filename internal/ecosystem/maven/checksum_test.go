package maven

import (
	"crypto/md5" //nolint:gosec // MD5 is one of the checksums Maven clients request
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseChecksumFile(t *testing.T) {
	const sum = "8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12"
	for _, in := range []string{
		sum,
		sum + "\n",
		sum + "  junit-4.13.2.jar\n",
		"\n\r\n  " + sum + "  \r\n",
		"SHA1 (junit-4.13.2.jar) = " + strings.ToUpper(sum),
		strings.ToUpper(sum),
	} {
		got, err := ParseChecksumFile(strings.NewReader(in), "sha1")
		if err != nil || got != sum {
			t.Errorf("ParseChecksumFile(%q) = %q, %v; want %q", in, got, err, sum)
		}
	}
	for _, in := range []string{
		"",
		"\n \n",
		sum[:39],
		sum + "0",
		"zz" + sum[2:],
		sum + "\tjunit-4.13.2.jar",
		strings.Repeat(" ", 1025) + sum,
		strings.Repeat("\n", 1024) + sum,
	} {
		if got, err := ParseChecksumFile(strings.NewReader(in), "sha1"); err == nil {
			t.Errorf("ParseChecksumFile(%.40q) = %q, nil; want error", in, got)
		}
	}
	if _, err := ParseChecksumFile(strings.NewReader(sum), "sha256"); err == nil {
		t.Error("a SHA-1 accepted as SHA-256")
	}
	if _, err := ParseChecksumFile(strings.NewReader(sum), "crc32"); err == nil {
		t.Error("unknown algorithm accepted")
	}
	md := strings.Repeat("ab", 16)
	if got, err := ParseChecksumFile(strings.NewReader(md), "md5"); err != nil || got != md {
		t.Errorf("md5: %q, %v", got, err)
	}
}

func TestHasher(t *testing.T) {
	h := NewHasher()
	_, _ = h.Write([]byte("hel"))
	_, _ = h.Write([]byte("lo"))
	b := []byte("hello")
	s1, s256, s512, m := sha1.Sum(b), sha256.Sum256(b), sha512.Sum512(b), md5.Sum(b) //nolint:gosec // see import
	want := Digests{hex.EncodeToString(s1[:]), hex.EncodeToString(s256[:]), hex.EncodeToString(s512[:]), hex.EncodeToString(m[:])}
	got := h.Digests()
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for alg, v := range map[string]string{"sha1": want.SHA1, "sha256": want.SHA256, "sha512": want.SHA512, "md5": want.MD5, "crc32": ""} {
		if got.Get(alg) != v {
			t.Errorf("Get(%q) = %q, want %q", alg, got.Get(alg), v)
		}
	}
}
