package apt

import (
	"strings"
	"testing"
)

func TestNames(t *testing.T) {
	for s, want := range map[string]bool{
		"acme": true, "lib+x.y-2": true, "a": false, "Acme": false, "-acme": false, "ac me": false,
		strings.Repeat("a", MaxName): true, strings.Repeat("a", MaxName+1): false, "": false,
	} {
		if got := ValidName(s); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", s, got, want)
		}
	}
	for s, want := range map[string]bool{
		"1:2.0-1": true, "1.0+git~1": true, "2.0-1": true, "a:1.0": false, "1.0 1": false, "": false, "1:": false,
		":1.0": false, "1.0/x": false, strings.Repeat("1", MaxName+1): false,
	} {
		if got := ValidVersion(s); got != want {
			t.Errorf("ValidVersion(%q) = %v, want %v", s, got, want)
		}
	}
	for s, want := range map[string]bool{"amd64": true, "all": true, "Amd64": false, "": false, "a_b": false, strings.Repeat("a", 33): false} {
		if got := ValidArch(s); got != want {
			t.Errorf("ValidArch(%q) = %v, want %v", s, got, want)
		}
	}
	for s, want := range map[string]bool{"bookworm": true, "main": true, "stable-updates": true, "v1.0_x": true, ".x": false, "Main": false, "": false, strings.Repeat("a", 65): false} {
		if got := ValidSuite(s); got != want {
			t.Errorf("ValidSuite(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestFileNames(t *testing.T) {
	if got := StripEpoch("1:2.0-1"); got != "2.0-1" {
		t.Errorf("StripEpoch = %q", got)
	}
	if got := StripEpoch("2.0-1"); got != "2.0-1" {
		t.Errorf("StripEpoch without epoch = %q", got)
	}
	if got := (Deb{"acme", "1:2.0-1", "amd64"}).FileName(); got != "acme_2.0-1_amd64.deb" {
		t.Errorf("FileName = %q", got)
	}
	d, err := ParseFileName("acme_2.0-1_amd64.deb")
	if err != nil || d != (Deb{"acme", "2.0-1", "amd64"}) || d.FileName() != "acme_2.0-1_amd64.deb" {
		t.Errorf("ParseFileName = %+v, %v", d, err)
	}
	for _, f := range []string{"acme_1.0.deb", "acme_1.0_amd64.udeb", "acme_1:1.0_amd64.deb", "a_1.0_amd64.deb", "acme_1.0_amd_64.deb", "Acme_1.0_amd64.deb", "acme__amd64.deb"} {
		if _, err := ParseFileName(f); err == nil {
			t.Errorf("ParseFileName(%q) accepted", f)
		}
	}
}
