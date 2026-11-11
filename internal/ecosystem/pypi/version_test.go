package pypi

import "testing"

func TestVersionCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"1.0":           "1",
		"1.0.0":         "1",
		"v1.0":          "1",
		"1.0.0.0":       "1",
		"1.2.0":         "1.2",
		"1.0rc1":        "1rc1",
		"1.0-RC1":       "1rc1",
		"1.0c1":         "1rc1",
		"1.0alpha2":     "1a2",
		"1.0.post0":     "1.post0",
		"1.0-1":         "1.post1",
		"1.0rev3":       "1.post3",
		"1!1.0":         "1!1",
		"0!1.0":         "1",
		"1.0+local.1":   "1+local.1",
		"1.0+Local_01":  "1+local.1",
		"1.0.0.dev1":    "1.dev1",
		"1.2.0a":        "1.2a0",
		"01.02.03":      "1.2.3",
		" 1.0 ":         "1",
		"1.0.dev":       "1.dev0",
		"2.0.0b3.post2": "2b3.post2",
	} {
		v, err := ParseVersion(in)
		if err != nil {
			t.Errorf("ParseVersion(%q): %v", in, err)
			continue
		}
		if got := v.Canonical(); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "1.0-foo-bar", "latest", "1..0", "1.0+", "v", "1.0+local!"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("ParseVersion(%q) accepted", bad)
		}
	}
}

func TestVersionString(t *testing.T) {
	for in, want := range map[string]string{
		"1.0.0":      "1.0.0",
		"V1.0-RC1":   "1.0rc1",
		"1.0-1":      "1.0.post1",
		"0!1.0":      "1.0",
		"1.0+Ab-1":   "1.0+ab.1",
		"1.2.0.DEV3": "1.2.0.dev3",
	} {
		v, err := ParseVersion(in)
		if err != nil || v.String() != want {
			t.Errorf("String(%q) = %q, %v; want %q", in, v.String(), err, want)
		}
	}
}

func TestVersionEqualSpellings(t *testing.T) {
	a, _ := ParseVersion("1.0")
	b, _ := ParseVersion("1.0.0")
	c, _ := ParseVersion("1.0.1")
	if a.Canonical() != b.Canonical() || a.Canonical() == c.Canonical() {
		t.Fatal("1.0 and 1.0.0 must be equal, 1.0.1 different")
	}
}
