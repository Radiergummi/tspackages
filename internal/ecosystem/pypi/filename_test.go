package pypi

import (
	"slices"
	"testing"
)

func TestParseWheelFilename(t *testing.T) {
	w, err := ParseWheelFilename("matchory_core-1.2.0-py3-none-any.whl")
	if err != nil || w.Name != "matchory_core" || w.Version != "1.2.0" || w.Build != "" || !slices.Equal(w.Tags, []string{"py3", "none", "any"}) {
		t.Fatalf("%+v %v", w, err)
	}
	w, err = ParseWheelFilename("torch-2.5.1-1-cp312-cp312-manylinux_2_28_x86_64.whl")
	if err != nil || w.Build != "1" || w.Tags[2] != "manylinux_2_28_x86_64" {
		t.Fatalf("with build tag: %+v %v", w, err)
	}
	if _, err := ParseWheelFilename("a-1.0-1_b-py2.py3-none-any.whl"); err != nil {
		t.Errorf("compressed tag set and build tag suffix: %v", err)
	}
	for _, bad := range []string{"x.whl", "a-1.0.whl", "a-1.0-py3-none-any.zip", "a-1.0-x-py3-none-any.whl", "../a-1.0-py3-none-any.whl",
		// Characters that break the file's URL.
		"a-1.0-py3-none-any#x.whl", "a-1.0-py3-none%20-any.whl", "a-1.0-py3?-none-any.whl", "a-1.0-1#-py3-none-any.whl", "a-1.0 -py3-none-any.whl"} {
		if _, err := ParseWheelFilename(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSdistFilename(t *testing.T) {
	v, _ := ParseVersion("1.2.0")
	if got := SdistFilename("matchory-core", v); got != "matchory_core-1.2.0.tar.gz" {
		t.Fatalf("SdistFilename = %q", got)
	}
	name, version, err := ParseSdistFilename("matchory_core-1.2.0.tar.gz")
	if err != nil || name != "matchory_core" || version != "1.2.0" {
		t.Fatalf("parse: %q %q %v", name, version, err)
	}
	if name, version, err := ParseSdistFilename("foo-bar-1.0.tar.gz"); err != nil || name != "foo-bar" || version != "1.0" {
		t.Fatalf("legacy dashed name: %q %q %v", name, version, err)
	}
	for _, bad := range []string{"a-1.0.zip", "a.tar.gz", "a-.tar.gz", "../a-1.0.tar.gz", "a-latest.tar.gz", "a-1.0 .tar.gz", "a-\t1.0.tar.gz"} {
		if _, _, err := ParseSdistFilename(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
