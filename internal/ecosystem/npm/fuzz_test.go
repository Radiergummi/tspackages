package npm

import (
	"net/url"
	"slices"
	"testing"
)

func FuzzParseName(f *testing.F) {
	for _, s := range []string{"name", "@scope/name", "@a/b/c", "@/x", "JSONStream", ".x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := ParseName(s)
		if err != nil {
			return
		}
		dec, err := url.PathUnescape(n.Escaped())
		if err != nil {
			t.Fatalf("Escaped %q: %v", n.Escaped(), err)
		}
		m, err := ParseName(dec)
		if err != nil || m != n {
			t.Fatalf("re-parse of %q = %+v, %v; want %+v", dec, m, err, n)
		}
	})
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"1.2.3", "1.2.3-alpha.1+build.5", "1.0.0-Beta", "01.2.3", "1.2.3-01"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseVersion(s)
		if err != nil {
			return
		}
		if v.String() != s {
			t.Fatalf("String() = %q, want %q", v.String(), s)
		}
		w, err := ParseVersion(v.String())
		if err != nil || w.Major != v.Major || w.Minor != v.Minor || w.Patch != v.Patch ||
			!slices.Equal(w.Pre, v.Pre) || w.Build != v.Build || Compare(v, w) != 0 {
			t.Fatalf("re-parse of %q differs: %+v, %v", s, w, err)
		}
	})
}
