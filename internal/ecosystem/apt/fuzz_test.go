package apt

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"github.com/radiergummi/tspackages/internal/testutil"
)

func FuzzParsePath(f *testing.F) {
	for _, s := range []string{
		"key.asc", "preferences", "hosted/dists/bookworm/InRelease", "hosted/dists/bookworm/main/binary-amd64/Packages.gz",
		"hosted/dists/bookworm/main/binary-amd64/by-hash/SHA256/" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12",
		"hosted/bookworm/main/acme_1.0_amd64.deb", "debian/pool/main/c/curl/curl_8.0_amd64.deb", "hosted/dists/../x", "a/b/c/d",
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, s string, put bool) {
		p, err := ParsePath(s, put)
		if err != nil {
			return
		}
		bad := func(field string) { t.Fatalf("ParsePath(%q, %v) = %+v: empty %s", s, put, p, field) }
		if p.Kind != KindKey && p.Kind != KindPreferences && p.Source == "" {
			bad("Source")
		}
		switch p.Kind {
		case KindKey, KindPreferences:
		case KindRelease, KindDist, KindByHash:
			if p.Suite == "" || p.Rel == "" {
				bad("Suite or Rel")
			}
			if p.Kind == KindByHash && len(p.Hash) != 64 {
				bad("Hash")
			}
		case KindPool:
			if p.Rel == "" || put {
				bad("Rel")
			}
		case KindUpload:
			if !put || p.Suite == "" || p.Component == "" || p.Deb.Name == "" || p.Deb.Version == "" || p.Deb.Arch == "" {
				bad("upload field")
			}
		}
	})
}

func FuzzParseStanza(f *testing.F) {
	for _, s := range []string{
		"Package: acme\nVersion: 1.0-1\nDescription: short\n long\n .\n more\n",
		"Files:\n abc 1 x\n def 2 y\n", "A: b", "A:\n\tb\n", "", "\n", "A: b\n\nC: d\n", "A: b\r\n", "A: \x00\n", "A: \xff\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseStanza(b, 1<<10)
		if err != nil {
			return
		}
		var buf bytes.Buffer
		if err := WriteStanza(&buf, s); err != nil {
			t.Fatalf("ParseStanza(%q) = %+v does not write: %v", b, s, err)
		}
		s2, err := ParseStanza(buf.Bytes(), 1<<10)
		if err != nil || !reflect.DeepEqual(s, s2) {
			t.Fatalf("round trip of %q: %+v, %v (wrote %q)", b, s2, err, buf.Bytes())
		}
	})
}

func FuzzInspect(f *testing.F) {
	for _, c := range []string{"gz", "xz", "zst", "none"} {
		f.Add(testutil.Deb(f, "Package: acme\nVersion: 1:2.0-1\nArchitecture: amd64\nDepends: libc6\n", testutil.DebOptions{Compression: c}))
	}
	f.Add([]byte("!<arch>\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := Inspect(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			return
		}
		if !ValidName(c.Deb.Name) || !ValidVersion(c.Deb.Version) || !ValidArch(c.Deb.Arch) {
			t.Fatalf("Inspect accepted %+v", c.Deb)
		}
		for _, fl := range c.Fields {
			if !slices.Contains(PublishableFields, fl.Name) {
				t.Fatalf("field %s not publishable", fl.Name)
			}
		}
	})
}
