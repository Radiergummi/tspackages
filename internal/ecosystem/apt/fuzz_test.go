package apt

import (
	"bytes"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"

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

func FuzzParseRelease(f *testing.F) {
	const h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for _, s := range []string{
		"Origin: x\nDate: Mon, 09 Nov 2026 10:12:43 UTC\nAcquire-By-Hash: yes\nSHA256:\n " + h + " 1 main/a\n " + h + " 0 b\n",
		"Date: Mon, 9 Nov 2026 10:12:43 GMT\nValid-Until: Mon, 16 Nov 2026 10:12:43 +0000\nMD5Sum:\n x 1 a\n",
		"Date: x\n", "", "\n\n", "A: b\n\nC: d\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := ParseRelease(b)
		if err != nil {
			return
		}
		for _, fh := range d.SHA256 {
			if got, ok := d.Lookup(fh.Path); !ok || got != fh || len(fh.SHA256) != 64 || fh.Size < 0 {
				t.Fatalf("Lookup(%q) = %+v, %v", fh.Path, got, ok)
			}
		}
		out := d.Render()
		d2, err := ParseRelease(out)
		if err != nil {
			t.Fatalf("Render of %q = %q does not parse: %v", b, out, err)
		}
		if !d2.Date.Equal(d.Date) || !d2.ValidUntil.Equal(d.ValidUntil) || d2.ByHash != d.ByHash || len(d2.SHA256) != len(d.SHA256) {
			t.Fatalf("round trip of %q: %+v, want %+v", b, d2, d)
		}
		for _, fh := range d.SHA256 {
			if got, ok := d2.Lookup(fh.Path); !ok || got != fh {
				t.Fatalf("round trip lost %+v", fh)
			}
		}
		if !bytes.Equal(d2.Render(), out) {
			t.Fatalf("Render not stable for %q", b)
		}
		typed := func(f Field) bool {
			return strings.EqualFold(f.Name, "Date") || strings.EqualFold(f.Name, "Valid-Until") || strings.EqualFold(f.Name, "Acquire-By-Hash")
		}
		if !slices.Equal(slices.DeleteFunc(slices.Clone(d.Fields), typed), slices.DeleteFunc(slices.Clone(d2.Fields), typed)) {
			t.Fatalf("fields changed in round trip of %q: %+v -> %+v", b, d.Fields, d2.Fields)
		}
	})
}

// FuzzXZGuard checks that the guard passes on exactly what the decoder
// reads when it accepts a file.
func FuzzXZGuard(f *testing.F) {
	data := []byte(strings.Repeat("Package: acme\n", 100))
	for _, bs := range []int64{0, 256} {
		var out bytes.Buffer
		w, err := xz.WriterConfig{BlockSize: bs}.NewWriter(&out)
		if err != nil {
			f.Fatal(err)
		}
		w.Write(data)
		w.Close()
		f.Add(out.Bytes())
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := newXZReader(bytes.NewReader(b), maxControlDict)
		if err != nil {
			return
		}
		got, err := io.ReadAll(io.LimitReader(r, 1<<20))
		if err != nil {
			return
		}
		plain, err := xz.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("guard accepted what the decoder refuses: %v", err)
		}
		want, err := io.ReadAll(io.LimitReader(plain, 1<<20))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("decoder alone: %d bytes, %v; through the guard %d bytes", len(want), err, len(got))
		}
	})
}
