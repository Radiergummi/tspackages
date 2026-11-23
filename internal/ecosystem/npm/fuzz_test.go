package npm

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/upstream"
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

func FuzzParsePath(f *testing.F) {
	for _, s := range []string{"@s%2fn", "@s/n/1.0.0", "%40s/n/-/n-1.0.0.tgz", "-/npm-11.0.0.tgz", "-/package/@s%2Fn/dist-tags/beta",
		"-/npm/v1/keys", "-/npm/v1/attestations/@s/n@1.0.0", "n/-/n-1.0.0.tgz/-rev/1-abc", "-/npm/v1/security/advisories/bulk"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParsePath(s)
		if err != nil || r.Kind == RouteKeys {
			return
		}
		n, err := ParseName(r.Name.Exact)
		if err != nil || n != r.Name {
			t.Fatalf("%q: route name %+v, ParseName = %+v, %v", s, r.Name, n, err)
		}
	})
}

func FuzzPackumentStream(f *testing.F) {
	for _, file := range []string{"packument-left-pad.json", "packument-scoped.json"} {
		b, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			f.Fatal(err)
		}
		f.Add("left-pad", b)
	}
	f.Add("x", []byte(`{"name":"x","versions":{"1.0.0":{"name":"x","version":"1.0.0","dist":{"shasum":"`+strings.Repeat("a", 40)+`","tarball":"https://registry.npmjs.org/x/-/x-1.0.0.tgz"}}},"dist-tags":{"latest":"1.0.0"},"time":{"1.0.0":"t"}}`))
	f.Add("x", []byte(`{"name":"x","time":{"unpublished":{}}}`))
	c := upstream.New(upstream.Options{FetchHosts: []string{"registry.npmjs.org"}})
	s := NewRegistrySource("fuzz", nil, "https://registry.npmjs.org/", c, nil, nil, nil, time.Minute, 1<<20, nil, f.TempDir(), nil)
	f.Fuzz(func(t *testing.T, name string, body []byte) {
		n, err := ParseName(name)
		if err != nil {
			return
		}
		var full, corgi, entries bytes.Buffer
		res, err := s.build(n, bytes.NewReader(body), &full, &corgi, &entries)
		if err != nil || res.miss {
			return
		}
		for kind, b := range map[string][]byte{"full": full.Bytes(), "corgi": corgi.Bytes()} {
			var out bytes.Buffer
			ex := Expand(&out, "https://tsp.example/npm/")
			ex.Write(b)
			ex.Close()
			if !json.Valid(out.Bytes()) {
				t.Fatalf("%s is not valid JSON:\n%s", kind, out.Bytes())
			}
		}
		if idx := append(append([]byte(`{`), entries.Bytes()...), '}'); !json.Valid(idx) {
			t.Fatalf("file index is not valid JSON:\n%s", idx)
		}
	})
}
