package apt

import "testing"

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
