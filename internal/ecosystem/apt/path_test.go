package apt

import (
	"strings"
	"testing"
)

func TestParsePath(t *testing.T) {
	hash := strings.Repeat("ab12", 16)
	for _, c := range []struct {
		in   string
		put  bool
		want Path
	}{
		{"key.asc", false, Path{Kind: KindKey}},
		{"preferences", false, Path{Kind: KindPreferences}},
		{"hosted/dists/bookworm/InRelease", false, Path{Kind: KindRelease, Source: "hosted", Suite: "bookworm", Rel: "InRelease"}},
		{"hosted/dists/bookworm/Release", false, Path{Kind: KindRelease, Source: "hosted", Suite: "bookworm", Rel: "Release"}},
		{"hosted/dists/bookworm/Release.gpg", false, Path{Kind: KindRelease, Source: "hosted", Suite: "bookworm", Rel: "Release.gpg"}},
		{"hosted/dists/bookworm/main/binary-amd64/Packages.gz", false, Path{Kind: KindDist, Source: "hosted", Suite: "bookworm", Rel: "main/binary-amd64/Packages.gz"}},
		{"hosted/dists/bookworm/main/binary-amd64/by-hash/SHA256/" + hash, false,
			Path{Kind: KindByHash, Source: "hosted", Suite: "bookworm", Rel: "main/binary-amd64/by-hash/SHA256/" + hash, Hash: hash}},
		{"hosted/dists/bookworm/main/binary-amd64/by-hash/SHA512/" + hash, false,
			Path{Kind: KindDist, Source: "hosted", Suite: "bookworm", Rel: "main/binary-amd64/by-hash/SHA512/" + hash}},
		{"hosted/bookworm/main/acme_1.0_amd64.deb", true, Path{Kind: KindUpload, Source: "hosted", Suite: "bookworm", Component: "main", Deb: Deb{"acme", "1.0", "amd64"}}},
		{"hosted/bookworm/main/acme_1.0_amd64.deb", false, Path{Kind: KindPool, Source: "hosted", Rel: "bookworm/main/acme_1.0_amd64.deb", Deb: Deb{"acme", "1.0", "amd64"}}},
		{"hosted/pool/acme/acme_1.0+git~1_all.deb", false, Path{Kind: KindPool, Source: "hosted", Rel: "pool/acme/acme_1.0+git~1_all.deb", Deb: Deb{"acme", "1.0+git~1", "all"}}},
		{"debian/pool/main/c/curl/curl_8.0_amd64.deb", false, Path{Kind: KindPool, Source: "debian", Rel: "pool/main/c/curl/curl_8.0_amd64.deb", Deb: Deb{"curl", "8.0", "amd64"}}},
		{"hosted/pool/acme/acme_1.0_all.deb", true, Path{Kind: KindUpload, Source: "hosted", Suite: "pool", Component: "acme", Deb: Deb{"acme", "1.0", "all"}}},
		{"debian/pool/main/c/curl/curl_8.0.orig.tar.gz", false, Path{Kind: KindPool, Source: "debian", Rel: "pool/main/c/curl/curl_8.0.orig.tar.gz"}},
	} {
		got, err := ParsePath(c.in, c.put)
		if err != nil || got != c.want {
			t.Errorf("ParsePath(%q, %v) = %+v, %v; want %+v", c.in, c.put, got, err, c.want)
		}
	}
	for _, c := range []struct {
		in  string
		put bool
	}{
		{"hosted/dists/../x", false}, {"hosted/.x/y", false}, {strings.Repeat("a/", 16) + "a", false},
		{"Hosted/dists/x/InRelease", false}, {"hosted/dists/bookworm/main/binary-amd64/by-hash/SHA256/" + strings.Repeat("a", 63), false},
		{"hosted/dists/bookworm/main/binary-amd64/by-hash/SHA256/" + strings.Repeat("A", 64), false},
		{"hosted/dists/bookworm", false}, {"hosted/dists", false}, {"hosted", false}, {"", false}, {"hosted//x", false}, {"hosted/a/", false},
		{"hosted/dists/bookworm/InRelease", true}, {"key.asc", true}, {"hosted/bookworm/main/x.deb", true},
		{"hosted/bookworm/main/sub/acme_1.0_amd64.deb", true}, {"hosted/bookworm/acme_1.0_amd64.deb", true},
		{"hosted/Bookworm/main/acme_1.0_amd64.deb", true},
		{"hosted/dists/Bookworm/InRelease", false}, {"hosted/dists/bookworm/" + strings.Repeat("a", 256), false},
		{"hosted/dists/bookworm/.hidden", false},
	} {
		if got, err := ParsePath(c.in, c.put); err == nil {
			t.Errorf("ParsePath(%q, %v) = %+v, want an error", c.in, c.put, got)
		}
	}
}
