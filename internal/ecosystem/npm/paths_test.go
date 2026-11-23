package npm

import (
	"strings"
	"testing"
)

func TestParsePath(t *testing.T) {
	// Every spelling of the scoped name "@s/n" a client may send.
	spellings := []string{"@s%2fn", "@s%2Fn", "@s/n", "%40s/n", "%40s%2fn"}
	type want struct {
		kind               RouteKind
		version, file, tag string
	}
	rows := []struct {
		path string // "<name>" stands for each spelling
		want want
	}{
		{"<name>", want{kind: RoutePackument}},
		{"<name>/1.0.0", want{kind: RouteVersion, version: "1.0.0"}},
		{"<name>/latest", want{kind: RouteVersion, version: "latest"}},
		{"<name>/1.0.0%2Bbuild", want{kind: RouteVersion, version: "1.0.0+build"}},
		{"<name>/-/n-1.0.0.tgz", want{kind: RouteTarball, file: "n-1.0.0.tgz"}},
		{"-/package/<name>/dist-tags", want{kind: RouteDistTags}},
		{"-/package/<name>/dist-tags/beta", want{kind: RouteDistTag, tag: "beta"}},
		{"-/package/<name>/dist-tags/next%2D1", want{kind: RouteDistTag, tag: "next-1"}},
		{"-/npm/v1/attestations/<name>@1.0.0", want{kind: RouteAttestations, version: "1.0.0"}},
		{"<name>/-rev/1-abc", want{kind: RouteRev}},
		{"<name>/-/n-1.0.0.tgz/-rev/1-abc", want{kind: RouteRev}},
	}
	for _, row := range rows {
		for _, sp := range spellings {
			p := strings.ReplaceAll(row.path, "<name>", sp)
			got, err := ParsePath(p)
			if err != nil {
				t.Errorf("%s: %v", p, err)
				continue
			}
			if got.Kind != row.want.kind || got.Version != row.want.version || got.File != row.want.file || got.Tag != row.want.tag {
				t.Errorf("%s: got %+v, want %+v", p, got, row.want)
			}
			if got.Name.Exact != "@s/n" || got.Name.Norm != "@s/n" {
				t.Errorf("%s: name %+v", p, got.Name)
			}
		}
	}

	for _, tt := range []struct {
		path string
		want Route
	}{
		{"n", Route{Kind: RoutePackument, Name: Name{Exact: "n", Norm: "n", Base: "n"}}},
		{"JSONStream", Route{Kind: RoutePackument, Name: Name{Exact: "JSONStream", Norm: "jsonstream", Base: "JSONStream"}}},
		{"@MATCHORY/x", Route{Kind: RoutePackument, Name: Name{Exact: "@MATCHORY/x", Norm: "@matchory/x", Scope: "MATCHORY", Base: "x"}}},
		{"-/npm-11.0.0.tgz", Route{Kind: RouteTarball, Name: Name{Exact: "npm", Norm: "npm", Base: "npm"}, File: "npm-11.0.0.tgz"}},
		{"npm/-/npm-11.0.0.tgz", Route{Kind: RouteTarball, Name: Name{Exact: "npm", Norm: "npm", Base: "npm"}, File: "npm-11.0.0.tgz"}},
		{"-/npm/v1/keys", Route{Kind: RouteKeys}},
		{"-/npm/v1/attestations/n@1.0.0", Route{Kind: RouteAttestations, Name: Name{Exact: "n", Norm: "n", Base: "n"}, Version: "1.0.0"}},
		{"-/package/n/dist-tags", Route{Kind: RouteDistTags, Name: Name{Exact: "n", Norm: "n", Base: "n"}}},
	} {
		got, err := ParsePath(tt.path)
		if err != nil || got != tt.want {
			t.Errorf("%s: got %+v, %v; want %+v", tt.path, got, err, tt.want)
		}
	}

	for _, p := range []string{
		"",
		"-/npm/v1/security/advisories/bulk",
		"-/npm/v1/security/audits/quick",
		"-/whoami",
		"-/user/org.couchdb.user:x",
		"-/v1/search",
		"-/npm/v1/keys/x",
		"-/npm-11.0.0.tar",
		"-",
		"n/",
		"n/-",
		"n/-/",
		"n/-/x.tar.gz",
		"n/-/a%2fb.tgz",
		"n/1.0.0/x",
		"n/-rev",
		"n/-/n-1.0.0.tgz/x/y",
		"@s",
		"@s/",
		"@/n",
		"@s/n/1.0.0/extra",
		"@s%2fn%2fx",
		"a%2fb",
		"a/b/c",
		".x",
		"_x",
		"x%zz",
		"-/package/n",
		"-/package/n/dist-tags/a/b",
		"-/package/n/other",
		"-/npm/v1/attestations/n",
		"-/npm/v1/attestations/@s/n",
		"-/npm/v1/attestations/n@",
		"n(1)",
		strings.Repeat("a", 157),
	} {
		if r, err := ParsePath(p); err == nil {
			t.Errorf("%q: got %+v, want error", p, r)
		}
	}
}
