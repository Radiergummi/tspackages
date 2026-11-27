package pypi

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/githubapp"
)

func TestBuildGHIndex(t *testing.T) {
	hexA := strings.Repeat("a", 64)
	hexB := strings.Repeat("b", 64)
	hexC := strings.Repeat("c", 64)
	at := func(h int) time.Time { return time.Date(2026, 1, 1, h, 0, 0, 0, time.UTC) }
	repoA := githubapp.Repo{ID: 1, FullName: "o/a"}
	repoB := githubapp.Repo{ID: 2, FullName: "o/b"}
	asset := func(id int64, name, digest string, created time.Time) githubapp.Asset {
		return githubapp.Asset{ID: id, Name: name, State: "uploaded", Digest: digest, Size: 10 + id, CreatedAt: created}
	}
	rel := func(id int64, tag string, created time.Time, as ...githubapp.Asset) githubapp.Release {
		return githubapp.Release{ID: id, Tag: tag, CreatedAt: created, Assets: as}
	}
	const whl = "acme_lib-1.0-py3-none-any.whl"

	tests := []struct {
		name       string
		claims     []string
		repos      map[githubapp.Repo][]githubapp.Release
		owners     map[string]int64
		digests    map[int64]string
		wantFiles  map[string][]string // project -> "filename=sha"
		wantSkips  []string            // "package/reason"
		wantNeed   []int64
		wantOwners map[string]string
		wantConf   []GitHubConflict
	}{
		{
			name:   "filtering",
			claims: []string{"acme-*"},
			repos: map[githubapp.Repo][]githubapp.Release{repoA: {
				func() githubapp.Release {
					r := rel(1, "draft", at(1), asset(1, whl, "sha256:"+hexA, at(1)))
					r.Draft = true
					return r
				}(),
				func() githubapp.Release {
					r := rel(2, "v1.0rc1", at(2),
						asset(2, "acme_lib-1.0rc1-py3-none-any.whl", "sha256:"+hexB, at(2)),
						githubapp.Asset{ID: 3, Name: "acme_lib-1.0rc2-py3-none-any.whl", State: "starter", Digest: "sha256:" + hexB},
						asset(4, "checksums.txt", "sha256:"+hexB, at(2)),
						asset(5, "uv-x86_64.tar.gz", "sha256:"+hexB, at(2)),
						asset(6, "requests-2.0-py3-none-any.whl", "sha256:"+hexB, at(2)))
					r.Prerelease = true
					return r
				}(),
			}},
			wantFiles:  map[string][]string{"acme-lib": {"acme_lib-1.0rc1-py3-none-any.whl=" + hexB}},
			wantSkips:  []string{"requests/unclaimed"},
			wantOwners: map[string]string{"acme-lib": "o/a"},
		},
		{
			name:    "digest pins and need hash",
			claims:  []string{"acme-*"},
			digests: map[int64]string{2: hexC, 3: hexC},
			repos: map[githubapp.Repo][]githubapp.Release{repoA: {rel(1, "v1", at(1),
				asset(1, "acme_lib-1.0-py3-none-any.whl", "", at(1)),
				asset(2, "acme_lib-1.1-py3-none-any.whl", "", at(1)),
				asset(3, "acme_lib-1.2-py3-none-any.whl", "sha256:"+hexA, at(1)),
				asset(4, "other-1.0-py3-none-any.whl", "", at(1)))}},
			wantFiles: map[string][]string{"acme-lib": {
				"acme_lib-1.1-py3-none-any.whl=" + hexC,
				"acme_lib-1.2-py3-none-any.whl=" + hexA,
			}},
			wantSkips:  []string{"acme-lib/no digest yet", "other/unclaimed"},
			wantNeed:   []int64{1},
			wantOwners: map[string]string{"acme-lib": "o/a"},
		},
		{
			name:   "earliest counting asset owns",
			claims: []string{"acme-*"},
			repos: map[githubapp.Repo][]githubapp.Release{
				repoA: {rel(1, "v1", at(1), asset(1, whl, "sha256:"+hexA, at(10)))},
				repoB: {rel(2, "v1", at(1), asset(2, whl, "sha256:"+hexB, at(9)))},
			},
			wantFiles:  map[string][]string{"acme-lib": {whl + "=" + hexB}},
			wantSkips:  []string{"acme-lib/owned by o/b"},
			wantOwners: map[string]string{"acme-lib": "o/b"},
		},
		{
			name:   "equal created_at: lower repo ID",
			claims: []string{"*"},
			repos: map[githubapp.Repo][]githubapp.Release{
				repoA: {rel(1, "v1", at(1), asset(1, whl, "sha256:"+hexA, at(9)))},
				repoB: {rel(2, "v1", at(1), asset(2, whl, "sha256:"+hexB, at(9)))},
			},
			wantFiles:  map[string][]string{"acme-lib": {whl + "=" + hexA}},
			wantSkips:  []string{"acme-lib/owned by o/a"},
			wantOwners: map[string]string{"acme-lib": "o/a"},
		},
		{
			name:   "non-counting asset never decides the owner",
			claims: []string{"*"},
			repos: map[githubapp.Repo][]githubapp.Release{
				repoA: {rel(1, "v1", at(1), asset(1, whl, "", at(1)))},
				repoB: {rel(2, "v1", at(1), asset(2, whl, "sha256:"+hexB, at(9)))},
			},
			wantFiles:  map[string][]string{"acme-lib": {whl + "=" + hexB}},
			wantSkips:  []string{"acme-lib/no digest yet"},
			wantNeed:   []int64{1},
			wantOwners: map[string]string{"acme-lib": "o/b"},
		},
		{
			name:   "existing owner wins over older asset",
			claims: []string{"*"},
			owners: map[string]int64{"acme-lib": 1},
			repos: map[githubapp.Repo][]githubapp.Release{
				repoA: {rel(1, "v1", at(1), asset(1, whl, "sha256:"+hexA, at(10)))},
				repoB: {rel(2, "v1", at(1), asset(2, whl, "sha256:"+hexB, at(1)))},
			},
			wantFiles: map[string][]string{"acme-lib": {whl + "=" + hexA}},
			wantSkips: []string{"acme-lib/owned by o/a"},
		},
		{
			name:   "same filename, same digest: newer release",
			claims: []string{"*"},
			repos: map[githubapp.Repo][]githubapp.Release{repoA: {
				rel(1, "v1", at(1), asset(1, whl, "sha256:"+hexA, at(1))),
				rel(2, "v1.1", at(5), asset(2, whl, "sha256:"+hexA, at(5))),
			}},
			wantFiles:  map[string][]string{"acme-lib": {whl + "=" + hexA}},
			wantOwners: map[string]string{"acme-lib": "o/a"},
		},
		{
			name:   "same filename, different digests: conflict",
			claims: []string{"*"},
			repos: map[githubapp.Repo][]githubapp.Release{repoA: {
				rel(1, "v1", at(1), asset(1, whl, "sha256:"+hexA, at(1))),
				rel(2, "v1.1", at(5), asset(2, whl, "sha256:"+hexB, at(5))),
			}},
			wantFiles:  map[string][]string{},
			wantOwners: map[string]string{"acme-lib": "o/a"},
			wantConf:   []GitHubConflict{{Package: "acme-lib", Filename: whl, Releases: []string{"v1", "v1.1"}}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := fmt.Sprintf("%+v", tc.repos)
			idx, owners := buildGHIndex(tc.claims, tc.repos, tc.owners, tc.digests)
			if after := fmt.Sprintf("%+v", tc.repos); before != after {
				t.Error("input modified")
			}
			gotFiles := map[string][]string{}
			for p, fs := range idx.Projects {
				for _, f := range fs {
					gotFiles[p] = append(gotFiles[p], f.Filename+"="+f.SHA256)
				}
			}
			if !reflect.DeepEqual(gotFiles, tc.wantFiles) {
				t.Errorf("files = %v, want %v", gotFiles, tc.wantFiles)
			}
			var gotSkips []string
			for _, s := range idx.Skipped {
				gotSkips = append(gotSkips, s.Package+"/"+s.Reason)
			}
			if !reflect.DeepEqual(gotSkips, tc.wantSkips) {
				t.Errorf("skips = %v, want %v", gotSkips, tc.wantSkips)
			}
			var gotNeed []int64
			for _, n := range idx.NeedHash {
				gotNeed = append(gotNeed, n.Asset.ID)
			}
			if !reflect.DeepEqual(gotNeed, tc.wantNeed) {
				t.Errorf("need hash = %v, want %v", gotNeed, tc.wantNeed)
			}
			gotOwners := map[string]string{}
			for p, r := range owners {
				gotOwners[p] = r.FullName
			}
			want := tc.wantOwners
			if want == nil {
				want = map[string]string{}
			}
			if !reflect.DeepEqual(gotOwners, want) {
				t.Errorf("new owners = %v, want %v", gotOwners, want)
			}
			if !reflect.DeepEqual(idx.Conflicts, tc.wantConf) {
				t.Errorf("conflicts = %v, want %v", idx.Conflicts, tc.wantConf)
			}
		})
	}
}

func TestBuildGHIndexFileFields(t *testing.T) {
	created := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	repo := githubapp.Repo{ID: 7, FullName: "o/x"}
	hex := strings.Repeat("d", 64)
	idx, _ := buildGHIndex([]string{"*"}, map[githubapp.Repo][]githubapp.Release{repo: {{
		ID: 1, Tag: "v1", CreatedAt: created,
		Assets: []githubapp.Asset{
			{ID: 9, Name: "Acme.Lib-1.0.0-py3-none-any.whl", State: "uploaded", Digest: "sha256:" + hex, Size: 123, CreatedAt: created},
			{ID: 10, Name: "acme_lib-1.1.tar.gz", State: "uploaded", Digest: "sha256:" + hex, Size: 5, CreatedAt: created},
		},
	}}}, nil, nil)
	fs := idx.Projects["acme-lib"]
	if len(fs) != 2 {
		t.Fatalf("files = %+v", fs)
	}
	f := fs[0]
	if f.SHA256 != hex || f.Size != 123 || !f.UploadTime.Equal(created) || f.AssetID != 9 || f.Repo != repo || f.Version != "1.0.0" {
		t.Errorf("file = %+v", f)
	}
	if fs[1].Version != "1.1" {
		t.Errorf("sdist version = %q", fs[1].Version)
	}
}
