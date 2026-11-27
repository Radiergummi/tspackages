package pypi

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/digest"
	"github.com/radiergummi/tspackages/internal/githubapp"
)

// ghFile is one served GitHub release asset.
type ghFile struct {
	File
	Version string // canonical PEP 440, as Project.Versions lists it
	Repo    githubapp.Repo
	AssetID int64
}

// GitHubSkip reports an asset left out of the index for a reason worth
// showing: "owned by <repo>", "no digest yet" or "owner not decided yet".
type GitHubSkip struct{ Repo, Release, Asset, Package, Reason string }

// GitHubConflict reports a filename that two releases of the owning
// repository publish with different digests; it is not served.
type GitHubConflict struct {
	Package, Filename string
	Releases          []string
}

// ghPending is a claimed asset that has no digest yet.
type ghPending struct {
	Repo    githubapp.Repo
	Asset   githubapp.Asset
	Package string
}

// ghIndex is the result of one pass: files per normalised project name.
type ghIndex struct {
	Projects  map[string][]ghFile
	Skipped   []GitHubSkip
	Conflicts []GitHubConflict
	NeedHash  []ghPending
	Unclaimed int // wheels and sdists of names no claim covers
}

type ghCandidate struct {
	repo    githubapp.Repo
	release githubapp.Release
	asset   githubapp.Asset
	pkg     string
	file    ghFile
}

// buildGHIndex turns the listed repositories into an index. A digest from
// digests (a pin by asset ID) is used only when GitHub reports none. owners
// maps a project to the ID of the repository that owns it; names without an
// entry go to the repository whose counting asset is earliest (ties: lower
// repository ID) and are returned for the caller to pin, unless an asset
// without a digest from another repository is older (or as old, from a
// lower repository ID): such a name has no owner until that asset is hashed,
// and none of its files are listed. The inputs are read-only and the result
// does not depend on map order.
func buildGHIndex(claims []string, repos map[githubapp.Repo][]githubapp.Release, owners map[string]int64, digests map[int64]string) (ghIndex, map[string]githubapp.Repo) {
	idx := ghIndex{Projects: map[string][]ghFile{}}
	names := map[int64]string{}
	sorted := make([]githubapp.Repo, 0, len(repos))
	for r := range repos {
		sorted = append(sorted, r)
		names[r.ID] = r.FullName
	}
	slices.SortFunc(sorted, func(a, b githubapp.Repo) int { return cmp.Compare(a.ID, b.ID) })

	var cands []ghCandidate
	for _, repo := range sorted {
		rels := slices.Clone(repos[repo])
		slices.SortFunc(rels, func(a, b githubapp.Release) int { return cmp.Compare(a.ID, b.ID) })
		for _, rel := range rels {
			if rel.Draft {
				continue
			}
			for _, a := range rel.Assets {
				if a.State != "uploaded" {
					continue
				}
				pkg, version, ok := ghParseAsset(a.Name)
				if !ok {
					continue
				}
				skip := GitHubSkip{Repo: repo.FullName, Release: rel.Tag, Asset: a.Name, Package: pkg}
				if !ghClaimed(claims, pkg) {
					idx.Unclaimed++
					continue
				}
				c := ghCandidate{repo: repo, release: rel, asset: a, pkg: pkg}
				sum := ""
				if s, ok := strings.CutPrefix(a.Digest, "sha256:"); ok && digest.IsHex(s, 64) {
					sum = s
				} else if pin := digests[a.ID]; digest.IsHex(pin, 64) {
					sum = pin
				}
				if id, ok := owners[pkg]; sum == "" && ok && id != repo.ID {
					// Never served, so never hashed.
					skip.Reason = "owned by " + ghRepoName(names, id)
					idx.Skipped = append(idx.Skipped, skip)
					continue
				}
				if sum == "" {
					idx.NeedHash = append(idx.NeedHash, ghPending{Repo: repo, Asset: a, Package: pkg})
					skip.Reason = "no digest yet"
					idx.Skipped = append(idx.Skipped, skip)
					// Without a digest the asset does not count toward ownership.
					continue
				}
				c.file = ghFile{
					Filename: a.Name, SHA256: sum, UploadTime: a.CreatedAt, Size: a.Size,
					Version: version, Repo: repo, AssetID: a.ID,
				}
				cands = append(cands, c)
			}
		}
	}

	// Ownership: a pin, else the earliest counting asset.
	decided := map[string]githubapp.Repo{}
	owner := map[string]int64{}
	first := map[string]ghCandidate{}
	for _, c := range cands {
		f, ok := first[c.pkg]
		if !ok || ghEarlier(c.asset.CreatedAt, c.repo.ID, f.asset.CreatedAt, f.repo.ID) {
			first[c.pkg] = c
		}
	}
	for pkg, c := range first {
		if id, ok := owners[pkg]; ok {
			owner[pkg] = id
			continue
		}
		if slices.ContainsFunc(idx.NeedHash, func(p ghPending) bool {
			return p.Package == pkg && p.Repo.ID != c.repo.ID &&
				ghEarlier(p.Asset.CreatedAt, p.Repo.ID, c.asset.CreatedAt, c.repo.ID)
		}) {
			continue // an older asset may win once hashed
		}
		owner[pkg] = c.repo.ID
		decided[pkg] = c.repo
	}

	byFile := map[[2]string][]ghCandidate{}
	var keys [][2]string
	for _, c := range cands {
		if id, ok := owner[c.pkg]; !ok || id != c.repo.ID {
			reason := "owner not decided yet"
			if ok {
				reason = "owned by " + ghRepoName(names, id)
			}
			idx.Skipped = append(idx.Skipped, GitHubSkip{
				Repo: c.repo.FullName, Release: c.release.Tag, Asset: c.asset.Name, Package: c.pkg, Reason: reason,
			})
			continue
		}
		k := [2]string{c.pkg, c.asset.Name}
		if _, ok := byFile[k]; !ok {
			keys = append(keys, k)
		}
		byFile[k] = append(byFile[k], c)
	}

	slices.SortFunc(keys, func(a, b [2]string) int {
		return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
	})
	for _, k := range keys {
		group := byFile[k]
		if slices.ContainsFunc(group, func(c ghCandidate) bool { return c.file.SHA256 != group[0].file.SHA256 }) {
			conf := GitHubConflict{Package: k[0], Filename: k[1]}
			for _, c := range group {
				conf.Releases = append(conf.Releases, c.release.Tag)
			}
			slices.Sort(conf.Releases)
			idx.Conflicts = append(idx.Conflicts, conf)
			continue
		}
		// Equal digests: the newest release's asset.
		best := slices.MaxFunc(group, func(a, b ghCandidate) int {
			return cmp.Or(a.release.CreatedAt.Compare(b.release.CreatedAt), cmp.Compare(a.release.ID, b.release.ID))
		})
		idx.Projects[k[0]] = append(idx.Projects[k[0]], best.file)
	}
	return idx, decided
}

// ghRepoName is the full name of the listed repository id, else
// "repository <id>".
func ghRepoName(names map[int64]string, id int64) string {
	if n, ok := names[id]; ok {
		return n
	}
	return fmt.Sprintf("repository %d", id)
}

// ghParseAsset returns the normalised project name and canonical version of
// a wheel or sdist filename.
func ghParseAsset(filename string) (pkg, version string, ok bool) {
	var name string
	if w, err := ParseWheelFilename(filename); err == nil {
		name, version = w.Name, w.Version
	} else if n, v, err := ParseSdistFilename(filename); err == nil {
		name, version = n, v
	} else {
		return "", "", false
	}
	pkg, err := Normalize(name)
	if err != nil {
		return "", "", false
	}
	v, err := ParseVersion(version)
	if err != nil {
		return "", "", false
	}
	return pkg, v.String(), true
}

func ghClaimed(claims []string, pkg string) bool {
	return slices.ContainsFunc(claims, func(c string) bool { return Match(c, pkg) })
}

// ghEarlier reports whether an asset created at at in repository id comes
// before one created at bt in repository bid: older, or as old from a lower
// repository ID.
func ghEarlier(at time.Time, id int64, bt time.Time, bid int64) bool {
	return at.Before(bt) || (at.Equal(bt) && id < bid)
}
