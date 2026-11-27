package pypi

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

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
// showing: "unclaimed", "owned by <repo>" or "no digest yet".
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
// repository ID) and are returned for the caller to pin. The inputs are
// read-only and the result does not depend on map order.
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
					skip.Reason = "unclaimed"
					idx.Skipped = append(idx.Skipped, skip)
					continue
				}
				c := ghCandidate{repo: repo, release: rel, asset: a, pkg: pkg}
				sum, ok := strings.CutPrefix(a.Digest, "sha256:")
				if !ok || !ghHex64(sum) {
					sum = strings.TrimPrefix(digests[a.ID], "sha256:")
				}
				if !ghHex64(sum) {
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
		if !ok || c.asset.CreatedAt.Before(f.asset.CreatedAt) ||
			(c.asset.CreatedAt.Equal(f.asset.CreatedAt) && c.repo.ID < f.repo.ID) {
			first[c.pkg] = c
		}
	}
	for pkg, c := range first {
		if id, ok := owners[pkg]; ok {
			owner[pkg] = id
			continue
		}
		owner[pkg] = c.repo.ID
		decided[pkg] = c.repo
	}

	byFile := map[[2]string][]ghCandidate{}
	var keys [][2]string
	for _, c := range cands {
		if owner[c.pkg] != c.repo.ID {
			who, ok := names[owner[c.pkg]]
			if !ok {
				who = fmt.Sprintf("repository %d", owner[c.pkg])
			}
			idx.Skipped = append(idx.Skipped, GitHubSkip{
				Repo: c.repo.FullName, Release: c.release.Tag, Asset: c.asset.Name, Package: c.pkg, Reason: "owned by " + who,
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
		best := group[0]
		same := true
		for _, c := range group[1:] {
			if c.file.SHA256 != best.file.SHA256 {
				same = false
			}
			if c.release.CreatedAt.After(best.release.CreatedAt) ||
				(c.release.CreatedAt.Equal(best.release.CreatedAt) && c.release.ID > best.release.ID) {
				best = c
			}
		}
		if !same {
			conf := GitHubConflict{Package: k[0], Filename: k[1]}
			for _, c := range group {
				conf.Releases = append(conf.Releases, c.release.Tag)
			}
			slices.Sort(conf.Releases)
			idx.Conflicts = append(idx.Conflicts, conf)
			continue
		}
		best.file.UploadTime = best.asset.CreatedAt
		idx.Projects[k[0]] = append(idx.Projects[k[0]], best.file)
	}
	return idx, decided
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

// ghHex64 reports whether s is 64 lowercase hex characters.
func ghHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
