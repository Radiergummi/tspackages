package composer

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/pins"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

// Conflict is a package name declared by more than one remote. Such a package
// is not served at all.
type Conflict struct {
	Package string
	Remotes []string
}

// GitSource serves packages built from git repositories. Tags are versions
// (pinned on first sight), the default branch (or those matching the branches
// allowlist) are dev versions. Dist zips are built once with git archive and
// kept in the state store as
//
//	composer-git/<source>/<commit>.zip
//
// so their checksum never changes. The index is held in memory and rebuilt by
// Index, which Run repeats every poll interval.
type GitSource struct {
	name       string
	claims     []string
	branches   []string
	mirrors    []*gitmirror.Mirror
	pins       *pins.Store
	rec        *records.Store
	state      storage.Driver
	poll       time.Duration
	log        *slog.Logger
	maxArchive int64 // largest zip kept in memory; bigger versions are skipped

	mu      sync.Mutex // serialises Index; guards the fields below
	prev    []remoteResult
	digests map[string]digest // by commit; archives are immutable
	prov    map[string]bool   // commit + version pairs whose provenance is stored

	idx atomic.Pointer[gitIndex]
}

var _ Source = (*GitSource)(nil)

type remoteResult struct {
	pkg      string
	versions []Version
}

type digest struct{ sha1, sha256 string }

type gitIndex struct {
	pkgs      map[string][]Version
	conflicts []Conflict
}

func NewGitSource(name string, claims, branches []string, mirrors []*gitmirror.Mirror, pins *pins.Store, rec *records.Store, state storage.Driver, poll time.Duration, log *slog.Logger, maxArchive int64) *GitSource {
	g := &GitSource{
		name: name, claims: claims, branches: branches, mirrors: mirrors, pins: pins, rec: rec,
		state: state, poll: poll, log: log, maxArchive: maxArchive,
		prev:    make([]remoteResult, len(mirrors)),
		digests: map[string]digest{},
		prov:    map[string]bool{},
	}
	g.idx.Store(&gitIndex{pkgs: map[string][]Version{}})
	return g
}

func (g *GitSource) Name() string     { return g.name }
func (g *GitSource) Claims() []string { return g.claims }
func (g *GitSource) Type() string     { return "git" }

func archiveKey(source, commit string) string {
	return "composer-git/" + source + "/" + commit + ".zip"
}

// Run indexes immediately and then every poll interval until ctx ends.
func (g *GitSource) Run(ctx context.Context) {
	for {
		if err := g.Index(ctx); err != nil && ctx.Err() == nil {
			g.log.Error("composer git index failed", "source", g.name, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(g.poll):
		}
	}
}

// Index runs one sync-and-index pass over all mirrors. A mirror whose sync
// fails keeps its previous entries. Problems with single remotes or versions
// are logged; only a cancelled context is returned.
func (g *GitSource) Index(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, m := range g.mirrors {
		if err := m.Sync(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			g.log.Warn("composer git sync failed; keeping previous index", "source", g.name, "remote", m.Remote(), "error", err)
			continue
		}
		g.prev[i] = g.indexRemote(ctx, m)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	g.idx.Store(g.assemble())
	return nil
}

// assemble merges the per-remote results; a name claimed by two remotes is
// dropped and reported as a conflict.
func (g *GitSource) assemble() *gitIndex {
	owners := map[string][]string{}
	for i, r := range g.prev {
		if r.pkg != "" {
			owners[r.pkg] = append(owners[r.pkg], g.mirrors[i].Remote())
		}
	}
	out := &gitIndex{pkgs: map[string][]Version{}}
	for _, r := range g.prev {
		if r.pkg != "" && len(owners[r.pkg]) == 1 && len(r.versions) > 0 {
			out.pkgs[r.pkg] = r.versions
		}
	}
	for pkg, remotes := range owners {
		if len(remotes) > 1 {
			slices.Sort(remotes)
			out.conflicts = append(out.conflicts, Conflict{Package: pkg, Remotes: remotes})
			g.log.Error("composer package declared by several remotes; not served", "source", g.name, "package", pkg, "remotes", remotes)
		}
	}
	slices.SortFunc(out.conflicts, func(a, b Conflict) int { return strings.Compare(a.Package, b.Package) })
	return out
}

func (g *GitSource) indexRemote(ctx context.Context, m *gitmirror.Mirror) remoteResult {
	remote := m.Remote()
	refs, err := m.Refs(ctx)
	if err != nil {
		g.log.Error("composer git: listing refs failed", "source", g.name, "remote", remote, "error", err)
		return remoteResult{}
	}
	def, err := m.DefaultBranch(ctx)
	if err != nil {
		g.log.Error("composer git: no default branch", "source", g.name, "remote", remote, "error", err)
		return remoteResult{}
	}
	var head string
	for _, r := range refs {
		if !r.IsTag && r.Short == def {
			head = r.Commit
		}
	}
	if head == "" {
		g.log.Error("composer git: default branch has no commit", "source", g.name, "remote", remote, "branch", def)
		return remoteResult{}
	}
	meta, err := readComposerJSON(ctx, m, head)
	if err != nil {
		g.log.Error("composer git: unreadable composer.json on default branch", "source", g.name, "remote", remote, "error", err)
		return remoteResult{}
	}
	declared, _ := meta["name"].(string)
	pkg, err := Normalize(declared)
	if err != nil {
		g.log.Error("composer git: invalid package name on default branch", "source", g.name, "remote", remote, "name", declared)
		return remoteResult{}
	}

	res := remoteResult{pkg: pkg}
	seen := map[string]bool{}
	add := func(version, normalized, commit string, meta map[string]any, dev bool) {
		if seen[normalized] {
			g.log.Debug("composer git: duplicate version skipped", "source", g.name, "remote", remote, "version", version)
			return
		}
		d, err := g.archive(ctx, m, pkg, version, commit)
		if err != nil {
			g.log.Warn("composer git: version skipped", "source", g.name, "remote", remote, "version", version, "commit", commit, "error", err)
			return
		}
		seen[normalized] = true
		res.versions = append(res.versions, Version{
			Package:   packageEntry(meta, pkg, version, normalized, commit, d.sha1),
			Version:   version,
			Reference: commit,
			Dev:       dev,
		})
	}

	for _, r := range refs {
		if !r.IsTag {
			continue
		}
		normalized, err := NormalizeVersion(r.Short)
		if err != nil {
			g.log.Debug("composer git: tag is not a version", "source", g.name, "remote", remote, "tag", r.Short)
			continue
		}
		commit, moved, err := g.pins.Pin(ctx, "composer", g.name, remote, r.Short, r.Commit)
		if err != nil {
			g.log.Warn("composer git: pinning tag failed", "source", g.name, "remote", remote, "tag", r.Short, "error", err)
			continue
		}
		if moved {
			g.log.Warn("composer git: tag moved upstream; serving the pinned commit", "source", g.name, "remote", remote, "tag", r.Short, "pinned", commit, "seen", r.Commit)
		}
		tm, err := readComposerJSON(ctx, m, commit)
		if err != nil {
			g.log.Warn("composer git: tag skipped", "source", g.name, "remote", remote, "tag", r.Short, "error", err)
			continue
		}
		if n, err := Normalize(strOf(tm["name"])); err != nil || n != pkg {
			g.log.Warn("composer git: tag names a different package", "source", g.name, "remote", remote, "tag", r.Short, "name", tm["name"], "want", pkg)
			continue
		}
		add(r.Short, normalized, commit, tm, false)
	}

	for _, r := range refs {
		if r.IsTag || !g.wantBranch(r.Short, def) {
			continue
		}
		name, normalized := NormalizeBranch(r.Short)
		version := normalized
		if !strings.HasPrefix(normalized, "dev-") {
			version = name + "-dev"
		}
		bm := meta
		if r.Commit != head {
			if bm, err = readComposerJSON(ctx, m, r.Commit); err != nil {
				g.log.Warn("composer git: branch skipped", "source", g.name, "remote", remote, "branch", r.Short, "error", err)
				continue
			}
		}
		if n, err := Normalize(strOf(bm["name"])); err != nil || n != pkg {
			g.log.Warn("composer git: branch names a different package", "source", g.name, "remote", remote, "branch", r.Short, "name", bm["name"], "want", pkg)
			continue
		}
		add(version, normalized, r.Commit, bm, true)
	}

	slices.SortStableFunc(res.versions, func(a, b Version) int {
		if a.Dev != b.Dev {
			if a.Dev {
				return 1
			}
			return -1
		}
		an, bn := normalizedOf(a), normalizedOf(b)
		if a.Dev && (strings.HasPrefix(an, "dev-") || strings.HasPrefix(bn, "dev-")) {
			return strings.Compare(an, bn)
		}
		return compareNormalized(bn, an)
	})
	return res
}

func strOf(v any) string { s, _ := v.(string); return s }

func (g *GitSource) wantBranch(branch, def string) bool {
	if len(g.branches) == 0 {
		return branch == def
	}
	return slices.ContainsFunc(g.branches, func(p string) bool {
		ok, _ := path.Match(p, branch)
		return ok
	})
}

func readComposerJSON(ctx context.Context, m *gitmirror.Mirror, commit string) (map[string]any, error) {
	raw, err := m.ReadFile(ctx, commit, "composer.json")
	if err != nil {
		return nil, err
	}
	var meta map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep large integers exact
	if err := dec.Decode(&meta); err != nil || meta == nil {
		return nil, errors.New("composer.json is not a valid JSON object")
	}
	return meta, nil
}

// packageEntry builds the served metadata of one version: the allowlisted
// composer.json fields plus version, version_normalized and dist.
func packageEntry(meta map[string]any, pkg, version, normalized, reference, sha1sum string) map[string]any {
	p := PublishableFields(meta)
	p["name"] = pkg
	p["version"] = version
	p["version_normalized"] = normalized
	p["dist"] = map[string]any{"type": "zip", "reference": reference, "shasum": sha1sum}
	return p
}

// errTooLarge marks an archive over the in-memory cap.
var errTooLarge = errors.New("archive too large")

type capWriter struct {
	buf  bytes.Buffer
	max  int64
	over bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if int64(w.buf.Len()+len(p)) > w.max {
		w.over = true
		return 0, errTooLarge
	}
	return w.buf.Write(p)
}

// archive makes sure the zip of commit is in the state store and returns its
// digests. A stored zip is canonical and is read back, never rebuilt.
func (g *GitSource) archive(ctx context.Context, m *gitmirror.Mirror, pkg, version, commit string) (digest, error) {
	d, ok := g.digests[commit]
	if !ok {
		data, err := g.zipBytes(ctx, m, commit)
		if err != nil {
			return digest{}, err
		}
		s1, s256 := sha1.Sum(data), sha256.Sum256(data)
		d = digest{sha1: hex.EncodeToString(s1[:]), sha256: hex.EncodeToString(s256[:])}
		g.digests[commit] = d
	}
	pk := commit + "\x00" + version
	if !g.prov[pk] {
		if err := g.rec.PutProvenance(ctx, records.Provenance{
			Ecosystem: "composer", Package: pkg, Version: version, Source: g.name, SourceType: "git",
			Remote: m.Remote(), Commit: commit, SHA1: d.sha1, SHA256: d.sha256,
		}); err != nil {
			return digest{}, err
		}
		g.prov[pk] = true
	}
	return d, nil
}

func (g *GitSource) zipBytes(ctx context.Context, m *gitmirror.Mirror, commit string) ([]byte, error) {
	key := archiveKey(g.name, commit)
	if data, err := g.readStored(ctx, key); err == nil {
		return data, nil
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	w := &capWriter{max: g.maxArchive}
	if err := m.ArchiveZip(ctx, commit, w); err != nil {
		if w.over {
			return nil, fmt.Errorf("%w: over %d bytes", errTooLarge, g.maxArchive)
		}
		return nil, err
	}
	if _, err := g.state.PutIfAbsent(ctx, key, bytes.NewReader(w.buf.Bytes())); err != nil {
		if errors.Is(err, storage.ErrExists) {
			return g.readStored(ctx, key) // someone else stored it first: theirs is canonical
		}
		return nil, err
	}
	return w.buf.Bytes(), nil
}

func (g *GitSource) readStored(ctx context.Context, key string) ([]byte, error) {
	rc, _, err := g.state.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// Conflicts lists package names declared by several remotes in the last pass.
func (g *GitSource) Conflicts() []Conflict { return slices.Clone(g.idx.Load().conflicts) }

func (g *GitSource) Packages(context.Context) ([]string, bool, error) {
	pkgs := g.idx.Load().pkgs
	names := slices.Sorted(maps.Keys(pkgs))
	return names, true, nil
}

// Versions returns the indexed versions of name: tags highest first, then dev
// branches. The returned metadata is a copy the caller may modify.
func (g *GitSource) Versions(_ context.Context, name string) ([]Version, error) {
	pkg, err := Normalize(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", resolve.ErrNotFound, err)
	}
	vs, ok := g.idx.Load().pkgs[pkg]
	if !ok {
		return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, name)
	}
	out := make([]Version, len(vs))
	for i, v := range vs {
		p := maps.Clone(v.Package)
		p["dist"] = maps.Clone(p["dist"].(map[string]any))
		v.Package = p
		out[i] = v
	}
	return out, nil
}

// Dist serves the stored zip of an indexed version. reference must be the
// commit indexed for that name and version; anything else is not found, so a
// client cannot reach commits that are not published.
func (g *GitSource) Dist(ctx context.Context, name, version, reference string) (Artifact, error) {
	pkg, err := Normalize(name)
	if err != nil {
		return Artifact{}, fmt.Errorf("%w: %v", resolve.ErrNotFound, err)
	}
	nv, nerr := NormalizeVersion(version)
	var found *Version
	for _, v := range g.idx.Load().pkgs[pkg] {
		if v.Reference == reference && (v.Version == version || normalizedOf(v) == version || (nerr == nil && normalizedOf(v) == nv)) {
			found = &v
			break
		}
	}
	if found == nil {
		return Artifact{}, fmt.Errorf("%w: %s %s", resolve.ErrNotFound, name, version)
	}
	rc, info, err := g.state.Get(ctx, archiveKey(g.name, found.Reference))
	if errors.Is(err, storage.ErrNotFound) {
		return Artifact{}, fmt.Errorf("%w: %s %s", resolve.ErrNotFound, name, version)
	}
	if err != nil {
		return Artifact{}, err
	}
	dist, _ := found.Package["dist"].(map[string]any)
	return Artifact{Body: rc, Size: info.Size, SHA1: strOf(dist["shasum"])}, nil
}
