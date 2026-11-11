package pypi

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

// ErrUnavailable is returned instead of a not-found when the source cannot
// say whether a name exists: it is withheld for a conflict, or the source has
// not indexed yet. It never wraps resolve.ErrNotFound.
var ErrUnavailable = errors.New("pypi: package unavailable")

// Conflict kinds.
const (
	ConflictNoBump       = "changed without a version bump"
	ConflictDivergent    = "divergent histories"
	ConflictRepositories = "declared by several repositories"
	ConflictRebuild      = "rebuilt sdist differs from its record; not written"
)

// errRebuildDiffers is a build whose sdist does not have the digest of the
// release record it completes (export-subst output, for one, can change).
var errRebuildDiffers = errors.New("pypi git: rebuilt sdist differs from its release record")

// Conflict is a release the git source does not serve as the tags suggest.
type Conflict struct {
	Package, Version, Kind string
	Tags, Remotes          []string
}

// Skipped is a package at a tag that cannot be served.
type Skipped struct {
	Remote, Tag, Dir, Package, Reason string
}

// release is a stored release's sidecar.
type release struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"` // as declared, normalised
	Canonical   string    `json:"canonical"`
	Identity    string    `json:"identity"`
	Filename    string    `json:"filename"`
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	Metadata    string    `json:"metadata_sha256,omitempty"`
	RequiresPy  string    `json:"requires_python,omitempty"`
	Remote      string    `json:"remote"`
	Tag         string    `json:"tag"`
	Commit      string    `json:"commit"`
	UploadTime  time.Time `json:"upload_time"`
	SdistFormat int       `json:"sdist_format"`
}

// candidate is a package found at a tagged commit.
type candidate struct {
	pkg      Package
	remote   *gitmirror.Mirror
	tag      string
	commit   string
	identity string
	refused  string
}

// gitIndex is what a pass publishes.
type gitIndex struct {
	releases  map[string][]release // by name
	withheld  map[string]bool      // names not served at all
	pending   map[string]bool      // names with a version withheld for divergent histories or not built
	conflicts []Conflict
	skipped   []Skipped
	// complete: every remote has been indexed at least once and every tag
	// of this pass was read. Until then a name the index lacks may still
	// exist, so it is unavailable rather than not found.
	complete bool
}

// GitSource serves every tagged release of configured repositories as a
// generated sdist. Releases are stored in the state store, keyed by name and
// canonical version, and never change once stored.
type GitSource struct {
	maxBytes int64 // cap on a package directory's archive, built in memory
	name     string
	claims   []string
	mirrors  []*gitmirror.Mirror
	tags     map[string]map[string][]string
	state    storage.Driver
	rec      *records.Store
	poll     time.Duration
	log      *slog.Logger

	mu       sync.Mutex             // serialises Index
	byCommit map[string][]candidate // discovery per remote+commit; commits are immutable
	smu      sync.Mutex             // guards stored
	stored   map[string]release     // sidecars by key; they never change
	idx      atomic.Pointer[gitIndex]
	lastScan map[string]scan // each remote's last successful scan; guarded by mu

	hmu    sync.Mutex
	health map[string]error // last pass outcome per remote
}

var (
	_ Source = (*GitSource)(nil)
	_ Lister = (*GitSource)(nil)
)

// NewGitSource returns a git source; tags maps a remote to tag patterns and
// the package directories each releases. poll <= 0 means one minute; log nil
// means slog.Default().
func NewGitSource(name string, claims []string, mirrors []*gitmirror.Mirror, tags map[string]map[string][]string, state storage.Driver, rec *records.Store, poll time.Duration, log *slog.Logger, maxBytes int64) (*GitSource, error) {
	if poll <= 0 {
		poll = time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	g := &GitSource{
		name: name, claims: claims, mirrors: mirrors, tags: tags, state: state, rec: rec, poll: poll, log: log, maxBytes: maxBytes,
		byCommit: map[string][]candidate{}, stored: map[string]release{}, health: map[string]error{}, lastScan: map[string]scan{},
	}
	g.idx.Store(&gitIndex{releases: map[string][]release{}, withheld: map[string]bool{}})
	// Serve what is stored at once; a pass adds to it.
	if releases, err := g.loadStored(context.Background()); err == nil {
		idx := g.idx.Load()
		idx.releases = releases
	}
	return g, nil
}

func (g *GitSource) Name() string     { return g.name }
func (g *GitSource) Claims() []string { return g.claims }

func (g *GitSource) prefix() string { return "pypi-git/" + storage.EscapeSegment(g.name) + "/" }

func (g *GitSource) releaseDir(name, canonical string) string {
	return g.prefix() + storage.EscapeSegment(name) + "/" + storage.EscapeSegment(canonical) + "/"
}

// Run indexes every poll interval until ctx is done.
func (g *GitSource) Run(ctx context.Context) {
	for {
		if err := g.Index(ctx); err != nil && ctx.Err() == nil {
			g.log.Error("pypi git index failed", "source", g.name, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(g.poll):
		}
	}
}

// Index syncs the mirrors, finds the releases at every tag, builds and
// stores the new ones and publishes what is served.
func (g *GitSource) Index(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	var cands []candidate
	var skipped []Skipped
	complete := true
	for _, m := range g.mirrors {
		cs, sk, unread, err := g.scanRemote(ctx, m)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		g.hmu.Lock()
		g.health[m.Remote()] = cmp.Or(err, unread)
		g.hmu.Unlock()
		if err != nil {
			// Its last scan stands in, so what it declared stays withheld
			// or pending rather than turning into a miss.
			g.log.Warn("pypi git: indexing a remote failed; its last scan stands", "source", g.name, "remote", m.Remote(), "error", err)
		} else {
			g.lastScan[m.Remote()] = scan{cs, sk, unread}
		}
		last, ok := g.lastScan[m.Remote()]
		cands, skipped = append(cands, last.cands...), append(skipped, last.skipped...)
		complete = complete && ok && last.unread == nil
	}
	stored, err := g.loadStored(ctx)
	if err != nil {
		return err
	}
	conflicts, withheld, pending, refused := g.resolve(ctx, cands, stored)
	skipped = append(skipped, refused...)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if stored, err = g.loadStored(ctx); err != nil {
		return err
	}
	slices.SortFunc(skipped, func(a, b Skipped) int {
		return strings.Compare(a.Remote+a.Tag+a.Dir, b.Remote+b.Tag+b.Dir)
	})
	g.idx.Store(&gitIndex{releases: stored, withheld: withheld, pending: pending, conflicts: conflicts, skipped: skipped, complete: complete})
	metrics.SetGitLastSync(g.name, time.Now())
	return nil
}

// scan is what scanRemote found at a remote's tags.
type scan struct {
	cands   []candidate
	skipped []Skipped
	unread  error // a tag that could not be read
}

// scanRemote syncs a mirror and returns the candidates at its tags. An
// unreachable remote is indexed from its local mirror when there is one.
// unread is the error of a tag that could not be read; the other tags are
// still returned.
func (g *GitSource) scanRemote(ctx context.Context, m *gitmirror.Mirror) (cands []candidate, skipped []Skipped, unread, err error) {
	if err := m.Sync(ctx); err != nil {
		if m.LastSync().IsZero() {
			return nil, nil, nil, err
		}
		g.log.Warn("pypi git sync failed; indexing the local mirror", "source", g.name, "remote", m.Remote(), "error", err)
	}
	refs, err := m.Refs(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, ref := range refs {
		if !ref.IsTag {
			continue
		}
		dirs, mapped := g.mapping(m.Remote(), ref.Short)
		if mapped && len(dirs) == 0 {
			continue
		}
		found, err := g.discover(ctx, m, ref.Commit)
		if err != nil {
			g.log.Warn("pypi git: reading a tag failed", "source", g.name, "remote", m.Remote(), "tag", ref.Short, "error", err)
			unread = fmt.Errorf("tag %s: %w", ref.Short, err)
			continue
		}
		for _, c := range found {
			if mapped && !slices.Contains(dirs, "*") && !slices.Contains(dirs, cmp.Or(c.pkg.Dir, ".")) {
				continue
			}
			c.tag = ref.Short
			reason := c.pkg.Skip
			if reason == "" {
				reason = c.refused
			}
			if reason != "" {
				skipped = append(skipped, Skipped{Remote: metrics.RedactRemote(m.Remote()), Tag: ref.Short, Dir: c.pkg.Dir, Package: c.pkg.Name, Reason: reason})
				continue
			}
			cands = append(cands, c)
		}
	}
	return cands, skipped, unread, nil
}

// mapping returns the directories a tag releases under the remote's tag
// mapping ("." is the root package); mapped is false when the remote has
// none. Patterns are tried in sorted order; the first match wins.
func (g *GitSource) mapping(remote, tag string) (dirs []string, mapped bool) {
	patterns, ok := g.tags[remote]
	if !ok || len(patterns) == 0 {
		return nil, false
	}
	keys := make([]string, 0, len(patterns))
	for k := range patterns {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if ok, _ := path.Match(k, tag); ok {
			return patterns[k], true
		}
	}
	return nil, true
}

// discover finds the packages at commit, with their identities. Results are
// cached: a commit's content never changes.
func (g *GitSource) discover(ctx context.Context, m *gitmirror.Mirror, commit string) ([]candidate, error) {
	key := m.Remote() + "\x00" + commit
	if c, ok := g.byCommit[key]; ok {
		return slices.Clone(c), nil
	}
	tree, err := m.ListTree(ctx, commit, "")
	if err != nil {
		return nil, err
	}
	dirSet := map[string]bool{}
	modes := map[string]string{}
	for _, e := range tree {
		modes[e.Path] = e.Mode
		for d := path.Dir(e.Path); d != "."; d = path.Dir(d) {
			dirSet[d] = true
		}
	}
	dirs := make([]string, 0, len(dirSet))
	for d := range dirSet {
		dirs = append(dirs, d)
	}
	slices.Sort(dirs)
	read := func(p string) ([]byte, error) {
		// git reads a symlink as its target path, and the sdist leaves
		// symlinks out.
		if mode, ok := modes[p]; ok && mode != "100644" && mode != "100755" {
			return nil, fmt.Errorf("%s: %w", p, errNotRegular)
		}
		return m.ReadFile(ctx, commit, p)
	}
	pkgs, err := DiscoverPackages(read, dirs)
	if err != nil {
		return nil, err
	}
	var out []candidate
	for _, p := range pkgs {
		c := candidate{pkg: p, remote: m, commit: commit}
		if p.Skip == "" {
			var entries, attrs []gitmirror.TreeEntry
			for _, e := range tree {
				if inPackage(e.Path, p.Dir) && !excluded(e.Path, p.Exclude) {
					entries = append(entries, e)
				} else if d := path.Dir(e.Path); path.Base(e.Path) == ".gitattributes" && (d == "." || strings.HasPrefix(p.Dir+"/", d+"/")) {
					attrs = append(attrs, e) // an ancestor directory's attributes
				}
			}
			c.refused = RefuseTree(entries)
			if c.refused == "" && usesLFS(read, append(slices.Clone(attrs), entries...)) {
				c.refused = "uses Git LFS (filter=lfs), which an sdist cannot resolve"
			}
			c.identity = Identity(entries, nil, attrs)
		}
		out = append(out, c)
	}
	g.byCommit[key] = out
	return slices.Clone(out), nil
}

// usesLFS reports whether any of the .gitattributes files among entries
// routes files through Git LFS.
func usesLFS(read func(string) ([]byte, error), entries []gitmirror.TreeEntry) bool {
	for _, e := range entries {
		if path.Base(e.Path) != ".gitattributes" {
			continue
		}
		if b, err := read(e.Path); err == nil && bytes.Contains(b, []byte("filter=lfs")) {
			return true
		}
	}
	return false
}

func inPackage(p, dir string) bool { return dir == "" || strings.HasPrefix(p, dir+"/") }

// resolve decides, per name and canonical version, what to build and what
// to report, and builds the new releases.
func (g *GitSource) resolve(ctx context.Context, cands []candidate, stored map[string][]release) (conflicts []Conflict, withheld, pending map[string]bool, refused []Skipped) {
	withheld, pending = map[string]bool{}, map[string]bool{}

	byName := map[string][]candidate{}
	for _, c := range cands {
		byName[c.pkg.Name] = append(byName[c.pkg.Name], c)
	}
	for _, name := range sortedKeys(byName) {
		cs := byName[name]
		remotes := uniq(cs, func(c candidate) string { return c.remote.Remote() })
		if len(remotes) > 1 {
			withheld[name] = true
			redacted := make([]string, len(remotes))
			for i, r := range remotes {
				redacted[i] = metrics.RedactRemote(r)
			}
			conflicts = append(conflicts, Conflict{Package: name, Kind: ConflictRepositories, Remotes: redacted})
			continue
		}
		byVersion := map[string][]candidate{}
		for _, c := range cs {
			canon := c.pkg.Version.Canonical()
			byVersion[canon] = append(byVersion[canon], c)
		}
		for _, canon := range sortedKeys(byVersion) {
			c, skip, failed := g.resolveVersion(ctx, name, canon, byVersion[canon], stored)
			if failed {
				pending[name] = true
			}
			if c != nil {
				conflicts = append(conflicts, *c)
				if c.Kind == ConflictDivergent {
					pending[name] = true
				}
			}
			if skip != nil {
				refused = append(refused, *skip)
			}
		}
	}
	return conflicts, withheld, pending, refused
}

// resolveVersion handles one release: the stored one wins; otherwise the
// candidate whose commit precedes all others is built; divergent contents are
// withheld. failed reports a build that failed for a reason other than
// refused content; the next pass tries again.
func (g *GitSource) resolveVersion(ctx context.Context, name, canon string, cs []candidate, stored map[string][]release) (c *Conflict, skip *Skipped, failed bool) {
	slices.SortFunc(cs, func(a, b candidate) int { return strings.Compare(a.tag, b.tag) })
	if i := slices.IndexFunc(stored[name], func(r release) bool { return r.Canonical == canon }); i >= 0 {
		served := stored[name][i]
		if err := g.repair(ctx, served, cs); errors.Is(err, errRebuildDiffers) {
			return &Conflict{Package: name, Version: served.Version, Kind: ConflictRebuild, Tags: []string{served.Tag}}, nil, false
		}
		return differing(name, cs, served.Identity, ConflictNoBump), nil, false
	}
	winner := g.earliest(ctx, cs)
	if winner == nil {
		var tags []string
		for _, c := range cs {
			tags = append(tags, c.tag)
		}
		return &Conflict{Package: name, Version: cs[0].pkg.Version.String(), Kind: ConflictDivergent, Tags: tags}, nil, false
	}
	if err := g.build(ctx, *winner); err != nil {
		if re, ok := errors.AsType[*RefusedError](err); ok {
			return nil, &Skipped{Remote: metrics.RedactRemote(winner.remote.Remote()), Tag: winner.tag, Dir: winner.pkg.Dir, Package: name, Reason: re.Reason}, false
		}
		if errors.Is(err, errRebuildDiffers) {
			return &Conflict{Package: name, Version: winner.pkg.Version.String(), Kind: ConflictRebuild, Tags: []string{winner.tag}}, nil, false
		}
		g.log.Error("pypi git: building a release failed", "source", g.name, "package", name, "version", winner.pkg.Version.String(), "tag", winner.tag, "error", err)
		return nil, nil, true
	}
	return differing(name, cs, winner.identity, ConflictNoBump), nil, false
}

// repair rebuilds the sdist of a claimed release whose file was never
// written (an indexer stopped in between). The rebuilt sdist is written only
// if it has the recorded digest; otherwise build returns errRebuildDiffers.
func (g *GitSource) repair(ctx context.Context, r release, cs []candidate) error {
	key := g.releaseDir(r.Name, r.Canonical) + storage.EscapeSegment(r.Filename)
	if _, err := g.state.Stat(ctx, key); !errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	i := slices.IndexFunc(cs, func(c candidate) bool { return c.identity == r.Identity })
	if i < 0 {
		return nil
	}
	err := g.build(ctx, cs[i])
	if err != nil && !errors.Is(err, errRebuildDiffers) {
		g.log.Error("pypi git: repairing a release failed", "source", g.name, "package", r.Name, "version", r.Version, "error", err)
	}
	return err
}

// differing reports the candidates whose identity is not the served one.
func differing(name string, cs []candidate, served, kind string) *Conflict {
	var tags []string
	for _, c := range cs {
		if c.identity != served {
			tags = append(tags, c.tag)
		}
	}
	if len(tags) == 0 {
		return nil
	}
	return &Conflict{Package: name, Version: cs[0].pkg.Version.String(), Kind: kind, Tags: tags}
}

// earliest returns the candidate whose commit is an ancestor of every other
// candidate's commit (ties: the first tag by name), or nil when the
// candidates with differing contents have no common first.
func (g *GitSource) earliest(ctx context.Context, cs []candidate) *candidate {
	for i := range cs {
		first := true
		for j := range cs {
			if i == j || cs[i].commit == cs[j].commit {
				continue
			}
			ok, err := cs[i].remote.IsAncestor(ctx, cs[i].commit, cs[j].commit)
			if err != nil || !ok {
				first = false
				break
			}
		}
		if first {
			return &cs[i]
		}
	}
	// No common first commit: fine if every candidate has the same content.
	if len(uniq(cs, func(c candidate) string { return c.identity })) == 1 {
		return &cs[0]
	}
	return nil
}

// build generates the sdist of a candidate and stores it: the sidecar is
// claimed first, so concurrent indexers agree on one release. An existing
// sidecar with the same identity is completed only with an sdist of its
// digest; otherwise build returns errRebuildDiffers and writes nothing.
func (g *GitSource) build(ctx context.Context, c candidate) error {
	m := c.remote
	read := func(p string) ([]byte, error) { return m.ReadFile(ctx, c.commit, p) }
	pkgInfo, err := WritePKGINFO(c.pkg, read)
	if err != nil {
		return err
	}
	var tarBuf bytes.Buffer
	var paths []string
	if c.pkg.Dir != "" {
		paths = []string{c.pkg.Dir}
	}
	// The sdist is built in memory, so its input is capped.
	cw := &cappedWriter{w: &tarBuf, left: g.maxBytes}
	if err := m.ArchiveTar(ctx, c.commit, paths, cw); err != nil {
		// git dies of the broken pipe, so the error needn't be ours.
		if cw.exceeded {
			return &RefusedError{Reason: fmt.Sprintf("package directory is larger than %d bytes; publish it through a storage source", g.maxBytes)}
		}
		return err
	}
	when, err := m.CommitTime(ctx, c.commit)
	if err != nil {
		return err
	}
	sd, err := BuildSdist(&tarBuf, c.pkg, pkgInfo, when)
	if err != nil {
		return err
	}
	meta, err := ParseMetadata(pkgInfo)
	if err != nil {
		return err
	}
	canon := c.pkg.Version.Canonical()
	r := release{
		Name: c.pkg.Name, Version: c.pkg.Version.String(), Canonical: canon, Identity: c.identity,
		Filename: SdistFilename(c.pkg.Name, c.pkg.Version), SHA256: digestOf(sd), Size: int64(len(sd)),
		RequiresPy: meta.RequiresPython, Remote: metrics.RedactRemote(m.Remote()), Tag: c.tag, Commit: c.commit,
		UploadTime: when, SdistFormat: SdistFormat,
	}
	if !dependenciesDynamic(meta) {
		r.Metadata = digestOf(pkgInfo)
	}
	dir := g.releaseDir(r.Name, canon)
	body, _ := json.Marshal(r)
	if _, err := g.state.PutIfAbsent(ctx, dir+"release.json", bytes.NewReader(body)); err != nil {
		if !errors.Is(err, storage.ErrExists) {
			return err
		}
		// Another indexer claimed it; only the same release may be completed.
		existing, rerr := g.readRelease(ctx, dir+"release.json")
		if rerr != nil {
			return rerr
		}
		if existing.Identity != r.Identity {
			return nil // reported as a conflict on the next pass
		}
		if existing.SHA256 != r.SHA256 {
			g.log.Warn("pypi git: a rebuilt sdist differs from its release record; not written", "source", g.name,
				"package", r.Name, "version", r.Version, "tag", c.tag, "recorded", existing.SHA256, "rebuilt", r.SHA256)
			return errRebuildDiffers
		}
		r = existing
	}
	if err := putIfAbsent(ctx, g.state, dir+storage.EscapeSegment(r.Filename), sd); err != nil {
		return err
	}
	if r.Metadata != "" {
		if err := putIfAbsent(ctx, g.state, dir+storage.EscapeSegment(r.Filename)+".metadata", pkgInfo); err != nil {
			return err
		}
	}
	return g.rec.PutProvenance(ctx, records.Provenance{
		Ecosystem: ecoName, Package: r.Name, Version: r.Version, Source: g.name, SourceType: "git",
		Remote: r.Remote, Commit: r.Commit, SHA256: r.SHA256,
	})
}

func putIfAbsent(ctx context.Context, d storage.Driver, key string, b []byte) error {
	if _, err := d.PutIfAbsent(ctx, key, bytes.NewReader(b)); err != nil && !errors.Is(err, storage.ErrExists) {
		return err
	}
	return nil
}

func (g *GitSource) readRelease(ctx context.Context, key string) (release, error) {
	rc, _, err := g.state.Get(ctx, key)
	if err != nil {
		return release{}, err
	}
	defer rc.Close()
	var r release
	err = json.NewDecoder(io.LimitReader(rc, 1<<20)).Decode(&r)
	return r, err
}

// loadStored returns every stored release by name. Sidecars never change, so
// each is read once.
func (g *GitSource) loadStored(ctx context.Context) (map[string][]release, error) {
	out := map[string][]release{}
	for info, err := range g.state.List(ctx, g.prefix()) {
		if err != nil {
			return nil, err
		}
		if !strings.HasSuffix(info.Key, "/release.json") {
			continue
		}
		r, ok := g.cachedRelease(info.Key)
		if !ok {
			var err error
			if r, err = g.readRelease(ctx, info.Key); err != nil {
				g.log.Warn("pypi git: unreadable release record", "source", g.name, "key", info.Key, "error", err)
				continue
			}
			g.cacheRelease(info.Key, r)
		}
		out[r.Name] = append(out[r.Name], r)
	}
	return out, nil
}

func (g *GitSource) cachedRelease(key string) (release, bool) {
	g.smu.Lock()
	defer g.smu.Unlock()
	r, ok := g.stored[key]
	return r, ok
}

func (g *GitSource) cacheRelease(key string, r release) {
	g.smu.Lock()
	defer g.smu.Unlock()
	g.stored[key] = r
}

// Project lists the stored releases of name.
func (g *GitSource) Project(_ context.Context, name string) (Project, error) {
	idx := g.idx.Load()
	if idx.withheld[name] {
		return Project{}, fmt.Errorf("%w: %s is declared by several repositories", ErrUnavailable, name)
	}
	rs := idx.releases[name]
	if len(rs) == 0 {
		if !idx.complete {
			return Project{}, fmt.Errorf("%w: %s (not every remote and tag is indexed yet)", ErrUnavailable, name)
		}
		if idx.pending[name] {
			return Project{}, fmt.Errorf("%w: %s has a release withheld for divergent histories or not built yet", ErrUnavailable, name)
		}
		return Project{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, name)
	}
	p := Project{Name: name}
	for _, r := range rs {
		p.Versions = append(p.Versions, r.Version)
		p.Files = append(p.Files, File{
			Filename: r.Filename, SHA256: r.SHA256, RequiresPython: r.RequiresPy, Yanked: false,
			UploadTime: r.UploadTime, Size: r.Size, CoreMetadata: r.Metadata,
		})
	}
	return p, nil
}

func (g *GitSource) lookup(ctx context.Context, name, filename string) (release, error) {
	if _, err := g.Project(ctx, name); err != nil {
		return release{}, err // withheld, not indexed yet or unknown
	}
	for _, r := range g.idx.Load().releases[name] {
		if r.Filename == filename {
			return r, nil
		}
	}
	return release{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, filename)
}

func (g *GitSource) open(ctx context.Context, key string) (Artifact, error) {
	rc, info, err := g.state.Get(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		// Claimed but not written yet (or lost): a fault, rebuilt by a pass.
		return Artifact{}, fmt.Errorf("pypi git: %s is missing", key)
	}
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Body: rc, Size: info.Size}, nil
}

// File streams a release's sdist.
func (g *GitSource) File(ctx context.Context, name, filename string) (Artifact, error) {
	r, err := g.lookup(ctx, name, filename)
	if err != nil {
		return Artifact{}, err
	}
	return g.open(ctx, g.releaseDir(name, r.Canonical)+storage.EscapeSegment(r.Filename))
}

// Metadata streams a release's PKG-INFO when its dependencies are static.
func (g *GitSource) Metadata(ctx context.Context, name, filename string) (Artifact, error) {
	r, err := g.lookup(ctx, name, filename)
	if err != nil {
		return Artifact{}, err
	}
	if r.Metadata == "" {
		return Artifact{}, fmt.Errorf("%w: no metadata for %s", resolve.ErrNotFound, filename)
	}
	return g.open(ctx, g.releaseDir(name, r.Canonical)+storage.EscapeSegment(r.Filename)+".metadata")
}

// Provenance is not served for git releases.
func (g *GitSource) Provenance(_ context.Context, _, filename string) (Artifact, error) {
	return Artifact{}, fmt.Errorf("%w: no provenance for %s", resolve.ErrNotFound, filename)
}

// Names lists the served projects.
func (g *GitSource) Names(context.Context) ([]string, error) {
	idx := g.idx.Load()
	var out []string
	for n := range idx.releases {
		if !idx.withheld[n] {
			out = append(out, n)
		}
	}
	return out, nil
}

// Conflicts returns the releases the last pass did not serve as tagged.
func (g *GitSource) Conflicts() []Conflict { return slices.Clone(g.idx.Load().conflicts) }

// Skipped returns the packages the last pass could not serve.
func (g *GitSource) Skipped() []Skipped { return slices.Clone(g.idx.Load().skipped) }

// Health reports each remote's last pass.
func (g *GitSource) Health(context.Context) []metrics.Health {
	g.hmu.Lock()
	defer g.hmu.Unlock()
	var out []metrics.Health
	for _, m := range g.mirrors {
		h := metrics.Health{Name: g.name + " " + metrics.RedactRemote(m.Remote())}
		err, seen := g.health[m.Remote()]
		switch {
		case !seen:
			h.Detail = "not indexed yet"
		case err != nil:
			h.Detail = "indexing failed; stored releases are served"
		default:
			h.OK, h.Detail = true, "indexed"
		}
		out = append(out, h)
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func uniq[T any](xs []T, key func(T) string) []string {
	var out []string
	for _, x := range xs {
		if k := key(x); !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// cappedWriter fails once more than left bytes were written.
type cappedWriter struct {
	w        io.Writer
	left     int64
	exceeded bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.left {
		c.exceeded = true
		return 0, errors.New("pypi: package directory too large")
	}
	c.left -= int64(len(p))
	return c.w.Write(p)
}
