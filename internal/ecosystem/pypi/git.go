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

// errClaimedElsewhere is a build that found the release claimed by another
// indexer with other content; nothing is written.
var errClaimedElsewhere = errors.New("pypi git: release claimed with other content")

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
	identity string // set for a release: name and version are known
	refused  string // why the release cannot be served, or ""
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
	// buildRefusals are the reasons builds were refused, by remote, commit
	// and package directory; guarded by mu.
	buildRefusals map[string]string

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
		buildRefusals: map[string]string{},
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
	conflicts, withheld, pending, refused := g.resolve(ctx, cands, stored, complete)
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
	metrics.SetGitLastSync(ecoName, g.name, g.oldestSync())
	return nil
}

// oldestSync is the oldest last successful sync among the remotes, zero
// while one never synced.
func (g *GitSource) oldestSync() time.Time {
	var oldest time.Time
	for i, m := range g.mirrors {
		t := m.LastSync()
		if t.IsZero() {
			return time.Time{}
		}
		if i == 0 || t.Before(oldest) {
			oldest = t
		}
	}
	return oldest
}

// scan is what scanRemote found at a remote's tags.
type scan struct {
	cands   []candidate
	skipped []Skipped
	unread  error // a tag that could not be read
}

// scanRemote syncs a mirror and returns the candidates at its tags. A
// remote that is unreachable after it synced in this process is indexed from
// its local mirror; one that has not synced since the process started is an
// error, even if a mirror from an earlier run is on disk.
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
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
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
			reason := cmp.Or(c.refused, c.pkg.Skip)
			if reason != "" {
				skipped = append(skipped, Skipped{Remote: metrics.RedactRemote(m.Remote()), Tag: ref.Short, Dir: c.pkg.Dir, Package: c.pkg.Name, Reason: reason})
			}
			// A refused candidate still takes part in resolution: when it
			// is a version's earliest tag, the version is refused.
			if c.identity != "" {
				cands = append(cands, c)
			}
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
	if errors.Is(err, gitmirror.ErrTreeTooLarge) {
		return g.refuseCommit(key, m, commit, fmt.Sprintf("tree is too large to list (more than %d entries or a path over 1MiB)", gitmirror.MaxTreeEntries)), nil
	}
	if err != nil {
		return nil, err
	}
	// Only a directory holding a pyproject.toml can be a workspace member.
	// Paths fsck rejects are refused by RefuseTree for the package holding
	// them.
	modes := map[string]string{}
	var dirs []string
	for _, e := range tree {
		modes[e.Path] = e.Mode
		if d := path.Dir(e.Path); path.Base(e.Path) == "pyproject.toml" && d != "." && cleanTreePath(e.Path) {
			dirs = append(dirs, d)
		}
	}
	slices.Sort(dirs)
	// Every file is in the tree, so its path and mode decide the outcome
	// before git is asked: ReadFile refuses a path that is not clean or holds
	// a newline or NUL, ArchiveTar a directory that starts with "-", and a
	// symlink would be read as its target path (the sdist leaves symlinks
	// out). Whatever ReadFile still fails on is not the content's doing: a
	// path the tree lists but git cannot find is a broken mirror, so its
	// not-found is not passed on as one.
	read := func(p string) ([]byte, error) {
		mode, ok := modes[p]
		switch {
		case !cleanTreePath(p) || strings.HasPrefix(p, "-") || strings.ContainsAny(p, "\x00\n\r"):
			return nil, fmt.Errorf("%q: %w", p, errBadPath)
		case !ok:
			return nil, fmt.Errorf("%s: %w", p, resolve.ErrNotFound)
		case mode != "100644" && mode != "100755":
			return nil, fmt.Errorf("%s: %w", p, errNotRegular)
		}
		b, err := m.ReadFile(ctx, commit, p)
		if errors.Is(err, resolve.ErrNotFound) {
			return nil, fmt.Errorf("%s is in the tree but not in the mirror: %v", p, err) //nolint:errorlint // a missing object is I/O, not a miss
		}
		return b, err
	}
	pkgs, err := DiscoverPackages(ctx, read, dirs)
	switch {
	case errors.Is(err, errTooManyPyprojects):
		return g.refuseCommit(key, m, commit, fmt.Sprintf("discovery would read more than %d pyproject.toml files", maxPyprojects)), nil
	case errors.Is(err, errWorkspaceTooLarge):
		return g.refuseCommit(key, m, commit, fmt.Sprintf("workspace has more than %d globs, or a glob or member directory over %d bytes, or too many to match", maxGlobs, maxGlobBytes)), nil
	case err != nil:
		return nil, err
	}
	entries, attrsAt := groupTree(tree, pkgs)
	// Packages share no entries, so this only guards the shapes that would
	// let them (Identity, RefuseTree and lfsRefusal walk each package's).
	if total := sumLen(entries); total > gitmirror.MaxTreeEntries {
		return g.refuseCommit(key, m, commit, fmt.Sprintf("packages hold %d entries in all, more than %d", total, gitmirror.MaxTreeEntries)), nil
	}
	// Each .gitattributes is read once per commit, however many packages
	// it is an ancestor of.
	lfsMemo := map[string]lfsResult{}
	lfsCheck := func(p string) (string, error) {
		r, ok := lfsMemo[p]
		if !ok {
			r.reason, r.err = lfsFileRefusal(read, p)
			lfsMemo[p] = r
		}
		return r.reason, r.err
	}
	var out []candidate
	for i, p := range pkgs {
		c := candidate{pkg: p, remote: m, commit: commit}
		// A package with a name and version is a release candidate, even
		// when it is refused: the earliest tag of a version decides.
		if isRelease(p) {
			entries := entries[i]
			var attrs []gitmirror.TreeEntry // the ancestor directories' attributes
			for d := p.Dir; d != ""; {
				if d = path.Dir(d); d == "." {
					d = ""
				}
				attrs = append(attrs, attrsAt[d]...)
			}
			c.refused = cmp.Or(p.Skip, RefuseTree(append(slices.Clone(entries), attrs...)))
			if c.refused == "" && !keysFit(SdistFilename(p.Name, p.Version)) {
				c.refused = "name and version are too long for the store's keys"
			}
			if c.refused == "" {
				if c.refused, err = lfsRefusal(lfsCheck, append(slices.Clone(attrs), entries...)); err != nil {
					return nil, err // unread this pass, and not cached
				}
			}
			c.identity = Identity(entries, nil, attrs)
		}
		out = append(out, c)
	}
	g.byCommit[key] = out
	return slices.Clone(out), nil
}

// isRelease reports whether p has a name and version.
func isRelease(p Package) bool { return p.Name != "" && len(p.Version.release) > 0 }

// refuseCommit caches and returns the refusal of every package at commit.
func (g *GitSource) refuseCommit(key string, m *gitmirror.Mirror, commit, reason string) []candidate {
	out := []candidate{{pkg: Package{Skip: reason}, remote: m, commit: commit}}
	g.byCommit[key] = out
	return slices.Clone(out)
}

// groupTree gives each release in pkgs its tree entries (those under its
// directory, for the root package without the member directories) and
// returns the .gitattributes files by directory ("" = the root), in one walk
// over the tree. Paths fsck rejects are matched by prefix, so the package
// holding one is refused; a .gitattributes at such a path is no directory's
// attributes (a walk per package used to count it for packages it did not
// belong to).
func groupTree(tree []gitmirror.TreeEntry, pkgs []Package) ([][]gitmirror.TreeEntry, map[string][]gitmirror.TreeEntry) {
	byDir := map[string][]int{}
	rootExclude := map[string]bool{}
	for i, p := range pkgs {
		if isRelease(p) {
			byDir[p.Dir] = append(byDir[p.Dir], i)
		}
		if p.Dir == "" {
			for _, d := range p.Exclude {
				rootExclude[strings.TrimSuffix(d, "/")] = true
			}
		}
	}
	entries := make([][]gitmirror.TreeEntry, len(pkgs))
	attrsAt := map[string][]gitmirror.TreeEntry{}
	for _, e := range tree {
		if !cleanTreePath(e.Path) {
			for i, p := range pkgs {
				if isRelease(p) && inPackage(e.Path, p.Dir) && !excluded(e.Path, p.Exclude) {
					entries[i] = append(entries[i], e)
				}
			}
			continue
		}
		if path.Base(e.Path) == ".gitattributes" {
			d := path.Dir(e.Path)
			if d == "." {
				d = ""
			}
			attrsAt[d] = append(attrsAt[d], e)
		}
		inMember := false
		for d := path.Dir(e.Path); d != "."; d = path.Dir(d) {
			inMember = inMember || rootExclude[d]
			for _, i := range byDir[d] {
				entries[i] = append(entries[i], e)
			}
		}
		if !inMember {
			for _, i := range byDir[""] {
				entries[i] = append(entries[i], e)
			}
		}
	}
	return entries, attrsAt
}

// lfsRefusal returns why the package is refused when one of the
// .gitattributes files among entries routes files through Git LFS or
// cannot be checked, or "". git ignores a symlinked .gitattributes, and so
// does this. An error is a read that failed.
func lfsRefusal(check func(path string) (string, error), entries []gitmirror.TreeEntry) (string, error) {
	for _, e := range entries {
		if path.Base(e.Path) != ".gitattributes" {
			continue
		}
		if reason, err := check(e.Path); reason != "" || err != nil {
			return reason, err
		}
	}
	return "", nil
}

// lfsResult is what lfsFileRefusal found for one file.
type lfsResult struct {
	reason string
	err    error
}

// lfsFileRefusal is lfsRefusal for the .gitattributes file at p.
func lfsFileRefusal(read func(string) ([]byte, error), p string) (string, error) {
	b, err := read(p)
	switch {
	case errors.Is(err, errNotRegular):
		return "", nil
	case errors.Is(err, gitmirror.ErrTooLarge), errors.Is(err, errBadPath):
		return fmt.Sprintf("%q cannot be checked for Git LFS (over 1MiB or an unreadable path)", p), nil
	case err != nil:
		return "", err
	case bytes.Contains(b, []byte("filter=lfs")):
		return "uses Git LFS (filter=lfs), which an sdist cannot resolve", nil
	}
	return "", nil
}

func sumLen[T any](xss [][]T) int {
	n := 0
	for _, xs := range xss {
		n += len(xs)
	}
	return n
}

func inPackage(p, dir string) bool { return dir == "" || strings.HasPrefix(p, dir+"/") }

// resolve decides, per name and canonical version, what to build and what
// to report, and builds the new releases. An incomplete pass builds nothing
// new: a remote not yet scanned may declare the name too, or an unread tag
// may be a version's earliest; those names are pending instead.
func (g *GitSource) resolve(ctx context.Context, cands []candidate, stored map[string][]release, complete bool) (conflicts []Conflict, withheld, pending map[string]bool, refused []Skipped) {
	withheld, pending = map[string]bool{}, map[string]bool{}

	byName := map[string][]candidate{}
	for _, c := range cands {
		byName[c.pkg.Name] = append(byName[c.pkg.Name], c)
	}
	for _, name := range sortedKeys(byName) {
		if ctx.Err() != nil {
			return conflicts, withheld, pending, refused
		}
		cs := byName[name]
		// A refused copy in another repository neither withholds the name
		// nor takes part in its releases; within the repository that
		// serves it, a refused tag still counts.
		remotes := uniq(slices.DeleteFunc(slices.Clone(cs), func(c candidate) bool { return c.refused != "" }),
			func(c candidate) string { return c.remote.Remote() })
		switch {
		case len(remotes) == 1:
			cs = slices.DeleteFunc(cs, func(c candidate) bool { return c.remote.Remote() != remotes[0] })
		case len(remotes) == 0 && len(uniq(cs, func(c candidate) string { return c.remote.Remote() })) > 1:
			continue // refused everywhere; scanRemote reported each
		}
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
			c, skip, failed := g.resolveVersion(ctx, name, canon, byVersion[canon], stored, complete)
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
// withheld. failed reports a release not stored in this pass for a reason
// other than refused content: the pass was incomplete (so nothing new is
// built), the build failed, or another indexer's record could not be
// completed; the next pass tries again.
func (g *GitSource) resolveVersion(ctx context.Context, name, canon string, cs []candidate, stored map[string][]release, complete bool) (c *Conflict, skip *Skipped, failed bool) {
	slices.SortFunc(cs, func(a, b candidate) int { return strings.Compare(a.tag, b.tag) })
	if i := slices.IndexFunc(stored[name], func(r release) bool { return r.Canonical == canon }); i >= 0 {
		served := stored[name][i]
		if err := g.repair(ctx, served, cs); errors.Is(err, errRebuildDiffers) {
			return &Conflict{Package: name, Version: served.Version, Kind: ConflictRebuild, Tags: []string{served.Tag}}, nil, false
		}
		return differing(name, cs, served.Identity, ConflictNoBump), nil, false
	}
	if !complete {
		return nil, nil, true
	}
	winner, err := g.earliest(ctx, cs)
	if err != nil {
		g.log.Warn("pypi git: deciding the earliest tag failed", "source", g.name, "package", name, "version", cs[0].pkg.Version.String(), "error", err)
		return nil, nil, true
	}
	if winner == nil {
		var tags []string
		for _, c := range cs {
			tags = append(tags, c.tag)
		}
		return &Conflict{Package: name, Version: cs[0].pkg.Version.String(), Kind: ConflictDivergent, Tags: tags}, nil, false
	}
	if winner.refused != "" {
		return nil, nil, false // the version is refused; scanRemote reported it
	}
	refusalKey := winner.remote.Remote() + "\x00" + winner.commit + "\x00" + winner.pkg.Dir
	refuse := func(reason string) *Skipped {
		return &Skipped{Remote: metrics.RedactRemote(winner.remote.Remote()), Tag: winner.tag, Dir: winner.pkg.Dir, Package: name, Reason: reason}
	}
	if reason, ok := g.buildRefusals[refusalKey]; ok {
		return nil, refuse(reason), false // a commit's content never changes
	}
	if err := g.build(ctx, *winner); err != nil {
		if re, ok := errors.AsType[*RefusedError](err); ok {
			g.buildRefusals[refusalKey] = re.Reason
			return nil, refuse(re.Reason), false
		}
		if errors.Is(err, errRebuildDiffers) {
			return &Conflict{Package: name, Version: winner.pkg.Version.String(), Kind: ConflictRebuild, Tags: []string{winner.tag}}, nil, true
		}
		if errors.Is(err, errClaimedElsewhere) {
			return nil, nil, true // reported as a conflict once the record is listed
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
// candidates with differing contents have no common first. An error is an
// ancestry git could not decide.
//
// It asks git at most twice per distinct commit: a pass that keeps the
// earliest commit seen so far (if there is a first commit, it ends up kept,
// as nothing else precedes it), then a pass confirming that commit precedes
// all others.
func (g *GitSource) earliest(ctx context.Context, cs []candidate) (*candidate, error) {
	var distinct []int // the first candidate (by tag) of each commit
	seen := map[string]bool{}
	for i, c := range cs {
		if !seen[c.commit] {
			seen[c.commit] = true
			distinct = append(distinct, i)
		}
	}
	first := distinct[0]
	for _, i := range distinct[1:] {
		ok, err := cs[i].remote.IsAncestor(ctx, cs[i].commit, cs[first].commit)
		if err != nil {
			return nil, err
		}
		if ok {
			first = i
		}
	}
	precedesAll := true
	for _, i := range distinct {
		if i == first {
			continue
		}
		ok, err := cs[first].remote.IsAncestor(ctx, cs[first].commit, cs[i].commit)
		if err != nil {
			return nil, err
		}
		if !ok {
			precedesAll = false
			break
		}
	}
	if precedesAll {
		return &cs[first], nil
	}
	// No common first commit: fine if every candidate has the same content.
	if len(uniq(cs, func(c candidate) string { return c.identity })) == 1 {
		return &cs[0], nil
	}
	return nil, nil
}

// build generates the sdist of a candidate and stores it: the sidecar is
// claimed first, so concurrent indexers agree on one release. An existing
// sidecar with the same identity is completed only with an sdist of its
// digest; otherwise build returns errRebuildDiffers and writes nothing. One
// with another identity is left alone (errClaimedElsewhere).
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
	// The release record holds the time as RFC 3339, years 0 to 9999.
	if errors.Is(err, gitmirror.ErrBadCommitTime) || err == nil && (when.Year() < 0 || when.Year() > 9999) {
		return &RefusedError{Reason: "the tagged commit's commit time is unusable"}
	}
	if err != nil {
		return err
	}
	sd, err := BuildSdist(&tarBuf, c.pkg, pkgInfo, when)
	if err != nil {
		return err
	}
	meta, err := ParseMetadata(pkgInfo)
	if err != nil {
		return &RefusedError{Reason: "generated PKG-INFO is invalid: " + err.Error()}
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
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
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
			return errClaimedElsewhere
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
	return g.idx.Load().project(name)
}

func (idx *gitIndex) project(name string) (Project, error) {
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

func (g *GitSource) lookup(name, filename string) (release, error) {
	idx := g.idx.Load()
	if _, err := idx.project(name); err != nil {
		return release{}, err // withheld, not indexed yet or unknown
	}
	for _, r := range idx.releases[name] {
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
	r, err := g.lookup(name, filename)
	if err != nil {
		return Artifact{}, err
	}
	return g.open(ctx, g.releaseDir(name, r.Canonical)+storage.EscapeSegment(r.Filename))
}

// Metadata streams a release's PKG-INFO when its dependencies are static.
func (g *GitSource) Metadata(ctx context.Context, name, filename string) (Artifact, error) {
	r, err := g.lookup(name, filename)
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
