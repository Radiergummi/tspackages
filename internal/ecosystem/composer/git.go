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
	"github.com/radiergummi/tspackages/internal/metrics"
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

// ErrUnavailable is returned (instead of a not-found) when the source cannot
// say whether a name exists: it is withheld because several remotes declare it,
// or the first index pass has not finished, or a remote has never been indexed
// successfully. It deliberately does not wrap resolve.ErrNotFound so that
// resolution never falls through to another source.
var ErrUnavailable = errors.New("composer git source unavailable")

// GitSource serves packages built from git repositories. Tags are versions
// (pinned on first sight, only once the tagged commit validates), the default
// branch (or those matching the branches allowlist) are dev versions. Dist zips
// are built once with git archive and kept in the state store as
//
//	composer-git/<source>/<commit>.zip
//
// next to composer-git/<source>/<commit>.meta.json holding the digests and the
// commit's composer.json, so a served version stays servable (with an
// unchanged checksum) even if its tag or commit later disappears upstream.
// The index is held in memory and rebuilt by Index, which Run repeats every
// poll interval.
//
// Archives are never deleted: every commit ever served as a dev branch head
// leaves a zip behind (no garbage collection in v1), and once a branch moves
// the old dev reference is no longer indexed, so it answers 404.
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

	now func() time.Time // replaced in tests

	hmu     sync.RWMutex // guards indexed
	indexed []bool       // per mirror: indexed successfully at least once

	mu     sync.Mutex // serialises Index; guards the fields below
	prev   []remoteResult
	loaded map[string]loaded // by commit; archives are immutable
	prov   map[string]bool   // commit + version pairs whose provenance is stored

	idx atomic.Pointer[gitIndex]
}

var _ Source = (*GitSource)(nil)

type remoteResult struct {
	ok       bool // indexed successfully at least once
	pkg      string
	versions []Version
}

type digest struct{ sha1, sha256 string }

type loaded struct {
	meta map[string]any
	d    digest
	size int64
}

type gitIndex struct {
	done      bool // first pass finished
	pending   bool // some remote has never been indexed successfully
	pkgs      map[string][]Version
	conflicts []Conflict
}

// NewGitSource validates the branch allowlist (path.Match syntax); poll <= 0
// means one minute.
func NewGitSource(name string, claims, branches []string, mirrors []*gitmirror.Mirror, pins *pins.Store, rec *records.Store, state storage.Driver, poll time.Duration, log *slog.Logger, maxArchive int64) (*GitSource, error) {
	for _, p := range branches {
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("composer git source %q: invalid branch pattern %q: %w", name, p, err)
		}
	}
	if poll <= 0 {
		poll = time.Minute
	}
	g := &GitSource{
		name: name, claims: claims, branches: branches, mirrors: mirrors, pins: pins, rec: rec,
		state: state, poll: poll, log: log, maxArchive: maxArchive,
		now: time.Now, indexed: make([]bool, len(mirrors)),
		prev:   make([]remoteResult, len(mirrors)),
		loaded: map[string]loaded{},
		prov:   map[string]bool{},
	}
	g.idx.Store(&gitIndex{pkgs: map[string][]Version{}})
	return g, nil
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

func archiveMetaKey(source, commit string) string {
	return "composer-git/" + source + "/" + commit + ".meta.json"
}

// Index runs one sync-and-index pass over all mirrors. A remote whose sync or
// indexing fails keeps its previous entries. Problems with single remotes or
// versions are logged; only a cancelled context is returned.
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
		metrics.SetGitLastSync(g.name, m.Remote(), m.LastSync())
		res, err := g.indexRemote(ctx, m)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			g.log.Error("composer git: indexing failed; keeping previous index", "source", g.name, "remote", m.Remote(), "error", err)
			continue
		}
		g.prev[i] = res
		g.hmu.Lock()
		g.indexed[i] = res.ok
		g.hmu.Unlock()
	}
	g.idx.Store(g.assemble())
	return nil
}

// assemble merges the per-remote results; a name claimed by two remotes is
// dropped and reported as a conflict.
func (g *GitSource) assemble() *gitIndex {
	owners := map[string][]string{}
	out := &gitIndex{done: true, pkgs: map[string][]Version{}}
	for i, r := range g.prev {
		if !r.ok {
			out.pending = true
		}
		if r.pkg != "" {
			owners[r.pkg] = append(owners[r.pkg], g.mirrors[i].Remote())
		}
	}
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

func (g *GitSource) claimsName(pkg string) bool {
	return len(g.claims) == 0 || slices.ContainsFunc(g.claims, func(c string) bool { return Match(c, pkg) })
}

// skip logs a skipped version unless the pass is being cancelled.
func (g *GitSource) skip(ctx context.Context, msg string, args ...any) {
	if ctx.Err() == nil {
		g.log.Warn(msg, args...)
	}
}

func (g *GitSource) indexRemote(ctx context.Context, m *gitmirror.Mirror) (remoteResult, error) {
	remote := m.Remote()
	refs, err := m.Refs(ctx)
	if err != nil {
		return remoteResult{}, fmt.Errorf("listing refs: %w", err)
	}
	def, err := m.DefaultBranch(ctx)
	if err != nil {
		return remoteResult{}, fmt.Errorf("default branch: %w", err)
	}
	var head string
	for _, r := range refs {
		if !r.IsTag && r.Short == def {
			head = r.Commit
		}
	}
	if head == "" {
		return remoteResult{}, fmt.Errorf("default branch %q has no commit", def)
	}
	meta, _, err := readComposerJSON(ctx, m, head)
	if err != nil {
		return remoteResult{}, fmt.Errorf("composer.json on default branch: %w", err)
	}
	declared, _ := meta["name"].(string)
	pkg, err := Normalize(declared)
	if err != nil {
		return remoteResult{}, fmt.Errorf("package name on default branch: %w", err)
	}
	if !g.claimsName(pkg) {
		g.log.Warn("composer git: package is outside the source's claims; ignored", "source", g.name, "remote", remote, "package", pkg)
		return remoteResult{ok: true}, nil
	}
	pinned, corrupt, err := g.pins.List(ctx, "composer", g.name, remote)
	if err != nil {
		return remoteResult{}, fmt.Errorf("listing pins: %w", err)
	}
	for _, cerr := range corrupt {
		g.log.Error("composer git: unreadable pin ignored", "source", g.name, "remote", remote, "error", cerr)
	}

	res := remoteResult{ok: true, pkg: pkg}
	seen := map[string]bool{}
	add := func(version, normalized, commit string, l loaded, dev bool) {
		if seen[normalized] {
			g.log.Debug("composer git: duplicate version skipped", "source", g.name, "remote", remote, "version", version)
			return
		}
		if err := g.recordProvenance(ctx, m, pkg, version, commit, l.d); err != nil {
			g.skip(ctx, "composer git: version skipped", "source", g.name, "remote", remote, "version", version, "commit", commit, "error", err)
			return
		}
		seen[normalized] = true
		res.versions = append(res.versions, Version{
			Package:   packageEntry(l.meta, pkg, version, normalized, commit, l.d.sha1),
			Version:   version,
			Reference: commit,
			Dev:       dev,
		})
	}

	// Tags: those upstream plus every pinned one, so versions already served
	// survive their tag (or commit) disappearing.
	upstream := map[string]string{}
	for _, r := range refs {
		if r.IsTag {
			upstream[r.Short] = r.Commit
		}
	}
	pinSHA := map[string]string{}
	tags := slices.Collect(maps.Keys(upstream))
	for _, p := range pinned {
		pinSHA[p.Tag] = p.SHA
		if _, ok := upstream[p.Tag]; !ok {
			tags = append(tags, p.Tag)
		}
	}
	slices.Sort(tags)
	for _, tag := range tags {
		normalized, err := NormalizeVersion(tag)
		if err != nil {
			g.log.Debug("composer git: tag is not a version", "source", g.name, "remote", remote, "tag", tag)
			continue
		}
		if strings.HasPrefix(normalized, "dev-") || strings.HasSuffix(normalized, "-dev") {
			g.skip(ctx, "composer git: tag is a dev version; skipped", "source", g.name, "remote", remote, "tag", tag)
			continue
		}
		commit, up := pinSHA[tag], upstream[tag]
		switch {
		case commit == "": // first sight: pin only a commit that validates
			if _, err := g.loadFor(ctx, m, pkg, up); err != nil {
				g.skip(ctx, "composer git: tag skipped", "source", g.name, "remote", remote, "tag", tag, "error", err)
				continue
			}
			var moved bool
			commit, moved, err = g.pins.Pin(ctx, "composer", g.name, remote, tag, up)
			if err != nil {
				g.skip(ctx, "composer git: pinning tag failed", "source", g.name, "remote", remote, "tag", tag, "error", err)
				continue
			}
			if moved { // another instance pinned it first
				g.log.Warn("composer git: tag moved upstream; serving the pinned commit", "source", g.name, "remote", remote, "tag", tag, "pinned", commit, "seen", up)
			}
		case up != "" && up != commit: // an existing pin always wins; record the move
			if commit, _, err = g.pins.Pin(ctx, "composer", g.name, remote, tag, up); err != nil {
				g.skip(ctx, "composer git: pinning tag failed", "source", g.name, "remote", remote, "tag", tag, "error", err)
				continue
			}
			g.log.Warn("composer git: tag moved upstream; serving the pinned commit", "source", g.name, "remote", remote, "tag", tag, "pinned", commit, "seen", up)
		}
		l, err := g.loadFor(ctx, m, pkg, commit)
		if err != nil {
			g.skip(ctx, "composer git: tag skipped", "source", g.name, "remote", remote, "tag", tag, "error", err)
			continue
		}
		add(tag, normalized, commit, l, false)
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
		l, err := g.loadFor(ctx, m, pkg, r.Commit)
		if err != nil {
			g.skip(ctx, "composer git: branch skipped", "source", g.name, "remote", remote, "branch", r.Short, "error", err)
			continue
		}
		add(version, normalized, r.Commit, l, true)
	}
	if ctx.Err() != nil {
		return remoteResult{}, ctx.Err()
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
	return res, nil
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

func readComposerJSON(ctx context.Context, m *gitmirror.Mirror, commit string) (map[string]any, []byte, error) {
	raw, err := m.ReadFile(ctx, commit, "composer.json")
	if err != nil {
		return nil, nil, err
	}
	meta, err := parseComposerJSON(raw)
	return meta, raw, err
}

func parseComposerJSON(raw []byte) (map[string]any, error) {
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

// archiveMeta is stored next to every archive, written with it and never
// changed.
type archiveMeta struct {
	SHA1         string          `json:"sha1"`
	SHA256       string          `json:"sha256"`
	Size         int64           `json:"size"`
	ComposerJSON json.RawMessage `json:"composer_json"`
}

// loadFor is load plus the check that the commit's composer.json names pkg.
func (g *GitSource) loadFor(ctx context.Context, m *gitmirror.Mirror, pkg, commit string) (loaded, error) {
	l, err := g.load(ctx, m, commit)
	if err != nil {
		return loaded{}, err
	}
	if n, err := Normalize(strOf(l.meta["name"])); err != nil || n != pkg {
		return loaded{}, fmt.Errorf("composer.json names %q, not %q", l.meta["name"], pkg)
	}
	return l, nil
}

// load returns the composer.json and digests of commit's archive. A stored
// sidecar is authoritative and needs neither the mirror nor the zip; without
// one the archive is read back (or built once, if absent) and the sidecar is
// written.
func (g *GitSource) load(ctx context.Context, m *gitmirror.Mirror, commit string) (loaded, error) {
	if l, ok := g.loaded[commit]; ok {
		return l, nil
	}
	key := archiveMetaKey(g.name, commit)
	l, err := g.readMeta(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		_, raw, rerr := readComposerJSON(ctx, m, commit)
		if rerr != nil {
			return loaded{}, rerr
		}
		data, zerr := g.zipBytes(ctx, m, commit)
		if zerr != nil {
			return loaded{}, zerr
		}
		s1, s256 := sha1.Sum(data), sha256.Sum256(data)
		body, merr := json.Marshal(archiveMeta{
			SHA1: hex.EncodeToString(s1[:]), SHA256: hex.EncodeToString(s256[:]),
			Size: int64(len(data)), ComposerJSON: raw,
		})
		if merr != nil {
			return loaded{}, merr
		}
		if _, perr := g.state.PutIfAbsent(ctx, key, bytes.NewReader(body)); perr != nil && !errors.Is(perr, storage.ErrExists) {
			return loaded{}, perr
		}
		// Read back whatever won, so every instance agrees on the digests.
		l, err = g.readMeta(ctx, key)
	}
	if err != nil {
		return loaded{}, err
	}
	g.loaded[commit] = l
	return l, nil
}

func (g *GitSource) readMeta(ctx context.Context, key string) (loaded, error) {
	data, err := g.readStored(ctx, key, 4*maxComposerJSONSize)
	if err != nil {
		return loaded{}, err
	}
	var am archiveMeta
	if err := json.Unmarshal(data, &am); err != nil {
		return loaded{}, fmt.Errorf("corrupt %s: %w", key, err)
	}
	meta, err := parseComposerJSON(am.ComposerJSON)
	if err != nil || am.SHA1 == "" || am.SHA256 == "" {
		return loaded{}, fmt.Errorf("corrupt %s", key)
	}
	return loaded{meta: meta, d: digest{sha1: am.SHA1, sha256: am.SHA256}, size: am.Size}, nil
}

func (g *GitSource) recordProvenance(ctx context.Context, m *gitmirror.Mirror, pkg, version, commit string, d digest) error {
	pk := commit + "\x00" + version
	if g.prov[pk] {
		return nil
	}
	if err := g.rec.PutProvenance(ctx, records.Provenance{
		Ecosystem: "composer", Package: pkg, Version: version, Source: g.name, SourceType: "git",
		Remote: m.Remote(), Commit: commit, SHA1: d.sha1, SHA256: d.sha256,
	}); err != nil {
		return err
	}
	g.prov[pk] = true
	return nil
}

// zipBytes returns the stored archive of commit, building and storing it only
// if there is none. A stored zip is canonical and is never rebuilt.
func (g *GitSource) zipBytes(ctx context.Context, m *gitmirror.Mirror, commit string) ([]byte, error) {
	key := archiveKey(g.name, commit)
	if data, err := g.readStored(ctx, key, g.maxArchive); err == nil {
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
			return g.readStored(ctx, key, g.maxArchive) // someone else stored it first: theirs is canonical
		}
		return nil, err
	}
	return w.buf.Bytes(), nil
}

// readStored reads key, failing with errTooLarge beyond max bytes.
func (g *GitSource) readStored(ctx context.Context, key string, max int64) ([]byte, error) {
	rc, _, err := g.state.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: %s over %d bytes", errTooLarge, key, max)
	}
	return data, nil
}

// Health reports one entry per remote: OK once indexed and synced within
// three poll intervals. Package-name conflicts are a separate, not-OK entry.
func (g *GitSource) Health(context.Context) []metrics.Health {
	g.hmu.RLock()
	indexed := slices.Clone(g.indexed)
	g.hmu.RUnlock()
	var out []metrics.Health
	for i, m := range g.mirrors {
		h := metrics.Health{Name: g.name + " " + m.Remote()}
		last := m.LastSync()
		switch {
		case !indexed[i]:
			h.Detail = "never indexed"
			if !last.IsZero() {
				h.Detail += "; last sync " + last.UTC().Format(time.RFC3339)
			}
		case g.now().Sub(last) > 3*g.poll:
			h.Detail = "last sync " + last.UTC().Format(time.RFC3339) + " is older than 3 poll intervals"
		default:
			h.OK = true
			h.Detail = "last sync " + last.UTC().Format(time.RFC3339)
		}
		out = append(out, h)
	}
	if cs := g.Conflicts(); len(cs) > 0 {
		names := make([]string, len(cs))
		for i, c := range cs {
			names[i] = c.Package
		}
		out = append(out, metrics.Health{Name: g.name + " conflicts", Detail: "package names declared by several remotes: " + strings.Join(names, ", ")})
	}
	return out
}

// Conflicts lists package names declared by several remotes in the last pass.
func (g *GitSource) Conflicts() []Conflict { return slices.Clone(g.idx.Load().conflicts) }

// lookup returns the indexed versions of pkg, ErrUnavailable when the source
// cannot yet say whether the name exists, or a not-found.
func (g *GitSource) lookup(pkg string) ([]Version, error) {
	idx := g.idx.Load()
	for _, c := range idx.conflicts {
		if c.Package == pkg {
			return nil, fmt.Errorf("%w: %s is declared by several remotes", ErrUnavailable, pkg)
		}
	}
	if vs, ok := idx.pkgs[pkg]; ok {
		return vs, nil
	}
	// Only a claimed name can fall through to another source, so only there
	// is a not-found wrong while the answer is unknown.
	if (!idx.done || idx.pending) && len(g.claims) > 0 && g.claimsName(pkg) {
		return nil, fmt.Errorf("%w: %s (not every remote is indexed yet)", ErrUnavailable, pkg)
	}
	return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, pkg)
}

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
	vs, err := g.lookup(pkg)
	if err != nil {
		return nil, err
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
	vs, err := g.lookup(pkg)
	if err != nil {
		return Artifact{}, err
	}
	nv, nerr := NormalizeVersion(version)
	var found *Version
	for _, v := range vs {
		if v.Reference == reference && (v.Version == version || normalizedOf(v) == version || (nerr == nil && normalizedOf(v) == nv)) {
			found = &v
			break
		}
	}
	if found == nil {
		return Artifact{}, fmt.Errorf("%w: %s %s", resolve.ErrNotFound, name, version)
	}
	// The reference is indexed, so a missing or altered zip is a fault of this
	// source, never a not-found that would let resolution try another one.
	l, err := g.readMeta(ctx, archiveMetaKey(g.name, found.Reference))
	if err != nil {
		return Artifact{}, fmt.Errorf("composer git: archive metadata of %s %s: %v", name, version, err)
	}
	rc, info, err := g.state.Get(ctx, archiveKey(g.name, found.Reference))
	if errors.Is(err, storage.ErrNotFound) {
		return Artifact{}, fmt.Errorf("composer git: stored archive of %s %s is missing", name, version)
	}
	if err != nil {
		return Artifact{}, err
	}
	if info.Size != l.size {
		rc.Close()
		return Artifact{}, fmt.Errorf("composer git: stored archive of %s %s is %d bytes, expected %d", name, version, info.Size, l.size)
	}
	dist, _ := found.Package["dist"].(map[string]any)
	return Artifact{Body: rc, Size: info.Size, SHA1: strOf(dist["shasum"])}, nil
}
