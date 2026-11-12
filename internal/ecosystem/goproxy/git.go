package goproxy

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/singleflight"

	"github.com/radiergummi/tspackages/internal/flight"
	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/pins"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

const (
	buildWorkers = 2
	buildTimeout = 10 * time.Minute // per job, from when a worker takes it
)

// GitOptions configures a GitSource.
type GitOptions struct {
	Name     string
	Claims   []string
	Modules  []Module                     // sorted by Path
	Mirrors  map[string]*gitmirror.Mirror // by remote
	Branches []string                     // path.Match patterns; nil = the default branch
	Pins     *pins.Store
	State    storage.Driver
	Cache    *storage.Cache
	Records  *records.Store
	Poll     time.Duration
	// MaxArtifact caps a module's git archive below MaxArchiveBytes; <= 0
	// leaves MaxArchiveBytes.
	MaxArtifact int64
	TmpDir      string // <work_dir>/go-build
	Log         *slog.Logger
}

// Refusal is a candidate tag version the git source does not serve as the
// tag suggests, as the status page lists it.
type Refusal struct {
	Module, Version, Remote, Tag, Commit string
	Kind                                 string // RefusalSkipped, RefusalRefused, RefusalMovedAfterStore
	Reason                               string
}

// Refusal kinds.
const (
	RefusalSkipped         = "skipped"
	RefusalRefused         = "refused"
	RefusalMovedAfterStore = "tag moved after the version was stored"
)

// versionRecord is a stored tag version's version.json.
type versionRecord struct {
	Format  int       `json:"format"` // GoZipFormat
	Version string    `json:"version"`
	Time    time.Time `json:"time"`
	Remote  string    `json:"remote"`
	Tag     string    `json:"tag"`
	Commit  string    `json:"commit"`
	Dir     string    `json:"dir"` // the directory the zip was built from
	ZipHash string    `json:"zip_h1"`
	ModHash string    `json:"mod_h1"`
	SHA256  string    `json:"sha256"`
	Size    int64     `json:"size"`
}

// verKey is a module path (P or P/vN) and version.
type verKey struct{ Path, Version string }

// dirKey is a directory of a commit of a remote.
type dirKey struct{ Remote, Commit, Dir string }

// candidate is a tag version from the mirror's current refs.
type candidate struct {
	key jobKey
	mod Module
	tag string
}

// goIndex is the served set: stored versions, each with its zip.
type goIndex struct {
	listed   map[verKey]versionRecord
	versions map[string][]string // by path, sorted by semver.Compare
}

// archiveRun is one git archive of a directory of a commit, spooled to a
// temp file and shared by the jobs that wait for it.
type archiveRun struct {
	id   uint64
	done chan struct{}
	path string
	err  error
	refs int // guarded by GitSource.mu
}

// errArchiveTimeout marks a git archive cut short by its job's timeout.
var errArchiveTimeout = errors.New("git archive timed out")

// GitSource serves the tagged versions of configured modules from git
// mirrors. A pass enqueues the build of every new tag version; a built
// version is stored in the state store and served from there from then on,
// whatever later happens to its tag or mirror.
type GitSource struct {
	name     string
	claims   []string
	modules  []Module
	mirrors  map[string]*gitmirror.Mirror
	remotes  []string // with modules, sorted
	pins     *pins.Store
	state    storage.Driver
	rec      *records.Store
	poll     time.Duration
	maxBytes int64
	tmpDir   string
	log      *slog.Logger
	q        *queue

	idx   atomic.Pointer[goIndex]
	pubMu sync.Mutex // serialises publishing; never held while building

	passMu sync.Mutex // serialises Index; guards loaded
	loaded bool

	treeFlight singleflight.Group

	mu sync.Mutex
	// unlisted are stored records without their zip: repairable, or refused
	// in recRefusals.
	unlisted map[verKey]versionRecord
	// recRefusals are derived from records; they are never pruned.
	recRefusals map[verKey]Refusal
	// refusals are keyed by tag candidate; a pass prunes them to its
	// candidates.
	refusals map[jobKey]Refusal
	// dirRefusals are the commit-level refusal reasons; pruned with the
	// candidates.
	dirRefusals map[dirKey]string
	treeOK      map[dirKey]bool
	failures    map[dirKey]map[uint64]bool // distinct failed attempts (timeouts, git archive exits)
	archives    map[dirKey]*archiveRun
	nextID      uint64
	// movedStored are the stored versions whose tag is pinned to another
	// commit, per remote as of its last pass.
	movedStored map[string]map[verKey]Refusal
	warnedMoves map[pins.MovedTag]bool
	// cands are each remote's candidates as of its last successful pass.
	cands  map[string]map[jobKey]candidate
	health map[string]error // last pass outcome per remote

	// Test seams; production uses the mirror's methods and no hook.
	archive       func(ctx context.Context, m *gitmirror.Mirror, commit, dir string, w io.Writer) error
	listTree      func(ctx context.Context, m *gitmirror.Mirror, commit, dir string) ([]gitmirror.TreeEntry, error)
	beforeRecheck func(jobKey) // runs just before a job re-checks its tag
}

var _ Source = (*GitSource)(nil)

// NewGitSource returns a git source and loads its stored versions; a
// failed load is retried by every pass until it succeeds.
func NewGitSource(o GitOptions) (*GitSource, error) { return newGitSource(o, nil) }

// newGitSource is NewGitSource with a hook that tests use to set seams
// before the stored versions are loaded.
func newGitSource(o GitOptions, hook func(*GitSource)) (*GitSource, error) {
	if o.TmpDir == "" {
		return nil, errors.New("goproxy git: TmpDir is required")
	}
	if o.Poll <= 0 {
		o.Poll = time.Minute
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	maxBytes := int64(MaxArchiveBytes)
	if o.MaxArtifact > 0 {
		maxBytes = min(maxBytes, o.MaxArtifact)
	}
	g := &GitSource{
		name: o.Name, claims: o.Claims, modules: slices.Clone(o.Modules), mirrors: o.Mirrors,
		pins: o.Pins, state: o.State, rec: o.Records, poll: o.Poll, maxBytes: maxBytes, tmpDir: o.TmpDir, log: o.Log,
		q:        newQueue(buildWorkers, buildTimeout, o.Log),
		unlisted: map[verKey]versionRecord{}, recRefusals: map[verKey]Refusal{}, refusals: map[jobKey]Refusal{},
		dirRefusals: map[dirKey]string{}, treeOK: map[dirKey]bool{}, failures: map[dirKey]map[uint64]bool{},
		archives: map[dirKey]*archiveRun{}, movedStored: map[string]map[verKey]Refusal{},
		warnedMoves: map[pins.MovedTag]bool{}, cands: map[string]map[jobKey]candidate{}, health: map[string]error{},
		archive: func(ctx context.Context, m *gitmirror.Mirror, commit, dir string, w io.Writer) error {
			return m.ArchiveModuleZip(ctx, commit, dir, w)
		},
		listTree: func(ctx context.Context, m *gitmirror.Mirror, commit, dir string) ([]gitmirror.TreeEntry, error) {
			return m.ListTree(ctx, commit, dir)
		},
	}
	for _, mod := range g.modules {
		if g.mirrors[mod.Remote] == nil {
			return nil, fmt.Errorf("goproxy git: no mirror for %s", mod.Remote)
		}
		if !slices.Contains(g.remotes, mod.Remote) {
			g.remotes = append(g.remotes, mod.Remote)
		}
	}
	slices.Sort(g.remotes)
	g.idx.Store(&goIndex{listed: map[verKey]versionRecord{}, versions: map[string][]string{}})
	if hook != nil {
		hook(g)
	}
	g.passMu.Lock()
	defer g.passMu.Unlock()
	if err := g.load(context.Background()); err != nil {
		g.log.Warn("goproxy git: loading stored versions failed; retrying with the next pass", "source", g.name, "error", err)
	}
	return g, nil
}

func (g *GitSource) Name() string     { return g.name }
func (g *GitSource) Claims() []string { return g.claims }

func (g *GitSource) prefix() string { return "go-git/" + g.name + "/" }

// versionDir is the state store directory of a stored version. The caller
// has checked that both segments fit.
func (g *GitSource) versionDir(vk verKey) string {
	p, _ := pathSeg(vk.Path)
	v, _ := versionSeg(vk.Version)
	return g.prefix() + p + "/" + v + "/"
}

// moduleFor returns the configured module serving p: p is its Path or
// Path+"/vN" (N >= 2).
func (g *GitSource) moduleFor(p string) (Module, bool) {
	for _, mod := range g.modules {
		if _, err := requestedMajor(mod.Path, p); err == nil {
			return mod, true
		}
	}
	return Module{}, false
}

// Run builds in the background and runs a pass every poll interval until
// ctx is done.
func (g *GitSource) Run(ctx context.Context) {
	done := make(chan struct{})
	go func() { g.q.run(ctx); close(done) }()
	defer func() { <-done }()
	for {
		if err := g.Index(ctx); err != nil && ctx.Err() == nil {
			g.log.Error("goproxy git: pass failed", "source", g.name, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(g.poll):
		}
	}
}

// load reads the stored versions once: each record is read and kept in
// memory, and a version is listed only when its module.zip exists. A record
// without its zip is queued for repair.
func (g *GitSource) load(ctx context.Context) error {
	type files struct{ record, zip bool }
	dirs := map[string]*files{}
	for info, err := range g.state.List(ctx, g.prefix()) {
		if err != nil {
			return err
		}
		dir, file := path.Split(strings.TrimPrefix(info.Key, g.prefix()))
		f := dirs[dir]
		if f == nil {
			f = &files{}
			dirs[dir] = f
		}
		switch file {
		case "version.json":
			f.record = true
		case "module.zip":
			f.zip = true
		}
	}
	listed := map[verKey]versionRecord{}
	unlisted := map[verKey]versionRecord{}
	for _, dir := range slices.Sorted(maps.Keys(dirs)) {
		if !dirs[dir].record {
			continue
		}
		segs := strings.Split(strings.TrimSuffix(dir, "/"), "/")
		if len(segs) != 2 {
			continue
		}
		p, perr := storage.UnescapeSegment(segs[0])
		v, verr := storage.UnescapeSegment(segs[1])
		if perr != nil || verr != nil {
			continue
		}
		if _, ok := g.moduleFor(p); !ok {
			continue // a module no longer configured
		}
		rec, err := g.readRecord(ctx, g.prefix()+dir+"version.json")
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			g.log.Warn("goproxy git: unreadable version record", "source", g.name, "module", p, "version", v, "error", err)
			continue
		}
		if rec.Version != v {
			g.log.Warn("goproxy git: version record for another version", "source", g.name, "module", p, "version", v, "recorded", rec.Version)
			continue
		}
		vk := verKey{p, v}
		if dirs[dir].zip {
			listed[vk] = rec
		} else {
			unlisted[vk] = rec
		}
	}
	idx := &goIndex{listed: listed, versions: map[string][]string{}}
	for vk := range listed {
		idx.versions[vk.Path] = append(idx.versions[vk.Path], vk.Version)
	}
	for _, vs := range idx.versions {
		slices.SortFunc(vs, semver.Compare)
	}
	g.pubMu.Lock()
	g.idx.Store(idx)
	g.pubMu.Unlock()
	for vk, rec := range unlisted {
		g.enqueueRepair(vk, rec)
	}
	g.loaded = true
	return nil
}

func (g *GitSource) readRecord(ctx context.Context, key string) (versionRecord, error) {
	rc, _, err := g.state.Get(ctx, key)
	if err != nil {
		return versionRecord{}, err
	}
	defer rc.Close()
	var r versionRecord
	err = json.NewDecoder(io.LimitReader(rc, 1<<20)).Decode(&r)
	return r, err
}

// Index runs one pass: per remote, sync, list the refs, pin the tags of
// stored versions and enqueue a build for every candidate that is neither
// stored, refused, skipped nor queued. It never waits for builds. A remote
// that fails keeps its last pass's state; one that has not synced in this
// process is not indexed from its mirror.
func (g *GitSource) Index(ctx context.Context) error {
	g.passMu.Lock()
	defer g.passMu.Unlock()
	if !g.loaded {
		if err := g.load(ctx); err != nil {
			return fmt.Errorf("goproxy git: load stored versions: %w", err)
		}
	}
	for _, remote := range g.remotes {
		err := g.passRemote(ctx, remote)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		g.mu.Lock()
		g.health[remote] = err
		g.mu.Unlock()
		if err != nil {
			g.log.Warn("goproxy git: indexing a remote failed", "source", g.name, "remote", metrics.RedactRemote(remote), "error", err)
		}
	}
	return nil
}

func (g *GitSource) passRemote(ctx context.Context, remote string) error {
	m := g.mirrors[remote]
	if err := m.Sync(ctx); err != nil {
		if m.LastSync().IsZero() {
			return err
		}
		g.log.Warn("goproxy git: sync failed; indexing the local mirror", "source", g.name, "remote", metrics.RedactRemote(remote), "error", err)
	}
	// Task 18: the stored commits' hidden refs are ensured here, after the
	// sync.
	refs, err := m.Refs(ctx)
	if err != nil {
		return err
	}
	cands := g.candidates(remote, refs)
	moved := map[verKey]Refusal{}
	for _, k := range slices.SortedFunc(maps.Keys(cands), compareJobKeys) {
		c := cands[k]
		vk := verKey{k.Path, k.Version}
		if rec, ok := g.idx.Load().listed[vk]; ok {
			if err := g.checkPin(ctx, c, rec, moved); err != nil {
				return err
			}
			continue
		}
		g.mu.Lock()
		_, unlisted := g.unlisted[vk]
		_, refused := g.refusals[k]
		g.mu.Unlock()
		if unlisted || refused {
			continue
		}
		g.q.enqueue(k, k.Path, jobPass, g.tagJob(m, c))
	}
	g.prune(remote, cands, moved)
	return nil
}

func compareJobKeys(a, b jobKey) int {
	return cmp.Or(strings.Compare(a.Path, b.Path), semver.Compare(a.Version, b.Version), strings.Compare(a.Commit, b.Commit))
}

// candidates returns the tag versions of the remote's modules at refs:
// for module path P with dir d, tag t names version v of P or of P/vN
// (N = semver.Major(v) >= 2) as TagVersion accepts it.
func (g *GitSource) candidates(remote string, refs []gitmirror.Ref) map[jobKey]candidate {
	out := map[jobKey]candidate{}
	for _, mod := range g.modules {
		if mod.Remote != remote {
			continue
		}
		prefix := ""
		if mod.Dir != "" {
			prefix = mod.Dir + "/"
		}
		add := func(p, v string, r gitmirror.Ref) {
			k := jobKey{Remote: remote, Commit: r.Commit, Dir: mod.Dir, Path: p, Version: v}
			out[k] = candidate{key: k, mod: mod, tag: r.Short}
		}
		for _, r := range refs {
			if !r.IsTag || !strings.HasPrefix(r.Short, prefix) {
				continue
			}
			if v, ok := TagVersion(r.Short, prefix, ""); ok {
				add(mod.Path, v, r)
				continue
			}
			major := semver.Major(r.Short[len(prefix):])
			if major == "" || major == "v0" || major == "v1" {
				continue
			}
			if v, ok := TagVersion(r.Short, prefix, "/"+major); ok {
				add(mod.Path+"/"+major, v, r)
			}
		}
	}
	return out
}

// checkPin pins a stored version's tag to the tag's current commit. A
// move is logged once and listed by the pin store; a pin on another commit
// than the record's (re-pinned after an operator deleted the pin) is
// reported in moved.
func (g *GitSource) checkPin(ctx context.Context, c candidate, rec versionRecord, moved map[verKey]Refusal) error {
	pinned, isMove, err := g.pins.Pin(ctx, ecoName, g.name, c.key.Remote, c.tag, c.key.Commit)
	if err != nil {
		return fmt.Errorf("pin %s: %w", c.tag, err)
	}
	if isMove {
		g.warnMove(c, pinned)
	}
	if pinned != rec.Commit {
		moved[verKey{c.key.Path, c.key.Version}] = g.movedRefusal(c, rec, pinned)
	}
	return nil
}

func (g *GitSource) warnMove(c candidate, pinned string) {
	mt := pins.MovedTag{Ecosystem: ecoName, Source: g.name, Remote: c.key.Remote, Tag: c.tag, Pinned: pinned, Seen: c.key.Commit}
	g.mu.Lock()
	seen := g.warnedMoves[mt]
	g.warnedMoves[mt] = true
	g.mu.Unlock()
	if !seen {
		g.log.Warn("goproxy git: tag moved upstream; serving the stored version", "source", g.name,
			"remote", metrics.RedactRemote(c.key.Remote), "tag", c.tag, "pinned", pinned, "seen", c.key.Commit)
	}
}

func (g *GitSource) movedRefusal(c candidate, rec versionRecord, pinned string) Refusal {
	return Refusal{
		Module: c.key.Path, Version: c.key.Version, Remote: metrics.RedactRemote(c.key.Remote), Tag: c.tag, Commit: pinned,
		Kind: RefusalMovedAfterStore, Reason: fmt.Sprintf("pinned to %s; stored from %s", pinned, rec.Commit),
	}
}

// prune keeps the tag-keyed refusals and commit-level state of remote that
// its current candidates (or a stored record awaiting repair) still use.
func (g *GitSource) prune(remote string, cands map[jobKey]candidate, moved map[verKey]Refusal) {
	g.mu.Lock()
	defer g.mu.Unlock()
	commits := map[string]bool{}
	for k := range cands {
		commits[k.Commit] = true
	}
	for _, rec := range g.unlisted {
		commits[rec.Commit] = true
	}
	for k := range g.refusals {
		if _, ok := cands[k]; k.Remote == remote && !ok {
			delete(g.refusals, k)
		}
	}
	stale := func(k dirKey) bool { return k.Remote == remote && !commits[k.Commit] }
	maps.DeleteFunc(g.dirRefusals, func(k dirKey, _ string) bool { return stale(k) })
	maps.DeleteFunc(g.treeOK, func(k dirKey, _ bool) bool { return stale(k) })
	maps.DeleteFunc(g.failures, func(k dirKey, _ map[uint64]bool) bool { return stale(k) })
	g.movedStored[remote] = moved
	g.cands[remote] = cands
}

// tagJob builds and stores a candidate. Once the job holds the version's
// record (it won or adopted it), retries never drop it.
func (g *GitSource) tagJob(m *gitmirror.Mirror, c candidate) func(context.Context) error {
	var claimed *versionRecord
	return func(ctx context.Context) error {
		err := g.buildTag(ctx, m, c, &claimed)
		var ref *RefusalError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &ref):
			return g.refuseJob(c, RefusalRefused, ref.Reason)
		case claimed == nil:
			// A moved or deleted tag (its commit possibly gone with it) ends
			// the job; the next pass enqueues the new commit.
			if cur, terr := tagCommit(ctx, m, c.tag); terr == nil && cur != c.key.Commit {
				g.log.Info("goproxy git: tag moved during its build; dropped", "source", g.name, "tag", c.tag, "commit", c.key.Commit, "error", err)
				return nil
			}
		}
		return err
	}
}

// refuseJob records a refusal for a tag candidate unless one is recorded
// for it, and returns it as a *RefusalError.
func (g *GitSource) refuseJob(c candidate, kind, reason string) error {
	k := c.key
	g.mu.Lock()
	_, have := g.refusals[k]
	_, haveRec := g.recRefusals[verKey{k.Path, k.Version}]
	if !have && !haveRec {
		g.refusals[k] = Refusal{
			Module: k.Path, Version: k.Version, Remote: metrics.RedactRemote(k.Remote), Tag: c.tag, Commit: k.Commit,
			Kind: kind, Reason: reason,
		}
	}
	g.mu.Unlock()
	if !have && !haveRec {
		g.log.Warn("goproxy git: tag version "+kind, "source", g.name, "module", k.Path, "version", k.Version,
			"tag", c.tag, "commit", k.Commit, "reason", reason)
	}
	return &RefusalError{Reason: reason}
}

// refuseRecord reports a stored record that cannot be completed; the
// version answers ErrUnavailable.
func (g *GitSource) refuseRecord(vk verKey, rec versionRecord, reason string) error {
	g.mu.Lock()
	g.unlisted[vk] = rec
	g.recRefusals[vk] = Refusal{
		Module: vk.Path, Version: vk.Version, Remote: metrics.RedactRemote(rec.Remote), Tag: rec.Tag, Commit: rec.Commit,
		Kind: RefusalRefused, Reason: reason,
	}
	g.mu.Unlock()
	g.log.Warn("goproxy git: stored version refused", "source", g.name, "module", vk.Path, "version", vk.Version,
		"commit", rec.Commit, "reason", reason)
	return &RefusalError{Reason: reason}
}

func (g *GitSource) dirRefusal(dk dirKey) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.dirRefusals[dk]
}

func (g *GitSource) refuseDir(dk dirKey, reason string) *RefusalError {
	g.mu.Lock()
	g.dirRefusals[dk] = reason
	g.mu.Unlock()
	return &RefusalError{Reason: reason}
}

// buildTag builds a candidate's zip and stores the version.
func (g *GitSource) buildTag(ctx context.Context, m *gitmirror.Mirror, c candidate, claimed **versionRecord) error {
	k := c.key
	if err := g.checkTree(ctx, m, dirKey{k.Remote, k.Commit, k.Dir}); err != nil {
		return err
	}
	read := func(file string) ([]byte, error) { return m.ReadFileMax(ctx, k.Commit, file, MaxGoMod) }
	found, reason, err := findModule(read, c.mod, k.Path)
	var ref *RefusalError
	switch {
	case reason != "":
		return g.refuseJob(c, RefusalSkipped, reason)
	case errors.As(err, &ref):
		return g.refuseDir(dirKey{k.Remote, k.Commit, found.Dir}, ref.Reason)
	case err != nil:
		return err
	}
	dk := dirKey{k.Remote, k.Commit, found.Dir}
	if reason := g.dirRefusal(dk); reason != "" {
		return &RefusalError{Reason: reason}
	}
	if reason := checkGoDirective(found.GoMod); reason != "" {
		return g.refuseDir(dk, reason)
	}
	if _, ok := pathSeg(k.Path); !ok {
		return &RefusalError{Reason: "module path or version too long for a storage key"}
	}
	if _, ok := versionSeg(k.Version); !ok {
		return &RefusalError{Reason: "module path or version too long for a storage key"}
	}
	when, err := m.CommitTime(ctx, k.Commit)
	switch {
	case errors.Is(err, gitmirror.ErrBadCommitTime) || err == nil && (when.Year() < 1 || when.Year() > 9999):
		return &RefusalError{Reason: "the tagged commit's commit time is unusable"}
	case err != nil:
		return err
	}
	zipPath, res, err := g.build(ctx, m, dk, module.Version{Path: k.Path, Version: k.Version}, found.GoMod)
	if err != nil {
		return err
	}
	defer os.Remove(zipPath)
	rec := versionRecord{
		Format: GoZipFormat, Version: k.Version, Time: when, Remote: metrics.RedactRemote(k.Remote), Tag: c.tag, Commit: k.Commit, Dir: found.Dir,
		ZipHash: res.ZipHash, ModHash: res.ModHash, SHA256: res.SHA256, Size: res.Size,
	}
	return g.store(ctx, m, c, rec, found.GoMod, zipPath, claimed)
}

// checkTree applies the ListTree caps to a directory of a commit, once per
// (remote, commit, dir).
func (g *GitSource) checkTree(ctx context.Context, m *gitmirror.Mirror, dk dirKey) error {
	_, err := flight.Do(ctx, &g.treeFlight, dk.Remote+"\x00"+dk.Commit+"\x00"+dk.Dir, func() (struct{}, error) {
		g.mu.Lock()
		reason, ok := g.dirRefusals[dk], g.treeOK[dk]
		g.mu.Unlock()
		switch {
		case reason != "":
			return struct{}{}, &RefusalError{Reason: reason}
		case ok:
			return struct{}{}, nil
		}
		_, err := g.listTree(ctx, m, dk.Commit, dk.Dir)
		switch {
		case errors.Is(err, gitmirror.ErrTreeTooLarge):
			return struct{}{}, g.refuseDir(dk, "tree over the listing caps")
		case err != nil:
			return struct{}{}, err
		}
		g.mu.Lock()
		g.treeOK[dk] = true
		g.mu.Unlock()
		return struct{}{}, nil
	})
	return err
}

// build builds the module zip of mv from directory dk of a commit. A
// refusal from the archive is recorded for dk; a timeout or a git archive
// exit is retried once per dk, and the second becomes a refusal.
func (g *GitSource) build(ctx context.Context, m *gitmirror.Mirror, dk dirKey, mv module.Version, gomod []byte) (string, ZipResult, error) {
	if reason := g.dirRefusal(dk); reason != "" {
		return "", ZipResult{}, &RefusalError{Reason: reason}
	}
	var run *archiveRun
	zipPath, res, err := BuildZip(ctx, BuildInput{
		Version: mv,
		Subdir:  dk.Dir,
		GoMod:   gomod,
		Archive: func(ctx context.Context, w io.Writer) error {
			r, release, err := g.sharedArchive(ctx, m, dk)
			run = r
			if err != nil {
				return err
			}
			defer release()
			f, err := os.Open(r.path)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(w, f)
			return err
		},
		License: func(ctx context.Context) ([]byte, error) {
			return m.ReadFileMax(ctx, dk.Commit, "LICENSE", MaxLICENSE)
		},
		TmpDir:   g.tmpDir,
		MaxBytes: g.maxBytes,
	})
	if err == nil {
		return zipPath, res, nil
	}
	if ref, ok := errors.AsType[*RefusalError](err); ok {
		// zip.Create's content checks depend on the version; the rest on
		// the directory alone.
		if !strings.HasPrefix(ref.Reason, "zip: ") {
			return "", ZipResult{}, g.refuseDir(dk, ref.Reason)
		}
		return "", ZipResult{}, err
	}
	if errors.Is(err, gitmirror.ErrArchiveFailed) || errors.Is(err, errArchiveTimeout) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		g.mu.Lock()
		id := run.idOrNext(g)
		if g.failures[dk] == nil {
			g.failures[dk] = map[uint64]bool{}
		}
		g.failures[dk][id] = true
		n := len(g.failures[dk])
		g.mu.Unlock()
		if n >= 2 {
			return "", ZipResult{}, g.refuseDir(dk, "git archive failed twice: "+err.Error())
		}
	}
	return "", ZipResult{}, err
}

// idOrNext returns the id of a failed shared archive, so that the jobs
// sharing it count one failure, or a new id for any other failed attempt.
// g.mu is held.
func (r *archiveRun) idOrNext(g *GitSource) uint64 {
	if r != nil && r.err != nil {
		return r.id
	}
	g.nextID++
	return g.nextID
}

// sharedArchive spools git archive's output for dk once for every job that
// asks while it runs or is still in use. release removes the spool after the
// last user.
func (g *GitSource) sharedArchive(ctx context.Context, m *gitmirror.Mirror, dk dirKey) (r *archiveRun, release func(), err error) {
	g.mu.Lock()
	r = g.archives[dk]
	leader := r == nil
	if leader {
		g.nextID++
		r = &archiveRun{id: g.nextID, done: make(chan struct{})}
		g.archives[dk] = r
	}
	r.refs++
	g.mu.Unlock()
	release = func() {
		g.mu.Lock()
		r.refs--
		last := r.refs == 0
		if last && g.archives[dk] == r {
			delete(g.archives, dk)
		}
		g.mu.Unlock()
		if last && r.path != "" {
			os.Remove(r.path)
		}
	}
	if leader {
		r.path, r.err = g.spool(ctx, m, dk)
		close(r.done)
	} else {
		select {
		case <-r.done:
		case <-ctx.Done():
			release()
			return r, nil, ctx.Err()
		}
	}
	if r.err != nil {
		release()
		return r, nil, r.err
	}
	return r, release, nil
}

// spool writes the git archive of dk to a temp file, capped at maxBytes.
func (g *GitSource) spool(ctx context.Context, m *gitmirror.Mirror, dk dirKey) (string, error) {
	f, err := os.CreateTemp(g.tmpDir, "shared-*.zip")
	if err != nil {
		return "", err
	}
	cw := &capWriter{w: f, max: g.maxBytes}
	err = g.archive(ctx, m, dk.Commit, dk.Dir, cw)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	switch {
	case cw.over:
		err = &RefusalError{Reason: fmt.Sprintf("archive over %d bytes", g.maxBytes)}
	case err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		err = fmt.Errorf("%w: %w", errArchiveTimeout, err)
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// tagCommit returns the commit the mirror's tag points at, "" when the tag
// is gone.
func tagCommit(ctx context.Context, m *gitmirror.Mirror, tag string) (string, error) {
	refs, err := m.Refs(ctx)
	if err != nil {
		return "", err
	}
	for _, r := range refs {
		if r.IsTag && r.Short == tag {
			return r.Commit, nil
		}
	}
	return "", nil
}

// store claims the version's record, completes it and pins its tag. Before
// the claim the tag is re-checked: a job whose tag moved is dropped. A job
// that finds the record claimed adopts it and pins its commit.
func (g *GitSource) store(ctx context.Context, m *gitmirror.Mirror, c candidate, rec versionRecord, gomod []byte, zipPath string, claimed **versionRecord) error {
	k := c.key
	vk := verKey{k.Path, k.Version}
	built := ZipResult{ZipHash: rec.ZipHash, ModHash: rec.ModHash, SHA256: rec.SHA256, Size: rec.Size}
	if *claimed == nil {
		if g.beforeRecheck != nil {
			g.beforeRecheck(k)
		}
		cur, err := tagCommit(ctx, m, c.tag)
		if err != nil {
			return err
		}
		if cur != k.Commit {
			g.log.Info("goproxy git: tag moved before its version was stored; dropped", "source", g.name,
				"tag", c.tag, "built", k.Commit, "now", cur)
			return nil
		}
		body, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		key := g.versionDir(vk) + "version.json"
		if _, err := g.state.PutIfAbsent(ctx, key, bytes.NewReader(body)); err != nil {
			if !errors.Is(err, storage.ErrExists) {
				return err
			}
			if rec, err = g.readRecord(ctx, key); err != nil {
				return err
			}
		}
		*claimed = &rec
	}
	rec = **claimed
	if err := g.complete(ctx, vk, rec, built, k.Commit, gomod, zipPath); err != nil {
		return err
	}
	pinned, isMove, err := g.pins.Pin(ctx, ecoName, g.name, k.Remote, c.tag, rec.Commit)
	if err != nil {
		return err
	}
	if isMove {
		g.warnMove(candidate{key: jobKey{Remote: k.Remote, Commit: rec.Commit}, tag: c.tag}, pinned)
	}
	if pinned != rec.Commit {
		g.mu.Lock()
		if g.movedStored[k.Remote] == nil {
			g.movedStored[k.Remote] = map[verKey]Refusal{}
		}
		g.movedStored[k.Remote][vk] = g.movedRefusal(c, rec, pinned)
		g.mu.Unlock()
	}
	return nil
}

// complete makes rec's version servable. When its zip is stored it is
// published; otherwise the zip built from commit is written if its h1
// hashes equal the record's. A record of another commit is left to a
// repair.
func (g *GitSource) complete(ctx context.Context, vk verKey, rec versionRecord, built ZipResult, commit string, gomod []byte, zipPath string) error {
	dir := g.versionDir(vk)
	_, err := g.state.Stat(ctx, dir+"module.zip")
	switch {
	case err == nil:
		g.publish(vk, rec)
		return nil
	case !errors.Is(err, storage.ErrNotFound):
		return err
	case commit != rec.Commit:
		g.enqueueRepair(vk, rec)
		return nil
	case built.ZipHash != rec.ZipHash || built.ModHash != rec.ModHash:
		return g.refuseRecord(vk, rec, "h1 differs from the record")
	}
	if err := putIfAbsent(ctx, g.state, dir+"go.mod", bytes.NewReader(gomod)); err != nil {
		return err
	}
	if err := g.rec.PutProvenance(ctx, records.Provenance{
		Ecosystem: ecoName, Package: vk.Path, Version: vk.Version, Source: g.name, SourceType: "git",
		Remote: rec.Remote, Commit: rec.Commit, DeclaredDigest: rec.ZipHash, SHA256: built.SHA256,
	}); err != nil {
		return err
	}
	f, err := os.Open(zipPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := putIfAbsent(ctx, g.state, dir+"module.zip", f); err != nil {
		return err
	}
	g.publish(vk, rec)
	return nil
}

func putIfAbsent(ctx context.Context, d storage.Driver, key string, r io.Reader) error {
	if _, err := d.PutIfAbsent(ctx, key, r); err != nil && !errors.Is(err, storage.ErrExists) {
		return err
	}
	return nil
}

// enqueueRepair marks a record without its zip and queues its rebuild.
func (g *GitSource) enqueueRepair(vk verKey, rec versionRecord) {
	mod, _ := g.moduleFor(vk.Path)
	g.mu.Lock()
	g.unlisted[vk] = rec
	g.mu.Unlock()
	k := jobKey{Remote: mod.Remote, Commit: rec.Commit, Dir: mod.Dir, Path: vk.Path, Version: vk.Version}
	g.q.enqueue(k, vk.Path, jobRepair, g.repairJob(g.mirrors[mod.Remote], vk, rec))
}

// repairJob rebuilds a stored version's missing zip from the recorded commit
// and directory, and writes it only if its h1 hashes equal the record's.
func (g *GitSource) repairJob(m *gitmirror.Mirror, vk verKey, rec versionRecord) func(context.Context) error {
	return func(ctx context.Context) error {
		gomod, err := m.ReadFileMax(ctx, rec.Commit, path.Join(rec.Dir, "go.mod"), MaxGoMod)
		switch {
		case errors.Is(err, gitmirror.ErrNoCommit):
			return g.refuseRecord(vk, rec, "zip missing and commit gone")
		case errors.Is(err, resolve.ErrNotFound):
			return g.refuseRecord(vk, rec, "zip missing and go.mod gone from the recorded commit")
		case errors.Is(err, gitmirror.ErrTooLarge):
			return g.refuseRecord(vk, rec, reasonGoModTooLarge)
		case err != nil:
			return err
		}
		dk := dirKey{m.Remote(), rec.Commit, rec.Dir}
		zipPath, res, err := g.build(ctx, m, dk, module.Version{Path: vk.Path, Version: vk.Version}, gomod)
		var ref *RefusalError
		switch {
		case errors.As(err, &ref):
			return g.refuseRecord(vk, rec, ref.Reason)
		case err != nil:
			return err
		}
		defer os.Remove(zipPath)
		return g.complete(ctx, vk, rec, res, rec.Commit, gomod, zipPath)
	}
}

// publish lists a stored version: the index is copied, changed and swapped.
func (g *GitSource) publish(vk verKey, rec versionRecord) {
	g.mu.Lock()
	delete(g.unlisted, vk)
	g.mu.Unlock()
	g.pubMu.Lock()
	defer g.pubMu.Unlock()
	old := g.idx.Load()
	if _, ok := old.listed[vk]; ok {
		return
	}
	idx := &goIndex{listed: maps.Clone(old.listed), versions: maps.Clone(old.versions)}
	idx.listed[vk] = rec
	vs := append(slices.Clone(idx.versions[vk.Path]), vk.Version)
	slices.SortFunc(vs, semver.Compare)
	idx.versions[vk.Path] = vs
	g.idx.Store(idx)
}

// lookup returns the stored record of a canonical version of a configured
// module. A record that cannot be served (its zip missing, awaiting repair
// or refused) is ErrUnavailable.
func (g *GitSource) lookup(p, v string) (versionRecord, error) {
	if _, ok := g.moduleFor(p); !ok {
		return versionRecord{}, fmt.Errorf("%w: %s is not a module of this source", resolve.ErrNotFound, p)
	}
	if !semver.IsValid(v) || semver.Canonical(v) != v {
		return versionRecord{}, fmt.Errorf("%w: %s@%s", resolve.ErrNotFound, p, v)
	}
	vk := verKey{p, v}
	if rec, ok := g.idx.Load().listed[vk]; ok {
		return rec, nil
	}
	g.mu.Lock()
	_, unlisted := g.unlisted[vk]
	refusal, refused := g.recRefusals[vk]
	g.mu.Unlock()
	switch {
	case refused:
		return versionRecord{}, fmt.Errorf("%w: %s@%s: %s", ErrUnavailable, p, v, refusal.Reason)
	case unlisted:
		return versionRecord{}, fmt.Errorf("%w: %s@%s: its zip is being repaired", ErrUnavailable, p, v)
	}
	return versionRecord{}, fmt.Errorf("%w: %s@%s", resolve.ErrNotFound, p, v)
}

// List returns the stored versions of p, sorted.
func (g *GitSource) List(_ context.Context, p string) ([]string, error) {
	if _, ok := g.moduleFor(p); !ok {
		return nil, fmt.Errorf("%w: %s is not a module of this source", resolve.ErrNotFound, p)
	}
	return slices.Clone(g.idx.Load().versions[p]), nil
}

// Info answers a stored canonical version; any other query is not found.
func (g *GitSource) Info(_ context.Context, p, v string) (Info, error) {
	rec, err := g.lookup(p, v)
	if err != nil {
		return Info{}, err
	}
	return Info{Version: v, Time: rec.Time}, nil
}

// Latest answers the highest stored release, else the highest stored
// prerelease.
func (g *GitSource) Latest(_ context.Context, p string) (Info, error) {
	if _, ok := g.moduleFor(p); !ok {
		return Info{}, fmt.Errorf("%w: %s is not a module of this source", resolve.ErrNotFound, p)
	}
	idx := g.idx.Load()
	vs := idx.versions[p]
	if len(vs) == 0 {
		return Info{}, fmt.Errorf("%w: %s has no stored versions", resolve.ErrNotFound, p)
	}
	best := vs[len(vs)-1]
	for _, v := range slices.Backward(vs) {
		if semver.Prerelease(v) == "" {
			best = v
			break
		}
	}
	return Info{Version: best, Time: idx.listed[verKey{p, best}].Time}, nil
}

// Mod streams a stored version's go.mod.
func (g *GitSource) Mod(ctx context.Context, p, v string) (Artifact, error) {
	return g.open(ctx, p, v, "go.mod")
}

// Zip streams a stored version's module zip.
func (g *GitSource) Zip(ctx context.Context, p, v string) (Artifact, error) {
	return g.open(ctx, p, v, "module.zip")
}

func (g *GitSource) open(ctx context.Context, p, v, file string) (Artifact, error) {
	if _, err := g.lookup(p, v); err != nil {
		return Artifact{}, err
	}
	rc, size, err := storage.OpenObject(ctx, g.state, g.versionDir(verKey{p, v})+file)
	if errors.Is(err, storage.ErrNotFound) {
		return Artifact{}, fmt.Errorf("%w: %s@%s: stored %s is missing", ErrUnavailable, p, v, file)
	}
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Body: rc, Size: size}, nil
}

// Refusals lists the skipped and refused tag versions and the stored
// versions whose tag was re-pinned elsewhere.
func (g *GitSource) Refusals() []Refusal {
	g.mu.Lock()
	out := slices.Collect(maps.Values(g.refusals))
	out = slices.AppendSeq(out, maps.Values(g.recRefusals))
	for _, rows := range g.movedStored {
		out = slices.AppendSeq(out, maps.Values(rows))
	}
	g.mu.Unlock()
	slices.SortFunc(out, func(a, b Refusal) int {
		return cmp.Or(strings.Compare(a.Module, b.Module), semver.Compare(a.Version, b.Version),
			strings.Compare(a.Kind, b.Kind), strings.Compare(a.Commit, b.Commit))
	})
	return out
}

// MovedPackage returns the module whose tag prefix the moved tag has (the
// longest dir wins), or "" for another source's tag or no module.
func (g *GitSource) MovedPackage(mt pins.MovedTag) string {
	if mt.Source != g.name || mt.Ecosystem != ecoName {
		return ""
	}
	best, bestLen := "", -1
	for _, mod := range g.modules {
		if mod.Remote != mt.Remote {
			continue
		}
		prefix := ""
		if mod.Dir != "" {
			prefix = mod.Dir + "/"
		}
		if strings.HasPrefix(mt.Tag, prefix) && len(prefix) > bestLen {
			best, bestLen = mod.Path, len(prefix)
		}
	}
	return best
}

// Health reports each remote's last pass.
func (g *GitSource) Health(context.Context) []metrics.Health {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]metrics.Health, 0, len(g.remotes))
	for _, remote := range g.remotes {
		h := metrics.Health{Name: g.name + " " + metrics.RedactRemote(remote), Ecosystem: ecoName, Scoped: true}
		for _, mod := range g.modules {
			if mod.Remote == remote {
				h.Packages = append(h.Packages, mod.Path)
			}
		}
		err, seen := g.health[remote]
		switch {
		case !seen:
			h.Detail = "not indexed yet"
		case err != nil:
			h.Detail = "indexing failed; stored versions are served"
		default:
			h.OK = true
			h.Detail = "last sync " + g.mirrors[remote].LastSync().UTC().Format(time.RFC3339)
		}
		out = append(out, h)
	}
	return out
}
