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

	"github.com/radiergummi/tspackages/internal/digest"
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
	RefusalCorruptPin      = "pin corrupt"
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

	passMu sync.Mutex // serialises Index and load
	// loaded is set once the stored versions are loaded; until then a
	// configured module answers ErrUnavailable.
	loaded atomic.Bool

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
	pinMemo     map[[2]string]string // (remote, tag) → the commit last pinned, current and recorded
	// cands are each remote's candidates from its latest scan of the refs
	// (a pass or an on-demand rescan); candSeq is that scan's number from
	// scanSeq, taken just before it read the refs. An older scan never
	// replaces a newer one's candidates.
	cands   map[string]map[jobKey]candidate
	candSeq map[string]uint64
	scanSeq uint64
	// kicked are the remotes an on-demand sync asks a pass for; kick
	// signals Run.
	kicked map[string]bool
	kick   chan struct{}
	health map[string]error // last pass outcome per remote

	// syncs are the remotes' throttles and restart gates, by mirror.
	syncs map[*gitmirror.Mirror]*remoteState
	// life is the source's lifetime: syncs run on it, whoever waits for
	// them. Run cancels it when its context ends.
	life     context.Context
	stopLife context.CancelFunc

	// Test seams; production uses time.Now, the mirror's methods, the
	// package's syncEvery and requestWait, and no hook.
	now           func() time.Time
	syncEvery     time.Duration
	requestWait   time.Duration
	sync          func(ctx context.Context, m *gitmirror.Mirror) error
	archive       func(ctx context.Context, m *gitmirror.Mirror, commit, dir string, w io.Writer) error
	listTree      func(ctx context.Context, m *gitmirror.Mirror, commit, dir string) ([]gitmirror.TreeEntry, error)
	beforeRecheck func(jobKey)        // runs just before a job re-checks its tag
	afterRefs     func(remote string) // runs in a pass just after it read the refs
	repairHook    func()              // runs at the start of every repair attempt
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
		warnedMoves: map[pins.MovedTag]bool{}, pinMemo: map[[2]string]string{}, cands: map[string]map[jobKey]candidate{}, health: map[string]error{},
		candSeq: map[string]uint64{}, kicked: map[string]bool{}, kick: make(chan struct{}, 1),
		syncs: map[*gitmirror.Mirror]*remoteState{},
		now:   time.Now, syncEvery: syncEvery, requestWait: requestWait,
		sync: func(ctx context.Context, m *gitmirror.Mirror) error { return m.Sync(ctx) },
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
			g.syncs[g.mirrors[mod.Remote]] = &remoteState{}
		}
	}
	slices.Sort(g.remotes)
	g.life, g.stopLife = context.WithCancel(context.Background()) //nolint:gosec // Run calls stopLife when its context ends
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

// Run builds in the background and runs a pass every poll interval, and a
// pass of the remotes an on-demand sync kicked, until ctx is done.
func (g *GitSource) Run(ctx context.Context) {
	stopLife := context.AfterFunc(ctx, g.stopLife)
	defer stopLife()
	done := make(chan struct{})
	go func() { g.q.run(ctx); close(done) }()
	defer func() { <-done }()
	logPass := func(err error) {
		if err != nil && ctx.Err() == nil {
			g.log.Error("goproxy git: pass failed", "source", g.name, "error", err)
		}
	}
	logPass(g.Index(ctx))
	next := time.After(g.poll)
	for {
		select {
		case <-ctx.Done():
			return
		case <-g.kick:
			logPass(g.indexRemotes(ctx, g.takeKicked()))
		case <-next:
			logPass(g.Index(ctx))
			next = time.After(g.poll)
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
	type badRecord struct {
		vk     verKey
		rec    versionRecord
		reason string
	}
	var bad []badRecord
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
		vk := verKey{p, v}
		rec, err := g.readRecord(ctx, g.prefix()+dir+"version.json")
		switch {
		case errors.Is(err, storage.ErrNotFound):
			continue // deleted since the listing
		case errors.Is(err, errBadRecord):
			bad = append(bad, badRecord{vk, versionRecord{Version: v}, "unreadable version record: " + err.Error()})
			continue
		case err != nil:
			return err
		}
		if reason := checkRecord(rec, v); reason != "" {
			bad = append(bad, badRecord{vk, rec, reason})
			continue
		}
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
	for _, b := range bad {
		_ = g.refuseRecord(b.vk, b.rec, b.reason)
	}
	g.loaded.Store(true)
	return nil
}

func (g *GitSource) readRecord(ctx context.Context, key string) (versionRecord, error) {
	rc, _, err := g.state.Get(ctx, key)
	if err != nil {
		return versionRecord{}, err
	}
	defer rc.Close()
	var r versionRecord
	if err := json.NewDecoder(io.LimitReader(rc, 1<<20)).Decode(&r); err != nil {
		if ctx.Err() != nil {
			return r, err
		}
		return r, fmt.Errorf("%w: %w", errBadRecord, err)
	}
	return r, nil
}

// errBadRecord marks a version.json that does not decode.
var errBadRecord = errors.New("goproxy git: undecodable version record")

// checkRecord returns why a decoded record of version v cannot be used, or
// "".
func checkRecord(rec versionRecord, v string) string {
	switch {
	case rec.Format != GoZipFormat:
		return fmt.Sprintf("version record format %d; this tspackages reads format %d", rec.Format, GoZipFormat)
	case rec.Version != v:
		return "invalid version record: it is for version " + rec.Version
	case !digest.IsHex(rec.Commit, 40, 64):
		return fmt.Sprintf("invalid version record: commit %q", rec.Commit)
	}
	return ""
}

// Index runs one pass: per remote, sync (sharing the on-demand throttle),
// list the refs, pin the tags of stored versions and enqueue a build for
// every candidate that is neither stored, refused, skipped nor queued. It
// never waits for builds. A remote that fails keeps its last pass's state;
// one that has not synced in this process (the restart gate) is not indexed
// from its mirror.
func (g *GitSource) Index(ctx context.Context) error {
	return g.indexRemotes(ctx, g.remotes)
}

// indexRemotes runs a pass of remotes.
func (g *GitSource) indexRemotes(ctx context.Context, remotes []string) error {
	g.passMu.Lock()
	defer g.passMu.Unlock()
	if !g.loaded.Load() {
		if err := g.load(ctx); err != nil {
			return fmt.Errorf("goproxy git: load stored versions: %w", err)
		}
	}
	for _, remote := range remotes {
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
	if err := g.syncRemote(ctx, m); err != nil {
		if ctx.Err() != nil || !g.synced(remote) {
			return err
		}
		g.log.Warn("goproxy git: sync failed; indexing the local mirror", "source", g.name, "remote", metrics.RedactRemote(remote), "error", err)
	}
	seq := g.nextScan()
	refs, err := m.Refs(ctx)
	if err != nil {
		return err
	}
	if g.afterRefs != nil {
		g.afterRefs(remote)
	}
	cands := g.candidates(remote, refs)
	moved := map[verKey]Refusal{}
	for _, k := range slices.SortedFunc(maps.Keys(cands), compareJobKeys) {
		c := cands[k]
		vk := verKey{k.Path, k.Version}
		if rec, ok := g.idx.Load().listed[vk]; ok {
			g.checkPin(ctx, c, rec, moved)
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
	g.prune(remote, seq, cands, moved)
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
// reported in moved. A tag last seen pinned to the record's commit and
// still there is not pinned again until the tag moves or the process
// restarts. A failed Pin keeps the version's previous row; a corrupt pin is
// reported.
func (g *GitSource) checkPin(ctx context.Context, c candidate, rec versionRecord, moved map[verKey]Refusal) {
	vk := verKey{c.key.Path, c.key.Version}
	mk := [2]string{c.key.Remote, c.tag}
	g.mu.Lock()
	memo := g.pinMemo[mk]
	prev, hadPrev := g.movedStored[c.key.Remote][vk]
	g.mu.Unlock()
	if memo == c.key.Commit {
		return
	}
	pinned, isMove, err := g.pins.Pin(ctx, ecoName, g.name, c.key.Remote, c.tag, c.key.Commit)
	switch {
	case errors.Is(err, pins.ErrCorrupt):
		g.log.Warn("goproxy git: corrupt pin; serving the stored version", "source", g.name, "tag", c.tag, "error", err)
		moved[vk] = Refusal{
			Module: vk.Path, Version: vk.Version, Remote: metrics.RedactRemote(c.key.Remote), Tag: c.tag, Commit: rec.Commit,
			Kind: RefusalCorruptPin, Reason: err.Error(),
		}
		return
	case err != nil:
		g.log.Warn("goproxy git: pinning a stored version's tag failed", "source", g.name, "tag", c.tag, "error", err)
		if hadPrev {
			moved[vk] = prev
		}
		return
	}
	if isMove {
		g.warnMove(c, pinned)
	}
	if pinned != rec.Commit {
		moved[vk] = g.movedRefusal(c, rec, pinned)
	}
	g.memoPin(c.key.Remote, c.tag, c.key.Commit, pinned, rec.Commit, isMove)
}

// memoPin remembers a tag pinned to the commit it points at and its record
// holds, and forgets any other outcome.
func (g *GitSource) memoPin(remote, tag, current, pinned, recorded string, isMove bool) {
	mk := [2]string{remote, tag}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !isMove && pinned == current && pinned == recorded {
		g.pinMemo[mk] = current
	} else {
		delete(g.pinMemo, mk)
	}
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

// prune records the pass's moved stored versions and keeps the tag-keyed
// refusals and commit-level state of remote that its current candidates (or
// a stored record awaiting repair) still use. A pass whose scan seq is older
// than the stored candidates' prunes nothing and keeps them.
func (g *GitSource) prune(remote string, seq uint64, cands map[jobKey]candidate, moved map[verKey]Refusal) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.movedStored[remote] = moved
	if seq < g.candSeq[remote] {
		return
	}
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
	tags := map[string]bool{}
	for _, c := range cands {
		tags[c.tag] = true
	}
	maps.DeleteFunc(g.pinMemo, func(k [2]string, _ string) bool { return k[0] == remote && !tags[k[1]] })
	g.cands[remote] = cands
	g.candSeq[remote] = seq
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
	left := false // a follower stopped waiting for the shared archive
	zipPath, res, err := BuildZip(ctx, BuildInput{
		Version: mv,
		Subdir:  dk.Dir,
		GoMod:   gomod,
		Archive: func(ctx context.Context, w io.Writer) error {
			r, release, err := g.sharedArchive(ctx, m, dk)
			if r == nil {
				left = true
				return err
			}
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
	// A follower's wait is not an attempt: the leader counts the archive.
	if !left && (errors.Is(err, gitmirror.ErrArchiveFailed) || errors.Is(err, errArchiveTimeout) || errors.Is(ctx.Err(), context.DeadlineExceeded)) {
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
// last user. A follower whose ctx ends while it waits gets a nil run.
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
			return nil, nil, ctx.Err()
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
			stored, err := g.readRecord(ctx, key)
			switch {
			case errors.Is(err, errBadRecord):
				return g.refuseRecord(vk, versionRecord{Version: k.Version}, "unreadable version record: "+err.Error())
			case err != nil:
				return err
			}
			if reason := checkRecord(stored, k.Version); reason != "" {
				return g.refuseRecord(vk, stored, reason)
			}
			rec = stored
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
	g.memoPin(k.Remote, c.tag, k.Commit, pinned, rec.Commit, isMove)
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

// complete makes rec's version servable. When its zip and go.mod are
// stored it is published; otherwise the files built from commit are written
// if their h1 hashes equal the record's. A record of another commit is left
// to a repair.
func (g *GitSource) complete(ctx context.Context, vk verKey, rec versionRecord, built ZipResult, commit string, gomod []byte, zipPath string) error {
	dir := g.versionDir(vk)
	_, zipErr := g.state.Stat(ctx, dir+"module.zip")
	_, modErr := g.state.Stat(ctx, dir+"go.mod")
	switch {
	case zipErr == nil && modErr == nil:
		g.publish(vk, rec)
		g.keepCommit(ctx, vk, rec)
		return nil
	case zipErr != nil && !errors.Is(zipErr, storage.ErrNotFound):
		return zipErr
	case modErr != nil && !errors.Is(modErr, storage.ErrNotFound):
		return modErr
	case commit != rec.Commit:
		g.enqueueRepair(vk, rec)
		return nil
	case built.ZipHash != rec.ZipHash || built.ModHash != rec.ModHash:
		return g.refuseRecord(vk, rec, "h1 differs from the record")
	}
	if modErr != nil {
		if err := putIfAbsent(ctx, g.state, dir+"go.mod", bytes.NewReader(gomod)); err != nil {
			return err
		}
	}
	if zipErr != nil {
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
	}
	g.publish(vk, rec)
	g.keepCommit(ctx, vk, rec)
	return nil
}

// keepCommit gives the commit of a version just published its hidden ref,
// so it is reachable for pseudo-versions at once rather than after the next
// sync. A failure is logged; the next sync's ensureStoredRefs retries.
func (g *GitSource) keepCommit(ctx context.Context, vk verKey, rec versionRecord) {
	mod, ok := g.moduleFor(vk.Path)
	if !ok {
		return
	}
	m := g.mirrors[mod.Remote]
	if err := m.EnsureStoredRefs(ctx, []string{rec.Commit}); err != nil && ctx.Err() == nil {
		g.log.Warn("goproxy git: keeping a stored commit in the mirror failed", "source", g.name,
			"remote", metrics.RedactRemote(m.Remote()), "commit", rec.Commit, "error", err)
	}
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
	g.q.enqueue(k, vk.Path, jobRepair, g.repairJob(mod.Remote, g.mirrors[mod.Remote], vk, rec))
}

// repairJob rebuilds a stored version's missing zip from the recorded commit
// and directory, and writes it only if its h1 hashes equal the record's. A
// commit missing from a mirror that has not synced in this process may only
// predate the record, so it is retried until the first sync.
func (g *GitSource) repairJob(remote string, m *gitmirror.Mirror, vk verKey, rec versionRecord) func(context.Context) error {
	return func(ctx context.Context) error {
		if g.repairHook != nil {
			g.repairHook()
		}
		gomod, err := m.ReadFileMax(ctx, rec.Commit, path.Join(rec.Dir, "go.mod"), MaxGoMod)
		switch {
		case errors.Is(err, gitmirror.ErrNoCommit) && !g.synced(remote):
			return err
		case errors.Is(err, gitmirror.ErrNoCommit):
			return g.refuseRecord(vk, rec, "zip missing and commit gone")
		case errors.Is(err, resolve.ErrNotFound):
			return g.refuseRecord(vk, rec, "zip missing and go.mod gone from the recorded commit")
		case errors.Is(err, gitmirror.ErrTooLarge):
			return g.refuseRecord(vk, rec, reasonGoModTooLarge)
		case err != nil:
			return err
		}
		dk := dirKey{remote, rec.Commit, rec.Dir}
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
	delete(g.recRefusals, vk)
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

// checkModule returns the configured module serving p: ErrNotFound for a
// path no configured module serves and ErrUnavailable while the stored
// versions are not loaded.
func (g *GitSource) checkModule(p string) (Module, error) {
	mod, ok := g.moduleFor(p)
	if !ok {
		return Module{}, fmt.Errorf("%w: %s is not a module of this source", resolve.ErrNotFound, p)
	}
	if !g.loaded.Load() {
		return Module{}, fmt.Errorf("%w: %s: stored versions not loaded yet", ErrUnavailable, p)
	}
	return mod, nil
}

// lookup returns the stored record of version v of a configured module. A
// record that cannot be served (its zip missing, awaiting repair or
// refused) is ErrUnavailable; any other version is answered on demand.
func (g *GitSource) lookup(ctx context.Context, p, v string) (versionRecord, error) {
	mod, err := g.checkModule(p)
	if err != nil {
		return versionRecord{}, err
	}
	if !semver.IsValid(v) || semver.Canonical(v) != v {
		return versionRecord{}, g.query(ctx, mod, p, v)
	}
	if rec, ok, err := g.served(p, v); ok {
		return rec, err
	}
	return g.demand(ctx, mod, p, v)
}

// List returns the stored versions of p, sorted. With none stored, a remote
// not synced since the start answers ErrUnavailable.
func (g *GitSource) List(_ context.Context, p string) ([]string, error) {
	mod, err := g.checkModule(p)
	if err != nil {
		return nil, err
	}
	vs := g.idx.Load().versions[p]
	if len(vs) == 0 && !g.synced(mod.Remote) {
		return nil, fmt.Errorf("%w: %s: its remote has not synced since the start", ErrUnavailable, p)
	}
	return slices.Clone(vs), nil
}

// Info answers a stored canonical version, building a tag version on
// demand; any other query is not found once the remote synced.
func (g *GitSource) Info(ctx context.Context, p, v string) (Info, error) {
	rec, err := g.lookup(ctx, p, v)
	if err != nil {
		return Info{}, err
	}
	return Info{Version: v, Time: rec.Time}, nil
}

// Latest answers the highest stored release, else the highest stored
// prerelease. With none stored it is ErrUnavailable while the remote has
// not synced since the start or a version of p is pending.
func (g *GitSource) Latest(_ context.Context, p string) (Info, error) {
	mod, err := g.checkModule(p)
	if err != nil {
		return Info{}, err
	}
	idx := g.idx.Load()
	vs := idx.versions[p]
	if len(vs) == 0 {
		switch {
		case !g.synced(mod.Remote):
			return Info{}, fmt.Errorf("%w: %s: its remote has not synced since the start", ErrUnavailable, p)
		case g.pendingWhere(p, func(string) bool { return true }):
			return Info{}, fmt.Errorf("%w: %s: a version is pending", ErrUnavailable, p)
		}
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
	rec, err := g.lookup(ctx, p, v)
	if err != nil {
		return Artifact{}, err
	}
	vk := verKey{p, v}
	rc, size, err := storage.OpenObject(ctx, g.state, g.versionDir(vk)+file)
	if errors.Is(err, storage.ErrNotFound) {
		// The version stays listed while its files are rebuilt; a rebuild
		// already refused is not repeated.
		g.mu.Lock()
		refusal, refused := g.recRefusals[vk]
		g.mu.Unlock()
		if refused {
			return Artifact{}, fmt.Errorf("%w: %s@%s: stored %s is missing: %s", ErrUnavailable, p, v, file, refusal.Reason)
		}
		g.enqueueRepair(vk, rec)
		return Artifact{}, fmt.Errorf("%w: %s@%s: stored %s is missing; repairing", ErrUnavailable, p, v, file)
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
