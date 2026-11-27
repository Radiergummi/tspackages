package pypi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/radiergummi/tspackages/internal/githubapp"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/relay"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

// GitHubAPI is what the github source needs from a GitHub App installation;
// *githubapp.App satisfies it.
type GitHubAPI interface {
	Repositories(ctx context.Context) ([]githubapp.Repo, error)
	Releases(ctx context.Context, r githubapp.Repo) ([]githubapp.Release, error)
	OpenAsset(ctx context.Context, r githubapp.Repo, assetID, maxBytes int64) (io.ReadCloser, int64, error)
	RateLimit() (remaining int, reset time.Time)
	InstallationID() int64
}

// ghHashIdle is how long a hash download may send nothing before it is
// abandoned; the relay allows a download as long.
const ghHashIdle = 2 * time.Minute

// ghHashConcurrency bounds the downloads a pass makes to hash assets that
// GitHub reports no digest for.
const ghHashConcurrency = 4

// GitHubSource serves the wheels and sdists attached to the releases of the
// repositories a GitHub App installation can see. A pass lists them every
// poll interval and replaces the index; downloads stream through the relay,
// verified against the indexed sha256.
type GitHubSource struct {
	name        string
	claims      []string
	api         GitHubAPI
	apiURL      string // ends in "/"
	pins        *ghPins
	relay       *relay.Relay
	rec         *records.Store
	poll        time.Duration
	maxArtifact int64
	log         *slog.Logger
	hashIdle    time.Duration                        // replaced in tests
	now         func() time.Time                     // replaced in tests
	after       func(time.Duration) <-chan time.Time // replaced in tests

	mu  sync.Mutex // one pass at a time
	idx atomic.Pointer[ghServed]

	hmu     sync.Mutex
	passErr error

	cmu     sync.Mutex
	seen    map[[3]string]bool // (project, filename, sha256) reported as changed
	changes []GitHubChange
}

// GitHubChange is a served file whose bytes differ from the first provenance
// record of its filename: the asset was deleted and uploaded again.
type GitHubChange struct {
	Package, Filename, FirstSHA256, NewSHA256 string
	Seen                                      time.Time
}

// ghRateLimitMargin is waited beyond a rate limit's reset time.
const ghRateLimitMargin = 5 * time.Second

// ghMaxRateLimitWait caps the wait for a rate limit's reset.
const ghMaxRateLimitWait = time.Hour

var _ Source = (*GitHubSource)(nil)

// ghServed is the index a pass published.
type ghServed struct {
	ghIndex
	unavailable map[string]bool   // projects with a conflict, an asset waiting for its hash or a corrupt owner pin
	owners      map[string]string // project -> owning repository's full name
	backlog     int
	repos       int       // repositories the installation is granted
	at          time.Time // when it was published
}

// NewGitHubSource builds a github source. apiURL is the API base api talks
// to, named in provenance records; state holds the owner and digest pins;
// log nil means slog.Default().
func NewGitHubSource(name string, claims []string, api GitHubAPI, apiURL string, state storage.Driver, rl *relay.Relay, rec *records.Store, poll time.Duration, maxArtifact int64, log *slog.Logger) *GitHubSource {
	if log == nil {
		log = slog.Default()
	}
	return &GitHubSource{
		name: name, claims: claims, api: api, apiURL: strings.TrimRight(apiURL, "/") + "/",
		pins: newGHPins(state, name, log), relay: rl, rec: rec, poll: poll, maxArtifact: maxArtifact, log: log,
		hashIdle: ghHashIdle, now: time.Now, after: time.After, seen: map[[3]string]bool{},
	}
}

func (s *GitHubSource) Name() string     { return s.name }
func (s *GitHubSource) Claims() []string { return s.claims }

// Run makes a pass at start and then every poll interval until ctx is done.
// After a rate-limited pass, the next one starts at the limit's reset.
func (s *GitHubSource) Run(ctx context.Context) {
	for {
		err := s.pass(ctx)
		if err != nil && ctx.Err() == nil {
			s.log.Error("pypi github index failed", "source", s.name, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-s.after(s.nextPass(err)):
		}
	}
}

// nextPass is the wait after a pass that returned err: until the reset
// (plus a margin, at most ghMaxRateLimitWait) when it was rate limited and
// the reset is known and ahead, else the poll interval.
func (s *GitHubSource) nextPass(err error) time.Duration {
	rl, limited := errors.AsType[*githubapp.RateLimitError](err)
	if !limited {
		return s.poll
	}
	reset := rl.Reset
	if reset.IsZero() {
		_, reset = s.api.RateLimit()
	}
	wait := reset.Sub(s.now())
	if reset.IsZero() || wait <= 0 {
		return s.poll
	}
	return min(wait+ghRateLimitMargin, ghMaxRateLimitWait)
}

// pass indexes once and records the outcome for Health and the metrics.
func (s *GitHubSource) pass(ctx context.Context) error {
	err := s.index(ctx)
	if ctx.Err() == nil {
		s.hmu.Lock()
		s.passErr = err
		s.hmu.Unlock()
		metrics.ObserveGitHubPass(s.name, err == nil)
		if remaining, _ := s.api.RateLimit(); remaining >= 0 {
			metrics.SetGitHubRateLimit(s.name, remaining)
		}
	}
	return err
}

// index lists the releases, decides and pins new owners and publishes the
// index; then it hashes the assets without a digest and publishes the index
// again with their digests. A failure before the index is built keeps the
// previous one. A rate limit hit while hashing is returned after the second
// index is published.
func (s *GitHubSource) index(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	repos, err := s.api.Repositories(ctx)
	if err != nil {
		return fmt.Errorf("list repositories: %w", err)
	}
	listed := make(map[githubapp.Repo][]githubapp.Release, len(repos))
	for _, r := range repos {
		rels, err := s.api.Releases(ctx, r)
		if err != nil {
			return fmt.Errorf("list releases of %s: %w", r.FullName, err)
		}
		listed[r] = rels
	}
	owners, err := s.pins.Owners(ctx)
	if err != nil {
		return fmt.Errorf("read owner pins: %w", err)
	}
	digests, err := s.pins.Digests(ctx)
	if err != nil {
		return fmt.Errorf("read digest pins: %w", err)
	}
	corrupt := map[string]bool{}
	idx, err := s.decide(ctx, listed, owners, digests, corrupt)
	if err != nil {
		return err
	}
	todo := ghHashTodo(idx.NeedHash, owners)
	s.publish(idx, listed, owners, corrupt, len(todo))
	if len(todo) == 0 {
		return nil
	}

	pinned, backlog, hashErr := s.hashPending(ctx, todo)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	maps.Copy(digests, pinned)
	idx, err = s.decide(ctx, listed, owners, digests, corrupt)
	if err != nil {
		return err
	}
	s.publish(idx, listed, owners, corrupt, backlog)
	return hashErr
}

// decide builds the index and pins the owners it decides, adding them to
// owners. A name whose owner pin is corrupt goes to corrupt (logged the first
// time) and is withheld by publish.
func (s *GitHubSource) decide(ctx context.Context, listed map[githubapp.Repo][]githubapp.Release, owners map[string]int64, digests map[int64]string, corrupt map[string]bool) (ghIndex, error) {
	idx, decided := buildGHIndex(s.claims, listed, owners, digests)
	lost := false
	for _, name := range sortedKeys(decided) {
		if corrupt[name] {
			continue
		}
		repo := decided[name]
		id, err := s.pins.PinOwner(ctx, name, repo)
		if errors.Is(err, errCorruptGHPin) {
			corrupt[name] = true
			s.log.Warn("pypi github: name unavailable: its owner pin is corrupt", "source", s.name, "package", name, "error", err)
			continue
		}
		if err != nil {
			return ghIndex{}, fmt.Errorf("pin owner of %s: %w", name, err)
		}
		owners[name] = id
		lost = lost || id != repo.ID
	}
	if lost {
		// Another writer pinned a name first: its pin decides.
		idx, _ = buildGHIndex(s.claims, listed, owners, digests)
	}
	return idx, nil
}

// publish serves idx; backlog is the number of assets waiting for a hash.
func (s *GitHubSource) publish(idx ghIndex, listed map[githubapp.Repo][]githubapp.Release, owners map[string]int64, corrupt map[string]bool, backlog int) {
	served := &ghServed{
		ghIndex: idx, unavailable: map[string]bool{}, owners: map[string]string{},
		backlog: backlog, repos: len(listed), at: s.now(),
	}
	served.Projects = maps.Clone(idx.Projects)
	for name := range corrupt {
		delete(served.Projects, name)
		served.unavailable[name] = true
	}
	for _, c := range idx.Conflicts {
		served.unavailable[c.Package] = true
	}
	for _, p := range idx.NeedHash {
		if id, ok := owners[p.Package]; !ok || id == p.Repo.ID {
			served.unavailable[p.Package] = true
		}
	}
	names := map[int64]string{}
	for r := range listed {
		names[r.ID] = r.FullName
	}
	for name, id := range owners {
		served.owners[name] = ghRepoName(names, id)
	}
	s.idx.Store(served)
}

// ghHashTodo returns the assets without a digest worth hashing, once each:
// not those of names another repository owns (they are never served).
func ghHashTodo(pending []ghPending, owners map[string]int64) []ghPending {
	var todo []ghPending
	seen := map[int64]bool{}
	for _, p := range pending {
		if id, ok := owners[p.Package]; (ok && id != p.Repo.ID) || seen[p.Asset.ID] {
			continue
		}
		seen[p.Asset.ID] = true
		todo = append(todo, p)
	}
	return todo
}

// hashPending downloads the assets in todo once, hashes them and pins their
// digests. It returns the pinned digests by asset ID and how many are still
// without a pin. A rate limit stops the remaining downloads and is returned;
// other failures are logged and retried by the next pass.
func (s *GitHubSource) hashPending(ctx context.Context, todo []ghPending) (map[int64]string, int, error) {
	var mu sync.Mutex
	pinned := map[int64]string{}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(ghHashConcurrency)
	for _, p := range todo {
		g.Go(func() error {
			sum, err := s.hashAsset(gctx, p)
			switch {
			case err == nil:
				mu.Lock()
				pinned[p.Asset.ID] = sum
				mu.Unlock()
			case errors.Is(err, githubapp.ErrRateLimited):
				return err
			case gctx.Err() == nil:
				s.log.Warn("pypi github: hashing an asset failed", "source", s.name, "repo", p.Repo.FullName,
					"asset", p.Asset.Name, "asset_id", p.Asset.ID, "error", err)
			}
			return nil
		})
	}
	err := g.Wait()
	if err != nil {
		err = fmt.Errorf("hash assets: %w", err)
	}
	return pinned, len(todo) - len(pinned), err
}

// errHashStalled is a hash download that sent nothing for s.hashIdle.
var errHashStalled = errors.New("download stalled")

// hashAsset streams an asset through sha256, pins the digest and returns the
// pinned one. Nothing is cached: the bytes are unverified until pinned. A
// download that sends nothing for s.hashIdle is abandoned, as the relay
// abandons a stalled upstream.
func (s *GitHubSource) hashAsset(ctx context.Context, p ghPending) (string, error) {
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stalled atomic.Bool
	timer := time.AfterFunc(s.hashIdle, func() { stalled.Store(true); cancel() })
	defer timer.Stop()
	h := sha256.New()
	n, err := func() (int64, error) {
		body, _, err := s.api.OpenAsset(dctx, p.Repo, p.Asset.ID, s.maxArtifact)
		if err != nil {
			return 0, err
		}
		defer body.Close()
		return io.Copy(h, ghIdleReader{body, func() { timer.Reset(s.hashIdle) }})
	}()
	if err != nil && stalled.Load() {
		return "", errHashStalled
	}
	if err != nil {
		return "", err
	}
	return s.pins.PinDigest(ctx, p.Asset.ID, hex.EncodeToString(h.Sum(nil)), n)
}

// ghIdleReader calls progress after every read that returned bytes.
type ghIdleReader struct {
	r        io.Reader
	progress func()
}

func (r ghIdleReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.progress()
	}
	return n, err
}

// files returns the indexed files of name.
func (s *GitHubSource) files(name string) ([]ghFile, error) {
	if !ghClaimed(s.claims, name) {
		return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, name)
	}
	st := s.idx.Load()
	if st == nil {
		return nil, fmt.Errorf("%w: %s (not indexed yet)", ErrUnavailable, name)
	}
	fs := st.Projects[name]
	if len(fs) == 0 {
		if st.unavailable[name] {
			return nil, fmt.Errorf("%w: %s has a conflicting asset or one not hashed yet", ErrUnavailable, name)
		}
		return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, name)
	}
	return fs, nil
}

// Project lists the indexed files of name.
func (s *GitHubSource) Project(_ context.Context, name string) (Project, error) {
	fs, err := s.files(name)
	if err != nil {
		return Project{}, err
	}
	p := Project{Name: name}
	for _, f := range fs {
		p.Files = append(p.Files, f.File)
		if !slices.Contains(p.Versions, f.Version) {
			p.Versions = append(p.Versions, f.Version)
		}
	}
	return p, nil
}

// File streams an indexed asset, verified against its sha256.
func (s *GitHubSource) File(ctx context.Context, name, filename string) (Artifact, error) {
	fs, err := s.files(name)
	if err != nil {
		return Artifact{}, err
	}
	i := slices.IndexFunc(fs, func(f ghFile) bool { return f.Filename == filename })
	if i < 0 {
		if s.conflicted(name, filename) {
			return Artifact{}, fmt.Errorf("%w: %s has conflicting assets", ErrUnavailable, filename)
		}
		return Artifact{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, filename)
	}
	f := fs[i]
	fetch := func(ctx context.Context) (io.ReadCloser, int64, error) {
		start := time.Now()
		body, size, err := s.api.OpenAsset(ctx, f.Repo, f.AssetID, s.maxArtifact)
		metrics.ObserveUpstream(s.name, time.Since(start))
		if errors.Is(err, resolve.ErrNotFound) {
			// Listed but gone: a source fault, not a miss.
			return nil, 0, fmt.Errorf("github asset missing for a listed file: %v", err) //nolint:errorlint // a listed file's 404 is a fault, not a miss
		}
		return body, size, err
	}
	onCommit := func(ctx context.Context, res relay.Result) error {
		if err := s.checkChanged(ctx, name, f.Version, filename, res.SHA256); err != nil {
			return err
		}
		if err := s.rec.PutProvenance(ctx, records.Provenance{
			Ecosystem: ecoName, Package: name, Version: f.Version, File: filename, Source: s.name, SourceType: "github",
			UpstreamURL:    s.apiURL + "repos/" + f.Repo.FullName + "/releases/assets/" + strconv.FormatInt(f.AssetID, 10),
			DeclaredDigest: "sha256:" + f.SHA256, SHA1: res.SHA1, SHA256: res.SHA256,
		}); err != nil {
			return fmt.Errorf("record provenance: %w", err)
		}
		return nil
	}
	body, size, hit, err := s.relay.Open(ctx, "pypi/"+s.name+"/files/"+f.SHA256, relay.Digest{SHA256: f.SHA256}, fetch, onCommit)
	if err != nil {
		return Artifact{}, err
	}
	if hit {
		metrics.ObserveCacheHit(ecoName, s.name)
	}
	return Artifact{Body: body, Size: max(size, 0)}, nil
}

// conflicted reports whether the last pass withheld filename of name for
// conflicting digests.
func (s *GitHubSource) conflicted(name, filename string) bool {
	st := s.idx.Load()
	return st != nil && slices.ContainsFunc(st.Conflicts, func(c GitHubConflict) bool {
		return c.Package == name && c.Filename == filename
	})
}

// checkChanged compares sum with the first digest this source recorded for
// the file; a difference is served, and logged and listed by Changed once.
func (s *GitHubSource) checkChanged(ctx context.Context, pkg, version, file, sum string) error {
	recs, err := s.rec.FileProvenance(ctx, ecoName, pkg, version, file)
	if err != nil {
		return fmt.Errorf("read provenance: %w", err)
	}
	var first *records.Provenance
	for i, p := range recs {
		if p.Source == s.name && (first == nil || p.Created.Before(first.Created)) {
			first = &recs[i]
		}
	}
	if first == nil || first.SHA256 == sum {
		return nil
	}
	key := [3]string{pkg, file, sum}
	s.cmu.Lock()
	seen := s.seen[key]
	if !seen {
		s.seen[key] = true
		s.changes = append(s.changes, GitHubChange{
			Package: pkg, Filename: file, FirstSHA256: first.SHA256, NewSHA256: sum, Seen: s.now(),
		})
	}
	s.cmu.Unlock()
	if !seen {
		s.log.Warn("pypi github: asset changed upstream; serving the new bytes", "source", s.name, "package", pkg,
			"version", version, "file", file, "first_sha256", first.SHA256, "seen_sha256", sum)
	}
	return nil
}

// Changed returns the files seen changing since start, in the order seen.
func (s *GitHubSource) Changed() []GitHubChange {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	return slices.Clone(s.changes)
}

// Metadata is not served: release assets carry no separate core metadata.
func (s *GitHubSource) Metadata(_ context.Context, _, filename string) (Artifact, error) {
	return Artifact{}, fmt.Errorf("%w: no metadata for %s", resolve.ErrNotFound, filename)
}

// Provenance is not served for release assets.
func (s *GitHubSource) Provenance(_ context.Context, _, filename string) (Artifact, error) {
	return Artifact{}, fmt.Errorf("%w: no provenance for %s", resolve.ErrNotFound, filename)
}

// Skipped returns the assets the last pass left out for a reason worth
// showing.
func (s *GitHubSource) Skipped() []GitHubSkip {
	if st := s.idx.Load(); st != nil {
		return slices.Clone(st.Skipped)
	}
	return nil
}

// Conflicts returns the filenames the last pass withheld.
func (s *GitHubSource) Conflicts() []GitHubConflict {
	if st := s.idx.Load(); st != nil {
		return slices.Clone(st.Conflicts)
	}
	return nil
}

// Owners returns the pinned owners as of the last pass: project to the
// owning repository's full name.
func (s *GitHubSource) Owners() map[string]string {
	if st := s.idx.Load(); st != nil {
		return maps.Clone(st.owners)
	}
	return map[string]string{}
}

// Backlog is the number of assets the last pass could not hash yet.
func (s *GitHubSource) Backlog() int {
	if st := s.idx.Load(); st != nil {
		return st.backlog
	}
	return 0
}

// Health reports the last pass, the installation and the number of
// repositories it is granted, the hashing backlog and the number of
// unclaimed assets skipped. Repository names are left out: they may be
// private.
func (s *GitHubSource) Health(context.Context) []metrics.Health {
	s.hmu.Lock()
	err := s.passErr
	s.hmu.Unlock()
	st := s.idx.Load()
	h := metrics.Health{Name: s.name, Ecosystem: "pypi"}
	kept := "nothing indexed yet"
	if st != nil {
		kept = "the index of " + st.at.UTC().Format(time.RFC3339) + " is served"
	}
	switch rl, limited := errors.AsType[*githubapp.RateLimitError](err); {
	case limited:
		reset := rl.Reset
		if reset.IsZero() {
			_, reset = s.api.RateLimit()
		}
		h.Detail = "rate limited; " + kept
		if !reset.IsZero() {
			h.Detail = "rate limited until " + reset.UTC().Format(time.RFC3339) + "; " + kept
		}
	case errors.Is(err, githubapp.ErrAuthFailed):
		h.Detail = "GitHub App authentication failed; " + kept
	case err != nil:
		h.Detail = "indexing failed; " + kept
	case st == nil:
		h.Detail = "not indexed yet"
	default:
		h.OK, h.Detail = true, "indexed at "+st.at.UTC().Format(time.RFC3339)
	}
	h.Detail += "; installation " + strconv.FormatInt(s.api.InstallationID(), 10)
	if st != nil {
		h.Detail += fmt.Sprintf(", %d repositories granted", st.repos)
		if st.backlog > 0 {
			h.Detail += fmt.Sprintf("; %d assets waiting to be hashed", st.backlog)
		}
		if st.Unclaimed > 0 {
			h.Detail += fmt.Sprintf("; %d unclaimed assets skipped", st.Unclaimed)
		}
	}
	return []metrics.Health{h}
}
