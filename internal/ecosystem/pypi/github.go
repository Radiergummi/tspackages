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
}

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
	pins        *ghPins
	relay       *relay.Relay
	rec         *records.Store
	poll        time.Duration
	maxArtifact int64
	log         *slog.Logger

	mu  sync.Mutex // one pass at a time
	idx atomic.Pointer[ghServed]

	hmu     sync.Mutex
	passErr error

	cmu     sync.Mutex
	changed map[[3]string]bool // (project, filename, sha256) reported as changed
}

var _ Source = (*GitHubSource)(nil)

// ghServed is the index a pass published.
type ghServed struct {
	ghIndex
	unavailable map[string]bool   // projects with a conflict or an asset waiting for its hash
	owners      map[string]string // project -> owning repository's full name
	backlog     int
}

// NewGitHubSource builds a github source. state holds the owner and digest
// pins; log nil means slog.Default().
func NewGitHubSource(name string, claims []string, api GitHubAPI, state storage.Driver, rl *relay.Relay, rec *records.Store, poll time.Duration, maxArtifact int64, log *slog.Logger) *GitHubSource {
	if log == nil {
		log = slog.Default()
	}
	return &GitHubSource{
		name: name, claims: claims, api: api, pins: newGHPins(state, name, log), relay: rl, rec: rec,
		poll: poll, maxArtifact: maxArtifact, log: log, changed: map[[3]string]bool{},
	}
}

func (s *GitHubSource) Name() string     { return s.name }
func (s *GitHubSource) Claims() []string { return s.claims }

// Run makes a pass at start and then every poll interval until ctx is done.
func (s *GitHubSource) Run(ctx context.Context) {
	for {
		if err := s.pass(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("pypi github index failed", "source", s.name, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.poll):
		}
	}
}

// pass indexes once and records the outcome for Health.
func (s *GitHubSource) pass(ctx context.Context) error {
	err := s.index(ctx)
	if ctx.Err() == nil {
		s.hmu.Lock()
		s.passErr = err
		s.hmu.Unlock()
	}
	return err
}

// index lists the releases, decides and pins new owners, hashes assets
// without a digest and publishes the index. A failure before the index is
// built keeps the previous one. A rate limit hit while hashing is returned
// after the index is published.
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
	idx, decided := buildGHIndex(s.claims, listed, owners, digests)
	lost := false
	for _, name := range sortedKeys(decided) {
		repo := decided[name]
		id, err := s.pins.PinOwner(ctx, name, repo)
		if err != nil {
			return fmt.Errorf("pin owner of %s: %w", name, err)
		}
		owners[name] = id
		lost = lost || id != repo.ID
	}
	if lost {
		// Another writer pinned a name first: its pin decides.
		idx, _ = buildGHIndex(s.claims, listed, owners, digests)
	}
	backlog, hashErr := s.hashPending(ctx, idx.NeedHash, owners)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	served := &ghServed{ghIndex: idx, unavailable: map[string]bool{}, owners: map[string]string{}, backlog: backlog}
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
		who, ok := names[id]
		if !ok {
			who = "repository " + strconv.FormatInt(id, 10)
		}
		served.owners[name] = who
	}
	s.idx.Store(served)
	return hashErr
}

// hashPending downloads the assets without a digest once, hashes them and
// pins the digest, skipping those of names another repository owns (they are
// never served). It returns how many are still without a pin. A rate limit
// stops the remaining downloads and is returned; other failures are logged
// and retried by the next pass.
func (s *GitHubSource) hashPending(ctx context.Context, pending []ghPending, owners map[string]int64) (int, error) {
	var todo []ghPending
	seen := map[int64]bool{}
	for _, p := range pending {
		if id, ok := owners[p.Package]; (ok && id != p.Repo.ID) || seen[p.Asset.ID] {
			continue
		}
		seen[p.Asset.ID] = true
		todo = append(todo, p)
	}
	var left atomic.Int64
	left.Store(int64(len(todo)))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(ghHashConcurrency)
	for _, p := range todo {
		g.Go(func() error {
			err := s.hashAsset(gctx, p)
			switch {
			case err == nil:
				left.Add(-1)
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
	return int(left.Load()), err
}

// hashAsset streams an asset through sha256 and pins the digest. Nothing is
// cached: the bytes are unverified until pinned.
func (s *GitHubSource) hashAsset(ctx context.Context, p ghPending) error {
	body, _, err := s.api.OpenAsset(ctx, p.Repo, p.Asset.ID, s.maxArtifact)
	if err != nil {
		return err
	}
	defer body.Close()
	h := sha256.New()
	n, err := io.Copy(h, body)
	if err != nil {
		return err
	}
	_, err = s.pins.PinDigest(ctx, p.Asset.ID, hex.EncodeToString(h.Sum(nil)), n)
	return err
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
			UpstreamURL:    "https://api.github.com/repos/" + f.Repo.FullName + "/releases/assets/" + strconv.FormatInt(f.AssetID, 10),
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

// checkChanged compares sum with the first digest this source recorded for
// the file; a difference is served and logged once.
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
	seen := s.changed[key]
	s.changed[key] = true
	s.cmu.Unlock()
	if !seen {
		s.log.Warn("pypi github: asset changed upstream; serving the new bytes", "source", s.name, "package", pkg,
			"version", version, "file", file, "first_sha256", first.SHA256, "seen_sha256", sum)
	}
	return nil
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

// Health reports the last pass.
func (s *GitHubSource) Health(context.Context) []metrics.Health {
	s.hmu.Lock()
	err := s.passErr
	s.hmu.Unlock()
	st := s.idx.Load()
	h := metrics.Health{Name: s.name, Ecosystem: "pypi"}
	kept := "the last index is served"
	if st == nil {
		kept = "nothing indexed yet"
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
	case err != nil:
		h.Detail = "indexing failed; " + kept
	case st == nil:
		h.Detail = "not indexed yet"
	default:
		h.OK, h.Detail = true, "indexed"
		if st.backlog > 0 {
			h.Detail = fmt.Sprintf("indexed; %d assets waiting to be hashed", st.backlog)
		}
	}
	return []metrics.Health{h}
}
