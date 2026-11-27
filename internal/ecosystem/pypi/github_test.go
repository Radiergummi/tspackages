package pypi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"iter"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/githubapp"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/relay"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
)

// fakeGH is a GitHubAPI over in-memory repositories and asset bodies.
type fakeGH struct {
	mu       sync.Mutex
	repos    []githubapp.Repo
	releases map[int64][]githubapp.Release // by repository ID
	bodies   map[int64][]byte              // by asset ID
	opens    map[int64]int
	listErr  error
	openErr  error
	reset    time.Time
}

func newFakeGH() *fakeGH {
	return &fakeGH{releases: map[int64][]githubapp.Release{}, bodies: map[int64][]byte{}, opens: map[int64]int{}}
}

func (f *fakeGH) Repositories(context.Context) ([]githubapp.Repo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]githubapp.Repo(nil), f.repos...), nil
}

func (f *fakeGH) Releases(_ context.Context, r githubapp.Repo) ([]githubapp.Release, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]githubapp.Release(nil), f.releases[r.ID]...), nil
}

func (f *fakeGH) OpenAsset(_ context.Context, _ githubapp.Repo, id, _ int64) (io.ReadCloser, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens[id]++
	if f.openErr != nil {
		return nil, 0, f.openErr
	}
	b, ok := f.bodies[id]
	if !ok {
		return nil, 0, &upstream.StatusError{Code: 404, URL: "/assets"}
	}
	return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
}

func (f *fakeGH) RateLimit() (int, time.Time) { return 0, f.reset }

func (f *fakeGH) openCount(id int64) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens[id]
}

// publish adds a release with one asset to repo; digest says whether GitHub
// reports the asset's sha256.
func (f *fakeGH) publish(repo githubapp.Repo, relID int64, tag string, assetID int64, name string, body []byte, digest bool, created time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !slices.Contains(f.repos, repo) {
		f.repos = append(f.repos, repo)
	}
	a := githubapp.Asset{ID: assetID, Name: name, State: "uploaded", Size: int64(len(body)), CreatedAt: created, UpdatedAt: created}
	if digest {
		a.Digest = "sha256:" + sha256Hex(body)
	}
	f.releases[repo.ID] = append(f.releases[repo.ID], githubapp.Release{ID: relID, Tag: tag, CreatedAt: created, Assets: []githubapp.Asset{a}})
	f.bodies[assetID] = body
}

func (f *fakeGH) clear(repo githubapp.Repo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases[repo.ID] = nil
}

func (f *fakeGH) setBody(id int64, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies[id] = b
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// lockedBuffer collects log output written from several goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type ghEnv struct {
	api   *fakeGH
	src   *GitHubSource
	rl    *relay.Relay
	rec   *records.Store
	state storage.Driver
	logs  *lockedBuffer
}

func newGHEnvWith(t *testing.T, state storage.Driver, apiURL string) *ghEnv {
	t.Helper()
	cache, err := storage.NewCache(context.Background(), fsDriver(t), 1<<30, nil)
	if err != nil {
		t.Fatal(err)
	}
	rl, err := relay.New(cache, filepath.Join(t.TempDir(), "relay"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rl.Wait)
	rec := records.New(fsDriver(t))
	logs := &lockedBuffer{}
	e := &ghEnv{api: newFakeGH(), rl: rl, rec: rec, state: state, logs: logs}
	e.src = NewGitHubSource("gh", []string{"acme-*"}, e.api, apiURL, state, rl, rec, time.Hour, 1<<20, slog.New(slog.NewTextHandler(logs, nil)))
	return e
}

func newGHEnv(t *testing.T) *ghEnv { return newGHEnvWith(t, fsDriver(t), "https://api.github.com") }

func (e *ghEnv) pass(t *testing.T) error {
	t.Helper()
	return e.src.pass(context.Background())
}

func (e *ghEnv) mustPass(t *testing.T) {
	t.Helper()
	if err := e.pass(t); err != nil {
		t.Fatal(err)
	}
}

func (e *ghEnv) read(name, filename string) ([]byte, error) {
	b, err := readAllArtifact(e.src.File(context.Background(), name, filename))
	e.rl.Wait()
	return b, err
}

var (
	repoA   = githubapp.Repo{ID: 7, FullName: "acme/lib"}
	repoB   = githubapp.Repo{ID: 3, FullName: "evil/lib"}
	wheel1  = "acme_lib-1.0.0-py3-none-any.whl"
	wheel2  = "acme_lib-2.0.0-py3-none-any.whl"
	t0      = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctxBg   = context.Background()
	bodyOne = []byte("wheel one")
)

func TestGitHubBeforeFirstPass(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	_, err := e.src.Project(ctxBg, "acme-lib")
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("Project before the first pass: %v", err)
	}
	_, err = e.src.File(ctxBg, "acme-lib", wheel1)
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("File before the first pass: %v", err)
	}
	if h := e.src.Health(ctxBg); len(h) != 1 || h[0].OK {
		t.Fatalf("health before the first pass: %+v", h)
	}
}

func TestGitHubProjectAndFile(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.mustPass(t)

	p, err := e.src.Project(ctxBg, "acme-lib")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Files) != 1 || p.Files[0].Filename != wheel1 || p.Files[0].SHA256 != sha256Hex(bodyOne) ||
		p.Files[0].Size != int64(len(bodyOne)) || !p.Files[0].UploadTime.Equal(t0) {
		t.Fatalf("files: %+v", p.Files)
	}
	if len(p.Versions) != 1 || p.Versions[0] != "1.0.0" {
		t.Fatalf("versions: %v", p.Versions)
	}
	b, err := e.read("acme-lib", wheel1)
	if err != nil || !bytes.Equal(b, bodyOne) {
		t.Fatalf("File: %q, %v", b, err)
	}
	recs, err := e.rec.FileProvenance(ctxBg, "pypi", "acme-lib", "1.0.0", wheel1)
	if err != nil || len(recs) != 1 {
		t.Fatalf("provenance: %+v, %v", recs, err)
	}
	r := recs[0]
	if r.SourceType != "github" || r.Source != "gh" || r.SHA256 != sha256Hex(bodyOne) ||
		r.UpstreamURL != "https://api.github.com/repos/acme/lib/releases/assets/10" {
		t.Fatalf("provenance record: %+v", r)
	}
	if _, err := e.src.Project(ctxBg, "acme-other"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("unknown claimed name: %v", err)
	}
	if _, err := e.src.File(ctxBg, "acme-lib", wheel2); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("unknown file: %v", err)
	}
	for _, m := range []func(context.Context, string, string) (Artifact, error){e.src.Metadata, e.src.Provenance} {
		if _, err := m(ctxBg, "acme-lib", wheel1); !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("metadata/provenance: %v", err)
		}
	}
	if h := e.src.Health(ctxBg); len(h) != 1 || !h[0].OK {
		t.Fatalf("health: %+v", h)
	}
}

func TestGitHubTamperedDownload(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.mustPass(t)
	e.api.setBody(10, []byte("tampered!"))
	if _, err := e.read("acme-lib", wheel1); err == nil {
		t.Fatal("tampered bytes were served without an error")
	}
	if _, err := e.read("acme-lib", wheel1); err == nil {
		t.Fatal("tampered bytes were served without an error")
	}
	if n := e.api.openCount(10); n != 2 {
		t.Fatalf("asset opened %d times; a failed download must not be cached", n)
	}
}

func TestGitHubListedButDeleted(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.mustPass(t)
	e.api.mu.Lock()
	e.api.openErr = &upstream.StatusError{Code: 404, URL: "/assets/10"}
	e.api.mu.Unlock()
	_, err := e.read("acme-lib", wheel1)
	if err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("listed asset gone: %v", err)
	}
}

func TestGitHubHashesOldAssets(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, false, t0)
	e.mustPass(t)
	if p, err := e.src.Project(ctxBg, "acme-lib"); err == nil {
		t.Fatalf("an unhashed asset is listed: %+v", p)
	} else if errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("a name waiting for its hash is a miss: %v", err)
	}
	if n := e.api.openCount(10); n != 1 {
		t.Fatalf("the pass opened the asset %d times", n)
	}
	digests, err := newGHPins(e.state, "gh", discardLog).Digests(ctxBg)
	if err != nil || digests[10] != sha256Hex(bodyOne) {
		t.Fatalf("digest pins: %v, %v", digests, err)
	}
	if n := e.src.Backlog(); n != 0 {
		t.Fatalf("backlog after hashing: %d", n)
	}

	e.mustPass(t)
	if n := e.api.openCount(10); n != 1 {
		t.Fatalf("a pinned asset was hashed again (%d opens)", n)
	}
	p, err := e.src.Project(ctxBg, "acme-lib")
	if err != nil || len(p.Files) != 1 || p.Files[0].SHA256 != sha256Hex(bodyOne) {
		t.Fatalf("pass 2: %+v, %v", p, err)
	}
	e.api.setBody(10, []byte("other bytes"))
	if _, err := e.read("acme-lib", wheel1); err == nil {
		t.Fatal("bytes differing from the pin were served without an error")
	}
}

func TestGitHubOwnerPinned(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.mustPass(t)

	// Earlier and from a lower repository ID: without the pin it would win.
	e.api.publish(repoB, 2, "v2.0.0", 20, wheel2, []byte("evil"), true, t0.Add(-time.Hour))
	e.api.publish(repoB, 3, "v2.0.1", 21, "acme_lib-2.0.1.tar.gz", []byte("evil sdist"), false, t0.Add(-time.Hour))
	e.mustPass(t)

	p, err := e.src.Project(ctxBg, "acme-lib")
	if err != nil || len(p.Files) != 1 || p.Files[0].Filename != wheel1 {
		t.Fatalf("project: %+v, %v", p, err)
	}
	var skipped bool
	for _, s := range e.src.Skipped() {
		if s.Repo == "evil/lib" && s.Asset == wheel2 && s.Reason == "owned by acme/lib" {
			skipped = true
		}
	}
	if !skipped {
		t.Fatalf("skipped: %+v", e.src.Skipped())
	}
	if got := e.src.Owners(); got["acme-lib"] != "acme/lib" {
		t.Fatalf("owners: %v", got)
	}
	if n := e.api.openCount(21); n != 0 {
		t.Fatalf("an asset of a name owned elsewhere was hashed (%d opens)", n)
	}
}

// racingDriver pins acme-lib to repoB right after the github source listed
// the owner pins, as a concurrent instance would.
type racingDriver struct {
	storage.Driver
	once sync.Once
}

func (r *racingDriver) List(ctx context.Context, prefix string) iter.Seq2[storage.Info, error] {
	return func(yield func(storage.Info, error) bool) {
		for info, err := range r.Driver.List(ctx, prefix) {
			if !yield(info, err) {
				return
			}
		}
		if strings.HasSuffix(prefix, "/owners/") {
			r.once.Do(func() {
				if _, err := newGHPins(r.Driver, "gh", discardLog).PinOwner(ctx, "acme-lib", repoB); err != nil {
					panic(err)
				}
			})
		}
	}
}

func TestGitHubOwnerRaceLost(t *testing.T) {
	e := newGHEnvWith(t, &racingDriver{Driver: fsDriver(t)}, "https://api.github.com/")
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.api.publish(repoB, 2, "v2.0.0", 20, wheel2, []byte("b"), true, t0.Add(time.Hour))
	e.mustPass(t)
	p, err := e.src.Project(ctxBg, "acme-lib")
	if err != nil || len(p.Files) != 1 || p.Files[0].Filename != wheel2 {
		t.Fatalf("project after a lost owner race: %+v, %v", p, err)
	}
	if got := e.src.Owners(); got["acme-lib"] != "evil/lib" {
		t.Fatalf("owners: %v", got)
	}
}

func TestGitHubRateLimitedPassKeepsIndex(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.mustPass(t)
	reset := time.Date(2026, 11, 27, 12, 30, 0, 0, time.UTC)
	e.api.mu.Lock()
	e.api.listErr = &githubapp.RateLimitError{Reset: reset}
	e.api.mu.Unlock()
	if err := e.pass(t); !errors.Is(err, githubapp.ErrRateLimited) {
		t.Fatalf("pass 2: %v", err)
	}
	if p, err := e.src.Project(ctxBg, "acme-lib"); err != nil || len(p.Files) != 1 {
		t.Fatalf("pass 1's index is gone: %+v, %v", p, err)
	}
	h := e.src.Health(ctxBg)
	if len(h) != 1 || h[0].OK || !strings.Contains(h[0].Detail, reset.Format(time.RFC3339)) {
		t.Fatalf("health: %+v", h)
	}
}

func TestGitHubChangedBytesReported(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.mustPass(t)
	if _, err := e.read("acme-lib", wheel1); err != nil {
		t.Fatal(err)
	}

	// Deleted and re-uploaded: a new asset ID with other bytes.
	e.api.clear(repoA)
	other := []byte("wheel one, rebuilt")
	e.api.publish(repoA, 1, "v1.0.0", 11, wheel1, other, true, t0.Add(time.Minute))
	e.mustPass(t)
	b, err := e.read("acme-lib", wheel1)
	if err != nil || !bytes.Equal(b, other) {
		t.Fatalf("File: %q, %v", b, err)
	}
	const msg = "pypi github: asset changed upstream; serving the new bytes"
	if n := strings.Count(e.logs.String(), msg); n != 1 {
		t.Fatalf("%d change reports in:\n%s", n, e.logs.String())
	}
	ch := e.src.Changed()
	if len(ch) != 1 || ch[0].Package != "acme-lib" || ch[0].Filename != wheel1 ||
		ch[0].FirstSHA256 != sha256Hex(bodyOne) || ch[0].NewSHA256 != sha256Hex(other) || ch[0].Seen.IsZero() {
		t.Fatalf("changed: %+v", ch)
	}
}

func TestGitHubDeletedAssetDisappears(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.mustPass(t)
	if _, err := e.read("acme-lib", wheel1); err != nil {
		t.Fatal(err)
	}
	e.api.clear(repoA)
	e.mustPass(t)
	if _, err := e.src.Project(ctxBg, "acme-lib"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("Project after deletion: %v", err)
	}
	if _, err := e.src.File(ctxBg, "acme-lib", wheel1); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("File after deletion: %v", err)
	}
}

func TestGitHubProvenanceNamesGHES(t *testing.T) {
	e := newGHEnvWith(t, fsDriver(t), "https://ghe.example/api/v3/")
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.mustPass(t)
	if _, err := e.read("acme-lib", wheel1); err != nil {
		t.Fatal(err)
	}
	recs, err := e.rec.FileProvenance(ctxBg, "pypi", "acme-lib", "1.0.0", wheel1)
	if err != nil || len(recs) != 1 || recs[0].UpstreamURL != "https://ghe.example/api/v3/repos/acme/lib/releases/assets/10" {
		t.Fatalf("provenance: %+v, %v", recs, err)
	}
}

// TestGitHubConflictedFileUnavailable: a filename two releases publish with
// different digests is withheld, never a miss, even next to served files.
func TestGitHubConflictedFileUnavailable(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.api.publish(repoA, 2, "v1.0.0-again", 11, wheel1, []byte("other"), true, t0.Add(time.Hour))
	e.api.publish(repoA, 3, "v2.0.0", 12, wheel2, []byte("two"), true, t0.Add(2*time.Hour))
	e.mustPass(t)
	p, err := e.src.Project(ctxBg, "acme-lib")
	if err != nil || len(p.Files) != 1 || p.Files[0].Filename != wheel2 {
		t.Fatalf("project: %+v, %v", p, err)
	}
	_, err = e.src.File(ctxBg, "acme-lib", wheel1)
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("conflicted file: %v", err)
	}
}

// TestGitHubRateLimitWaitsForReset: after a rate-limited pass, Run waits for
// the reset (plus a margin) rather than the poll interval.
func TestGitHubRateLimitWaitsForReset(t *testing.T) {
	e := newGHEnv(t)
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	e.src.now = func() time.Time { return now }
	e.src.poll = time.Millisecond
	waits := make(chan time.Duration, 1)
	e.src.after = func(d time.Duration) <-chan time.Time {
		waits <- d
		return make(chan time.Time) // never fires; the test cancels
	}
	e.api.mu.Lock()
	e.api.listErr = &githubapp.RateLimitError{Reset: now.Add(10 * time.Minute)}
	e.api.mu.Unlock()
	ctx, cancel := context.WithCancel(ctxBg)
	done := make(chan struct{})
	go func() { e.src.Run(ctx); close(done) }()
	got := <-waits
	cancel()
	<-done
	if got != 10*time.Minute+ghRateLimitMargin {
		t.Fatalf("Run waited %v after a rate-limited pass", got)
	}

	e.api.reset = now.Add(20 * time.Minute)
	for _, tc := range []struct {
		err  error
		want time.Duration
	}{
		{nil, time.Millisecond},
		{errors.New("boom"), time.Millisecond},
		{&githubapp.RateLimitError{}, 20*time.Minute + ghRateLimitMargin}, // reset from RateLimit()
		{&githubapp.RateLimitError{Reset: now.Add(3 * time.Hour)}, ghMaxRateLimitWait},
		{&githubapp.RateLimitError{Reset: now.Add(-time.Minute)}, time.Millisecond},
	} {
		if got := e.src.nextPass(tc.err); got != tc.want {
			t.Errorf("nextPass(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
