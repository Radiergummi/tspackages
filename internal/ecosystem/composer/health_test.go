package composer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/pins"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
)

// counter returns the value of the named counter series with exactly the given labels.
func counter(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	fams, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
	next:
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if labels[l.GetName()] != l.GetValue() {
					continue next
				}
			}
			if len(m.GetLabel()) != len(labels) {
				continue
			}
			if m.Counter != nil {
				return m.GetCounter().GetValue()
			}
			return float64(m.GetHistogram().GetSampleCount())
		}
	}
	return 0
}

func TestHandlerObservesRequests(t *testing.T) {
	g, _ := gitAndReg()
	h := server(t, []Source{g}, readAll)
	lbl := map[string]string{"ecosystem": "composer", "source": "git-fake", "code": "200"}
	before := counter(t, "tspackages_requests_total", lbl)
	do(h, "GET", "/composer/p2/matchory/a.json", nil)
	if got := counter(t, "tspackages_requests_total", lbl) - before; got != 1 {
		t.Fatalf("200 delta = %v", got)
	}
	// An authorised read of an unknown name is a 404 attributed to no source.
	nf := map[string]string{"ecosystem": "composer", "source": "none", "code": "404"}
	before = counter(t, "tspackages_requests_total", nf)
	do(h, "GET", "/composer/p2/matchory/missing.json", nil)
	if got := counter(t, "tspackages_requests_total", nf) - before; got != 1 {
		t.Fatalf("404 delta = %v", got)
	}
}

func TestRegistryObservesCacheHitAndUpstream(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, "", "r1"))
	hit := map[string]string{"ecosystem": "composer", "source": "packagist"}
	up := map[string]string{"source": "packagist"}
	h0, u0 := counter(t, "tspackages_cache_hits_total", hit), counter(t, "tspackages_upstream_request_duration_seconds", up)
	for range 3 {
		if _, err := e.src.Versions(context.Background(), "acme/pkg", false); err != nil {
			t.Fatal(err)
		}
	}
	if d := counter(t, "tspackages_cache_hits_total", hit) - h0; d != 2 {
		t.Errorf("cache hits delta = %v", d)
	}
	if d := counter(t, "tspackages_upstream_request_duration_seconds", up) - u0; d != 1 {
		t.Errorf("upstream observations delta = %v", d)
	}
}

func TestRegistryHealth(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	if h := e.src.Health(ctx); len(h) != 1 || !h[0].OK {
		t.Fatalf("fresh: %+v", h)
	}
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, "", "r1"))
	if _, err := e.src.Versions(ctx, "acme/pkg", false); err != nil {
		t.Fatal(err)
	}
	e.f.setStatus(500)
	e.clock = e.clock.Add(time.Hour)
	if _, err := e.src.Versions(ctx, "acme/pkg", false); err != nil { // stale served
		t.Fatal(err)
	}
	h := e.src.Health(ctx)
	if h[0].OK || h[0].Detail != "serving stale" {
		t.Fatalf("after failure: %+v", h)
	}
	e.f.setStatus(0)
	e.clock = e.clock.Add(time.Hour)
	if _, err := e.src.Versions(ctx, "acme/pkg", false); err != nil {
		t.Fatal(err)
	}
	if h := e.src.Health(ctx); !h[0].OK {
		t.Fatalf("after recovery: %+v", h)
	}
	// Without a cache the failure is not "stale".
	e2 := newRegEnv(t)
	e2.f.setStatus(500)
	_, _ = e2.src.Versions(ctx, "acme/pkg", false)
	if h := e2.src.Health(ctx); h[0].OK || h[0].Detail != "upstream error" {
		t.Fatalf("no cache: %+v", h)
	}
}

func TestRegistryCancelledFetchNotRecorded(t *testing.T) {
	e := newRegEnv(t)
	reached := false
	e.src.wait = func(context.Context) error { reached = true; return nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Directly, since flight returns on a cancelled ctx without waiting for fn.
	if _, err := e.src.refreshMetadata(ctx, e.src.metaKey("acme/pkg", false), "acme/pkg", false, false); err == nil {
		t.Fatal("expected error")
	}
	if !reached {
		t.Fatal("the upstream fetch (and so noteFetch) was never reached")
	}
	if h := e.src.Health(context.Background()); !h[0].OK {
		t.Fatalf("client cancellation marked source unhealthy: %+v", h)
	}
}

func TestRegistryLogsHealthTransitions(t *testing.T) {
	var buf bytes.Buffer
	e := newRegEnv(t)
	e.src.log = slog.New(slog.NewTextHandler(&buf, nil))
	count := func(msg string) int { return strings.Count(buf.String(), msg) }
	e.f.setStatus(500)
	_, _ = e.src.Versions(context.Background(), "acme/pkg", false)
	e.f.setStatus(503) // a different error while unhealthy is not a transition
	_, _ = e.src.Versions(context.Background(), "acme/pkg", false)
	if n := count("composer upstream unhealthy"); n != 1 {
		t.Fatalf("unhealthy logged %d times, want 1", n)
	}
	e.f.setStatus(0)
	e.f.set("/p2/acme/pkg.json", []byte(`{"packages":{"acme/pkg":[]}}`))
	_, _ = e.src.Versions(context.Background(), "acme/pkg", false)
	if n := count("composer upstream recovered"); n != 1 {
		t.Fatalf("recovered logged %d times, want 1", n)
	}
	e.f.setStatus(500) // acme/pkg is cached now; fetch another package
	_, _ = e.src.Versions(context.Background(), "acme/other", false)
	if n := count("composer upstream unhealthy"); n != 2 {
		t.Fatalf("unhealthy logged %d times after relapse, want 2", n)
	}
}

func TestGitHealth(t *testing.T) {
	good := gitRepo(t, "matchory/a")
	bad := gitRepo(t, "matchory/b")
	commitFile(t, bad, "composer.json", `{broken`, "break")
	g, _ := newGit(t, fsState(t), nil, good, bad)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	h := g.Health(ctx)
	if len(h) != 2 || !h[0].OK || h[1].OK || h[1].Detail != "never indexed" {
		t.Fatalf("%+v", h)
	}
	// Remote rows are scoped to the package the remote declares; unknown is "".
	if !h[0].Scoped || h[0].Package != "matchory/a" || !h[1].Scoped || h[1].Package != "" {
		t.Fatalf("scoping: %+v", h)
	}
	g.now = func() time.Time { return time.Now().Add(10 * time.Minute) } // poll is 1m
	if h := g.Health(ctx); h[0].OK || h[0].Detail != "sync stale" {
		t.Fatalf("stale: %+v", h[0])
	}
	g.now = time.Now
	commitFile(t, good, "composer.json", `{broken`, "break")
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if h := g.Health(ctx); h[0].OK || h[0].Detail != "index failing" {
		t.Fatalf("failing index: %+v", h[0])
	}
	fams, _ := metrics.Registry().Gather()
	found := false
	for _, f := range fams {
		if f.GetName() == "tspackages_git_last_sync_timestamp_seconds" {
			for _, m := range f.GetMetric() {
				// The only label is the source; remotes never become label values.
				if len(m.GetLabel()) == 1 && m.GetLabel()[0].GetName() == "source" && m.GetLabel()[0].GetValue() == "git" && m.GetGauge().GetValue() > 0 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("last sync gauge not set")
	}
}

func TestGitMovedPackage(t *testing.T) {
	a := gitRepo(t, "matchory/a")
	g, _ := newGit(t, fsState(t), nil, a)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := g.MovedPackage(pins.MovedTag{Source: "git", Remote: a}); got != "matchory/a" {
		t.Errorf("got %q", got)
	}
	if got := g.MovedPackage(pins.MovedTag{Source: "other", Remote: a}); got != "" {
		t.Errorf("foreign source: %q", got)
	}
}

func TestGitHealthConflict(t *testing.T) {
	a, b := gitRepo(t, "matchory/a"), gitRepo(t, "matchory/a")
	g, _ := newGit(t, fsState(t), nil, a, b)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := g.Health(context.Background())
	if len(h) != 3 || h[2].OK || h[2].Detail != "conflict" {
		t.Fatalf("%+v", h)
	}
}

type failStat struct {
	storage.Driver
	err error
}

func (f failStat) Stat(context.Context, string) (storage.Info, error) { return storage.Info{}, f.err }

func TestStorageHealth(t *testing.T) {
	s, d := newSource(t)
	if h := s.Health(context.Background()); !h[0].OK {
		t.Fatalf("empty store: %+v", h)
	}
	s = newSourceOn(failStat{Driver: d, err: errors.New("open /var/secret/path: boom")})
	if h := s.Health(context.Background()); h[0].OK || h[0].Detail != "unreachable" {
		t.Fatalf("failing store: %+v", h)
	}
}

func TestNoCallerRequestObserved(t *testing.T) {
	g, _ := gitAndReg()
	mux := http.NewServeMux()
	New([]Source{g}, archive.Limits{MaxBytes: 1}, nil).Mount(mux)
	lbl := map[string]string{"ecosystem": "composer", "source": "none", "code": "403"}
	before := counter(t, "tspackages_requests_total", lbl)
	do(mux, "GET", "/composer/packages.json", nil)
	if got := counter(t, "tspackages_requests_total", lbl) - before; got != 1 {
		t.Fatalf("delta = %v", got)
	}
}

func TestSourcesLogToInjectedLogger(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	_, d := newSource(t)
	l := archive.Limits{MaxBytes: 1 << 20, MaxDecompressed: 16 << 20, MaxEntries: 1000}
	s := NewStorageSource("internal", []string{"matchory-internal/*"}, failStat{Driver: d, err: errors.New("boom")}, records.New(d), l, log)
	s.Health(context.Background())
	if !strings.Contains(buf.String(), "composer storage source unreachable") {
		t.Errorf("storage source: %q", buf.String())
	}
	buf.Reset()
	e := newRegEnv(t)
	src := NewRegistrySource("packagist", nil, e.f.srv.URL, upstream.New(upstream.Options{FetchHosts: []string{"127.0.0.1"}, AllowPrivateForTesting: true}),
		e.cache, testRelay(t, e.cache), e.rec, time.Minute, 1<<20, 0, nil, log)
	e.f.setStatus(500)
	_, _ = src.Versions(context.Background(), "acme/pkg", false)
	if !strings.Contains(buf.String(), "composer upstream unhealthy") {
		t.Errorf("registry source: %q", buf.String())
	}
}

func TestRegistryObservesDistCacheHit(t *testing.T) {
	e := newRegEnv(t)
	zip := []byte("PK-hit")
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, sum1(zip), "r1"))
	e.f.set("/dist/pkg.zip", zip)
	hit := map[string]string{"ecosystem": "composer", "source": "packagist"}
	read := func() {
		t.Helper()
		a, err := e.src.Dist(context.Background(), "acme/pkg", "1.0.0", "r1")
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(a.Body)
		a.Body.Close()
	}
	read() // metadata miss, dist miss
	h0 := counter(t, "tspackages_cache_hits_total", hit)
	read() // metadata hit, dist hit
	if d := counter(t, "tspackages_cache_hits_total", hit) - h0; d != 2 {
		t.Errorf("cache hits delta = %v, want 2 (metadata and dist)", d)
	}
}
