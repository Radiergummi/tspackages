package composer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/storage"
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
		if _, err := e.src.Versions(context.Background(), "acme/pkg"); err != nil {
			t.Fatal(err)
		}
	}
	if d := counter(t, "tspackages_cache_hits_total", hit) - h0; d != 4 {
		t.Errorf("cache hits delta = %v", d)
	}
	if d := counter(t, "tspackages_upstream_request_duration_seconds", up) - u0; d != 2 {
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
	if _, err := e.src.Versions(ctx, "acme/pkg"); err != nil {
		t.Fatal(err)
	}
	e.f.setStatus(500)
	e.clock = e.clock.Add(time.Hour)
	if _, err := e.src.Versions(ctx, "acme/pkg"); err != nil { // stale served
		t.Fatal(err)
	}
	h := e.src.Health(ctx)
	if h[0].OK || !strings.Contains(h[0].Detail, "serving stale") {
		t.Fatalf("after failure: %+v", h)
	}
	e.f.setStatus(0)
	e.clock = e.clock.Add(time.Hour)
	if _, err := e.src.Versions(ctx, "acme/pkg"); err != nil {
		t.Fatal(err)
	}
	if h := e.src.Health(ctx); !h[0].OK {
		t.Fatalf("after recovery: %+v", h)
	}
	// Without a cache the failure is not "stale".
	e2 := newRegEnv(t)
	e2.f.setStatus(500)
	_, _ = e2.src.Versions(ctx, "acme/pkg")
	if h := e2.src.Health(ctx); h[0].OK || strings.Contains(h[0].Detail, "stale") {
		t.Fatalf("no cache: %+v", h)
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
	if len(h) != 2 || !h[0].OK || h[1].OK || !strings.Contains(h[1].Detail, "never indexed") {
		t.Fatalf("%+v", h)
	}
	g.now = func() time.Time { return time.Now().Add(10 * time.Minute) } // poll is 1m
	if h := g.Health(ctx); h[0].OK || !strings.Contains(h[0].Detail, "older than") {
		t.Fatalf("stale: %+v", h[0])
	}
	lbl := map[string]string{"source": "git", "remote": good}
	fams, _ := metrics.Registry().Gather()
	found := false
	for _, f := range fams {
		if f.GetName() == "tspackages_git_last_sync_timestamp_seconds" {
			for _, m := range f.GetMetric() {
				if m.GetLabel()[0].GetValue() == lbl["remote"] && m.GetGauge().GetValue() > 0 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("last sync gauge not set")
	}
}

func TestGitHealthConflict(t *testing.T) {
	a, b := gitRepo(t, "matchory/a"), gitRepo(t, "matchory/a")
	g, _ := newGit(t, fsState(t), nil, a, b)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := g.Health(context.Background())
	if len(h) != 3 || h[2].OK || !strings.Contains(h[2].Detail, "matchory/a") {
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
	s = newSourceOn(failStat{Driver: d, err: errors.New("boom")})
	if h := s.Health(context.Background()); h[0].OK || !strings.Contains(h[0].Detail, "boom") {
		t.Fatalf("failing store: %+v", h)
	}
}
