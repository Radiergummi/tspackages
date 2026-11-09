package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/ecosystem/composer"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/pins"
)

type fakeEco struct{}

func (fakeEco) Name() string         { return "composer" }
func (fakeEco) Mount(*http.ServeMux) {}

var _ ecosystem.Ecosystem = fakeEco{}

type fakeSource []Health

func (f fakeSource) Health(context.Context) []Health { return f }

func serve(t *testing.T, w *Web, path string, c *identity.Caller) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	w.Mount(mux)
	r := httptest.NewRequest("GET", path, nil)
	r.Host = "pkgs.tail.ts.net"
	if c != nil {
		r = r.WithContext(identity.WithCaller(r.Context(), *c))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

func reader() *identity.Caller {
	return &identity.Caller{Login: "a@b", Rules: []authz.Rule{{Read: []string{"*"}}}}
}

func newWeb(ready func(context.Context) error) *Web {
	return New("fallback", []ecosystem.Ecosystem{fakeEco{}},
		[]StatusSource{fakeSource{{Name: "main", OK: true, Detail: "fine"}, {Name: "<b>bad</b>", OK: false, Detail: "never indexed"}}},
		func() []pins.MovedTag {
			return []pins.MovedTag{{Ecosystem: "composer", Source: "git", Remote: "https://x/y.git", Tag: "v1.0.0<script>", Pinned: "aaa", Seen: "bbb"}}
		},
		func() []composer.Conflict {
			return []composer.Conflict{{Package: "a/b", Remotes: []string{"r1", "r2"}}}
		},
		ready)
}

func TestStatusShowsMovedTag(t *testing.T) {
	rec := serve(t, newWeb(nil), "/", reader())
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"v1.0.0&lt;script&gt;", "never indexed", "&lt;b&gt;bad&lt;/b&gt;", "a/b", "r2",
		`{"repositories":[{"type":"composer","url":"https://pkgs.tail.ts.net/composer"},{"packagist.org":false}]}`,
		"curl -fT pkg.zip https://pkgs.tail.ts.net/composer/upload/",
	} {
		if !strings.Contains(strings.ReplaceAll(body, "&#34;", `"`), want) {
			t.Errorf("body lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>") || strings.Contains(body, "<b>bad") {
		t.Error("unescaped attacker-influenced text")
	}
}

func TestStatusForbiddenWithoutRules(t *testing.T) {
	if rec := serve(t, newWeb(nil), "/", &identity.Caller{Login: "a@b"}); rec.Code != 403 {
		t.Fatalf("no rules: %d", rec.Code)
	}
	if rec := serve(t, newWeb(nil), "/", nil); rec.Code != 403 {
		t.Fatalf("no caller: %d", rec.Code)
	}
}

func TestHealthEndpointsNeedCallerNotCapability(t *testing.T) {
	bare := &identity.Caller{Login: "a@b"}
	for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
		if rec := serve(t, newWeb(nil), p, bare); rec.Code != 200 {
			t.Errorf("%s with bare caller: %d", p, rec.Code)
		}
		if rec := serve(t, newWeb(nil), p, nil); rec.Code != 403 {
			t.Errorf("%s without caller: %d", p, rec.Code)
		}
	}
	if rec := serve(t, newWeb(nil), "/healthz", bare); rec.Body.String() != "ok" {
		t.Error("healthz body")
	}
}

func TestReadyz(t *testing.T) {
	w := newWeb(func(context.Context) error { return errors.New("store down") })
	rec := serve(t, w, "/readyz", reader())
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "store down") {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestMetricsExposed(t *testing.T) {
	metrics.ObserveRequest("composer", "main", 200)
	metrics.ObserveCacheHit("composer", "main")
	metrics.ObserveUpstream("main", time.Second)
	metrics.SetGitLastSync("git", "https://x/y.git", time.Unix(1700000000, 0))
	w := newWeb(nil)
	w.SetRejected(func() uint64 { return 7 })
	rec := serve(t, w, "/metrics", reader())
	body := rec.Body.String()
	for _, want := range []string{
		`tspackages_requests_total{code="200",ecosystem="composer",source="main"}`,
		"tspackages_cache_hits_total",
		"tspackages_upstream_request_duration_seconds_bucket",
		`tspackages_git_last_sync_timestamp_seconds{remote="https://x/y.git",source="git"} 1.7e+09`,
		"tspackages_rate_limited_total 7",
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
}
