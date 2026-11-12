package goproxy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/module"

	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
)

type fakeProxy struct {
	srv   *httptest.Server
	mu    sync.Mutex
	pages map[string]fakePage
	hits  map[string]int
	down  bool
}

type fakePage struct {
	status int
	ctype  string
	body   string
}

func newFakeProxy(t *testing.T) *fakeProxy {
	t.Helper()
	f := &fakeProxy{pages: map[string]fakePage{}, hits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits[r.URL.Path]++
		if f.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		p, ok := f.pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if p.ctype != "" {
			w.Header().Set("Content-Type", p.ctype)
		}
		if p.status != 0 {
			w.WriteHeader(p.status)
		}
		w.Write([]byte(p.body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeProxy) set(path, ctype, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pages[path] = fakePage{ctype: ctype, body: body}
}

func (f *fakeProxy) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *fakeProxy) setDown(d bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = d
}

type regEnv struct {
	px    *fakeProxy
	src   *RegistrySource
	clock time.Time
}

func newRegEnv(t *testing.T) *regEnv {
	t.Helper()
	px := newFakeProxy(t)
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := storage.NewCache(context.Background(), d, 1<<30, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := upstream.New(upstream.Options{FetchHosts: []string{"127.0.0.1"}, AllowPrivateForTesting: true})
	e := &regEnv{px: px, clock: time.Now()}
	e.src = NewRegistrySource(RegistryOptions{Name: "proxy", BaseURL: px.srv.URL, Client: c, Cache: cache, TTL: time.Minute, MaxArtifact: 1 << 20})
	e.src.now = func() time.Time { return e.clock }
	return e
}

const textCT = "text/plain; charset=utf-8"

func TestRegistryListValidated(t *testing.T) {
	e := newRegEnv(t)
	e.px.set("/example.com/m/@v/list", textCT, "v1.0.0\nv1.1.0 2026-01-01T00:00:00Z\nv0.0.0-20260101000000-abcdefabcdef\ngarbage\nv2.0.0\n")
	got, err := e.src.List(context.Background(), "example.com/m")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "\n") != "v1.0.0\nv1.1.0" {
		t.Fatalf("got %q", got)
	}
}

func TestRegistryListHTMLIsAFailure(t *testing.T) {
	for name, page := range map[string]fakePage{
		"html":    {ctype: "text/html", body: "<html>v1.0.0</html>"},
		"doctype": {ctype: textCT, body: "<!doctype html><title>x</title>"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newRegEnv(t)
			p := "/example.com/m/@v/list"
			e.px.set(p, page.ctype, page.body)
			if _, err := e.src.List(context.Background(), "example.com/m"); err == nil || errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("want a failure, got %v", err)
			}
			// Never cached: a good answer is fetched at once.
			e.px.set(p, textCT, "v1.0.0\n")
			got, err := e.src.List(context.Background(), "example.com/m")
			if err != nil || len(got) != 1 {
				t.Fatalf("got %q, %v", got, err)
			}
			// And with a cached copy, the failure serves it stale.
			e.px.set(p, "text/html", "<html>")
			e.clock = e.clock.Add(2 * time.Minute)
			got, err = e.src.List(context.Background(), "example.com/m")
			if err != nil || len(got) != 1 {
				t.Fatalf("stale: got %q, %v", got, err)
			}
		})
	}
}

func TestRegistryListNamingAnotherModule(t *testing.T) {
	e := newRegEnv(t)
	e.px.set("/example.com/m/@v/list", textCT, "example.com/other v1.0.0\n")
	got, err := e.src.List(context.Background(), "example.com/m")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestRegistryInfoStripped(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	e.px.set("/example.com/m/@v/v1.0.0.info", "application/json", `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05+01:00","Origin":{"VCS":"git"}}`)
	in, err := e.src.Info(ctx, "example.com/m", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if b, _, ok := e.src.readCached(ctx, "go/proxy/"+mustSeg("example.com/m")+"/"+mustSeg("v1.0.0")+".info"); !ok || string(b) != `{"Version":"v1.0.0","Time":"2026-01-02T02:04:05Z"}` {
		t.Fatalf("cached %q", b)
	}
	if in.Version != "v1.0.0" || !in.Time.Equal(time.Date(2026, 1, 2, 2, 4, 5, 0, time.UTC)) || in.Time.Location() != time.UTC {
		t.Fatalf("got %+v", in)
	}
	e.px.set("/example.com/m/@v/v1.1.0.info", "application/json", `{"Version":"v1.2.0","Time":"2026-01-02T03:04:05Z"}`)
	if _, err := e.src.Info(ctx, "example.com/m", "v1.1.0"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("version mismatch: %v", err)
	}
	e.px.set("/example.com/m/@v/main.info", "application/json", `{"Version":"v0.0.0-20260101000000-abcdefabcdef","Time":"2026-01-01T00:00:00Z"}`)
	in, err = e.src.Info(ctx, "example.com/m", "main")
	if err != nil || in.Version != "v0.0.0-20260101000000-abcdefabcdef" {
		t.Fatalf("query: %+v, %v", in, err)
	}
	e.px.set("/example.com/m/@v/v1.3.0.info", "application/json", `{"Version":"v1.3.0","Time":"yesterday"}`)
	if _, err := e.src.Info(ctx, "example.com/m", "v1.3.0"); err == nil {
		t.Fatal("bad time accepted")
	}
	e.px.set("/example.com/m/@latest", "application/json", `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`)
	if in, err := e.src.Latest(ctx, "example.com/m"); err != nil || in.Version != "v1.0.0" {
		t.Fatalf("latest: %+v, %v", in, err)
	}
}

func TestRegistryCanonicalInfoImmutable(t *testing.T) {
	e := newRegEnv(t)
	p := "/example.com/m/@v/v1.0.0.info"
	e.px.set(p, "application/json", `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`)
	if _, err := e.src.Info(context.Background(), "example.com/m", "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	e.clock = e.clock.Add(24 * time.Hour)
	if _, err := e.src.Info(context.Background(), "example.com/m", "v1.0.0"); err != nil || e.px.count(p) != 1 {
		t.Fatalf("hits %d, %v", e.px.count(p), err)
	}
}

func TestRegistryCanonicalInfoMissThenPublished(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	p := "/example.com/m/@v/v1.0.0.info"
	if _, err := e.src.Info(ctx, "example.com/m", "v1.0.0"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	e.px.set(p, "application/json", `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`)
	e.clock = e.clock.Add(2 * time.Minute)
	if in, err := e.src.Info(ctx, "example.com/m", "v1.0.0"); err != nil || in.Version != "v1.0.0" {
		t.Fatalf("got %+v, %v", in, err)
	}
	if n := e.px.count(p); n != 2 {
		t.Fatalf("%d requests, want 2", n)
	}
}

func TestRegistryExpiredMissRefreshFailureIsNotAMiss(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	if _, err := e.src.List(ctx, "example.com/m"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	e.px.setDown(true)
	e.clock = e.clock.Add(2 * time.Minute)
	if _, err := e.src.List(ctx, "example.com/m"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("expired marker, upstream down: got %v", err)
	}
	// An unexpired marker is still a miss.
	e.px.setDown(false)
	if _, err := e.src.List(ctx, "example.com/m"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	e.clock = time.Now() // the cache stamps writes with the wall clock
	e.px.setDown(true)
	if _, err := e.src.List(ctx, "example.com/m"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("unexpired marker: got %v", err)
	}
}

func TestRegistryQueryInfoMustBeCanonical(t *testing.T) {
	e := newRegEnv(t)
	for _, v := range []string{"v1.0", "1.0.0", "v1.0.0+meta"} {
		e.px.set("/example.com/m/@v/main.info", "application/json", `{"Version":"`+v+`","Time":"2026-01-02T03:04:05Z"}`)
		if _, err := e.src.Info(context.Background(), "example.com/m", "main"); err == nil {
			t.Fatalf("%q accepted", v)
		}
	}
}

func TestRegistry410IsNotFound(t *testing.T) {
	for _, status := range []int{http.StatusGone, http.StatusNotFound} {
		e := newRegEnv(t)
		p := "/example.com/m/@v/list"
		e.px.mu.Lock()
		e.px.pages[p] = fakePage{status: status, ctype: textCT, body: "gone"}
		e.px.mu.Unlock()
		for range 2 {
			if _, err := e.src.List(context.Background(), "example.com/m"); !errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("%d: got %v", status, err)
			}
		}
		if n := e.px.count(p); n != 1 {
			t.Fatalf("%d: %d requests, want 1", status, n)
		}
		e.clock = e.clock.Add(2 * time.Minute)
		e.src.List(context.Background(), "example.com/m")
		if n := e.px.count(p); n != 2 {
			t.Fatalf("%d: %d requests after TTL, want 2", status, n)
		}
	}
}

func TestRegistryStaleOnUpstreamDown(t *testing.T) {
	e := newRegEnv(t)
	e.px.set("/example.com/m/@v/list", textCT, "v1.0.0\n")
	if _, err := e.src.List(context.Background(), "example.com/m"); err != nil {
		t.Fatal(err)
	}
	e.px.setDown(true)
	e.clock = e.clock.Add(2 * time.Minute)
	got, err := e.src.List(context.Background(), "example.com/m")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %q, %v", got, err)
	}
	if h := e.src.Health(context.Background()); h[0].OK || h[0].Detail != "serving stale" {
		t.Fatalf("health %+v", h)
	}
	if _, err := e.src.List(context.Background(), "example.com/other"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("uncached: %v", err)
	}
}

func TestRegistryTooLarge(t *testing.T) {
	e := newRegEnv(t)
	e.px.set("/example.com/m/@v/v1.0.0.info", "application/json", `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z","X":"`+strings.Repeat("a", 65<<10)+`"}`)
	if _, err := e.src.Info(context.Background(), "example.com/m", "v1.0.0"); !errors.Is(err, upstream.ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestRegistryURLsEscaped(t *testing.T) {
	e := newRegEnv(t)
	e.px.set("/github.com/!acme/x/@v/list", textCT, "v1.0.0\n")
	e.px.set("/github.com/!acme/x/@v/v1.0.0-!r!c1.info", "application/json", `{"Version":"v1.0.0-RC1","Time":"2026-01-02T03:04:05Z"}`)
	got, err := e.src.List(context.Background(), "github.com/Acme/x")
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %q, %v", got, err)
	}
	if in, err := e.src.Info(context.Background(), "github.com/Acme/x", "v1.0.0-RC1"); err != nil || in.Version != "v1.0.0-RC1" {
		t.Fatalf("info: %+v, %v", in, err)
	}
}

func TestRegistryModZipUnavailable(t *testing.T) {
	e := newRegEnv(t)
	if _, err := e.src.Mod(context.Background(), "example.com/m", "v1.0.0"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := e.src.Zip(context.Background(), "example.com/m", "v1.0.0"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func mustSeg(s string) string { e, _ := seg(s); return e }

func FuzzRegistryList(f *testing.F) {
	for _, s := range []string{"v1.0.0\n", "<html>", "v1.0.0 x\r\nv2.0.0\n", "\xff", "v0.0.0-20260101000000-abcdefabcdef\n", "example.com/m v1.0.0"} {
		f.Add(s)
	}
	e := &RegistrySource{name: "p", log: slog.New(slog.DiscardHandler)}
	f.Fuzz(func(t *testing.T, body string) {
		out, err := e.cleanList("example.com/m", []byte(body))
		if err != nil {
			return
		}
		for line := range strings.SplitSeq(strings.TrimSuffix(string(out), "\n"), "\n") {
			if line == "" {
				continue
			}
			if module.Check("example.com/m", line) != nil || module.IsPseudoVersion(line) {
				t.Fatalf("served %q", line)
			}
		}
	})
}

func FuzzRegistryInfo(f *testing.F) {
	for _, s := range []string{`{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`, `{}`, `[]`, `{"Version":"v1.0.0","Time":"x","Origin":1}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		out, err := cleanInfo("example.com/m", "", []byte(body))
		if err != nil {
			return
		}
		if _, err := cleanInfo("example.com/m", "", out); err != nil {
			t.Fatalf("served %q does not re-validate: %v", out, err)
		}
		var in Info
		if json.Unmarshal(out, &in) != nil {
			t.Fatalf("served %q does not decode", out)
		}
		if out2, err := cleanInfo("example.com/m", in.Version, out); err != nil || string(out2) != string(out) {
			t.Fatalf("served %q with want %q: %q, %v", out, in.Version, out2, err)
		}
		if _, err := cleanInfo("example.com/m", "v9.9.9", out); err == nil && in.Version != "v9.9.9" {
			t.Fatalf("want mismatch accepted: %q", out)
		}
	})
}
