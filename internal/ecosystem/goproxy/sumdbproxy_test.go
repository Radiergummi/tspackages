package goproxy

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/storage"
)

// proxyEnv is a sumdb proxy over an offline database, with an unclaimed
// registry source followed by a git fake claiming github.com/acme/*.
type proxyEnv struct {
	sum   *sumEnv
	proxy SumDB
	srcs  []Source
}

func newProxyEnv(t testing.TB) *proxyEnv {
	t.Helper()
	sum := newSumEnv(t)
	reg := NewRegistrySource(RegistryOptions{Name: "proxy", BaseURL: "http://127.0.0.1:1"})
	git := &fakeSource{name: "git", claims: []string{"github.com/acme/*"}}
	srcs := []Source{reg, git}
	return &proxyEnv{sum: sum, srcs: srcs, proxy: NewSumDBProxy(sum.verifier(), srcs, gitPrivate(srcs), slog.New(slog.DiscardHandler))}
}

// gitPrivate reports whether a fake (git) source among srcs claims a path.
func gitPrivate(srcs []Source) func(string) bool {
	return func(p string) bool {
		for _, s := range srcs {
			if _, ok := s.(*fakeSource); !ok {
				continue
			}
			for _, c := range s.Claims() {
				if Match(c, p) {
					return true
				}
			}
		}
		return false
	}
}

func (e *proxyEnv) handler(t *testing.T, rules ...string) http.Handler {
	t.Helper()
	return server(t, e.srcs, e.proxy, rules...)
}

func TestSupported(t *testing.T) {
	e := newProxyEnv(t)
	w := do(e.handler(t, `{"read":["go:github.com/other/*"]}`), "GET", "/go/sumdb/sum.golang.org/supported")
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("rule holder: %d %q", w.Code, w.Body)
	}
	if w := do(e.handler(t), "GET", "/go/sumdb/sum.golang.org/supported"); w.Code != 403 {
		t.Fatalf("no rule: %d", w.Code)
	}
	if n := e.sum.db.total("/"); n != 0 {
		t.Fatalf("%d database requests", n)
	}
}

// Review Focus 4: a lookup for a path any git source claims never leaves the
// node, even when an unclaimed registry source comes first.
func TestLookupPrivatePathNeverForwarded(t *testing.T) {
	e := newProxyEnv(t)
	// The same path claimed by the git source and a later registry source.
	claimedReg := NewRegistrySource(RegistryOptions{Name: "claimed", Claims: []string{"github.com/acme/*"}, BaseURL: "http://127.0.0.1:1"})
	e.srcs = append(e.srcs, claimedReg)
	e.proxy = NewSumDBProxy(e.sum.verifier(), e.srcs, gitPrivate(e.srcs), slog.New(slog.DiscardHandler))
	h := e.handler(t, readAll)
	for _, p := range []string{"github.com/acme/x", "github.com/Acme/x"} {
		esc, _ := module.EscapePath(p)
		w := do(h, "GET", "/go/sumdb/sum.golang.org/lookup/"+esc+"@v1.0.0")
		want := p + " is private: add it to GONOSUMDB"
		if w.Code != 404 || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %q", p, w.Code, w.Body)
		}
	}
	if n := e.sum.db.total("/"); n != 0 {
		t.Fatalf("%d database requests", n)
	}
}

func TestLookupServesRawRecord(t *testing.T) {
	e := newProxyEnv(t)
	h := e.handler(t, readAll)
	const p = "/go/sumdb/sum.golang.org" + lookupM
	w := do(h, "GET", p)
	want := e.sum.db.served(lookupM)
	if w.Code != 200 || len(want) == 0 || !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatalf("%d %q, want %q", w.Code, w.Body, want)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("content type %q", ct)
	}
	n := e.sum.db.count(lookupM)
	again := do(h, "GET", p)
	if again.Code != 200 || !bytes.Equal(again.Body.Bytes(), want) || e.sum.db.count(lookupM) != n {
		t.Fatalf("repeat: %d %q, %d requests", again.Code, again.Body, e.sum.db.count(lookupM))
	}
	// A version the database does not know is a 404.
	if w := do(h, "GET", "/go/sumdb/sum.golang.org/lookup/example.com/m@v9.0.0"); w.Code != 404 {
		t.Fatalf("unknown version: %d", w.Code)
	}
	// A database failure is a 502.
	e.sum.db.set(e.sum.db.fail, "/lookup/example.com/m@v1.1.0", http.StatusInternalServerError)
	if w := do(h, "GET", "/go/sumdb/sum.golang.org/lookup/example.com/m@v1.1.0"); w.Code != 502 {
		t.Fatalf("database failure: %d", w.Code)
	}
}

func TestLookupNeedsRegistrySource(t *testing.T) {
	e := newProxyEnv(t)
	// Only a non-registry source resolves the path: nothing is forwarded.
	other := &fakeSource{name: "other", claims: []string{"example.com/*"}}
	e.srcs = append([]Source{other}, e.srcs...)
	e.proxy = NewSumDBProxy(e.sum.verifier(), e.srcs, func(string) bool { return false }, slog.New(slog.DiscardHandler))
	if w := do(e.handler(t, readAll), "GET", "/go/sumdb/sum.golang.org"+lookupM); w.Code != 404 {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
	if n := e.sum.db.total("/"); n != 0 {
		t.Fatalf("%d database requests", n)
	}
}

// A proxy built without a private predicate treats every path as private.
func TestLookupNilPrivateFailsClosed(t *testing.T) {
	e := newProxyEnv(t)
	e.proxy = NewSumDBProxy(e.sum.verifier(), e.srcs, nil, slog.New(slog.DiscardHandler))
	w := do(e.handler(t, readAll), "GET", "/go/sumdb/sum.golang.org"+lookupM)
	if w.Code != 404 || !strings.Contains(w.Body.String(), "example.com/m is private") {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
	if n := e.sum.db.total("/"); n != 0 {
		t.Fatalf("%d database requests", n)
	}
}

func TestLookupForbidden(t *testing.T) {
	e := newProxyEnv(t)
	// Straight to the proxy, past the handler's own check.
	caller := identity.Caller{Login: "x", Rules: []authz.Rule{{Read: []string{"go:github.com/other/*"}}}}
	w := httptest.NewRecorder()
	e.proxy.ServeSumDB(w, httptest.NewRequest("GET", "/", nil), caller, "sum.golang.org"+lookupM)
	if w.Code != 403 {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
	if n := e.sum.db.total("/"); n != 0 {
		t.Fatalf("%d database requests", n)
	}
}

func TestLookupBadEscape404(t *testing.T) {
	e := newProxyEnv(t)
	caller := identity.Caller{Login: "x", Rules: []authz.Rule{{Read: []string{"*"}}}}
	for _, rest := range []string{
		"sum.golang.org/lookup/example.com/M@v1.0.0",
		"sum.golang.org/lookup/example.com/m@V1.0.0",
		"sum.golang.org/lookup/example.com/m",
		"sum.golang.org/lookup/example.com/m@v1.0.0/go.mod",
		"sum.golang.org/lookup/example.com/m@v1.0",
	} {
		w := httptest.NewRecorder()
		e.proxy.ServeSumDB(w, httptest.NewRequest("GET", "/", nil), caller, rest)
		if w.Code != 404 {
			t.Errorf("%s: %d", rest, w.Code)
		}
	}
	if n := e.sum.db.total("/"); n != 0 {
		t.Fatalf("%d database requests", n)
	}
}

func TestTileValidated(t *testing.T) {
	e := newProxyEnv(t)
	h := e.handler(t, `{"read":["go:github.com/other/*"]}`)
	if w := do(h, "GET", "/go/sumdb/sum.golang.org/tile/x/0/000"); w.Code != 404 {
		t.Fatalf("bad path: %d", w.Code)
	}
	if w := do(h, "GET", "/go/sumdb/sum.golang.org/tile/8/0/x"); w.Code != 404 {
		t.Fatalf("bad path: %d", w.Code)
	}
	// Grow the tree so tile 8/0/000.p/1 exists, without the verifier.
	resp, err := http.Get(e.sum.db.srv.URL + lookupM)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	const good = "tile/8/0/000.p/1"
	w := do(h, "GET", "/go/sumdb/sum.golang.org/"+good)
	if w.Code != 200 || w.Body.Len() != tlog.HashSize {
		t.Fatalf("hash tile: %d, %d bytes", w.Code, w.Body.Len())
	}
	if !e.cached(t, "go-sumdb-proxy/"+mustSeg(good)) {
		t.Fatal("tile not cached under go-sumdb-proxy/")
	}
	if e.cached(t, "go-sumdb/"+mustSeg(SumDBName+"/"+good)) {
		t.Fatal("pass-through wrote a verifier key")
	}
	e.sum.db.mu.Lock()
	e.sum.db.body["/tile/8/0/000.p/2"] = []byte("short")
	e.sum.db.body["/tile/8/data/000.p/2"] = []byte("data")
	e.sum.db.mu.Unlock()
	if w := do(h, "GET", "/go/sumdb/sum.golang.org/tile/8/0/000.p/2"); w.Code != 502 {
		t.Fatalf("short hash tile: %d", w.Code)
	}
	if e.cached(t, "go-sumdb-proxy/"+mustSeg("tile/8/0/000.p/2")) {
		t.Fatal("short hash tile cached")
	}
	if w := do(h, "GET", "/go/sumdb/sum.golang.org/tile/8/data/000.p/2"); w.Code != 200 || w.Body.String() != "data" {
		t.Fatalf("data tile: %d %q", w.Code, w.Body)
	}
}

func (e *proxyEnv) cached(t testing.TB, key string) bool {
	t.Helper()
	rc, _, err := e.sum.cache.Get(context.Background(), key)
	if errors.Is(err, storage.ErrNotFound) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	return true
}

func TestOtherDatabase404(t *testing.T) {
	e := newProxyEnv(t)
	h := e.handler(t, readAll)
	for _, p := range []string{
		"/go/sumdb/sum.example.org/supported",
		"/go/sumdb/sum.example.org/lookup/example.com/m@v1.0.0",
		"/go/sumdb/sum.golang.org/latest",
		"/go/sumdb/sum.golang.org/",
		"/go/sumdb/sum.golang.org/supported/x",
	} {
		if w := do(h, "GET", p); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if n := e.sum.db.total("/"); n != 0 {
		t.Fatalf("%d database requests", n)
	}
}

// sumdbPathValid reports whether rest names something the proxy may answer
// from the database: supported, a decodable lookup or a tile.
func sumdbPathValid(rest string) bool {
	sub, ok := strings.CutPrefix(rest, SumDBName+"/")
	if !ok {
		return false
	}
	if sub == "supported" {
		return true
	}
	if l, ok := strings.CutPrefix(sub, "lookup/"); ok {
		ep, ev, ok := strings.Cut(l, "@")
		if !ok {
			return false
		}
		_, perr := module.UnescapePath(ep)
		_, verr := module.UnescapeVersion(ev)
		return perr == nil && verr == nil
	}
	_, err := tlog.ParseTilePath(sub)
	return err == nil
}

func FuzzSumDBPath(f *testing.F) {
	for _, s := range []string{
		"sum.golang.org/supported", "sum.golang.org/lookup/example.com/m@v1.0.0",
		"sum.golang.org/lookup/github.com/!acme/x@v1.0.0", "sum.golang.org/tile/8/0/000",
		"sum.golang.org/tile/8/data/000.p/2", "sum.golang.org/tile/../x", "sum.example.org/supported",
		"sum.golang.org/lookup/a@b@c", "", "sum.golang.org", "sum.golang.org/lookup/",
	} {
		f.Add(s)
	}
	e := newProxyEnv(f)
	caller := identity.Caller{Login: "x", Rules: []authz.Rule{{Read: []string{"*"}}}}
	f.Fuzz(func(t *testing.T, rest string) {
		before := e.sum.db.total("/")
		w := httptest.NewRecorder()
		e.proxy.ServeSumDB(w, httptest.NewRequest("GET", "/", nil), caller, rest)
		if !sumdbPathValid(rest) {
			if w.Code != 404 {
				t.Fatalf("%q: %d", rest, w.Code)
			}
			if n := e.sum.db.total("/"); n != before {
				t.Fatalf("%q: %d database requests", rest, n-before)
			}
		}
	})
}
