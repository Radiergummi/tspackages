package composer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/testutil"
	"tailscale.com/tailcfg/peercap"
)

const hCap peercap.Cap = "github.com/radiergummi/tspackages"

type fakeSource struct {
	name    string
	claims  []string
	pkgs    map[string][]Version
	err     error
	calls   atomic.Int32
	distHit atomic.Int32
}

func (f *fakeSource) Name() string     { return f.name }
func (f *fakeSource) Claims() []string { return f.claims }
func (f *fakeSource) Versions(_ context.Context, name string, dev bool) ([]Version, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	vs, ok := f.pkgs[name]
	if !ok {
		return nil, resolve.ErrNotFound
	}
	out := []Version{}
	for _, v := range vs {
		if v.Dev == dev {
			out = append(out, v)
		}
	}
	return out, nil
}
func (f *fakeSource) Dist(_ context.Context, name, version, reference string) (Artifact, error) {
	f.calls.Add(1)
	f.distHit.Add(1)
	if f.err != nil {
		return Artifact{}, f.err
	}
	return Artifact{Body: io.NopCloser(strings.NewReader("ZIP:" + version + ":" + reference)), Size: int64(len("ZIP:" + version + ":" + reference))}, nil
}

// shared is deliberately reused by every version, as real sources may.
var shared = map[string]any{"type": "zip", "shasum": "abc"}

func ver(name, v string, dev bool) Version {
	return Version{
		Version: v, Reference: "ref-" + v, Dev: dev,
		Package: map[string]any{"name": name, "version": v, "dist": shared},
	}
}

const readAll = `{"read":["*"]}`

func server(t *testing.T, srcs []Source, rules ...string) http.Handler {
	t.Helper()
	return serverLog(t, slog.New(slog.DiscardHandler), srcs, rules...)
}

func serverLog(t *testing.T, log *slog.Logger, srcs []Source, rules ...string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	New(srcs, archive.Limits{MaxBytes: 1 << 20, MaxDecompressed: 16 << 20, MaxEntries: 1000}, log).Mount(mux)
	return identity.Middleware(testutil.Who{Cap: hCap, Rules: rules}, hCap, nil)(mux)
}

func do(h http.Handler, method, path string, body io.Reader, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, body)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func gitAndReg() (*fakeSource, *fakeSource) {
	g := &fakeSource{name: "git-fake", claims: []string{"matchory/*"},
		pkgs: map[string][]Version{"matchory/a": {ver("matchory/a", "1.0.0", false), ver("matchory/a", "dev-main", true)}}}
	r := &fakeSource{name: "registry-fake",
		pkgs: map[string][]Version{"matchory/a": {ver("matchory/a", "9.9.9", false)}, "monolog/monolog": {ver("monolog/monolog", "3.0.0", false)}}}
	return g, r
}

type p2Resp struct {
	Packages map[string][]map[string]any `json:"packages"`
}

func TestP2RoutesClaimedToClaimingSource(t *testing.T) {
	g, r := gitAndReg()
	w := do(server(t, []Source{g, r}, readAll), "GET", "/composer/p2/matchory/a.json", nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var resp p2Resp
	json.Unmarshal(w.Body.Bytes(), &resp)
	if vs := resp.Packages["matchory/a"]; len(vs) != 1 || vs[0]["version"] != "1.0.0" {
		t.Fatalf("%v", resp)
	}
	if r.calls.Load() != 0 {
		t.Fatal("unclaimed source was asked")
	}
}

func TestP2ClaimedNotFoundNoFallThrough(t *testing.T) {
	g, r := gitAndReg()
	w := do(server(t, []Source{g, r}, readAll), "GET", "/composer/p2/matchory/missing.json", nil)
	if w.Code != 404 || r.calls.Load() != 0 {
		t.Fatalf("%d, registry calls %d", w.Code, r.calls.Load())
	}
}

func TestP2UnclaimedFallsToRegistry(t *testing.T) {
	g, r := gitAndReg()
	w := do(server(t, []Source{g, r}, readAll), "GET", "/composer/p2/monolog/monolog.json", nil)
	if w.Code != 200 || r.calls.Load() != 1 {
		t.Fatalf("%d", w.Code)
	}
}

func TestP2MixedCase(t *testing.T) {
	g, r := gitAndReg()
	w := do(server(t, []Source{g, r}, readAll), "GET", "/composer/p2/Matchory/A.json", nil)
	if w.Code != 200 || g.calls.Load() != 1 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestP2SourceErrorIs502(t *testing.T) {
	g, r := gitAndReg()
	h := server(t, []Source{g, r}, readAll)
	g.err = errors.New("boom https://secret.internal/x")
	w := do(h, "GET", "/composer/p2/matchory/a.json", nil)
	if w.Code != 502 || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	g.err = context.DeadlineExceeded
	if w := do(h, "GET", "/composer/p2/matchory/a.json", nil); w.Code != 504 {
		t.Fatalf("%d", w.Code)
	}
	g.err = ErrUnavailable
	if w := do(h, "GET", "/composer/p2/matchory/a.json", nil); w.Code != 502 {
		t.Fatalf("%d", w.Code)
	}
	if r.calls.Load() != 0 {
		t.Fatal("fell through on error")
	}
}

func TestP2Forbidden(t *testing.T) {
	g, r := gitAndReg()
	w := do(server(t, []Source{g, r}, `{"read":["composer:other/*"]}`), "GET", "/composer/p2/matchory/a.json", nil)
	if w.Code != 403 || g.calls.Load() != 0 {
		t.Fatalf("%d", w.Code)
	}
}

func TestP2InvalidName(t *testing.T) {
	g, r := gitAndReg()
	h := server(t, []Source{g, r}, readAll)
	for _, p := range []string{"/composer/p2/matchory/a", "/composer/p2/ma%20tchory/a.json", "/composer/p2/matchory/.json"} {
		if w := do(h, "GET", p, nil); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}

func TestP2DevSplit(t *testing.T) {
	g, r := gitAndReg()
	h := server(t, []Source{g, r}, readAll)
	w := do(h, "GET", "/composer/p2/matchory/a~dev.json", nil)
	var resp p2Resp
	json.Unmarshal(w.Body.Bytes(), &resp)
	if vs := resp.Packages["matchory/a"]; len(vs) != 1 || vs[0]["version"] != "dev-main" {
		t.Fatalf("%s", w.Body)
	}
	g.pkgs["matchory/b"] = []Version{ver("matchory/b", "1.0.0", false)}
	w = do(h, "GET", "/composer/p2/matchory/b~dev.json", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"matchory/b":[]`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestDistURLsAreLocal(t *testing.T) {
	g, r := gitAndReg()
	h := server(t, []Source{g, r}, readAll)
	req := httptest.NewRequest("GET", "/composer/p2/matchory/a.json", nil)
	req.Host = "pkgs.tail.ts.net"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var resp p2Resp
	json.Unmarshal(w.Body.Bytes(), &resp)
	for _, v := range resp.Packages["matchory/a"] {
		u := v["dist"].(map[string]any)["url"].(string)
		if u != "http://pkgs.tail.ts.net/composer/dist/git-fake/matchory/a/1.0.0/ref-1.0.0" {
			t.Fatalf("url %q", u)
		}
		if v["dist"].(map[string]any)["shasum"] != "abc" {
			t.Fatal("shasum lost")
		}
	}
	if _, has := shared["url"]; has {
		t.Fatal("shared source map was mutated")
	}
	// TLS request gets https.
	req = httptest.NewRequest("GET", "https://pkgs.tail.ts.net/composer/p2/matchory/a.json", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `"url":"https://pkgs.tail.ts.net/composer/dist/`) {
		t.Fatalf("%s", w.Body)
	}
}

func TestDistStreams(t *testing.T) {
	g, r := gitAndReg()
	h := server(t, []Source{g, r}, readAll)
	w := do(h, "GET", "/composer/dist/git-fake/matchory/a/dev-feature%2Fx/ref", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" || w.Body.String() != "ZIP:dev-feature/x:ref" {
		t.Fatalf("%d %q %v", w.Code, w.Body, w.Header())
	}
	if w.Header().Get("Content-Length") == "" {
		t.Fatal("no length")
	}
	// Unclaimed name via the registry source.
	if w := do(h, "GET", "/composer/dist/registry-fake/monolog/monolog/3.0.0/r", nil); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
}

func TestDistWrongSourceForClaimedName(t *testing.T) {
	g, r := gitAndReg()
	h := server(t, []Source{g, r}, readAll)
	w := do(h, "GET", "/composer/dist/registry-fake/matchory/a/9.9.9/ref-9.9.9", nil)
	if w.Code != 404 || r.distHit.Load() != 0 {
		t.Fatalf("%d", w.Code)
	}
	if w := do(h, "GET", "/composer/dist/nosuch/matchory/a/1/r", nil); w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
}

// With two claiming sources, p2 answers from the first that knows the name,
// so dist must not serve the same name from a later one.
func TestDistOnlyFromTheResolvingSource(t *testing.T) {
	first := &fakeSource{name: "first", claims: []string{"acme/*"},
		pkgs: map[string][]Version{"acme/a": {ver("acme/a", "1.0.0", false)}}}
	second := &fakeSource{name: "second", claims: []string{"acme/*"},
		pkgs: map[string][]Version{"acme/a": {ver("acme/a", "1.0.0", false)}, "acme/b": {ver("acme/b", "1.0.0", false)}}}
	h := server(t, []Source{first, second}, readAll)

	if w := do(h, "GET", "/composer/dist/second/acme/a/1.0.0/ref-1.0.0", nil); w.Code != 404 || second.distHit.Load() != 0 {
		t.Fatalf("shadowed source: %d, dist calls %d", w.Code, second.distHit.Load())
	}
	if w := do(h, "GET", "/composer/dist/second/acme/b/1.0.0/ref-1.0.0", nil); w.Code != 200 {
		t.Fatalf("first source does not know acme/b: %d", w.Code)
	}
	if w := do(h, "GET", "/composer/dist/first/acme/a/1.0.0/ref-1.0.0", nil); w.Code != 200 {
		t.Fatalf("resolving source: %d", w.Code)
	}
	for _, err := range []error{errors.New("boom"), errors.Join(resolve.ErrNotFound, errors.New("boom"))} {
		first.err = err
		if w := do(h, "GET", "/composer/dist/second/acme/b/1.0.0/ref-1.0.0", nil); w.Code != 502 {
			t.Fatalf("earlier source failing with %v: %d", err, w.Code)
		}
	}
}

func TestDistForbiddenAndError(t *testing.T) {
	g, r := gitAndReg()
	if w := do(server(t, []Source{g, r}, `{"read":["composer:x/*"]}`), "GET", "/composer/dist/git-fake/matchory/a/1/r", nil); w.Code != 403 || g.distHit.Load() != 0 {
		t.Fatalf("%d", w.Code)
	}
	g.err = ErrUnavailable
	if w := do(server(t, []Source{g, r}, readAll), "GET", "/composer/dist/git-fake/matchory/a/1/r", nil); w.Code != 502 {
		t.Fatalf("%d", w.Code)
	}
}

func TestUploadFlow(t *testing.T) {
	store, _ := newSource(t)
	g, r := gitAndReg()
	srcs := []Source{g, store, r}
	zipData := pkgZip(t, fooJSON)
	put := func(h http.Handler, hdr ...string) *httptest.ResponseRecorder {
		return do(h, "PUT", "/composer/upload/Matchory-Internal/foo/1.0.0", bytes.NewReader(zipData), hdr...)
	}

	h := server(t, srcs, `{"write":["composer:matchory-internal/*"]}`)
	w := put(h)
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var pkg map[string]any
	json.Unmarshal(w.Body.Bytes(), &pkg)
	u, _ := pkg["dist"].(map[string]any)["url"].(string)
	if pkg["version"] != "1.0.0" || !strings.HasPrefix(u, "http://example.com/composer/dist/internal/matchory-internal/foo/1.0.0/") {
		t.Fatalf("%s", w.Body)
	}
	if w := put(h); w.Code != 409 {
		t.Fatalf("repeat: %d", w.Code)
	}
	if w := put(server(t, srcs, `{"read":["*"]}`)); w.Code != 403 {
		t.Fatalf("read-only: %d", w.Code)
	}
	if w := do(h, "PUT", "/composer/upload/matchory-internal/foo/2.0.0", bytes.NewReader(make([]byte, 2<<20))); w.Code != 413 {
		t.Fatalf("oversize: %d", w.Code)
	}
	if w := do(h, "PUT", "/composer/upload/matchory-internal/foo/2.0.0", strings.NewReader("not a zip")); w.Code != 400 {
		t.Fatalf("bad zip: %d %s", w.Code, w.Body)
	}
	// Unclaimed names have no storage source.
	h2 := server(t, srcs, `{"write":["*"]}`)
	w = do(h2, "PUT", "/composer/upload/other/pkg/1.0.0", bytes.NewReader(zipData))
	if w.Code != 403 || !strings.Contains(w.Body.String(), `no storage source claims "other/pkg"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// Claimed by git only: still no storage source.
	if w := do(h2, "PUT", "/composer/upload/matchory/a/1.0.0", bytes.NewReader(zipData)); w.Code != 403 {
		t.Fatalf("%d", w.Code)
	}
}

func TestNoCallerIs403(t *testing.T) {
	g, _ := gitAndReg()
	mux := http.NewServeMux()
	New([]Source{g}, archive.Limits{MaxBytes: 1}, nil).Mount(mux)
	if w := do(mux, "GET", "/composer/p2/matchory/a.json", nil); w.Code != 403 || g.calls.Load() != 0 {
		t.Fatalf("%d", w.Code)
	}
}

func TestPackagesJSONAvailablePackagePatterns(t *testing.T) {
	store, _ := newSource(t)
	g := &fakeSource{name: "git-fake", claims: []string{"matchory/*", "acme/x"}}
	reg := &fakeSource{name: "reg-fake", claims: []string{"acme/x", "vendor/*"}}
	get := func(srcs []Source, rules ...string) (int, map[string]any) {
		w := do(server(t, srcs, rules...), "GET", "/composer/packages.json", nil)
		var m map[string]any
		json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	// A caller who may read one pattern still sees every pattern.
	code, m := get([]Source{g, reg, store}, `{"read":["composer:vendor/*"]}`)
	got, _ := json.Marshal(m["available-package-patterns"])
	if code != 200 || string(got) != `["acme/x","matchory-internal/*","matchory/*","vendor/*"]` {
		t.Fatalf("%d %s", code, got)
	}
	if _, has := m["available-packages"]; has {
		t.Fatal("old key present")
	}
	if m["metadata-url"] != "/composer/p2/%package%.json" {
		t.Fatalf("%v", m)
	}
	// Any unclaimed source: key absent.
	_, m = get([]Source{g, &fakeSource{name: "pub"}}, readAll)
	if _, has := m["available-package-patterns"]; has {
		t.Fatalf("%v", m)
	}
	// A claim of "*" covers everything: key absent.
	_, m = get([]Source{g, &fakeSource{name: "all", claims: []string{"*"}}}, readAll)
	if _, has := m["available-package-patterns"]; has {
		t.Fatalf("%v", m)
	}
	// No composer rule at all.
	if code, _ := get([]Source{g}, `{"read":["npm:*"]}`); code != 403 {
		t.Fatalf("%d", code)
	}
	if code, _ := get([]Source{g}); code != 403 {
		t.Fatalf("%d", code)
	}
	if g.calls.Load() != 0 {
		t.Fatal("packages.json enumerated sources")
	}
}

type logLine map[string]any

func captured(buf *bytes.Buffer) []logLine {
	var out []logLine
	for l := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var m logLine
		if json.Unmarshal([]byte(l), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func TestLogLevels(t *testing.T) {
	g, r := gitAndReg()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := serverLog(t, log, []Source{g, r}, `{"read":["composer:monolog/*"]}`)
	do(h, "GET", "/composer/p2/matchory/a.json", nil)           // claimed, forbidden
	do(h, "GET", "/composer/dist/git-fake/matchory/a/1/r", nil) // claimed, forbidden
	do(h, "GET", "/composer/p2/monolog/monolog.json", nil)      // unclaimed
	ls := captured(&buf)
	if len(ls) != 3 {
		t.Fatalf("%v", ls)
	}
	for i, want := range []struct {
		level  string
		status float64
	}{{"INFO", 403}, {"INFO", 403}, {"DEBUG", 200}} {
		if ls[i]["level"] != want.level || ls[i]["status"] != want.status || ls[i]["caller"] != "tag:ci" {
			t.Errorf("line %d: %v", i, ls[i])
		}
	}

	buf.Reset()
	mux := http.NewServeMux()
	New([]Source{g}, archive.Limits{MaxBytes: 1}, log).Mount(mux)
	do(mux, "GET", "/composer/p2/matchory/a.json", nil)
	ls = captured(&buf)
	if len(ls) != 1 || ls[0]["level"] != "WARN" {
		t.Fatalf("%v", ls)
	}
}

func TestResponseHeaders(t *testing.T) {
	store, _ := newSource(t)
	g, r := gitAndReg()
	h := server(t, []Source{g, r, store}, `{"read":["*"],"write":["*"]}`)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"packages": do(h, "GET", "/composer/packages.json", nil),
		"p2":       do(h, "GET", "/composer/p2/matchory/a.json", nil),
		"dist":     do(h, "GET", "/composer/dist/git-fake/matchory/a/1/r", nil),
		"upload":   do(h, "PUT", "/composer/upload/matchory-internal/foo/1.0.0", bytes.NewReader(pkgZip(t, fooJSON))),
		"p2-404":   do(h, "GET", "/composer/p2/matchory/zzz.json", nil),
	} {
		hd := w.Header()
		if hd.Get("Cache-Control") != "private, no-store" || hd.Get("Vary") != "Host" || hd.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: %v", name, hd)
		}
	}
}

func TestDistURLOnlyWhenReferenceKnown(t *testing.T) {
	g, r := gitAndReg()
	g.pkgs["matchory/n"] = []Version{
		{Version: "1.0.0", Package: map[string]any{"name": "matchory/n", "version": "1.0.0"}},
		{Version: "2.0.0", Reference: "", Package: map[string]any{"name": "matchory/n", "dist": map[string]any{"url": "https://upstream.example/z", "type": "zip"}}},
	}
	w := do(server(t, []Source{g, r}, readAll), "GET", "/composer/p2/matchory/n.json", nil)
	var resp p2Resp
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Packages["matchory/n"]) != 2 {
		t.Fatalf("%s", w.Body)
	}
	for _, v := range resp.Packages["matchory/n"] {
		if _, has := v["dist"]; has {
			t.Fatalf("dist invented or upstream url leaked: %v", v)
		}
	}
}

func TestDistHeadIs405(t *testing.T) {
	g, r := gitAndReg()
	w := do(server(t, []Source{g, r}, readAll), "HEAD", "/composer/dist/git-fake/matchory/a/1/r", nil)
	if w.Code != 405 || g.distHit.Load() != 0 {
		t.Fatalf("%d", w.Code)
	}
}

type failBody struct{ n int }

func (f *failBody) Read(p []byte) (int, error) {
	if f.n > 0 {
		return 0, errors.New("disk exploded")
	}
	f.n++
	return copy(p, "abc"), nil
}

type brokenDist struct{ fakeSource }

func (b *brokenDist) Dist(context.Context, string, string, string) (Artifact, error) {
	return Artifact{Body: io.NopCloser(&failBody{}), Size: 100}, nil
}

func TestDistCopyErrorLogged(t *testing.T) {
	b := &brokenDist{fakeSource{name: "b", claims: []string{"matchory/*"}}}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	do(serverLog(t, log, []Source{b}, readAll), "GET", "/composer/dist/b/matchory/a/1/r", nil)
	found := false
	for _, l := range captured(&buf) {
		if l["level"] == "WARN" && strings.Contains(l["error"].(string), "disk exploded") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no warn: %s", buf.String())
	}
}

func TestSourceKeyRemoved(t *testing.T) {
	g, r := gitAndReg()
	v := ver("monolog/monolog", "3.0.0", false)
	v.Package = map[string]any{"name": "monolog/monolog", "version": "3.0.0", "dist": map[string]any{"type": "zip"},
		"source": map[string]any{"type": "git", "url": "https://github.com/x/y.git"}}
	r.pkgs["monolog/monolog"] = []Version{v}
	w := do(server(t, []Source{g, r}, readAll), "GET", "/composer/p2/monolog/monolog.json", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "github.com") || strings.Contains(w.Body.String(), `"source"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if _, ok := v.Package["source"]; !ok {
		t.Fatal("source map mutated")
	}
}

// Composer follows dist mirrors (preferred ones first) and posts install
// notices to notification-url, so upstream values for either would send
// clients past tspackages.
func TestUpstreamRedirectingKeysRemoved(t *testing.T) {
	g, r := gitAndReg()
	v := ver("monolog/monolog", "3.0.0", false)
	v.Package = map[string]any{
		"name": "monolog/monolog", "version": "3.0.0", "extra": map[string]any{"k": "kept"},
		"notification-url":  "https://notify.example/downloads/",
		"transport-options": map[string]any{"ssl": map[string]any{"verify_peer": false}},
		"dist": map[string]any{
			"type": "zip", "url": "https://codeload.example/z", "reference": "abc", "shasum": "",
			"mirrors":           []any{map[string]any{"url": "https://mirror.example/%package%", "preferred": true}},
			"transport-options": map[string]any{"http": map[string]any{"header": []any{"X: y"}}},
		},
	}
	r.pkgs["monolog/monolog"] = []Version{v}
	w := do(server(t, []Source{g, r}, readAll), "GET", "/composer/p2/monolog/monolog.json", nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, leak := range []string{"example/", "mirrors", "transport-options", "notification-url"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("response contains %q: %s", leak, w.Body)
		}
	}
	if !strings.Contains(w.Body.String(), `"kept"`) || !strings.Contains(w.Body.String(), `"reference":"abc"`) {
		t.Errorf("other fields dropped: %s", w.Body)
	}
}

func TestClientAuthorizationStripped(t *testing.T) {
	store, _ := newSource(t)
	mux := http.NewServeMux()
	New([]Source{store}, archive.Limits{MaxBytes: 1 << 20, MaxDecompressed: 16 << 20, MaxEntries: 1000}, nil).Mount(mux)
	var seen string
	h := identity.Middleware(testutil.Who{Cap: hCap, Rules: []string{`{"write":["composer:matchory-internal/*"]}`}}, hCap, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.Header.Get("Authorization") + r.Header.Get("Proxy-Authorization")
			mux.ServeHTTP(w, r)
		}))
	w := do(h, "PUT", "/composer/upload/matchory-internal/foo/1.0.0", bytes.NewReader(pkgZip(t, fooJSON)),
		"Authorization", "Bearer junk", "Proxy-Authorization", "Basic junk")
	if w.Code != 201 || seen != "" {
		t.Fatalf("%d, header seen by handlers: %q", w.Code, seen)
	}
}

// Over a real connection the upload handler sets a read deadline; the upload
// must still succeed.
func TestUploadOverRealServer(t *testing.T) {
	store, _ := newSource(t)
	srv := httptest.NewServer(server(t, []Source{store}, `{"write":["composer:matchory-internal/*"]}`))
	defer srv.Close()
	req, err := http.NewRequest("PUT", srv.URL+"/composer/upload/matchory-internal/foo/1.0.0", bytes.NewReader(pkgZip(t, fooJSON)))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestUploadShadowedByEarlierSourceIs409(t *testing.T) {
	store, _ := newSource(t)
	shadow := &fakeSource{name: "shadow", claims: []string{"matchory-internal/f*"}}
	h := server(t, []Source{shadow, store}, `{"write":["composer:matchory-internal/*"]}`)
	w := do(h, "PUT", "/composer/upload/matchory-internal/foo/1.0.0", bytes.NewReader(pkgZip(t, fooJSON)))
	if w.Code != 409 || !strings.Contains(w.Body.String(), `"matchory-internal/foo" is served by source "shadow"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if _, err := store.Versions(context.Background(), "matchory-internal/foo", false); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("shadowed upload was stored: %v", err)
	}
}

func TestUploadLogLine(t *testing.T) {
	store, _ := newSource(t)
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	data := pkgZip(t, fooJSON)
	w := do(serverLog(t, log, []Source{store}, `{"write":["composer:matchory-internal/*"]}`), "PUT", "/composer/upload/matchory-internal/foo/1.0.0", bytes.NewReader(data))
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	sum := sha256.Sum256(data)
	ls := captured(&buf)
	if len(ls) != 1 {
		t.Fatalf("%v", ls)
	}
	l := ls[0]
	if l["level"] != "INFO" || l["caller"] != "tag:ci" || l["node"] != "nid" || l["node_name"] != "ci.ts.net" ||
		l["package"] != "matchory-internal/foo" || l["version"] != "1.0.0" || l["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("log line: %v", l)
	}
}

func TestSecurityHeadersOnEarlyResponses(t *testing.T) {
	g, _ := gitAndReg()
	mux := http.NewServeMux()
	New([]Source{g}, archive.Limits{MaxBytes: 1}, slog.New(slog.DiscardHandler)).Mount(mux)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"no caller": do(mux, "GET", "/composer/packages.json", nil),
		"HEAD dist": do(server(t, []Source{g}, readAll), "HEAD", "/composer/dist/git-fake/matchory/a/1/r", nil),
	} {
		h := w.Header()
		if h.Get("Cache-Control") != "private, no-store" || h.Get("Vary") != "Host" || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s (%d): headers %v", name, w.Code, h)
		}
	}
}
