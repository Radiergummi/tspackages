package composer

import (
	"bytes"
	"context"
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
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

const hCap tailcfg.PeerCapability = "github.com/radiergummi/tspackages"

type fakeSource struct {
	name    string
	claims  []string
	pkgs    map[string][]Version
	err     error
	enum    bool
	calls   atomic.Int32
	distHit atomic.Int32
}

func (f *fakeSource) Name() string     { return f.name }
func (f *fakeSource) Claims() []string { return f.claims }
func (f *fakeSource) Type() string     { return "fake" }
func (f *fakeSource) Versions(_ context.Context, name string) ([]Version, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	vs, ok := f.pkgs[name]
	if !ok {
		return nil, resolve.ErrNotFound
	}
	return vs, nil
}
func (f *fakeSource) Dist(_ context.Context, name, version, reference string) (Artifact, error) {
	f.calls.Add(1)
	f.distHit.Add(1)
	if f.err != nil {
		return Artifact{}, f.err
	}
	return Artifact{Body: io.NopCloser(strings.NewReader("ZIP:" + version + ":" + reference)), Size: int64(len("ZIP:" + version + ":" + reference))}, nil
}
func (f *fakeSource) Packages(context.Context) ([]string, bool, error) {
	var out []string
	for n := range f.pkgs {
		out = append(out, n)
	}
	return out, f.enum, nil
}

// shared is deliberately reused by every version, as real sources may.
var shared = map[string]any{"type": "zip", "shasum": "abc"}

func ver(name, v string, dev bool) Version {
	return Version{
		Version: v, Reference: "ref-" + v, Dev: dev,
		Package: map[string]any{"name": name, "version": v, "dist": shared},
	}
}

type whoiser struct{ rules []string }

func (w whoiser) WhoIs(context.Context, string) (*apitype.WhoIsResponse, error) {
	var vals []tailcfg.RawMessage
	for _, r := range w.rules {
		vals = append(vals, tailcfg.RawMessage(r))
	}
	return &apitype.WhoIsResponse{
		Node:   &tailcfg.Node{Name: "n.ts.net.", StableID: "nid", Tags: []string{"tag:ci"}},
		CapMap: tailcfg.PeerCapMap{hCap: vals},
	}, nil
}

const readAll = `{"read":["*"]}`

func server(t *testing.T, srcs []Source, rules ...string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	New(srcs, archive.Limits{MaxBytes: 1 << 20, MaxDecompressed: 16 << 20, MaxEntries: 1000},
		slog.New(slog.NewTextHandler(io.Discard, nil))).Mount(mux)
	return identity.Middleware(whoiser{rules}, hCap, nil)(mux)
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
	g := &fakeSource{name: "git-fake", claims: []string{"matchory/*"}, enum: true,
		pkgs: map[string][]Version{"matchory/a": {ver("matchory/a", "1.0.0", false), ver("matchory/a", "dev-main", true)}}}
	r := &fakeSource{name: "registry-fake", enum: true,
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

func TestPackagesJSONAvailablePackages(t *testing.T) {
	g, r := gitAndReg()
	g.pkgs["matchory/secret"] = []Version{ver("matchory/secret", "1.0.0", false)}
	g.pkgs["Matchory/Mixed"] = nil
	h := server(t, []Source{g}, `{"read":["composer:matchory/a","composer:matchory/mixed"]}`)
	w := do(h, "GET", "/composer/packages.json", nil)
	var resp struct {
		Packages  []any    `json:"packages"`
		MetaURL   string   `json:"metadata-url"`
		Available []string `json:"available-packages"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != 200 || resp.MetaURL != "/composer/p2/%package%.json" || len(resp.Packages) != 0 ||
		strings.Join(resp.Available, ",") != "matchory/a,matchory/mixed" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// With an unclaimed source the key is absent.
	w = do(server(t, []Source{g, r}, readAll), "GET", "/composer/packages.json", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "available-packages") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// No composer rule at all.
	if w := do(server(t, []Source{g}, `{"read":["npm:*"]}`), "GET", "/composer/packages.json", nil); w.Code != 403 {
		t.Fatalf("%d", w.Code)
	}
	if w := do(server(t, []Source{g}), "GET", "/composer/packages.json", nil); w.Code != 403 {
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

func TestClientAuthorizationIgnored(t *testing.T) {
	store, _ := newSource(t)
	h := server(t, []Source{store}, `{"write":["composer:matchory-internal/*"]}`)
	w := do(h, "PUT", "/composer/upload/matchory-internal/foo/1.0.0", bytes.NewReader(pkgZip(t, fooJSON)), "Authorization", "Bearer junk")
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
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
