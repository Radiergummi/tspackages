package npm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/testutil"
	"github.com/radiergummi/tspackages/internal/upstream"
	"tailscale.com/tailcfg/peercap"
)

const hCap peercap.Cap = "github.com/radiergummi/tspackages"

const (
	readAll  = `{"read":["npm:*"]}`
	writeAll = `{"read":["npm:*"],"write":["npm:*"]}`
	corgiAcc = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"

	tarballCache = "private, max-age=31536000, immutable"
)

// fakeSource serves stored documents keyed by normalised name. Full and
// corgi documents hold BaseToken where the base URL belongs.
type fakeSource struct {
	name     string
	claims   []string
	full     map[string]string
	corgi    map[string]string
	versions map[string]string // "<norm>@<version-or-tag>"
	tarballs map[string]string // "<norm>/<file>"
	tags     map[string]map[string]string
	err      error

	calls    atomic.Int32
	mu       sync.Mutex
	lastName Name
	lastFile string
}

func (f *fakeSource) Name() string     { return f.name }
func (f *fakeSource) Claims() []string { return f.claims }

func (f *fakeSource) record(n Name, file string) error {
	f.calls.Add(1)
	f.mu.Lock()
	f.lastName, f.lastFile = n, file
	f.mu.Unlock()
	return f.err
}

func docOf(s string) Doc {
	sum := sha256.Sum256([]byte(s))
	return Doc{Body: io.NopCloser(strings.NewReader(s)), Size: int64(len(s)), SHA256: hex.EncodeToString(sum[:]), Tokens: strings.Count(s, BaseToken)}
}

func (f *fakeSource) Packument(_ context.Context, n Name, corgi bool) (Doc, error) {
	if err := f.record(n, ""); err != nil {
		return Doc{}, err
	}
	m := f.full
	if corgi {
		m = f.corgi
	}
	s, ok := m[n.Norm]
	if !ok {
		return Doc{}, resolve.ErrNotFound
	}
	return docOf(s), nil
}

func (f *fakeSource) Version(_ context.Context, n Name, v string) ([]byte, error) {
	if err := f.record(n, v); err != nil {
		return nil, err
	}
	s, ok := f.versions[n.Norm+"@"+v]
	if !ok {
		return nil, resolve.ErrNotFound
	}
	return []byte(s), nil
}

func (f *fakeSource) Tarball(_ context.Context, n Name, file string) (Artifact, error) {
	if err := f.record(n, file); err != nil {
		return Artifact{}, err
	}
	s, ok := f.tarballs[n.Norm+"/"+file]
	if !ok {
		return Artifact{}, resolve.ErrNotFound
	}
	return Artifact{Body: io.NopCloser(strings.NewReader(s)), Size: int64(len(s))}, nil
}

func (f *fakeSource) DistTags(_ context.Context, n Name) (map[string]string, error) {
	if err := f.record(n, ""); err != nil {
		return nil, err
	}
	t, ok := f.tags[n.Norm]
	if !ok {
		return nil, resolve.ErrNotFound
	}
	return t, nil
}

type tagOp struct{ op, tag, version string }

type fakePublisher struct {
	*fakeSource
	notice    string
	pubErr    error
	published []string
	tagOps    []tagOp
}

func (p *fakePublisher) Publish(_ context.Context, _ identity.Caller, n Name, body *os.File, size int64) (string, error) {
	p.record(n, "")
	if p.pubErr != nil {
		return "", p.pubErr
	}
	b, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	if int64(len(b)) != size {
		return "", fmt.Errorf("size %d, read %d", size, len(b))
	}
	p.published = append(p.published, string(b))
	return p.notice, nil
}

func (p *fakePublisher) SetTag(_ context.Context, _ identity.Caller, n Name, tag, version string) error {
	p.record(n, "")
	if p.pubErr != nil {
		return p.pubErr
	}
	p.tagOps = append(p.tagOps, tagOp{"set", tag, version})
	return nil
}

func (p *fakePublisher) RemoveTag(_ context.Context, _ identity.Caller, n Name, tag string) error {
	p.record(n, "")
	if p.pubErr != nil {
		return p.pubErr
	}
	p.tagOps = append(p.tagOps, tagOp{"rm", tag, ""})
	return nil
}

type fakeAttester struct {
	*fakeSource
	attest map[string]string // "<norm>@<version>"
}

func (a *fakeAttester) Keys(context.Context) (Artifact, error) {
	if err := a.record(Name{}, "keys"); err != nil {
		return Artifact{}, err
	}
	return Artifact{Body: io.NopCloser(strings.NewReader(`{"keys":[]}`)), Size: 11}, nil
}

func (a *fakeAttester) Attestations(_ context.Context, n Name, version string) (Artifact, error) {
	if err := a.record(n, version); err != nil {
		return Artifact{}, err
	}
	s, ok := a.attest[n.Norm+"@"+version]
	if !ok {
		return Artifact{}, resolve.ErrNotFound
	}
	return Artifact{Body: io.NopCloser(strings.NewReader(s)), Size: int64(len(s))}, nil
}

func server(t *testing.T, srcs []Source, rules ...string) http.Handler {
	t.Helper()
	h, _ := serverIn(t, srcs, 1<<20, rules...)
	return h
}

// serverIn also returns the directory publish bodies are spooled in.
func serverIn(t *testing.T, srcs []Source, maxUpload int64, rules ...string) (http.Handler, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(srcs, maxUpload, dir, slog.New(slog.DiscardHandler)).Mount(mux)
	return identity.Middleware(testutil.Who{Cap: hCap, Rules: rules}, hCap, nil)(mux), dir
}

func do(h http.Handler, method, path string, body io.Reader, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, body)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			r.Host = hdr[i+1]
			continue
		}
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func registryFake() *fakeAttester {
	return &fakeAttester{fakeSource: &fakeSource{name: "npmjs",
		full:     map[string]string{"left-pad": `{"name":"left-pad","versions":{"1.0.0":{"dist":{"tarball":"` + BaseToken + `left-pad/-/left-pad-1.0.0.tgz"}}},"readme":"x"}`},
		corgi:    map[string]string{"left-pad": `{"name":"left-pad","versions":{"1.0.0":{"dist":{"tarball":"` + BaseToken + `left-pad/-/left-pad-1.0.0.tgz"}}}}`},
		versions: map[string]string{"left-pad@1.0.0": `{"dist":{"tarball":"` + BaseToken + `left-pad/-/left-pad-1.0.0.tgz"}}`},
		tarballs: map[string]string{"left-pad/left-pad-1.0.0.tgz": "TGZ", "npm/npm-11.0.0.tgz": "NPM"},
		tags:     map[string]map[string]string{"left-pad": {"latest": "1.0.0"}},
	}, attest: map[string]string{"left-pad@1.0.0": `{"attestations":[]}`}}
}

func storageFake() *fakePublisher {
	return &fakePublisher{fakeSource: &fakeSource{name: "hosted", claims: []string{"@matchory/*", "@s/*"},
		full:  map[string]string{"@s/n": `{"name":"@s/n"}`},
		corgi: map[string]string{"@s/n": `{"name":"@s/n"}`},
		tags:  map[string]map[string]string{"@s/n": {"latest": "1.0.0"}},
	}}
}

func TestPackumentNegotiation(t *testing.T) {
	reg := registryFake()
	h := server(t, []Source{reg}, readAll)
	base := "http://example.com/npm/"
	etags := map[string]string{}
	for _, tt := range []struct{ accept, ctype, doc string }{
		{corgiAcc, "application/vnd.npm.install-v1+json", "corgi"},
		{"application/vnd.npm.install-v1+json", "application/vnd.npm.install-v1+json", "corgi"},
		{"application/json", "application/json", "full"},
		{"*/*", "application/json", "full"},
		{"", "application/json", "full"},
	} {
		w := do(h, "GET", "/npm/left-pad", nil, "Accept", tt.accept)
		if w.Code != 200 {
			t.Fatalf("%q: %d %s", tt.accept, w.Code, w.Body)
		}
		want := reg.full["left-pad"]
		if tt.doc == "corgi" {
			want = reg.corgi["left-pad"]
		}
		want = strings.ReplaceAll(want, BaseToken, base)
		if w.Body.String() != want {
			t.Errorf("%q: body %s, want %s", tt.accept, w.Body, want)
		}
		hd := w.Header()
		if hd.Get("Content-Type") != tt.ctype {
			t.Errorf("%q: Content-Type %q", tt.accept, hd.Get("Content-Type"))
		}
		if hd.Get("Content-Length") != fmt.Sprint(len(want)) {
			t.Errorf("%q: Content-Length %q, body %d", tt.accept, hd.Get("Content-Length"), len(want))
		}
		et := hd.Get("ETag")
		if len(et) != 66 || et[0] != '"' || et[65] != '"' {
			t.Errorf("%q: ETag %q", tt.accept, et)
		}
		if prev, ok := etags[tt.doc]; ok && prev != et {
			t.Errorf("%q: ETag %q, earlier %q for the same document", tt.accept, et, prev)
		}
		etags[tt.doc] = et
		if hd.Get("Cache-Control") != "no-cache" || hd.Get("Vary") != "Accept" {
			t.Errorf("%q: Cache-Control %q Vary %q", tt.accept, hd.Get("Cache-Control"), hd.Get("Vary"))
		}
		if hd.Get("Last-Modified") != "" {
			t.Errorf("%q: Last-Modified %q", tt.accept, hd.Get("Last-Modified"))
		}
	}
	if etags["full"] == etags["corgi"] {
		t.Fatal("full and corgi share an ETag")
	}
	// Another host expands to other bytes, so the ETag differs too.
	w := do(h, "GET", "/npm/left-pad", nil, "Host", "other.example")
	if w.Header().Get("ETag") == etags["full"] || !strings.Contains(w.Body.String(), "http://other.example/npm/left-pad/-/") {
		t.Fatalf("other host: ETag %q body %s", w.Header().Get("ETag"), w.Body)
	}
	// The first step of unpublish and deprecate is an ordinary read.
	if w := do(h, "GET", "/npm/left-pad?write=true", nil); w.Code != 200 || w.Header().Get("ETag") != etags["full"] {
		t.Fatalf("?write=true: %d %q", w.Code, w.Header().Get("ETag"))
	}
}

func TestVersionDocument(t *testing.T) {
	reg := registryFake()
	h := server(t, []Source{reg}, readAll)
	w := do(h, "GET", "/npm/left-pad/1.0.0", nil)
	want := `{"dist":{"tarball":"http://example.com/npm/left-pad/-/left-pad-1.0.0.tgz"}}`
	if w.Code != 200 || w.Body.String() != want || w.Header().Get("Content-Length") != fmt.Sprint(len(want)) {
		t.Fatalf("%d %q %s", w.Code, w.Header().Get("Content-Length"), w.Body)
	}
	if w.Header().Get("ETag") == "" || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("headers %v", w.Header())
	}
	if reg.lastFile != "1.0.0" {
		t.Fatalf("asked for %q", reg.lastFile)
	}
	if w := do(h, "GET", "/npm/left-pad/9.9.9", nil); w.Code != 404 {
		t.Fatalf("missing version: %d", w.Code)
	}
}

func TestConditional(t *testing.T) {
	h := server(t, []Source{registryFake()}, readAll)
	for _, path := range []string{"/npm/left-pad", "/npm/left-pad/1.0.0"} {
		first := do(h, "GET", path, nil)
		et := first.Header().Get("ETag")
		w := do(h, "GET", path, nil, "If-None-Match", et)
		if w.Code != http.StatusNotModified || w.Body.Len() != 0 || w.Header().Get("ETag") != et {
			t.Fatalf("%s: %d %q %s", path, w.Code, w.Header().Get("ETag"), w.Body)
		}
		if w := do(h, "GET", path, nil, "If-None-Match", `"other", `+et); w.Code != http.StatusNotModified {
			t.Fatalf("%s list: %d", path, w.Code)
		}
		if w := do(h, "GET", path, nil, "If-None-Match", `"other"`); w.Code != 200 {
			t.Fatalf("%s mismatch: %d", path, w.Code)
		}
		w = do(h, "HEAD", path, nil)
		if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != first.Header().Get("Content-Length") || w.Header().Get("ETag") != et {
			t.Fatalf("%s HEAD: %d %v %q", path, w.Code, w.Header(), w.Body)
		}
	}
}

func TestClaimsRouteBeforeUnclaimed(t *testing.T) {
	reg, st := registryFake(), storageFake()
	reg.full["@matchory/x"] = `{"name":"@matchory/x"}`
	h := server(t, []Source{st, reg}, readAll)
	for _, path := range []string{"/npm/@matchory%2fx", "/npm/@MATCHORY/x", "/npm/@matchory/x/-/x-1.0.0.tgz", "/npm/-/package/@matchory%2fx/dist-tags"} {
		if w := do(h, "GET", path, nil); w.Code != 404 {
			t.Errorf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	if n := reg.calls.Load(); n != 0 {
		t.Fatalf("unclaimed source called %d times for a claimed name", n)
	}
	if st.lastName.Exact != "@matchory/x" {
		t.Fatalf("storage got %+v", st.lastName)
	}
	// Sources receive the name as requested.
	do(h, "GET", "/npm/@MATCHORY/x", nil)
	if st.lastName.Exact != "@MATCHORY/x" || st.lastName.Norm != "@matchory/x" {
		t.Fatalf("storage got %+v", st.lastName)
	}
	if w := do(h, "GET", "/npm/left-pad", nil); w.Code != 200 || reg.calls.Load() != 1 {
		t.Fatalf("unclaimed: %d, calls %d", w.Code, reg.calls.Load())
	}
}

func TestForbiddenBodies(t *testing.T) {
	st := storageFake()
	h := server(t, []Source{st, registryFake()}, `{"read":["npm:other"]}`)
	for _, path := range []string{"/npm/@s%2fn", "/npm/@s/n/1.0.0", "/npm/@s/n/-/n-1.0.0.tgz", "/npm/-/package/@s/n/dist-tags", "/npm/-/npm/v1/attestations/@s/n@1.0.0"} {
		w := do(h, "GET", path, nil)
		if w.Code != 403 || w.Body.String() != `{"error":"forbidden: no npm:@s/n read rule"}` || w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: %d %q %s", path, w.Code, w.Header().Get("Content-Type"), w.Body)
		}
	}
	h = server(t, []Source{st, registryFake()}, readAll)
	for _, tt := range []struct{ method, path string }{
		{"PUT", "/npm/@s%2fn"},
		{"PUT", "/npm/-/package/@s%2fn/dist-tags/beta"},
		{"DELETE", "/npm/-/package/@s%2fn/dist-tags/beta"},
	} {
		w := do(h, tt.method, tt.path, strings.NewReader(`"1.0.0"`), "Content-Type", "application/json")
		if w.Code != 403 || w.Body.String() != `{"error":"forbidden: no npm:@s/n write rule"}` {
			t.Errorf("%s %s: %d %s", tt.method, tt.path, w.Code, w.Body)
		}
	}
	// Keys need some npm read rule.
	h = server(t, []Source{registryFake()}, `{"read":["go:*"]}`)
	if w := do(h, "GET", "/npm/-/npm/v1/keys", nil); w.Code != 403 || w.Body.String() != `{"error":"forbidden: no npm: read rule"}` {
		t.Fatalf("keys: %d %s", w.Code, w.Body)
	}
	if st.calls.Load() != 0 {
		t.Fatal("a source was asked for a denied request")
	}
}

func TestPublishRouting(t *testing.T) {
	put := func(h http.Handler, path, ctype, body string) *httptest.ResponseRecorder {
		return do(h, "PUT", path, strings.NewReader(body), "Content-Type", ctype)
	}
	reg := registryFake()

	// No storage source claims the name.
	h := server(t, []Source{storageFake(), reg}, writeAll)
	if w := put(h, "/npm/left-pad", "application/json", "{}"); w.Code != 403 || w.Body.String() != `{"error":"no storage source claims left-pad"}` {
		t.Fatalf("unclaimed: %d %s", w.Code, w.Body)
	}
	// A registry claiming the name first.
	claimingReg := registryFake()
	claimingReg.claims = []string{"@s/*"}
	h = server(t, []Source{claimingReg, storageFake()}, writeAll)
	if w := put(h, "/npm/@s%2fn", "application/json", "{}"); w.Code != 409 || !strings.HasPrefix(w.Body.String(), `{"error":`) {
		t.Fatalf("registry first: %d %s", w.Code, w.Body)
	}
	// Claimed only by a registry.
	h = server(t, []Source{claimingReg}, writeAll)
	if w := put(h, "/npm/@s%2fn", "application/json", "{}"); w.Code != 403 || w.Body.String() != `{"error":"no storage source claims @s/n"}` {
		t.Fatalf("registry only: %d %s", w.Code, w.Body)
	}

	st := storageFake()
	h, dir := serverIn(t, []Source{st, reg}, 3, writeAll)
	if w := put(h, "/npm/@s%2fn", "text/plain", "{}"); w.Code != 400 {
		t.Fatalf("non-JSON: %d %s", w.Code, w.Body)
	}
	// ceil(3*4/3) + 2 MiB.
	limit := 4 + 2<<20
	if w := put(h, "/npm/@s%2fn", "application/json", strings.Repeat("x", limit+1)); w.Code != 413 {
		t.Fatalf("over cap: %d %s", w.Code, w.Body)
	}
	if len(st.published) != 0 {
		t.Fatal("an oversized body reached Publish")
	}
	body := strings.Repeat("y", limit)
	if w := put(h, "/npm/@s%2fn", "application/json; charset=utf-8", body); w.Code != 201 || w.Body.String() != `{"ok":true}` {
		t.Fatalf("at cap: %d %s", w.Code, w.Body)
	}
	if len(st.published) != 1 || st.published[0] != body || st.lastName.Exact != "@s/n" {
		t.Fatalf("published %d bodies, name %+v", len(st.published), st.lastName)
	}
	st.notice = "latest stayed at 2.0.0"
	if w := put(h, "/npm/@s%2fn", "application/json", "{}"); w.Code != 201 || w.Header().Get("npm-notice") != st.notice {
		t.Fatalf("notice: %d %q", w.Code, w.Header().Get("npm-notice"))
	}
	st.notice = ""
	if w := put(h, "/npm/@s%2fn", "application/json", "{}"); w.Header().Values("npm-notice") != nil {
		t.Fatalf("empty notice sent: %q", w.Header().Values("npm-notice"))
	}

	for _, tt := range []struct {
		err    error
		status int
		body   string
	}{
		{ErrNoTarball, 405, `{"error":"this registry does not support deprecate"}`},
		{fmt.Errorf("@s/n@1.0.0: %w", ErrVersionExists), 409, `{"error":"@s/n@1.0.0: version already exists"}`},
		{&RequestError{Status: 400, Reason: "bad tarball"}, 400, `{"error":"bad tarball"}`},
		{&RequestError{Status: 413, Reason: "tarball too large"}, 413, `{"error":"tarball too large"}`},
		{errors.New("disk full"), 500, `{"error":"internal server error"}`},
	} {
		st.pubErr = tt.err
		w := put(h, "/npm/@s%2fn", "application/json", "{}")
		if w.Code != tt.status || w.Body.String() != tt.body {
			t.Errorf("%v: %d %s", tt.err, w.Code, w.Body)
		}
		if errors.Is(tt.err, ErrNoTarball) && w.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("deprecate: Allow %q", w.Header().Get("Allow"))
		}
	}
	left, err := os.ReadDir(dir)
	if err != nil || len(left) != 0 {
		t.Fatalf("spool dir: %v %v", left, err)
	}
}

func TestDistTagRoutes(t *testing.T) {
	reg, st := registryFake(), storageFake()
	h := server(t, []Source{st, reg}, writeAll)

	w := do(h, "GET", "/npm/-/package/left-pad/dist-tags", nil)
	if w.Code != 200 || w.Body.String() != `{"latest":"1.0.0"}` || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("GET: %d %s", w.Code, w.Body)
	}
	for _, method := range []string{"PUT", "DELETE"} {
		w := do(h, method, "/npm/-/package/left-pad/dist-tags/beta", strings.NewReader(`"1.0.0"`))
		if w.Code != 405 || w.Body.String() != `{"error":"dist-tags of left-pad come from npmjs"}` {
			t.Fatalf("%s on registry: %d %s", method, w.Code, w.Body)
		}
	}

	if w := do(h, "PUT", "/npm/-/package/@s%2fn/dist-tags/next%2D1", strings.NewReader(`"1.2.3"`), "Content-Type", "application/json"); w.Code != 200 {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	if w := do(h, "DELETE", "/npm/-/package/@s/n/dist-tags/beta", nil); w.Code != 200 {
		t.Fatalf("DELETE: %d %s", w.Code, w.Body)
	}
	want := []tagOp{{"set", "next-1", "1.2.3"}, {"rm", "beta", ""}}
	if fmt.Sprint(st.tagOps) != fmt.Sprint(want) {
		t.Fatalf("tag ops %v, want %v", st.tagOps, want)
	}
	for _, body := range []string{`1.2.3`, `{"v":"1"}`, `"` + strings.Repeat("1", 1024) + `"`} {
		if w := do(h, "PUT", "/npm/-/package/@s%2fn/dist-tags/beta", strings.NewReader(body)); w.Code/100 != 4 {
			t.Errorf("body %.20q: %d", body, w.Code)
		}
	}
	st.pubErr = &RequestError{Status: 400, Reason: "latest can't be removed"}
	if w := do(h, "DELETE", "/npm/-/package/@s/n/dist-tags/latest", nil); w.Code != 400 || w.Body.String() != `{"error":"latest can't be removed"}` {
		t.Fatalf("rm latest: %d %s", w.Code, w.Body)
	}
	if len(st.tagOps) != 2 {
		t.Fatalf("tag ops %v", st.tagOps)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := server(t, []Source{storageFake(), registryFake()}, writeAll)
	for _, tt := range []struct{ method, path, allow string }{
		{"DELETE", "/npm/@s%2fn/-rev/1-abc", ""},
		{"PUT", "/npm/@s%2fn/-rev/1-abc", ""},
		{"GET", "/npm/@s%2fn/-rev/1-abc", ""},
		{"DELETE", "/npm/@s/n/-/n-1.0.0.tgz/-rev/1-abc", ""},
		{"DELETE", "/npm/@s%2fn", "GET, HEAD, PUT"},
		{"POST", "/npm/left-pad", "GET, HEAD, PUT"},
		{"PUT", "/npm/left-pad/1.0.0", "GET, HEAD"},
		{"DELETE", "/npm/left-pad/-/left-pad-1.0.0.tgz", "GET, HEAD"},
		{"PUT", "/npm/-/package/left-pad/dist-tags", "GET, HEAD"},
		{"GET", "/npm/-/package/left-pad/dist-tags/beta", "PUT, DELETE"},
		{"POST", "/npm/-/npm/v1/keys", "GET, HEAD"},
	} {
		w := do(h, tt.method, tt.path, nil)
		allow, sent := w.Header()["Allow"]
		if w.Code != 405 || !sent || strings.Join(allow, ",") != tt.allow || !strings.HasPrefix(w.Body.String(), `{"error":"`) || w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s %s: %d Allow=%q %s", tt.method, tt.path, w.Code, allow, w.Body)
		}
	}
}

func TestNever401(t *testing.T) {
	paths := []string{
		"/npm/@s%2fn", "/npm/left-pad", "/npm/@s/n/1.0.0", "/npm/left-pad/latest",
		"/npm/@s/n/-/n-1.0.0.tgz", "/npm/-/npm-11.0.0.tgz",
		"/npm/-/package/@s%2fn/dist-tags", "/npm/-/package/left-pad/dist-tags/beta", "/npm/-/package/@s/n/dist-tags/beta",
		"/npm/-/npm/v1/keys", "/npm/-/npm/v1/attestations/left-pad@1.0.0",
		"/npm/@s%2fn/-rev/1", "/npm/-/whoami", "/npm/-/npm/v1/security/advisories/bulk", "/npm/",
	}
	errs := []error{
		nil,
		resolve.ErrNotFound,
		errors.New("boom"),
		&upstream.StatusError{Code: 401, URL: "https://registry.npmjs.org/x"},
		context.DeadlineExceeded,
		&RequestError{Status: 401, Reason: "one-time pass"},
		ErrVersionExists,
		ErrNoTarball,
	}
	for _, rules := range [][]string{nil, {readAll}, {writeAll}} {
		for _, e := range errs {
			reg, st := registryFake(), storageFake()
			reg.err, st.err, st.pubErr = e, e, e
			h := server(t, []Source{st, reg}, rules...)
			for _, path := range paths {
				for _, method := range []string{"GET", "HEAD", "PUT", "DELETE", "POST"} {
					w := do(h, method, path, strings.NewReader(`"1.0.0"`), "Content-Type", "application/json")
					if w.Code == http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "" {
						t.Errorf("rules %v, err %v: %s %s = %d", rules, e, method, path, w.Code)
					}
				}
			}
		}
	}
	// An upstream 401 is a gateway failure.
	reg := registryFake()
	reg.err = &upstream.StatusError{Code: 401, URL: "https://registry.npmjs.org/x"}
	if w := do(server(t, []Source{reg}, readAll), "GET", "/npm/left-pad", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("upstream 401: %d", w.Code)
	}
}

func TestAuditBulk404(t *testing.T) {
	reg, st := registryFake(), storageFake()
	h := server(t, []Source{st, reg}, writeAll)
	for _, method := range []string{"POST", "GET"} {
		w := do(h, method, "/npm/-/npm/v1/security/advisories/bulk", strings.NewReader(`{"left-pad":["1.0.0"]}`), "Content-Type", "application/json")
		if w.Code != 404 || w.Body.String() != `{"error":"not found"}` {
			t.Fatalf("%s: %d %s", method, w.Code, w.Body)
		}
	}
	if reg.calls.Load()+st.calls.Load() != 0 {
		t.Fatal("a source was asked for an audit request")
	}
}

func TestNPMPackageTarball(t *testing.T) {
	reg := registryFake()
	h := server(t, []Source{storageFake(), reg}, readAll)
	for _, path := range []string{"/npm/-/npm-11.0.0.tgz", "/npm/npm/-/npm-11.0.0.tgz"} {
		w := do(h, "GET", path, nil)
		if w.Code != 200 || w.Body.String() != "NPM" || w.Header().Get("Content-Length") != "3" || w.Header().Get("Content-Type") != "application/octet-stream" {
			t.Fatalf("%s: %d %v %s", path, w.Code, w.Header(), w.Body)
		}
		if w.Header().Get("Cache-Control") != tarballCache {
			t.Fatalf("%s: Cache-Control %q", path, w.Header().Get("Cache-Control"))
		}
		if reg.lastName.Norm != "npm" || reg.lastName.Exact != "npm" || reg.lastFile != "npm-11.0.0.tgz" {
			t.Fatalf("%s: Tarball(%+v, %q)", path, reg.lastName, reg.lastFile)
		}
	}
	w := do(h, "HEAD", "/npm/left-pad/-/left-pad-1.0.0.tgz", nil)
	if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "3" || w.Header().Get("Cache-Control") != tarballCache {
		t.Fatalf("HEAD tarball: %d %v", w.Code, w.Header())
	}
	// Errors on the tarball route are not cacheable.
	if w := do(h, "GET", "/npm/left-pad/-/left-pad-9.9.9.tgz", nil); w.Code != 404 || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("missing tarball: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	reg.err = errors.New("boom")
	if w := do(h, "GET", "/npm/left-pad/-/left-pad-1.0.0.tgz", nil); w.Code != 502 || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("failing tarball: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	reg.err = nil
	// Keys and attestations stay uncached.
	for _, path := range []string{"/npm/-/npm/v1/keys", "/npm/-/npm/v1/attestations/left-pad@1.0.0"} {
		if w := do(h, "GET", path, nil); w.Code != 200 || w.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatalf("%s: %d %q", path, w.Code, w.Header().Get("Cache-Control"))
		}
	}
}

func TestKeysAndAttestations(t *testing.T) {
	reg := registryFake()
	h := server(t, []Source{storageFake(), reg}, readAll)
	if w := do(h, "GET", "/npm/-/npm/v1/keys", nil); w.Code != 200 || w.Body.String() != `{"keys":[]}` || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("keys: %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", "/npm/-/npm/v1/attestations/left-pad@1.0.0", nil); w.Code != 200 || w.Body.String() != `{"attestations":[]}` {
		t.Fatalf("attestations: %d %s", w.Code, w.Body)
	}
	// A storage-served name has no attestations, and a claimed name never
	// reaches the unclaimed source.
	reg.attest["@s/n@1.0.0"] = `{}`
	if w := do(h, "GET", "/npm/-/npm/v1/attestations/@s/n@1.0.0", nil); w.Code != 404 {
		t.Fatalf("storage attestations: %d %s", w.Code, w.Body)
	}
	// Without an unclaimed Attester there are no keys.
	plain := &fakeSource{name: "plain"}
	if w := do(server(t, []Source{storageFake(), plain}, readAll), "GET", "/npm/-/npm/v1/keys", nil); w.Code != 404 {
		t.Fatalf("no attester: %d", w.Code)
	}
	claimed := registryFake()
	claimed.claims = []string{"*"}
	if w := do(server(t, []Source{claimed}, readAll), "GET", "/npm/-/npm/v1/keys", nil); w.Code != 404 || claimed.calls.Load() != 0 {
		t.Fatalf("claimed attester: %d", w.Code)
	}
}

func TestMalformedRulesMatchNothing(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	mux := http.NewServeMux()
	New([]Source{registryFake()}, 1<<20, t.TempDir(), log).Mount(mux)
	h := identity.Middleware(testutil.Who{Cap: hCap, Rules: []string{`{"read":["npm:LEFT-pad","npm:a/b","nocolon","go:*"]}`}}, hCap, nil)(mux)
	if w := do(h, "GET", "/npm/left-pad", nil); w.Code != 403 {
		t.Fatalf("%d", w.Code)
	}
	out := buf.String()
	if strings.Count(out, "malformed") != 1 || !strings.Contains(out, "npm:LEFT-pad") || !strings.Contains(out, "npm:a/b") || !strings.Contains(out, "nocolon") || strings.Contains(out, "go:*") {
		t.Fatalf("log: %s", out)
	}
}
