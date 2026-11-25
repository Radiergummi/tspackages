package apt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/testutil"
	"tailscale.com/tailcfg/peercap"
)

const hCap peercap.Cap = "github.com/radiergummi/tspackages"

var modified = time.Date(2026, 11, 23, 10, 10, 10, 0, time.UTC)

const (
	debPath    = "/apt/hosted/bookworm/main/acme_1.0-1_amd64.deb"
	releaseURL = "/apt/hosted/dists/bookworm/Release"
	controlFmt = "Package: %s\nVersion: 1.0-1\nArchitecture: amd64\nMaintainer: A <a@example.com>\nDescription: short\n"
)

type fakeSource struct {
	name   string
	claims []string
	err    error

	mu       sync.Mutex
	pools    []Path
	uploaded map[string]string // file name -> bytes
	exists   bool
	uploads  int
	lastCtl  Control
	viewer   string // of the last Release request
}

func (f *fakeSource) Name() string     { return f.name }
func (f *fakeSource) Claims() []string { return f.claims }

func (f *fakeSource) blob(s string) (Blob, error) {
	if f.err != nil {
		return Blob{}, f.err
	}
	return Blob{Body: io.NopCloser(strings.NewReader(s)), Size: int64(len(s)), ETag: `"e1"`, Modified: modified, Immutable: true}, nil
}

func (f *fakeSource) Release(_ context.Context, acc ReadAccess, suite, which string) (Blob, error) {
	f.mu.Lock()
	f.viewer = acc.Viewer
	f.mu.Unlock()
	return f.blob(which + " of " + suite)
}

func (f *fakeSource) Dist(_ context.Context, _ ReadAccess, _, rel string) (Blob, error) {
	return f.blob("dist " + rel)
}

func (f *fakeSource) ByHash(_ context.Context, _ ReadAccess, _, _, h string) (Blob, error) {
	return f.blob("byhash " + h)
}

func (f *fakeSource) Pool(_ context.Context, _ ReadAccess, p Path) (Blob, error) {
	f.mu.Lock()
	f.pools = append(f.pools, p)
	f.mu.Unlock()
	return f.blob("deb")
}

func (f *fakeSource) Upload(_ context.Context, _ identity.Caller, _, _ string, ctl Control, body *os.File, size int64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploads++
	f.lastCtl = ctl
	if f.exists {
		return false, ErrExists
	}
	b, err := io.ReadAll(body)
	if err != nil || int64(len(b)) != size {
		return false, errors.New("bad spool")
	}
	if f.uploaded == nil {
		f.uploaded = map[string]string{}
	}
	file := ctl.Deb.FileName()
	if old, ok := f.uploaded[file]; ok {
		if old != string(b) {
			return false, ErrExists
		}
		return false, nil
	}
	f.uploaded[file] = string(b)
	return true, nil
}

func hosted() *fakeSource {
	return &fakeSource{name: "hosted", claims: []string{"acme-*", "acme"}}
}

func serverIn(t *testing.T, srcs []Source, signer *Signer, maxUpload int64, rules ...string) (http.Handler, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(srcs, signer, maxUpload, dir, slog.New(slog.DiscardHandler)).Mount(mux)
	return identity.Middleware(testutil.Who{Cap: hCap, Rules: rules}, hCap, nil)(mux), dir
}

func server(t *testing.T, srcs []Source, rules ...string) http.Handler {
	t.Helper()
	h, _ := serverIn(t, srcs, nil, 1<<20, rules...)
	return h
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

func debFor(t *testing.T, pkg string) []byte {
	t.Helper()
	return testutil.Deb(t, strings.Replace(controlFmt, "%s", pkg, 1), testutil.DebOptions{})
}

func rule(read, write string) string {
	s := `{"read":[` + read + `]`
	if write != "" {
		s += `,"write":[` + write + `]`
	}
	return s + "}"
}

var (
	readAcme = rule(`"apt:acme-*"`, "")
	readAll  = rule(`"*"`, "")
	writeAcm = rule(`"apt:acme"`, `"apt:acme"`)
)

func TestNeverUnauthorized(t *testing.T) {
	paths := []string{"/apt/key.asc", "/apt/preferences", releaseURL, "/apt/hosted/dists/bookworm/main/binary-amd64/Packages",
		"/apt/hosted/dists/bookworm/main/by-hash/SHA256/" + strings.Repeat("a", 64), "/apt/hosted/pool/acme/acme_1.0_all.deb", "/apt/nope/pool/x", "/apt/%2e%2e/x"}
	rules := [][]string{nil, {`{}`}, {readAcme}, {readAll}, {writeAcm}, {`{"read":["apt:A*B"]}`}}
	for _, rs := range rules {
		h := server(t, []Source{hosted()}, rs...)
		for _, m := range []string{"GET", "HEAD", "PUT", "POST", "DELETE"} {
			for _, p := range append(paths, debPath) {
				if w := do(h, m, p, strings.NewReader("x")); w.Code == 401 {
					t.Errorf("%s %s with %v: 401", m, p, rs)
				}
			}
		}
	}
}

func TestNoRuleForbidden(t *testing.T) {
	h := server(t, []Source{hosted()}, `{"read":["maven:*"]}`)
	for _, p := range []string{releaseURL, "/apt/hosted/dists/bookworm/main/binary-amd64/Packages",
		"/apt/hosted/dists/bookworm/main/by-hash/SHA256/" + strings.Repeat("a", 64), "/apt/hosted/pool/acme/acme_1.0_all.deb", "/apt/key.asc", "/apt/preferences"} {
		w := do(h, "GET", p, nil)
		if w.Code != 403 {
			t.Errorf("%s: %d", p, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != textType {
			t.Errorf("%s: Content-Type %q", p, ct)
		}
	}
}

func TestMalformedRuleDoesNotGrant(t *testing.T) {
	h := server(t, []Source{hosted()}, `{"read":["apt:Acme!"]}`)
	if w := do(h, "GET", releaseURL, nil); w.Code != 403 {
		t.Fatalf("%d", w.Code)
	}
}

func TestReaderGetsRelease(t *testing.T) {
	h := server(t, []Source{hosted()}, readAcme)
	w := do(h, "GET", releaseURL, nil)
	if w.Code != 200 || w.Body.String() != "Release of bookworm" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for k, v := range map[string]string{
		"Content-Type":           textType,
		"Cache-Control":          "no-cache",
		"ETag":                   `"e1"`,
		"Last-Modified":          modified.Format(http.TimeFormat),
		"X-Content-Type-Options": "nosniff",
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestContentTypes(t *testing.T) {
	h := server(t, []Source{hosted()}, readAll)
	for p, want := range map[string]string{
		"/apt/hosted/dists/bookworm/Release.gpg":                                    "application/pgp-signature",
		"/apt/hosted/dists/bookworm/InRelease":                                      textType,
		"/apt/hosted/dists/bookworm/main/binary-amd64/Packages":                     textType,
		"/apt/hosted/dists/bookworm/main/binary-amd64/Packages.gz":                  "application/gzip",
		"/apt/hosted/pool/acme/acme_1.0_all.deb":                                    "application/vnd.debian.binary-package",
		"/apt/hosted/dists/bookworm/main/by-hash/SHA256/" + strings.Repeat("a", 64): "application/octet-stream",
	} {
		if got := do(h, "GET", p, nil).Header().Get("Content-Type"); got != want {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
}

func TestImmutableCache(t *testing.T) {
	h := server(t, []Source{hosted()}, readAll)
	for _, p := range []string{"/apt/hosted/pool/acme/acme_1.0_all.deb", "/apt/hosted/dists/bookworm/main/by-hash/SHA256/" + strings.Repeat("a", 64)} {
		if got := do(h, "GET", p, nil).Header().Get("Cache-Control"); got != immutableCache {
			t.Errorf("%s: %q", p, got)
		}
	}
	if got := do(h, "GET", "/apt/hosted/dists/bookworm/main/binary-amd64/Packages", nil).Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Packages: %q", got)
	}
}

func TestKeyAndPreferences(t *testing.T) {
	h := server(t, []Source{hosted()}, readAll)
	if w := do(h, "GET", "/apt/key.asc", nil); w.Code != 404 {
		t.Fatalf("key without signer: %d", w.Code)
	}
	w := do(h, "GET", "/apt/preferences", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Package: acme-* acme\nPin: release o=tspackages,l=hosted") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w.Header().Get("Content-Type") != textType {
		t.Fatalf("Content-Type %q", w.Header().Get("Content-Type"))
	}
	priv, _ := testutil.PGPKey(t, "tsp")
	s, err := LoadSigner(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	hs, _ := serverIn(t, []Source{hosted()}, s, 1<<20, readAll)
	w = do(hs, "GET", "/apt/key.asc", nil)
	if w.Code != 200 || w.Body.String() != string(s.PublicKey()) || w.Header().Get("Content-Type") != "application/pgp-keys" {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestUnknownSource(t *testing.T) {
	h := server(t, []Source{hosted()}, readAll, writeAcm)
	if w := do(h, "GET", "/apt/other/dists/bookworm/Release", nil); w.Code != 404 {
		t.Errorf("GET: %d", w.Code)
	}
	r := httptest.NewRequest("PUT", "/apt/other/bookworm/main/acme_1.0-1_amd64.deb", failBody{t})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("PUT: %d", w.Code)
	}
}

// TestSourceLabelOnlyForConfiguredSources: a name taken from the URL never
// reaches the log or metrics label, which only a configured source does.
func TestSourceLabelOnlyForConfiguredSources(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mux := http.NewServeMux()
	New([]Source{hosted()}, nil, 1<<20, t.TempDir(), log).Mount(mux)
	h := identity.Middleware(testutil.Who{Cap: hCap, Rules: []string{readAll, writeAcm}}, hCap, nil)(mux)
	for _, c := range [][2]string{{"GET", "/apt/random/dists/bookworm/Release"}, {"PUT", "/apt/random/bookworm/main/acme_1.0-1_amd64.deb"}} {
		do(h, c[0], c[1], nil)
	}
	do(h, "GET", releaseURL, nil)
	var sources []string
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		sources = append(sources, m["source"].(string))
	}
	if want := []string{"", "", "hosted"}; !slices.Equal(sources, want) {
		t.Fatalf("sources = %q, want %q", sources, want)
	}
}

func TestUploadReceivesInspectedControl(t *testing.T) {
	src := hosted()
	h := server(t, []Source{src}, writeAcm)
	b := testutil.Deb(t, "Package: acme\nVersion: 2:1.0-1\nArchitecture: amd64\nMaintainer: A <a@example.com>\nDescription: x\n", testutil.DebOptions{})
	if w := do(h, "PUT", debPath, strings.NewReader(string(b))); w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if src.lastCtl.Deb.Version != "2:1.0-1" {
		t.Fatalf("Version = %q", src.lastCtl.Deb.Version)
	}
	if m, ok := src.lastCtl.Fields.Get("Maintainer"); !ok || m != "A <a@example.com>" {
		t.Fatalf("Maintainer = %q, %v", m, ok)
	}
}

func TestMethods(t *testing.T) {
	h := server(t, []Source{hosted()}, readAll)
	w := do(h, "DELETE", releaseURL, nil)
	if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD, PUT" {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Allow"))
	}
}

func TestHeadEqualsGet(t *testing.T) {
	h := server(t, []Source{hosted()}, readAll)
	for _, p := range []string{releaseURL, "/apt/hosted/pool/acme/acme_1.0_all.deb", "/apt/preferences"} {
		g, hd := do(h, "GET", p, nil), do(h, "HEAD", p, nil)
		if hd.Code != g.Code || hd.Body.Len() != 0 {
			t.Fatalf("%s: HEAD %d body %d", p, hd.Code, hd.Body.Len())
		}
		for _, k := range []string{"Content-Type", "Content-Length", "ETag", "Last-Modified", "Cache-Control"} {
			if g.Header().Get(k) != hd.Header().Get(k) {
				t.Errorf("%s %s: GET %q HEAD %q", p, k, g.Header().Get(k), hd.Header().Get(k))
			}
		}
	}
}

func TestNotModified(t *testing.T) {
	h := server(t, []Source{hosted()}, readAll)
	for _, hdr := range [][]string{
		{"If-None-Match", `"e1"`},
		{"If-None-Match", `"x", W/"e1"`},
		{"If-Modified-Since", modified.Format(http.TimeFormat)},
	} {
		if w := do(h, "GET", releaseURL, nil, hdr...); w.Code != 304 || w.Body.Len() != 0 {
			t.Errorf("%v: %d", hdr, w.Code)
		}
	}
	for _, hdr := range [][]string{
		{"If-None-Match", `"other"`},
		{"If-Modified-Since", modified.Add(-time.Hour).Format(http.TimeFormat)},
		{"If-None-Match", `"other"`, "If-Modified-Since", modified.Format(http.TimeFormat)},
	} {
		if w := do(h, "GET", releaseURL, nil, hdr...); w.Code != 200 {
			t.Errorf("%v: %d", hdr, w.Code)
		}
	}
}

func TestSourceErrors(t *testing.T) {
	for _, c := range []struct {
		err  error
		code int
	}{
		{resolve.ErrNotFound, 404},
		{&resolve.SourceError{Source: "x", Err: errors.New("boom")}, 502},
		{&resolve.SourceError{Source: "x", Err: errors.New("slow"), Timeout: true}, 504},
		{errors.New("internal"), 500},
	} {
		src := hosted()
		src.err = c.err
		w := do(server(t, []Source{src}, readAll), "GET", releaseURL, nil)
		if w.Code != c.code {
			t.Errorf("%v: %d", c.err, w.Code)
		}
		if c.code >= 500 && strings.Contains(w.Body.String(), "boom") {
			t.Errorf("leaked: %s", w.Body)
		}
	}
}

func TestPoolPathEncoded(t *testing.T) {
	src := hosted()
	h := server(t, []Source{src}, readAll)
	if w := do(h, "GET", "/apt/hosted/pool/acme/acme_1.0%2Bgit~1_all.deb", nil); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	if len(src.pools) != 1 || src.pools[0].Deb.Version != "1.0+git~1" {
		t.Fatalf("%+v", src.pools)
	}
}

// failBody fails the test when read.
type failBody struct{ t *testing.T }

func (b failBody) Read([]byte) (int, error) {
	b.t.Helper()
	b.t.Error("request body was read")
	return 0, io.EOF
}

func TestPutRefusedBeforeBody(t *testing.T) {
	for name, c := range map[string]struct {
		rules []string
		path  string
		want  string
	}{
		"no rule":   {[]string{readAll}, debPath, "forbidden: no apt:acme write rule"},
		"unclaimed": {[]string{rule(`"*"`, `"apt:other"`)}, "/apt/hosted/bookworm/main/other_1.0-1_amd64.deb", "other is not claimed by source hosted"},
	} {
		t.Run(name, func(t *testing.T) {
			src := hosted()
			h := server(t, []Source{src}, c.rules...)
			r := httptest.NewRequest("PUT", c.path, failBody{t})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 403 || strings.TrimSpace(w.Body.String()) != c.want {
				t.Fatalf("%d %q", w.Code, w.Body)
			}
			if src.uploads != 0 {
				t.Fatal("uploaded")
			}
		})
	}
}

func TestPutRegistrySourceNotAllowed(t *testing.T) {
	h := server(t, []Source{&registryFake{hosted()}}, writeAcm)
	w := do(h, "PUT", "/apt/deb/bookworm/main/acme_1.0-1_amd64.deb", failBody{t})
	if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Allow"))
	}
}

// registryFake is a Source that is not an Uploader.
type registryFake struct{ src *fakeSource }

func (*registryFake) Name() string { return "deb" }

func (f *registryFake) Release(ctx context.Context, a ReadAccess, s, w string) (Blob, error) {
	return f.src.Release(ctx, a, s, w)
}

func (f *registryFake) Dist(ctx context.Context, a ReadAccess, s, r string) (Blob, error) {
	return f.src.Dist(ctx, a, s, r)
}

func (f *registryFake) ByHash(ctx context.Context, a ReadAccess, s, r, h string) (Blob, error) {
	return f.src.ByHash(ctx, a, s, r, h)
}

func (f *registryFake) Pool(ctx context.Context, a ReadAccess, p Path) (Blob, error) {
	return f.src.Pool(ctx, a, p)
}

func TestPutWrongControl(t *testing.T) {
	src := hosted()
	h := server(t, []Source{src}, writeAcm)
	w := do(h, "PUT", debPath, strings.NewReader(string(debFor(t, "other"))))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "Package") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	other := testutil.Deb(t, "Package: acme\nVersion: 2.0\nArchitecture: amd64\nDescription: x\n", testutil.DebOptions{})
	if w := do(h, "PUT", debPath, strings.NewReader(string(other))); w.Code != 400 || !strings.Contains(w.Body.String(), "Version") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	arch := testutil.Deb(t, "Package: acme\nVersion: 1.0-1\nArchitecture: arm64\nDescription: x\n", testutil.DebOptions{})
	if w := do(h, "PUT", debPath, strings.NewReader(string(arch))); w.Code != 400 || !strings.Contains(w.Body.String(), "Architecture") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do(h, "PUT", debPath, strings.NewReader("not a deb")); w.Code != 400 {
		t.Fatalf("%d", w.Code)
	}
	if src.uploads != 0 {
		t.Fatal("uploaded")
	}
}

func TestPutEpochAccepted(t *testing.T) {
	src := hosted()
	h := server(t, []Source{src}, writeAcm)
	b := testutil.Deb(t, "Package: acme\nVersion: 2:1.0-1\nArchitecture: amd64\nDescription: x\n", testutil.DebOptions{})
	if w := do(h, "PUT", debPath, strings.NewReader(string(b))); w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestPutTwiceAndConflict(t *testing.T) {
	src := hosted()
	h := server(t, []Source{src}, writeAcm)
	deb := string(debFor(t, "acme"))
	for i := range 2 {
		if w := do(h, "PUT", debPath, strings.NewReader(deb)); w.Code != 201 {
			t.Fatalf("put %d: %d %s", i, w.Code, w.Body)
		}
	}
	if src.uploaded["acme_1.0-1_amd64.deb"] != deb {
		t.Fatal("not stored")
	}
	other := string(testutil.Deb(t, "Package: acme\nVersion: 1.0-1\nArchitecture: amd64\nDescription: other\n", testutil.DebOptions{}))
	w := do(h, "PUT", debPath, strings.NewReader(other))
	if w.Code != 409 || strings.TrimSpace(w.Body.String()) != "acme_1.0-1_amd64.deb already exists with other content" {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
	src.exists = true
	if w := do(h, "PUT", debPath, strings.NewReader(deb)); w.Code != 409 {
		t.Fatalf("%d", w.Code)
	}
}

func TestPutOversize(t *testing.T) {
	h, dir := serverIn(t, []Source{hosted()}, nil, 100, writeAcm)
	body := strings.NewReader(strings.Repeat("x", 500))
	if w := do(h, "PUT", debPath, body); w.Code != 413 {
		t.Fatalf("%d", w.Code)
	}
	// Unknown length: the cap applies while spooling.
	r := httptest.NewRequest("PUT", debPath, io.MultiReader(strings.NewReader(strings.Repeat("x", 500))))
	r.ContentLength = -1
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("%d", w.Code)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("spool left behind: %v", ents)
	}
}

func TestViewerIsTheNode(t *testing.T) {
	src := hosted()
	h := server(t, []Source{src}, readAcme)
	if w := do(h, "GET", releaseURL, nil); w.Code != 200 {
		t.Fatalf("GET = %d", w.Code)
	}
	if src.viewer != "nid" {
		t.Errorf("Viewer = %q, want the node's stable ID", src.viewer)
	}
}

// TestNoNodeForbidden: a caller without a node stable ID has no apt client
// state of its own, so it is refused, and logged, before any source sees it.
func TestNoNodeForbidden(t *testing.T) {
	src := hosted()
	src.viewer = "none yet"
	var logs bytes.Buffer
	mux := http.NewServeMux()
	New([]Source{src}, nil, 1<<20, t.TempDir(), slog.New(slog.NewTextHandler(&logs, nil))).Mount(mux)
	noNode := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := identity.FromContext(r.Context())
		c.NodeStableID = ""
		mux.ServeHTTP(w, r.WithContext(identity.WithCaller(r.Context(), c)))
	})
	h := identity.Middleware(testutil.Who{Cap: hCap, Rules: []string{writeAcm, readAll}}, hCap, nil)(noNode)
	for _, tc := range []struct{ method, path string }{
		{"GET", releaseURL}, {"GET", "/apt/hosted/dists/bookworm/main/binary-amd64/Packages"},
		{"GET", "/apt/hosted/dists/bookworm/main/by-hash/SHA256/" + strings.Repeat("a", 64)},
		{"GET", "/apt/hosted/pool/acme/acme_1.0_all.deb"}, {"PUT", debPath},
	} {
		var body io.Reader
		if tc.method == "PUT" {
			body = bytes.NewReader(debFor(t, "acme"))
		}
		if w := do(h, tc.method, tc.path, body); w.Code != 403 {
			t.Errorf("%s %s: %d, want 403", tc.method, tc.path, w.Code)
		}
	}
	if src.viewer != "none yet" || len(src.pools) != 0 || src.uploads != 0 {
		t.Errorf("a source was asked: viewer %q, pools %v, uploads %d", src.viewer, src.pools, src.uploads)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "node stable ID") {
		t.Errorf("no warning logged:\n%s", logs.String())
	}
}
