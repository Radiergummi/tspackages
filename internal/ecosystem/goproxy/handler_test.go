package goproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tailcfg/peercap"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/testutil"
)

const hCap peercap.Cap = "github.com/radiergummi/tspackages"

const readAll = `{"read":["*"]}`

type fakeSource struct {
	name     string
	claims   []string
	versions []string
	info     Info
	mod, zip []byte
	zipBody  func() io.ReadCloser // overrides zip
	err      error                // returned by every method when set
	missing  bool                 // every method misses
	calls    atomic.Int32
	paths    []string
}

func (f *fakeSource) Name() string     { return f.name }
func (f *fakeSource) Claims() []string { return f.claims }

func (f *fakeSource) enter(path string) error {
	f.calls.Add(1)
	f.paths = append(f.paths, path)
	if f.err != nil {
		return f.err
	}
	if f.missing {
		return fmt.Errorf("%w: %s", resolve.ErrNotFound, path)
	}
	return nil
}

func (f *fakeSource) List(_ context.Context, p string) ([]string, error) {
	return f.versions, f.enter(p)
}

func (f *fakeSource) Info(_ context.Context, p, _ string) (Info, error) { return f.info, f.enter(p) }
func (f *fakeSource) Latest(_ context.Context, p string) (Info, error)  { return f.info, f.enter(p) }

func (f *fakeSource) Mod(_ context.Context, p, _ string) (Artifact, error) {
	if err := f.enter(p); err != nil {
		return Artifact{}, err
	}
	return Artifact{Body: io.NopCloser(bytes.NewReader(f.mod)), Size: int64(len(f.mod))}, nil
}

func (f *fakeSource) Zip(_ context.Context, p, _ string) (Artifact, error) {
	if err := f.enter(p); err != nil {
		return Artifact{}, err
	}
	if f.zipBody != nil {
		return Artifact{Body: f.zipBody(), Size: int64(len(f.zip))}, nil
	}
	return Artifact{Body: nopSeeker{bytes.NewReader(f.zip)}, Size: int64(len(f.zip))}, nil
}

type nopSeeker struct{ *bytes.Reader }

func (nopSeeker) Close() error { return nil }

type fakeSumDB struct{ got []string }

func (s *fakeSumDB) ServeSumDB(w http.ResponseWriter, _ *http.Request, _ identity.Caller, rest string) {
	s.got = append(s.got, rest)
	_, _ = io.WriteString(w, "sumdb:"+rest)
}

func server(t *testing.T, srcs []Source, sumdb SumDB, rules ...string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	New(srcs, sumdb, slog.New(slog.DiscardHandler)).Mount(mux)
	return identity.Middleware(testutil.Who{Cap: hCap, Rules: rules}, hCap, nil)(mux)
}

func do(h http.Handler, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func one(f *fakeSource) []Source { return []Source{f} }

func TestListContentType(t *testing.T) {
	f := &fakeSource{name: "s", versions: []string{"v1.0.0", "v1.1.0"}}
	w := do(server(t, one(f), nil, readAll), "GET", "/go/github.com/acme/x/@v/list")
	if w.Code != 200 || w.Body.String() != "v1.0.0\nv1.1.0\n" || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("%d %q %q", w.Code, w.Body, w.Header().Get("Content-Type"))
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("no nosniff")
	}
}

func TestListEmpty(t *testing.T) {
	w := do(server(t, one(&fakeSource{name: "s"}), nil, readAll), "GET", "/go/github.com/acme/x/@v/list")
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
}

func TestInfoJSON(t *testing.T) {
	f := &fakeSource{name: "s", info: Info{Version: "v1.0.0", Time: time.Date(2026, 1, 2, 4, 4, 5, 0, time.FixedZone("x", 3600))}}
	h := server(t, one(f), nil, readAll)
	for _, p := range []string{"/go/github.com/acme/x/@v/v1.0.0.info", "/go/github.com/acme/x/@v/main.info", "/go/github.com/acme/x/@latest"} {
		w := do(h, "GET", p)
		const want = `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`
		if w.Code != 200 || w.Body.String() != want || w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: %d %q %q", p, w.Code, w.Body, w.Header().Get("Content-Type"))
		}
	}
}

func TestModAndZip(t *testing.T) {
	f := &fakeSource{name: "s", mod: []byte("module x\n"), zip: []byte("ZIPBYTES")}
	h := server(t, one(f), nil, readAll)
	w := do(h, "GET", "/go/github.com/acme/x/@v/v1.0.0.mod")
	if w.Code != 200 || w.Body.String() != "module x\n" || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("mod: %d %q %q", w.Code, w.Body, w.Header().Get("Content-Type"))
	}
	w = do(h, "GET", "/go/github.com/acme/x/@v/v1.0.0.zip")
	if w.Code != 200 || w.Body.String() != "ZIPBYTES" || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("zip: %d %q %q", w.Code, w.Body, w.Header().Get("Content-Type"))
	}
	r := httptest.NewRequest("GET", "/go/github.com/acme/x/@v/v1.0.0.zip", nil)
	r.Header.Set("Range", "bytes=0-2")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusPartialContent || w.Body.String() != "ZIP" {
		t.Fatalf("range: %d %q", w.Code, w.Body)
	}
}

func TestPlusIncompatibleIsCanonical(t *testing.T) {
	f := &fakeSource{name: "s", mod: []byte("module x\n")}
	w := do(server(t, one(f), nil, readAll), "GET", "/go/github.com/acme/x/@v/v2.0.0+incompatible.mod")
	if w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
}

func TestUnknownVersion404(t *testing.T) {
	f := &fakeSource{name: "s", missing: true}
	w := do(server(t, one(f), nil, readAll), "GET", "/go/github.com/acme/x/@v/v1.0.0.info")
	if w.Code != 404 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestUnavailable502(t *testing.T) {
	f := &fakeSource{name: "s", err: fmt.Errorf("%w: conflict", ErrUnavailable)}
	w := do(server(t, one(f), nil, readAll), "GET", "/go/github.com/acme/x/@v/list")
	if w.Code != 502 {
		t.Fatalf("%d", w.Code)
	}
}

func TestLatestUntagged404(t *testing.T) {
	f := &fakeSource{name: "s", missing: true}
	w := do(server(t, one(f), nil, readAll), "GET", "/go/github.com/acme/x/@latest")
	if w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
}

func TestNonCanonicalZip404(t *testing.T) {
	f := &fakeSource{name: "s", mod: []byte("m"), zip: []byte("z")}
	h := server(t, one(f), nil, readAll)
	for _, p := range []string{
		"/go/github.com/acme/x/@v/main.zip", "/go/github.com/acme/x/@v/main.mod",
		"/go/github.com/acme/x/@v/v1.0.zip", "/go/github.com/acme/x/@v/v1.0.0.info.zip",
		"/go/github.com/acme/x/@v/%20x.mod", "/go/github.com/acme/x/@v/%20x.info",
	} {
		if w := do(h, "GET", p); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatalf("source called %d times", f.calls.Load())
	}
}

func TestForbidden403(t *testing.T) {
	f := &fakeSource{name: "s"}
	w := do(server(t, one(f), nil, `{"read":["go:github.com/other/*"]}`), "GET", "/go/github.com/!acme/!x/@v/list")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "go:github.com/acme/x") {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
	if f.calls.Load() != 0 {
		t.Fatal("source called")
	}
}

func TestReadRuleOnLowercasedPath(t *testing.T) {
	f := &fakeSource{name: "s", versions: []string{"v1.0.0"}}
	w := do(server(t, one(f), nil, `{"read":["go:github.com/acme/*"]}`), "GET", "/go/github.com/!acme/!x/@v/list")
	if w.Code != 200 || f.paths[0] != "github.com/Acme/X" {
		t.Fatalf("%d %v", w.Code, f.paths)
	}
}

// Review Focus 1.
func TestMixedCaseClaimedNeverFallsThrough(t *testing.T) {
	git := &fakeSource{name: "git", claims: []string{"github.com/acme/*"}, missing: true}
	reg := &fakeSource{name: "registry", versions: []string{"v9.9.9"}}
	w := do(server(t, []Source{git, reg}, nil, readAll), "GET", "/go/github.com/!acme/x/@v/list")
	if w.Code != 404 || git.calls.Load() != 1 || reg.calls.Load() != 0 {
		t.Fatalf("%d git=%d reg=%d", w.Code, git.calls.Load(), reg.calls.Load())
	}
}

func TestHeadIs405(t *testing.T) {
	f := &fakeSource{name: "s", versions: []string{"v1.0.0"}}
	w := do(server(t, one(f), nil, readAll), "HEAD", "/go/github.com/acme/x/@v/list")
	if w.Code != http.StatusMethodNotAllowed || f.calls.Load() != 0 {
		t.Fatalf("%d", w.Code)
	}
}

func TestSumDBRoutedWithoutParse(t *testing.T) {
	sd := &fakeSumDB{}
	f := &fakeSource{name: "s"}
	w := do(server(t, one(f), sd, readAll), "GET", "/go/sumdb/sum.golang.org/supported")
	if w.Code != 200 || w.Body.String() != "sumdb:sum.golang.org/supported" || f.calls.Load() != 0 {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
	w = do(server(t, one(f), nil, readAll), "GET", "/go/sumdb/sum.golang.org/supported")
	if w.Code != 404 {
		t.Fatalf("nil sumdb: %d", w.Code)
	}
}

// net/http decodes the path once; the handler parses that, so a percent-encoded
// request names the same module as its literal form and nothing is decoded twice.
func TestPercentEncodedPathDecodedOnce(t *testing.T) {
	f := &fakeSource{name: "s", versions: []string{"v1.0.0"}}
	h := server(t, one(f), nil, readAll)
	for _, p := range []string{
		"/go/github.com/!acme/x/@v/list",
		"/go/github.com/%21acme/x/%40v/list",
	} {
		if w := do(h, "GET", p); w.Code != 200 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if len(f.paths) != 2 || f.paths[0] != "github.com/Acme/x" || f.paths[1] != "github.com/Acme/x" {
		t.Fatalf("%v", f.paths)
	}
	// "%2521" decodes once to "%21", which is no module path.
	if w := do(h, "GET", "/go/github.com/%2521acme/x/@v/list"); w.Code != 404 || len(f.paths) != 2 {
		t.Fatalf("double-encoded: %d %v", w.Code, f.paths)
	}
}

type failingBody struct{ n int }

func (b *failingBody) Read(p []byte) (int, error) {
	if b.n > 0 {
		b.n = 0
		return copy(p, "PART"), nil
	}
	return 0, errors.New("boom")
}
func (b *failingBody) Close() error { return nil }

func TestZipAbortsOnMidStreamError(t *testing.T) {
	f := &fakeSource{name: "s", zip: []byte("ZIPBYTES"), zipBody: func() io.ReadCloser { return &failingBody{n: 1} }}
	h := server(t, one(f), nil, readAll)
	defer func() {
		r := recover()
		if err, _ := r.(error); !errors.Is(err, http.ErrAbortHandler) {
			t.Fatalf("recovered %v, want http.ErrAbortHandler", r)
		}
	}()
	do(h, "GET", "/go/github.com/acme/x/@v/v1.0.0.zip")
	t.Fatal("handler returned normally")
}
