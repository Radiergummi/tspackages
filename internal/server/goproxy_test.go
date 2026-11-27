package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/testutil"
	"tailscale.com/client/tailscale/apitype"
)

// goRepo returns a git repository holding go.mod with content gomod,
// tagged v1.0.0.
func goRepo(t *testing.T, gomod string) string {
	t.Helper()
	repo := t.TempDir()
	testutil.Git(t, repo, "init", "-q")
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	testutil.Git(t, repo, "add", "-A")
	testutil.Git(t, repo, "commit", "-q", "-m", "c")
	testutil.Git(t, repo, "tag", "v1.0.0")
	return repo
}

// startLoops runs Build's background loops until the test ends and waits
// for them, so no build writes into a temp dir being removed.
func startLoops(t *testing.T, start func(context.Context)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { start(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// eventually polls get until ok accepts its response or 30 s pass.
func eventually(t *testing.T, what string, get func() *httptest.ResponseRecorder, ok func(*httptest.ResponseRecorder) bool) *httptest.ResponseRecorder {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		w := get()
		if ok(w) {
			return w
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: last answer %d %s", what, w.Code, w.Body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestBuildWiresGo(t *testing.T) {
	repo := goRepo(t, "module github.com/acme/x\n\ngo 1.21\n")
	_, key, err := note.GenerateKey(rand.Reader, "sum.golang.org")
	if err != nil {
		t.Fatal(err)
	}
	sumdb := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(sumdb.Close)
	u, _ := url.Parse(sumdb.URL)
	cfg := fsConfig(t)
	cfg.Ecosystems["go"] = config.Ecosystem{Sources: []config.Source{
		{
			Name: "gosrc", Type: "git", Claims: []string{"github.com/acme/*"},
			Modules: map[string]config.GoModule{"github.com/acme/x": {Remote: repo}}, PollInterval: time.Hour,
		},
		{
			Name: "public", Type: "registry", URL: "https://proxy.golang.org",
			FetchHosts: []string{"proxy.golang.org", "sum.golang.org", u.Host},
		},
	}}
	h, start, err := Build(t.Context(), cfg, testutil.NewWho(testCap, `{"read":["go:*"]}`), nil, quiet, Hooks{
		AllowFileRemotes: true, AllowPrivateUpstreams: true, GoSumDB: GoSumDB{URL: sumdb.URL, Key: key},
	})
	if err != nil {
		t.Fatal(err)
	}
	startLoops(t, start)
	eventually(t, "GET list", func() *httptest.ResponseRecorder { return do(h, "GET", "/go/github.com/acme/x/@v/list", nil) },
		func(w *httptest.ResponseRecorder) bool {
			return w.Code == http.StatusOK && strings.Contains(w.Body.String(), "v1.0.0")
		})
	if w := do(h, "GET", "/go/sumdb/sum.golang.org/supported", nil); w.Code != http.StatusOK {
		t.Fatalf("GET supported = %d %s", w.Code, w.Body)
	}
	w := do(h, "GET", "/", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "go env -w GOPROXY=https://example.com/go") {
		t.Fatalf("status page lacks the Go snippet: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "sum.golang.org") {
		t.Errorf("status page lacks the checksum database row")
	}
	m := do(h, "GET", "/metrics", nil).Body.String()
	for _, want := range []string{
		`tspackages_requests_total{code="200",ecosystem="go",source="gosrc"}`,
		`tspackages_requests_total{code="200",ecosystem="go",source="sumdb"}`,
		`tspackages_git_last_sync_timestamp_seconds{ecosystem="go",source="gosrc"} 1`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

// countingServer answers every request with status and counts them.
func countingServer(t *testing.T, status int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// A path a git source claims never reaches the proxy or the checksum
// database through a later claiming registry source, whatever its case.
func TestGoGitClaimedPathNeverForwarded(t *testing.T) {
	repo := goRepo(t, "module github.com/acme/x\n\ngo 1.21\n")
	_, key, err := note.GenerateKey(rand.Reader, "sum.golang.org")
	if err != nil {
		t.Fatal(err)
	}
	sumdb, sumHits := countingServer(t, http.StatusNotFound)
	proxy, proxyHits := countingServer(t, http.StatusOK)
	su, _ := url.Parse(sumdb.URL)
	pu, _ := url.Parse(proxy.URL)
	cfg := fsConfig(t)
	cfg.Ecosystems["go"] = config.Ecosystem{Sources: []config.Source{
		{
			Name: "gosrc", Type: "git", Claims: []string{"github.com/acme/*"},
			Modules: map[string]config.GoModule{"github.com/acme/x": {Remote: repo}}, PollInterval: time.Hour,
		},
		{
			Name: "public", Type: "registry", URL: proxy.URL, Claims: []string{"*"},
			FetchHosts: []string{"sum.golang.org", pu.Host, su.Host},
		},
	}}
	h, start, err := Build(t.Context(), cfg, testutil.NewWho(testCap, `{"read":["go:*"]}`), nil, quiet, Hooks{
		AllowFileRemotes: true, AllowPrivateUpstreams: true, GoSumDB: GoSumDB{URL: sumdb.URL, Key: key},
	})
	if err != nil {
		t.Fatal(err)
	}
	startLoops(t, start)
	eventually(t, "GET list", func() *httptest.ResponseRecorder { return do(h, "GET", "/go/github.com/acme/x/@v/list", nil) },
		func(w *httptest.ResponseRecorder) bool { return w.Code == http.StatusOK })
	for _, p := range []string{
		"/go/github.com/acme/private/@v/v1.0.0.mod",
		"/go/github.com/acme/private/@v/v1.0.0.zip",
		"/go/github.com/acme/private/@v/v1.0.0.info",
		"/go/github.com/acme/private/@v/list",
		"/go/github.com/acme/private/@latest",
		"/go/github.com/!acme/private/@v/v1.0.0.mod",
		"/go/github.com/!acme/private/@v/v1.0.0.zip",
	} {
		if w := do(h, "GET", p, nil); w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d %s", p, w.Code, w.Body)
		}
	}
	w := do(h, "GET", "/go/sumdb/sum.golang.org/lookup/github.com/!acme/private@v1.0.0", nil)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "github.com/Acme/private is private: add it to GONOSUMDB") {
		t.Errorf("lookup = %d %s", w.Code, w.Body)
	}
	if n := proxyHits.Load(); n != 0 {
		t.Errorf("%d proxy requests", n)
	}
	if n := sumHits.Load(); n != 0 {
		t.Errorf("%d checksum database requests", n)
	}
}

func TestGoKeyFilesDoNotCollide(t *testing.T) {
	src := func(key string, claims ...string) config.Source {
		s := sshSource
		s.Name, s.SSHKey, s.Claims = "acme", key, claims
		return s
	}
	cfg := gitConfig(t, src("COMPOSER KEY", "acme/*"))
	cfg.Ecosystems["pypi"] = config.Ecosystem{Sources: []config.Source{src("PYPI KEY", "acme-*")}}
	goSrc := src("GO KEY", "git.example.com/acme/*")
	goSrc.Remotes = nil
	goSrc.Modules = map[string]config.GoModule{"git.example.com/acme/repo": {Remote: sshSource.Remotes[0]}}
	cfg.Ecosystems["go"] = config.Ecosystem{Sources: []config.Source{goSrc}}
	if _, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap, `{"read":["*"]}`), nil, quiet, Hooks{}); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(cfg.Storage.WorkDir, "keys")
	for p, want := range map[string]string{
		filepath.Join(keys, "acme.key"):         "COMPOSER KEY",
		filepath.Join(keys, "pypi", "acme.key"): "PYPI KEY",
		filepath.Join(keys, "go", "acme.key"):   "GO KEY",
	} {
		if b, err := os.ReadFile(p); err != nil || !strings.HasPrefix(string(b), want) {
			t.Errorf("%s: %q %v, want %s", p, b, err, want)
		}
	}
	if m := mode(t, filepath.Join(keys, "go")); !m.IsDir() || m.Perm() != 0o700 {
		t.Errorf("keys/go mode = %v, want 0700 dir", m)
	}
}

func TestGONOSUMDBSnippet(t *testing.T) {
	t.Run("git", func(t *testing.T) {
		cfg := fsConfig(t)
		cfg.Ecosystems["go"] = config.Ecosystem{Sources: []config.Source{{
			Name: "gosrc", Type: "git", Claims: []string{"github.com/acme", "github.com/acme/*"},
			Modules: map[string]config.GoModule{"github.com/Acme/SDK": {Remote: t.TempDir()}},
		}}}
		if got, want := gonosumdb(cfg.Ecosystems["go"]), "github.com/acme,github.com/Acme/SDK"; got != want {
			t.Errorf("gonosumdb = %q, want %q", got, want)
		}
		h, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap, `{"read":["go:*"]}`), nil, quiet, Hooks{AllowFileRemotes: true})
		if err != nil {
			t.Fatal(err)
		}
		body := do(h, "GET", "/", nil).Body.String()
		for _, want := range []string{
			"go env -w GOPROXY=https://example.com/go\ngo env -w GONOSUMDB=github.com/acme,github.com/Acme/SDK\ngo env -u GOPRIVATE GONOPROXY",
			"No <code>,direct</code>: a 404 for a private module would fall through to VCS.",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("status page lacks %q:\n%s", want, body)
			}
		}
		// Without a registry source there is no checksum database.
		if w := do(h, "GET", "/go/sumdb/sum.golang.org/supported", nil); w.Code != http.StatusNotFound {
			t.Errorf("GET supported without a registry source = %d, want 404", w.Code)
		}
	})
	t.Run("registry only", func(t *testing.T) {
		cfg := fsConfig(t)
		cfg.Ecosystems["go"] = config.Ecosystem{Sources: []config.Source{{
			Name: "public", Type: "registry", URL: "https://proxy.golang.org",
			FetchHosts: []string{"proxy.golang.org", "sum.golang.org"},
		}}}
		h, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap, `{"read":["go:*"]}`), nil, quiet, Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		body := do(h, "GET", "/", nil).Body.String()
		if !strings.Contains(body, "go env -w GOPROXY=https://example.com/go\ngo env -u GOPRIVATE GONOPROXY") {
			t.Errorf("status page lacks the snippet without GONOSUMDB:\n%s", body)
		}
	})
}

// whoByAddr answers WhoIs with the Who registered for the request's remote
// address.
type whoByAddr map[string]testutil.Who

func (w whoByAddr) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	return w[addr].WhoIs(ctx, addr)
}

func TestGoStatusFiltersByReadRules(t *testing.T) {
	repo := goRepo(t, "module github.com/other/y\n\ngo 1.21\n")
	cfg := fsConfig(t)
	cfg.Ecosystems["go"] = config.Ecosystem{Sources: []config.Source{{
		Name: "gosrc", Type: "git", Claims: []string{"github.com/acme/*"},
		Modules: map[string]config.GoModule{"github.com/acme/x": {Remote: repo}}, PollInterval: time.Hour,
	}}}
	who := whoByAddr{
		"192.0.2.1:1": testutil.NewWho(testCap, `{"read":["go:github.com/acme/*"]}`),
		"192.0.2.2:1": testutil.NewWho(testCap, `{"read":["go:github.com/other/*"]}`),
	}
	h, start, err := Build(t.Context(), cfg, who, nil, quiet, Hooks{AllowFileRemotes: true})
	if err != nil {
		t.Fatal(err)
	}
	startLoops(t, start)
	page := func(addr string) func() *httptest.ResponseRecorder {
		return func() *httptest.ResponseRecorder {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = addr
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w
		}
	}
	const reason = "module declares its path as github.com/other/y"
	w := eventually(t, "refusal shown to the acme reader", page("192.0.2.1:1"), func(w *httptest.ResponseRecorder) bool {
		return strings.Contains(w.Body.String(), reason)
	})
	if !strings.Contains(w.Body.String(), "gosrc "+repo) {
		t.Errorf("acme reader does not see the remote's health row:\n%s", w.Body)
	}
	other := page("192.0.2.2:1")().Body.String()
	if !strings.Contains(other, "go env -w GOPROXY") {
		t.Fatalf("other reader's page lacks the Go section:\n%s", other)
	}
	if strings.Contains(other, reason) || strings.Contains(other, repo) {
		t.Errorf("other reader sees the refusal or the remote:\n%s", other)
	}
}

func TestHostWideClaimWarns(t *testing.T) {
	cfg := fsConfig(t)
	cfg.Ecosystems["go"] = config.Ecosystem{Sources: []config.Source{{
		Name: "gosrc", Type: "git", Claims: []string{"go.acme.dev/*"},
		Modules: map[string]config.GoModule{"go.acme.dev/sdk": {Remote: t.TempDir()}},
	}}}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if _, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, log, Hooks{AllowFileRemotes: true}); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for l := range strings.Lines(buf.String()) {
		if strings.Contains(l, "go.acme.dev/*") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "level=WARN") {
		t.Fatalf("warn lines naming the claim = %q, want one", lines)
	}
}

func TestGoBuildDirSwept(t *testing.T) {
	cfg := fsConfig(t)
	dir := filepath.Join(cfg.Storage.WorkDir, "go-build")
	if err := os.MkdirAll(filepath.Join(dir, "stale"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.Storage.WorkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, quiet, Hooks{}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("go-build after Build: %v %v", entries, err)
	}
	if m := mode(t, dir); m.Perm() != 0o700 {
		t.Errorf("go-build mode = %v, want 0700", m)
	}
}
