package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/testutil"
)

const testCap = "github.com/radiergummi/tspackages"

var quiet = slog.New(slog.DiscardHandler)

func fsConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Tailscale: config.Tailscale{Hostname: "registry", Capability: testCap, StateDir: t.TempDir()},
		Storage: config.Storage{
			WorkDir: filepath.Join(t.TempDir(), "work"),
			Cache:   config.StoreConfig{Driver: "fs", Path: t.TempDir(), MaxSize: 1 << 30},
			State:   config.StoreConfig{Driver: "fs", Path: t.TempDir()},
			Stores:  map[string]config.StoreConfig{"main": {Driver: "fs", Path: t.TempDir()}},
		},
		Limits: config.Limits{
			MaxUploadBytes: 1 << 20, MaxDecompressedBytes: 16 << 20, MaxArchiveEntries: 1000,
			RequestsPerSecond: 1000, Burst: 1000, UpstreamFetchesPerSecond: 10,
		},
		Ecosystems: map[string]config.Ecosystem{},
	}
}

func do(h http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, body))
	return w
}

func TestBuildRejectsInvalidConfig(t *testing.T) {
	cfg := fsConfig(t)
	cfg.Storage.Stores["remote"] = config.StoreConfig{
		Driver: "s3", Bucket: "b", Endpoint: "http://127.0.0.1:1", Region: "us-east-1",
		AccessKeyID: "k", SecretAccessKey: "s",
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _, err := Build(ctx, cfg, testutil.NewWho(testCap), nil, quiet, Hooks{})
	if err == nil || !strings.Contains(err.Error(), "storage.stores.remote") {
		t.Fatalf("Build error = %v, want one naming storage.stores.remote", err)
	}
}

func TestBuildServes(t *testing.T) {
	h, _, err := Build(t.Context(), fsConfig(t), testutil.NewWho(testCap, `{"read":["*"]}`), nil, quiet, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if w := do(h, "GET", "/healthz", nil); w.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", "/readyz", nil); w.Code != http.StatusOK {
		t.Fatalf("GET /readyz = %d %s", w.Code, w.Body)
	}
}

func TestBuildWiresComposer(t *testing.T) {
	cfg := fsConfig(t)
	cfg.Ecosystems["composer"] = config.Ecosystem{Sources: []config.Source{
		{Name: "hosted", Type: "storage", Claims: []string{"acme/*"}, Store: "main"},
	}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h, start, err := Build(ctx, cfg, testutil.NewWho(testCap, `{"read":["*"],"write":["composer:acme/*"]}`), nil, quiet, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	go start(ctx)
	if w := do(h, "PUT", "/composer/upload/acme/pkg/1.0.0", bytes.NewReader(testutil.ZipOf(t, map[string]string{"composer.json": `{"name":"acme/pkg","description":"x"}`}))); w.Code != http.StatusCreated {
		t.Fatalf("PUT upload = %d %s", w.Code, w.Body)
	}
	w := do(h, "GET", "/composer/p2/acme/pkg.json", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"1.0.0"`) {
		t.Fatalf("GET p2 = %d %s", w.Code, w.Body)
	}
}

func gitConfig(t *testing.T, sources ...config.Source) *config.Config {
	t.Helper()
	cfg := fsConfig(t)
	cfg.Ecosystems["composer"] = config.Ecosystem{Sources: sources}
	return cfg
}

var sshSource = config.Source{
	Name: "internal", Type: "git", Claims: []string{"acme/*"},
	Remotes:    []string{"ssh://git@git.example.com/acme/repo.git"},
	SSHKey:     "PRIVATE KEY MATERIAL",
	KnownHosts: "git.example.com ssh-ed25519 AAAA",
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode()
}

func TestBuildWritesSSHKeyFiles(t *testing.T) {
	cfg := gitConfig(t, sshSource)
	keys := filepath.Join(cfg.Storage.WorkDir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(keys, "old-0.key")
	if err := os.WriteFile(stray, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, quiet, Hooks{}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{cfg.Storage.WorkDir, keys, filepath.Join(cfg.Storage.WorkDir, "git")} {
		if m := mode(t, d); !m.IsDir() || m.Perm() != 0o700 {
			t.Errorf("%s mode = %v, want 0700 dir", d, m)
		}
	}
	want := map[string]string{
		"internal.key":         "PRIVATE KEY MATERIAL\n",
		"internal.known_hosts": "git.example.com ssh-ed25519 AAAA\n",
	}
	files, _ := os.ReadDir(keys)
	if len(files) != len(want) {
		t.Fatalf("key files = %v, want %d (stray file must be removed)", files, len(want))
	}
	for name, content := range want {
		p := filepath.Join(keys, name)
		if m := mode(t, p); m.Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", p, m)
		}
		if data, _ := os.ReadFile(p); string(data) != content {
			t.Errorf("%s = %q, want %q", p, data, content)
		}
	}
}

// captureMirrors records every mirror Build creates.
func captureMirrors(t *testing.T) *[]*gitmirror.Mirror {
	t.Helper()
	var got []*gitmirror.Mirror
	old := onMirror
	onMirror = func(m *gitmirror.Mirror) { got = append(got, m) }
	t.Cleanup(func() { onMirror = old })
	return &got
}

func TestBuildMirrorDirStable(t *testing.T) {
	got := captureMirrors(t)
	cfg := gitConfig(t, sshSource)
	for range 2 {
		if _, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, quiet, Hooks{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(*got) != 2 || (*got)[0].Dir() != (*got)[1].Dir() {
		t.Fatalf("mirror dirs across restarts = %v", *got)
	}
	if !strings.HasPrefix((*got)[0].Dir(), filepath.Join(cfg.Storage.WorkDir, "git")+"/") {
		t.Errorf("mirror dir %s not under work_dir/git", (*got)[0].Dir())
	}
}

func TestBuildSharesMirrors(t *testing.T) {
	got := captureMirrors(t)
	remote := []string{"https://git.example.com/acme/repo.git"}
	cfg := gitConfig(t,
		config.Source{Name: "a", Type: "git", Claims: []string{"acme/a"}, Remotes: remote},
		config.Source{Name: "b", Type: "git", Claims: []string{"acme/b"}, Remotes: remote},
		config.Source{Name: "c", Type: "git", Claims: []string{"acme/c"}, Remotes: remote, Token: "t"},
	)
	if _, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, quiet, Hooks{}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 {
		t.Fatalf("mirrors created = %d, want 2 (a and b share one, c has a token)", len(*got))
	}

	set := mirrorSet{}
	o := gitmirror.Options{Remote: remote[0], BaseDir: t.TempDir()}
	m1, err1 := set.get(o)
	m2, err2 := set.get(o)
	if err1 != nil || err2 != nil || m1 != m2 {
		t.Fatalf("same options gave %p, %p (%v, %v); want one shared *Mirror", m1, m2, err1, err2)
	}
}

func TestBuildRejectsPathInSourceName(t *testing.T) {
	src := sshSource
	src.Name = "../escape"
	_, _, err := Build(t.Context(), gitConfig(t, src), testutil.NewWho(testCap), nil, quiet, Hooks{})
	if err == nil || !strings.Contains(err.Error(), "invalid source name") {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildPrunesUnknownMirrorDirs(t *testing.T) {
	got := captureMirrors(t)
	cfg := gitConfig(t, sshSource)
	if _, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, quiet, Hooks{}); err != nil {
		t.Fatal(err)
	}
	gitDir := filepath.Join(cfg.Storage.WorkDir, "git")
	keep := (*got)[0].Dir()
	stray := []string{filepath.Join(gitDir, "0123456789abcdef.git"), keep + ".tmp", filepath.Join(gitDir, "file")}
	for _, d := range append([]string{keep}, stray[:2]...) {
		if err := os.MkdirAll(filepath.Join(d, "objects"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(stray[2], nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, quiet, Hooks{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("configured mirror removed: %v", err)
	}
	for _, p := range stray {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s not pruned", p)
		}
	}
}

func TestBuildRejectsUnsafeWorkDir(t *testing.T) {
	t.Run("too wide", func(t *testing.T) {
		cfg := fsConfig(t)
		if err := os.MkdirAll(cfg.Storage.WorkDir, 0o755); err != nil {
			t.Fatal(err)
		}
		os.Chmod(cfg.Storage.WorkDir, 0o755)
		_, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, quiet, Hooks{})
		if err == nil || !strings.Contains(err.Error(), cfg.Storage.WorkDir) {
			t.Fatalf("err = %v, want one naming %s", err, cfg.Storage.WorkDir)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		cfg := fsConfig(t)
		target := t.TempDir()
		if err := os.Symlink(target, cfg.Storage.WorkDir); err != nil {
			t.Fatal(err)
		}
		_, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, quiet, Hooks{})
		if err == nil || !strings.Contains(err.Error(), cfg.Storage.WorkDir) {
			t.Fatalf("err = %v, want one naming %s", err, cfg.Storage.WorkDir)
		}
	})
	t.Run("keys subdir too wide", func(t *testing.T) {
		cfg := fsConfig(t)
		keys := filepath.Join(cfg.Storage.WorkDir, "keys")
		if err := os.MkdirAll(keys, 0o700); err != nil {
			t.Fatal(err)
		}
		os.Chmod(keys, 0o750)
		_, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, quiet, Hooks{})
		if err == nil || !strings.Contains(err.Error(), keys) {
			t.Fatalf("err = %v, want one naming %s", err, keys)
		}
	})
}

func TestBuildAppliesDefaults(t *testing.T) {
	cfg := fsConfig(t)
	cfg.Limits = config.Limits{}
	cfg.Tailscale = config.Tailscale{StateDir: cfg.Tailscale.StateDir}
	if _, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, quiet, Hooks{}); err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.RequestsPerSecond != 50 || cfg.Limits.MaxArtifactBytes != 8<<30 || cfg.Tailscale.Capability != testCap {
		t.Fatalf("defaults not applied: %+v %+v", cfg.Limits, cfg.Tailscale)
	}
}

// start runs the background loops until ctx ends and returns only once they
// have stopped, so callers can wait for them before removing work_dir.
func TestStartReturnsAfterLoopsStop(t *testing.T) {
	cfg := gitConfig(t, config.Source{Name: "g", Type: "git", Claims: []string{"acme/*"}, Remotes: []string{t.TempDir()}, PollInterval: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, start, err := Build(ctx, cfg, testutil.NewWho(testCap), nil, quiet, Hooks{AllowFileRemotes: true})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { start(ctx); close(done) }()
	select {
	case <-done:
		t.Fatal("start returned before ctx ended")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("start did not return after ctx ended")
	}
}

func pypiUpload(t *testing.T, name, version, filename string, content []byte) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range map[string]string{":action": "file_upload", "name": name, "version": version} {
		mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("content", filename)
	fw.Write(content)
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestBuildWiresPyPI(t *testing.T) {
	cfg := fsConfig(t)
	cfg.Ecosystems["pypi"] = config.Ecosystem{Sources: []config.Source{
		{Name: "hosted", Type: "storage", Claims: []string{"acme-*"}, Store: "main"},
		{Name: "pypi", Type: "registry", URL: "https://pypi.org/simple/", FetchHosts: []string{"pypi.org", "files.pythonhosted.org"}},
	}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h, start, err := Build(ctx, cfg, testutil.NewWho(testCap, `{"read":["*"],"write":["pypi:acme-*"]}`), nil, quiet, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	go start(ctx)
	meta := "Metadata-Version: 2.1\nName: acme-core\nVersion: 1.0.0\n"
	whl := testutil.ZipOf(t, map[string]string{"acme_core/__init__.py": "", "acme_core-1.0.0.dist-info/METADATA": meta})
	body, ct := pypiUpload(t, "acme-core", "1.0.0", "acme_core-1.0.0-py3-none-any.whl", whl)
	r := httptest.NewRequest("POST", "/pypi/legacy/", body)
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("upload = %d %s", w.Code, w.Body)
	}
	w = do(h, "GET", "/pypi/simple/acme-core/", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "acme_core-1.0.0-py3-none-any.whl") {
		t.Fatalf("index = %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", "/", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/pypi/simple/") {
		t.Fatalf("status page lacks the PyPI snippet: %d", w.Code)
	}
	entries, err := os.ReadDir(filepath.Join(cfg.Storage.WorkDir, "uploads"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("upload spool: %v %v", entries, err)
	}
	if st, err := os.Stat(filepath.Join(cfg.Storage.WorkDir, "uploads")); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("upload spool mode: %v %v", st, err)
	}
}

// A composer and a pypi git source may share a name, and a composer source
// may be named like a prefixed pypi one; their key files must not collide.
func TestBuildPyPIKeyFilesDoNotCollide(t *testing.T) {
	prefixed := sshSource
	prefixed.Name, prefixed.SSHKey, prefixed.Claims = "pypi-internal", "PREFIXED KEY", []string{"other/*"}
	cfg := gitConfig(t, sshSource, prefixed)
	pypiSSH := sshSource
	pypiSSH.SSHKey = "PYPI KEY"
	pypiSSH.Claims = []string{"acme-*"}
	cfg.Ecosystems["pypi"] = config.Ecosystem{Sources: []config.Source{pypiSSH}}
	got := captureMirrors(t)
	if _, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap, `{"read":["*"]}`), nil, quiet, Hooks{}); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(cfg.Storage.WorkDir, "keys")
	for p, want := range map[string]string{
		filepath.Join(keys, "internal.key"):         "PRIVATE KEY MATERIAL",
		filepath.Join(keys, "pypi-internal.key"):    "PREFIXED KEY",
		filepath.Join(keys, "pypi", "internal.key"): "PYPI KEY",
	} {
		if b, err := os.ReadFile(p); err != nil || !strings.HasPrefix(string(b), want) {
			t.Errorf("%s: %q %v, want %s", p, b, err, want)
		}
	}
	if m := mode(t, filepath.Join(keys, "pypi")); !m.IsDir() || m.Perm() != 0o700 {
		t.Errorf("keys/pypi mode = %v, want 0700 dir", m)
	}
	if len(*got) != 3 {
		t.Fatalf("%d mirrors, want 3", len(*got))
	}
}

func TestBuildersCoverEveryEcosystem(t *testing.T) {
	var names []string
	for _, b := range builders {
		names = append(names, b.name)
	}
	slices.Sort(names)
	want := config.SupportedEcosystems()
	if !slices.Equal(names, want) {
		t.Fatalf("builders = %v, config.SupportedEcosystems = %v", names, want)
	}
}

func TestBuildNPM(t *testing.T) {
	cfg := fsConfig(t)
	cfg.Ecosystems["npm"] = config.Ecosystem{Sources: []config.Source{
		{Name: "hosted", Type: "storage", Claims: []string{"@example/*"}, Store: "main"},
		{Name: "npmjs", Type: "registry", URL: "https://registry.npmjs.org/", FetchHosts: []string{"registry.npmjs.org"}},
	}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h, start, err := Build(ctx, cfg, testutil.NewWho(testCap, `{"read":["npm:@example/*"]}`), nil, quiet, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	go start(ctx)
	if w := do(h, "GET", "/npm/@example%2fx", nil); w.Code != http.StatusNotFound {
		t.Fatalf("claimed missing package = %d %s", w.Code, w.Body)
	}
	if w := do(h, "POST", "/-/npm/v1/oidc/token/exchange/package/x", nil); w.Code != http.StatusNotFound {
		t.Fatalf("oidc exchange at the root = %d", w.Code)
	}
	if w := do(h, "GET", "/", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/npm/") {
		t.Fatalf("status page lacks the npm snippet: %d", w.Code)
	}
}

func TestBuildMaven(t *testing.T) {
	cfg := fsConfig(t)
	cfg.Ecosystems["maven"] = config.Ecosystem{Sources: []config.Source{
		{Name: "hosted", Type: "storage", Claims: []string{"com.example", "com.example.*"}, Store: "main"},
		{Name: "central", Type: "registry", URL: "https://repo.maven.apache.org/maven2/", FetchHosts: []string{"repo.maven.apache.org"}},
	}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h, start, err := Build(ctx, cfg, testutil.NewWho(testCap, `{"read":["maven:com.example","maven:com.example.*"],"write":["maven:com.example","maven:com.example.*"]}`), nil, quiet, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	go start(ctx)
	if w := do(h, "GET", "/maven/com/example/x/maven-metadata.xml", nil); w.Code != http.StatusNotFound {
		t.Fatalf("claimed missing artifact = %d %s", w.Code, w.Body)
	}
	if w := do(h, "PUT", "/maven//com/example/x/1.0/x-1.0.jar", strings.NewReader("x")); w.Code != http.StatusCreated {
		t.Fatalf("PUT with a doubled slash = %d %s, want 201", w.Code, w.Body)
	}
	if w := do(h, "GET", "/", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/maven/") {
		t.Fatalf("status page lacks the maven snippet: %d", w.Code)
	}
}

// tailnetConn reports a Tailscale address as its remote end, as a tsnet
// connection to a tailnet host does.
type tailnetConn struct{ net.Conn }

func (tailnetConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 443}
}

// loopbackTailnet dials over loopback but looks like a tailnet dial.
func loopbackTailnet(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return tailnetConn{c}, nil
}

func githubKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

// githubFake is a GitHub Enterprise Server API whose App installation sees
// acme/lib, whose release v1.0.0 carries a claimed wheel and an unclaimed
// sdist, both with digests.
func githubFake(t *testing.T) *httptest.Server {
	t.Helper()
	sum := strings.Repeat("ab", 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Ratelimit-Remaining", "4990")
		w.Header().Set("X-Ratelimit-Reset", "1900000000")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v3/app/installations/2/access_tokens":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"token":"tok","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		case r.URL.Path == "/api/v3/installation/repositories":
			io.WriteString(w, `{"repositories":[{"id":10,"full_name":"acme/lib"}]}`)
		case r.URL.Path == "/api/v3/repos/acme/lib/releases":
			fmt.Fprintf(w, `[{"id":1,"tag_name":"v1.0.0","created_at":"2026-01-01T00:00:00Z","assets":[
				{"id":100,"name":"acme_lib-1.0.0-py3-none-any.whl","state":"uploaded","digest":"sha256:%[1]s","size":3,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},
				{"id":101,"name":"other_pkg-1.0.0.tar.gz","state":"uploaded","digest":"sha256:%[1]s","size":3,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}]}]`, sum)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func githubConfig(t *testing.T, apiURL string) *config.Config {
	t.Helper()
	cfg := fsConfig(t)
	cfg.Ecosystems["pypi"] = config.Ecosystem{Sources: []config.Source{{
		Name: "gh", Type: "github", URL: apiURL, Claims: []string{"acme-*"},
		AppID: 1, InstallationID: 2, PrivateKey: githubKeyPEM(t),
	}}}
	return cfg
}

func TestBuildGitHubSource(t *testing.T) {
	api := githubFake(t)
	cfg := githubConfig(t, api.URL+"/api/v3/")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h, start, err := Build(ctx, cfg, testutil.NewWho(testCap, `{"read":["*"]}`), loopbackTailnet, quiet,
		Hooks{AllowPrivateUpstreams: true})
	if err != nil {
		t.Fatal(err)
	}
	go start(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for {
		w := do(h, "GET", "/pypi/simple/acme-lib/", nil)
		if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "acme_lib-1.0.0-py3-none-any.whl") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("index = %d %s", w.Code, w.Body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	m := do(h, "GET", "/metrics", nil).Body.String()
	for _, want := range []string{
		`tspackages_github_index_passes_total{result="ok",source="gh"}`,
		`tspackages_github_api_requests_total{source="gh",status="201"}`,
		`tspackages_github_api_requests_total{source="gh",status="200"}`,
		`tspackages_github_ratelimit_remaining{source="gh"} 4990`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("/metrics lacks %s", want)
		}
	}
	page := do(h, "GET", "/", nil).Body.String()
	for _, want := range []string{"acme-lib", "acme/lib", "indexed at ", "installation 2, 1 repositories granted", "1 unclaimed assets skipped"} {
		if !strings.Contains(page, want) {
			t.Errorf("status page lacks %q", want)
		}
	}
	if strings.Contains(page, "other_pkg-1.0.0.tar.gz") {
		t.Error("status page lists an unclaimed asset")
	}
}

// TestGitHubStatusFiltersByReadRules: the github tables' rows are shown only
// to callers who may read their package.
func TestGitHubStatusFiltersByReadRules(t *testing.T) {
	api := githubFake(t)
	cfg := githubConfig(t, api.URL+"/api/v3/")
	who := whoByAddr{
		"192.0.2.1:1": testutil.NewWho(testCap, `{"read":["pypi:acme-*"]}`),
		"192.0.2.2:1": testutil.NewWho(testCap, `{"read":["pypi:other-*"]}`),
	}
	h, start, err := Build(t.Context(), cfg, who, loopbackTailnet, quiet, Hooks{AllowPrivateUpstreams: true})
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
	eventually(t, "the owner row shown to the acme reader", page("192.0.2.1:1"), func(w *httptest.ResponseRecorder) bool {
		return strings.Contains(w.Body.String(), "acme/lib")
	})
	other := page("192.0.2.2:1")().Body.String()
	if !strings.Contains(other, "GitHub release names") || !strings.Contains(other, "indexed at ") {
		t.Fatalf("other reader's page lacks the github tables or the health row:\n%s", other)
	}
	if strings.Contains(other, "acme-lib") || strings.Contains(other, "acme/lib") {
		t.Errorf("other reader sees the acme rows:\n%s", other)
	}
}

// Uploading a name only a github source claims gets the answer of any
// claimed name without a storage source.
func TestUploadToGitHubClaimedName(t *testing.T) {
	api := githubFake(t)
	cfg := githubConfig(t, api.URL+"/api/v3/")
	who := testutil.NewWho(testCap, `{"read":["*"],"write":["pypi:acme-*"]}`)
	h, _, err := Build(t.Context(), cfg, who, loopbackTailnet, quiet, Hooks{AllowPrivateUpstreams: true})
	if err != nil {
		t.Fatal(err)
	}
	meta := "Metadata-Version: 2.1\nName: acme-lib\nVersion: 2.0.0\n"
	whl := testutil.ZipOf(t, map[string]string{"acme_lib/__init__.py": "", "acme_lib-2.0.0.dist-info/METADATA": meta})
	body, ct := pypiUpload(t, "acme-lib", "2.0.0", "acme_lib-2.0.0-py3-none-any.whl", whl)
	r := httptest.NewRequest("POST", "/pypi/legacy/", body)
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `no storage source claims "acme-lib"`) {
		t.Fatalf("upload = %d %s", w.Code, w.Body)
	}
}

func TestBuildGHESNeedsDialer(t *testing.T) {
	cfg := githubConfig(t, "https://ghe.example.com/api/v3/")
	_, _, err := Build(t.Context(), cfg, testutil.NewWho(testCap), nil, quiet, Hooks{})
	if err == nil || err.Error() != `pypi source "gh": GitHub Enterprise Server needs the tailnet dialer` {
		t.Fatalf("err = %v", err)
	}
}
