package server

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/gitmirror"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

const testCap = "github.com/radiergummi/tspackages"

type fakeWho struct{ rules []string }

func (f fakeWho) WhoIs(context.Context, string) (*apitype.WhoIsResponse, error) {
	var vals []tailcfg.RawMessage
	for _, r := range f.rules {
		vals = append(vals, tailcfg.RawMessage(r))
	}
	return &apitype.WhoIsResponse{
		Node:   &tailcfg.Node{Name: "ci.ts.net.", StableID: "nid", Tags: []string{"tag:ci"}},
		CapMap: tailcfg.PeerCapMap{testCap: vals},
	}, nil
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func fsConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Tailscale: config.Tailscale{Hostname: "registry", Capability: testCap},
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
	_, _, err := Build(ctx, cfg, fakeWho{}, quiet, Hooks{})
	if err == nil || !strings.Contains(err.Error(), "storage.stores.remote") {
		t.Fatalf("Build error = %v, want one naming storage.stores.remote", err)
	}
}

func TestBuildServes(t *testing.T) {
	h, _, err := Build(t.Context(), fsConfig(t), fakeWho{}, quiet, Hooks{})
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

func pkgZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("composer.json")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(f, `{"name":"acme/pkg","description":"x"}`)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestBuildWiresComposer(t *testing.T) {
	cfg := fsConfig(t)
	cfg.Ecosystems["composer"] = config.Ecosystem{Sources: []config.Source{
		{Name: "hosted", Type: "storage", Claims: []string{"acme/*"}, Store: "main"},
	}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h, start, err := Build(ctx, cfg, fakeWho{rules: []string{`{"read":["*"],"write":["composer:acme/*"]}`}}, quiet, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	start(ctx)
	if w := do(h, "PUT", "/composer/upload/acme/pkg/1.0.0", bytes.NewReader(pkgZip(t))); w.Code != http.StatusCreated {
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
	if _, _, err := Build(t.Context(), cfg, fakeWho{}, quiet, Hooks{}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{cfg.Storage.WorkDir, keys, filepath.Join(cfg.Storage.WorkDir, "git")} {
		if m := mode(t, d); !m.IsDir() || m.Perm() != 0o700 {
			t.Errorf("%s mode = %v, want 0700 dir", d, m)
		}
	}
	want := map[string]string{
		"internal-0.key":         "PRIVATE KEY MATERIAL\n",
		"internal-0.known_hosts": "git.example.com ssh-ed25519 AAAA\n",
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
		if _, _, err := Build(t.Context(), cfg, fakeWho{}, quiet, Hooks{}); err != nil {
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
	if _, _, err := Build(t.Context(), cfg, fakeWho{}, quiet, Hooks{}); err != nil {
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
	_, _, err := Build(t.Context(), gitConfig(t, src), fakeWho{}, quiet, Hooks{})
	if err == nil || !strings.Contains(err.Error(), "path separator") {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildRejectsUnsafeWorkDir(t *testing.T) {
	t.Run("too wide", func(t *testing.T) {
		cfg := fsConfig(t)
		if err := os.MkdirAll(cfg.Storage.WorkDir, 0o755); err != nil {
			t.Fatal(err)
		}
		os.Chmod(cfg.Storage.WorkDir, 0o755)
		_, _, err := Build(t.Context(), cfg, fakeWho{}, quiet, Hooks{})
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
		_, _, err := Build(t.Context(), cfg, fakeWho{}, quiet, Hooks{})
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
		_, _, err := Build(t.Context(), cfg, fakeWho{}, quiet, Hooks{})
		if err == nil || !strings.Contains(err.Error(), keys) {
			t.Fatalf("err = %v, want one naming %s", err, keys)
		}
	})
}
