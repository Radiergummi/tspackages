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
			Cache:  config.StoreConfig{Driver: "fs", Path: t.TempDir(), MaxSize: 1 << 30},
			State:  config.StoreConfig{Driver: "fs", Path: t.TempDir()},
			Stores: map[string]config.StoreConfig{"main": {Driver: "fs", Path: t.TempDir()}},
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

// shortTempDir returns a directory whose path passes gitmirror's SSH path
// allowlist; macOS's $TMPDIR contains "_", which does not.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "tspkg-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestBuildWritesSSHKeyFiles(t *testing.T) {
	root := shortTempDir(t)
	old := cacheRoot
	cacheRoot = func() string { return root }
	t.Cleanup(func() { cacheRoot = old })

	cfg := fsConfig(t)
	cfg.Ecosystems["composer"] = config.Ecosystem{Sources: []config.Source{{
		Name: "internal", Type: "git", Claims: []string{"acme/*"},
		Remotes:    []string{"ssh://git@git.example.com/acme/repo.git"},
		SSHKey:     "PRIVATE KEY MATERIAL",
		KnownHosts: "git.example.com ssh-ed25519 AAAA",
	}}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if _, _, err := Build(ctx, cfg, fakeWho{}, quiet, Hooks{}); err != nil {
		t.Fatal(err)
	}

	dirs, _ := filepath.Glob(filepath.Join(root, "keys-*"))
	if len(dirs) != 1 {
		t.Fatalf("key dirs = %v, want one", dirs)
	}
	if st, err := os.Stat(dirs[0]); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("key dir stat = %v, %v; want mode 0700", st, err)
	}
	want := map[string]string{"PRIVATE KEY MATERIAL": "", "git.example.com ssh-ed25519 AAAA": ""}
	files, _ := os.ReadDir(dirs[0])
	if len(files) != len(want) {
		t.Fatalf("key files = %v, want %d", files, len(want))
	}
	for _, f := range files {
		p := filepath.Join(dirs[0], f.Name())
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v; want mode 0600", p, st, err)
		}
		data, _ := os.ReadFile(p)
		if _, ok := want[strings.TrimSuffix(string(data), "\n")]; !ok {
			t.Errorf("%s: unexpected content %q", p, data)
		}
	}

	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(dirs[0]); err != nil && os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("key dir not removed after ctx ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
