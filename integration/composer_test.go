//go:build integration

// Package integration runs real clients against a fully wired server.
package integration

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/server"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

const capName = "github.com/radiergummi/tspackages"

type fakeWho struct{}

func (fakeWho) WhoIs(context.Context, string) (*apitype.WhoIsResponse, error) {
	return &apitype.WhoIsResponse{
		Node: &tailcfg.Node{Name: "ci.ts.net.", StableID: "nid", Tags: []string{"tag:ci"}},
		CapMap: tailcfg.PeerCapMap{capName: {
			tailcfg.RawMessage(`{"read":["*"],"write":["composer:matchory-internal/*"]}`),
		}},
	}, nil
}

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(f, content)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha1Hex(b []byte) string {
	s := sha1.Sum(b)
	return hex.EncodeToString(s[:])
}

func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// fakePackagist serves psr/log 3.0.0 and a decoy matchory/a 9.9.9, and records
// every request path.
type fakePackagist struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func (f *fakePackagist) saw(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.paths {
		if p == path {
			return true
		}
	}
	return false
}

func newFakePackagist(t *testing.T) *fakePackagist {
	t.Helper()
	logZip := zipOf(t, map[string]string{
		"log-3.0.0/composer.json": `{"name":"psr/log"}`,
		"log-3.0.0/src/Foo.php":   `<?php`,
	})
	decoyZip := zipOf(t, map[string]string{"a-9.9.9/composer.json": `{"name":"matchory/a"}`})
	f := &fakePackagist{}
	mux := http.NewServeMux()
	meta := func(name, version string, zipBytes []byte, distPath string) string {
		doc := map[string]any{"packages": map[string]any{name: []any{map[string]any{
			"name": name, "version": version, "version_normalized": version + ".0",
			"dist": map[string]any{
				"type": "zip", "url": f.URL + distPath, "reference": "ref" + version,
				"shasum": sha1Hex(zipBytes),
			},
		}}}}
		b, _ := json.Marshal(doc)
		return string(b)
	}
	serve := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, body)
		}
	}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.Close)
	mux.HandleFunc("/p2/psr/log.json", serve(meta("psr/log", "3.0.0", logZip, "/dist/log.zip")))
	mux.HandleFunc("/p2/matchory/a.json", serve(meta("matchory/a", "9.9.9", decoyZip, "/dist/decoy.zip")))
	mux.HandleFunc("/dist/log.zip", func(w http.ResponseWriter, _ *http.Request) { w.Write(logZip) })
	mux.HandleFunc("/dist/decoy.zip", func(w http.ResponseWriter, _ *http.Request) { w.Write(decoyZip) })
	return f
}

func TestComposerEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("composer"); err != nil {
		t.Skip("composer not on PATH")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	root := t.TempDir()

	// Bare repo for matchory/a with tag v1.0.0.
	work := filepath.Join(root, "a-work")
	bare := filepath.Join(root, "a.git")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	gitEnv := []string{"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_GLOBAL=/dev/null"}
	run(t, work, gitEnv, "git", "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(work, "composer.json"), []byte(`{"name":"matchory/a","description":"a"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, work, gitEnv, "git", "add", ".")
	run(t, work, gitEnv, "git", "commit", "-q", "-m", "one")
	run(t, work, gitEnv, "git", "tag", "v1.0.0")
	commit := strings.TrimSpace(run(t, work, gitEnv, "git", "rev-parse", "v1.0.0^{commit}"))
	run(t, root, gitEnv, "git", "clone", "-q", "--bare", work, bare)

	packagist := newFakePackagist(t)
	pu, _ := url.Parse(packagist.URL)

	statePath := filepath.Join(root, "state")
	cfg := &config.Config{
		Tailscale: config.Tailscale{Hostname: "registry", Capability: capName},
		Storage: config.Storage{
			WorkDir: filepath.Join(root, "work"),
			Cache:   config.StoreConfig{Driver: "fs", Path: filepath.Join(root, "cache"), MaxSize: 1 << 30},
			State:   config.StoreConfig{Driver: "fs", Path: statePath},
			Stores:  map[string]config.StoreConfig{"main": {Driver: "fs", Path: filepath.Join(root, "hosted")}},
		},
		Ecosystems: map[string]config.Ecosystem{"composer": {Sources: []config.Source{
			{Name: "matchory-git", Type: "git", Claims: []string{"matchory/*"}, Remotes: []string{bare}, PollInterval: time.Second},
			{Name: "hosted", Type: "storage", Store: "main", Claims: []string{"matchory-internal/*"}},
			{Name: "packagist", Type: "registry", URL: packagist.URL, FetchHosts: []string{pu.Host}},
		}}},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, start, err := server.Build(ctx, cfg, fakeWho{}, log, server.Hooks{AllowPrivateUpstreams: true, AllowFileRemotes: true})
	if err != nil {
		t.Fatal(err)
	}
	start(ctx)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Wait for the git index.
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(srv.URL + "/composer/p2/matchory/a.json")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("git source never became ready")
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Upload matchory-internal/b 1.0.0.
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/composer/upload/matchory-internal/b/1.0.0",
		bytes.NewReader(zipOf(t, map[string]string{"composer.json": `{"name":"matchory-internal/b","description":"b"}`})))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload = %d %s", resp.StatusCode, body)
	}

	project := t.TempDir()
	composerJSON, _ := json.Marshal(map[string]any{
		"repositories": []any{
			map[string]any{"type": "composer", "url": srv.URL + "/composer"},
			map[string]any{"packagist.org": false},
		},
		"config":  map[string]any{"secure-http": false},
		"require": map[string]any{"matchory/a": "^1.0", "matchory-internal/b": "^1.0", "psr/log": "^3.0"},
	})
	if err := os.WriteFile(filepath.Join(project, "composer.json"), composerJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"COMPOSER_HOME=" + filepath.Join(root, "composer-home"),
		"COMPOSER_CACHE_DIR=" + filepath.Join(root, "composer-cache"),
		"COMPOSER_NO_INTERACTION=1",
	}
	out := run(t, project, env, "composer", "install", "--no-interaction", "--prefer-dist")
	t.Log(out)

	for _, p := range []string{"matchory/a/composer.json", "matchory-internal/b/composer.json", "psr/log"} {
		if _, err := os.Stat(filepath.Join(project, "vendor", p)); err != nil {
			t.Errorf("vendor/%s: %v", p, err)
		}
	}

	checkLock := func() {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(project, "composer.lock"))
		if err != nil {
			t.Fatal(err)
		}
		var lock struct {
			Packages []struct {
				Name    string
				Version string
				Dist    struct{ URL, Shasum string }
			}
		}
		if err := json.Unmarshal(raw, &lock); err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, p := range lock.Packages {
			found[p.Name] = true
			if !strings.HasPrefix(p.Dist.URL, srv.URL) {
				t.Errorf("%s dist.url = %q, want prefix %q", p.Name, p.Dist.URL, srv.URL)
			}
			if p.Name != "matchory/a" {
				continue
			}
			if p.Version != "v1.0.0" {
				t.Errorf("matchory/a resolved to %q, want v1.0.0", p.Version)
			}
			stored, err := os.ReadFile(filepath.Join(statePath, "composer-git", "matchory-git", commit+".zip"))
			if err != nil {
				t.Fatalf("stored archive: %v", err)
			}
			if p.Dist.Shasum != sha1Hex(stored) {
				t.Errorf("matchory/a shasum = %q, want sha1 of stored archive %q", p.Dist.Shasum, sha1Hex(stored))
			}
		}
		for _, n := range []string{"matchory/a", "matchory-internal/b", "psr/log"} {
			if !found[n] {
				t.Errorf("%s missing from composer.lock", n)
			}
		}
	}
	checkLock()

	// Dependency confusion: packagist offers matchory/a 9.9.9, but the claim keeps it away.
	if err := os.Remove(filepath.Join(project, "composer.lock")); err != nil {
		t.Fatal(err)
	}
	out = run(t, project, env, "composer", "update", "--no-interaction", "--prefer-dist")
	t.Log(out)
	checkLock()
	if packagist.saw("/p2/matchory/a.json") || packagist.saw("/p2/matchory/a~dev.json") {
		t.Errorf("fake Packagist received a request for matchory/a: %v", packagist.paths)
	}
}
