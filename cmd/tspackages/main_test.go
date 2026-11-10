package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/workdir"
	"tailscale.com/tsnet"
)

var quiet = slog.New(slog.DiscardHandler)

func TestScrubEnv(t *testing.T) {
	for _, k := range []string{"TSP_SECRET", "PATH", "HOME", "USER", "TMPDIR", "LANG", "LC_ALL", "TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET", "TS_ID_TOKEN"} {
		t.Setenv(k, "v")
	}
	scrubEnv([]string{"TSP_SECRET", "PATH", "HOME", "USER", "TMPDIR", "LANG", "LC_ALL"})
	if _, ok := os.LookupEnv("TSP_SECRET"); ok {
		t.Error("referenced secret not unset")
	}
	for _, k := range []string{"PATH", "HOME", "USER", "TMPDIR", "LANG", "LC_ALL"} {
		if _, ok := os.LookupEnv(k); !ok {
			t.Errorf("%s unset", k)
		}
	}
	scrubEnv(tsnetEnv)
	for _, k := range []string{"TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET", "TS_ID_TOKEN"} {
		if _, ok := os.LookupEnv(k); ok {
			t.Errorf("%s not unset", k)
		}
	}
}

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	log, err := newLogger(&buf, "warn", "text")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hidden")
	log.Warn("shown")
	if out := buf.String(); strings.Contains(out, "hidden") || !strings.Contains(out, "level=WARN msg=shown") {
		t.Fatalf("text output: %q", out)
	}
	buf.Reset()
	log, _ = newLogger(&buf, "info", "json")
	log.Info("x")
	if !strings.HasPrefix(buf.String(), `{"time":`) {
		t.Fatalf("json output: %q", buf.String())
	}
	if _, err := newLogger(&buf, "loud", "json"); err == nil {
		t.Error("bad level accepted")
	}
	if _, err := newLogger(&buf, "info", "xml"); err == nil {
		t.Error("bad format accepted")
	}
}

// writeConfig writes a minimal valid config whose directories live under
// root, and returns its path. extra is appended to the composer sources.
func writeConfig(t *testing.T, root, extra string) string {
	t.Helper()
	cfg := `tailscale:
  hostname: registry
  state_dir: ` + filepath.Join(root, "tailscale") + `
  capability: example.com/cap/tspackages
storage:
  work_dir: ` + filepath.Join(root, "work") + `
  cache: {driver: fs, path: ` + filepath.Join(root, "cache") + `}
  state: {driver: fs, path: ` + filepath.Join(root, "state") + `}
  stores:
    main: {driver: fs, path: ` + filepath.Join(root, "main") + `}
ecosystems:
  composer:
    sources:
      - {name: hosted, type: storage, store: main, claims: ["acme/*"]}
` + extra
	p := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// noNode fails the test if run gets as far as joining the tailnet.
func noNode(t *testing.T) func(*config.Config, *slog.Logger) *tsnet.Server {
	return func(*config.Config, *slog.Logger) *tsnet.Server {
		t.Error("run joined the tailnet")
		return &tsnet.Server{}
	}
}

func TestRunRejectsInvalidConfig(t *testing.T) {
	root := t.TempDir()
	p := writeConfig(t, root, "      - {name: hosted2, type: storage, store: main, claims: [\"Acme/*\"]}\n")
	err := run(t.Context(), p, quiet, noNode(t))
	if err == nil || !strings.Contains(err.Error(), "Acme/*") {
		t.Fatalf("run = %v, want a claim error", err)
	}
	if err := run(t.Context(), filepath.Join(root, "missing.yaml"), quiet, noNode(t)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing config: %v", err)
	}
}

func TestRunRefusesAnOpenStateDir(t *testing.T) {
	root := t.TempDir()
	p := writeConfig(t, root, "")
	if err := os.Mkdir(filepath.Join(root, "tailscale"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := run(t.Context(), p, quiet, noNode(t))
	if err == nil || !strings.Contains(err.Error(), "tsnet state dir") || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("run = %v, want a state dir mode error", err)
	}
}

func TestRunWaitsForTheWorkDirLock(t *testing.T) {
	root := t.TempDir()
	p := writeConfig(t, root, "")
	unlock, err := workdir.Lock(t.Context(), filepath.Join(root, "work"), 0, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = run(ctx, p, quiet, noNode(t))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run = %v, want it to wait for the lock until cancelled", err)
	}
	if d := time.Since(start); d < 250*time.Millisecond {
		t.Fatalf("run returned after %s; it did not wait", d)
	}
}
