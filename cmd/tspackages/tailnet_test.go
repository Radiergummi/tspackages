//go:build tailnet

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/testutil"
	"github.com/radiergummi/tspackages/internal/workdir"
	"tailscale.com/tsnet"
)

// TestRunOverTailnet runs the real startup and shutdown path against an
// in-process control server: credentials leave the environment once they are
// used, the registry listens on :443 while holding the work_dir lock, and a
// cancelled run stops and releases the lock.
func TestRunOverTailnet(t *testing.T) {
	control := testutil.StartControl(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	laptop := testutil.StartNode(ctx, t, control, "laptop")

	root := t.TempDir()
	p := writeConfig(t, root, `      - name: upstream
        type: registry
        url: https://packagist.invalid
        fetch_hosts: [packagist.invalid]
        download_credentials:
          packagist.invalid: {bearer: "${env:TSP_TEST_TOKEN}"}
`)
	t.Setenv("TSP_TEST_TOKEN", "secret")
	t.Setenv("TS_AUTHKEY", "tskey-test")

	nodes := make(chan *tsnet.Server, 1)
	node := func(cfg *config.Config, _ *slog.Logger) *tsnet.Server {
		s := testutil.Node(control, cfg.Tailscale.Hostname, cfg.Tailscale.StateDir)
		nodes <- s
		return s
	}
	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- run(runCtx, p, quiet, node) }()

	var srv *tsnet.Server
	select {
	case srv = <-nodes:
	case err := <-done:
		t.Fatalf("run stopped before joining the tailnet: %v", err)
	}
	// Up waits for the node run is starting; it is safe to call twice.
	if _, err := srv.Up(ctx); err != nil {
		t.Fatal(err)
	}
	ip4, _ := srv.TailscaleIPs()
	// Serving once a peer can connect to :443.
	for {
		if c, err := laptop.Dial(ctx, "tcp", ip4.String()+":443"); err == nil {
			c.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("run stopped before serving: %v", err)
		case <-ctx.Done():
			t.Fatal("registry never listened on :443")
		case <-time.After(100 * time.Millisecond):
		}
	}

	for _, k := range []string{"TS_AUTHKEY", "TSP_TEST_TOKEN"} {
		if _, ok := os.LookupEnv(k); ok {
			t.Errorf("%s still set while serving", k)
		}
	}
	work := filepath.Join(root, "work")
	if unlock, err := workdir.Lock(ctx, work, 0, quiet); err == nil {
		unlock()
		t.Error("work_dir not locked while serving")
	}

	stopRun()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run after cancel = %v", err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("run did not stop after cancel")
	}
	unlock, err := workdir.Lock(ctx, work, 0, quiet)
	if err != nil {
		t.Fatalf("work_dir still locked after run returned: %v", err)
	}
	unlock()
}
