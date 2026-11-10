//go:build tailnet

package testutil

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// StartControl runs an in-process control server with its own DERP and STUN
// servers and returns it, stopped at the end of the test.
func StartControl(t *testing.T) *testcontrol.Server {
	t.Helper()
	netns.SetEnabled(false) // as tsnet's own tests do
	t.Cleanup(func() { netns.SetEnabled(true) })
	control := &testcontrol.Server{
		DERPMap:        integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1"),
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           logger.Discard,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control
}

// Node returns an ephemeral tsnet server for control, keeping its state in
// memory and in dir.
func Node(control *testcontrol.Server, hostname, dir string) *tsnet.Server {
	return &tsnet.Server{
		Dir:        dir,
		ControlURL: control.HTTPTestServer.URL,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logger.Discard,
	}
}

// StartNode brings a Node up and closes it at the end of the test.
func StartNode(ctx context.Context, t *testing.T, control *testcontrol.Server, hostname string) *tsnet.Server {
	t.Helper()
	s := Node(control, hostname, filepath.Join(t.TempDir(), hostname))
	t.Cleanup(func() { s.Close() })
	if _, err := s.Up(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}
