//go:build tailnet

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/testutil"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

func startNode(ctx context.Context, t *testing.T, controlURL, hostname string) *tsnet.Server {
	t.Helper()
	s := &tsnet.Server{
		Dir:        filepath.Join(t.TempDir(), hostname),
		ControlURL: controlURL,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logger.Discard,
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Up(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestOverRealTailnet runs tspackages and a client as real tsnet nodes
// against an in-process control server, proving that WhoIs delivers the
// grant's capability as the identity middleware expects it, and that the
// rules it carries decide reads and writes.
func TestOverRealTailnet(t *testing.T) {
	netns.SetEnabled(false) // as tsnet's own tests do
	t.Cleanup(func() { netns.SetEnabled(true) })
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           logger.Discard,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	control.SetGlobalAppCaps(tailcfg.PeerCapMap{testCap: {`{"read":["*"],"write":["composer:acme/a*"]}`}})

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	registry := startNode(ctx, t, control.HTTPTestServer.URL, "registry")
	laptop := startNode(ctx, t, control.HTTPTestServer.URL, "laptop")

	lc, err := registry.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	cfg := fsConfig(t)
	cfg.Ecosystems["composer"] = config.Ecosystem{Sources: []config.Source{
		{Name: "hosted", Type: "storage", Claims: []string{"acme/*"}, Store: "main"},
	}}
	h, start, err := Build(ctx, cfg, lc, quiet, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	go start(ctx)
	// Plain HTTP: certificates need a real control plane, and TLS is not what
	// this test is about.
	ln, err := registry.Listen("tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	defer srv.Close()

	ip4, _ := registry.TailscaleIPs()
	base := "http://" + ip4.String()
	hc := laptop.HTTPClient()
	call := func(method, path string, body []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	zip := func(name string) []byte {
		return testutil.ZipOf(t, map[string]string{"composer.json": `{"name":"` + name + `","description":"x"}`})
	}

	if code, body := call("PUT", "/composer/upload/acme/abc/1.0.0", zip("acme/abc")); code != http.StatusCreated {
		t.Fatalf("upload with write grant = %d %s", code, body)
	}
	if code, body := call("PUT", "/composer/upload/acme/xyz/1.0.0", zip("acme/xyz")); code != http.StatusForbidden {
		t.Fatalf("upload outside the write grant = %d %s", code, body)
	}
	code, body := call("GET", "/composer/p2/acme/abc.json", nil)
	if code != http.StatusOK {
		t.Fatalf("p2 = %d %s", code, body)
	}
	var p2 struct {
		Packages map[string][]struct {
			Dist struct{ URL string } `json:"dist"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &p2); err != nil || len(p2.Packages["acme/abc"]) != 1 {
		t.Fatalf("p2 body: %s (%v)", body, err)
	}
	dist := p2.Packages["acme/abc"][0].Dist.URL
	if !strings.HasPrefix(dist, base+"/") {
		t.Fatalf("dist URL %q does not point at the registry", dist)
	}
	if code, _ := call("GET", strings.TrimPrefix(dist, base), nil); code != http.StatusOK {
		t.Fatalf("dist download = %d", code)
	}
}
