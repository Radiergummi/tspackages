//go:build tailnet

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/testutil"
	"tailscale.com/tailcfg"
)

// TestOverRealTailnet runs tspackages and a client as real tsnet nodes
// against an in-process control server, proving that WhoIs delivers the
// grant's capability as the identity middleware expects it, and that the
// rules it carries decide reads and writes.
func TestOverRealTailnet(t *testing.T) {
	control := testutil.StartControl(t)
	control.SetGlobalAppCaps(tailcfg.PeerCapMap{testCap: {`{"read":["*"],"write":["composer:acme/a*"]}`}})

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	registry := testutil.StartNode(ctx, t, control, "registry")
	laptop := testutil.StartNode(ctx, t, control, "laptop")

	lc, err := registry.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	cfg := fsConfig(t)
	cfg.Ecosystems["composer"] = config.Ecosystem{Sources: []config.Source{
		{Name: "hosted", Type: "storage", Claims: []string{"acme/*"}, Store: "main"},
	}}
	h, start, err := Build(ctx, cfg, lc, nil, quiet, Hooks{})
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

// ghesFake is a GitHub Enterprise Server: its API sees acme/lib with one
// release carrying whl, and redirects the asset download to the download
// handler served at download, which refuses requests carrying Authorization.
func ghesFake(whl []byte, download string) (api, dl http.Handler) {
	const fn = "acme_lib-1.0.0-py3-none-any.whl"
	api = http.StripPrefix("/api/v3", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/2/access_tokens":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"token":"tok","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		case r.Header.Get("Authorization") != "Bearer tok":
			http.Error(w, "no installation token", http.StatusUnauthorized)
		case r.URL.Path == "/installation/repositories":
			io.WriteString(w, `{"repositories":[{"id":10,"full_name":"acme/lib"}]}`)
		case r.URL.Path == "/repos/acme/lib/releases":
			fmt.Fprintf(w, `[{"id":1,"tag_name":"v1.0.0","created_at":"2026-01-01T00:00:00Z","assets":[
				{"id":100,"name":%q,"state":"uploaded","digest":"sha256:%x","size":%d,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}]}]`,
				fn, sha256.Sum256(whl), len(whl))
		case r.URL.Path == "/repos/acme/lib/releases/assets/100" && r.Header.Get("Accept") == "application/octet-stream":
			http.Redirect(w, r, download+"/assets/100", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	dl = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.URL.Path != "/assets/100" {
			http.Error(w, "bad download", http.StatusBadRequest)
			return
		}
		w.Write(whl)
	})
	return api, dl
}

func serveOn(t *testing.T, ln net.Listener, h http.Handler) {
	t.Helper()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
}

// TestGHESOverTailnet: a github source reaches a GitHub Enterprise Server on
// another tailnet node through the tsnet dialer, lists its release and
// serves the wheel to a third node; the same server on loopback, a
// non-Tailscale address, is refused before any request reaches it.
func TestGHESOverTailnet(t *testing.T) {
	control := testutil.StartControl(t)
	control.SetGlobalAppCaps(tailcfg.PeerCapMap{testCap: {`{"read":["*"]}`}})

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	registry := testutil.StartNode(ctx, t, control, "registry")
	laptop := testutil.StartNode(ctx, t, control, "laptop")
	ghes := testutil.StartNode(ctx, t, control, "ghes")

	whl := testutil.ZipOf(t, map[string]string{"acme_lib/__init__.py": ""})
	ghIP, _ := ghes.TailscaleIPs()
	download := ghIP.String() + ":8080"
	api, dl := ghesFake(whl, "http://"+download)
	for addr, h := range map[string]http.Handler{":80": api, ":8080": dl} {
		ln, err := ghes.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		serveOn(t, ln, h)
	}

	lc, err := registry.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	source := func(name, apiURL string, fetch ...string) *config.Config {
		cfg := fsConfig(t)
		cfg.Ecosystems["pypi"] = config.Ecosystem{Sources: []config.Source{{
			Name: name, Type: "github", URL: apiURL, Claims: []string{"acme-*"}, FetchHosts: fetch,
			AppID: 1, InstallationID: 2, PrivateKey: githubKeyPEM(t), PollInterval: 100 * time.Millisecond,
		}}}
		return cfg
	}
	h, start, err := Build(ctx, source("ghes", "http://"+ghIP.String()+"/api/v3/", download), lc, registry.Dial, quiet,
		Hooks{AllowPrivateUpstreams: true})
	if err != nil {
		t.Fatal(err)
	}
	go start(ctx)
	ln, err := registry.Listen("tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	serveOn(t, ln, h)

	regIP, _ := registry.TailscaleIPs()
	base := "http://" + regIP.String()
	hc := laptop.HTTPClient()
	get := func(path string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
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
	const fn = "acme_lib-1.0.0-py3-none-any.whl"
	for {
		code, body := get("/pypi/simple/acme-lib/")
		if code == http.StatusOK && strings.Contains(string(body), fn) {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("index = %d %s", code, body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code, body := get("/pypi/files/ghes/acme-lib/" + fn); code != http.StatusOK || !bytes.Equal(body, whl) {
		t.Fatalf("wheel = %d, %d bytes", code, len(body))
	}

	// The same server on loopback, dialled through the tailnet.
	var hits atomic.Int32
	lo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		api.ServeHTTP(w, r)
	}))
	defer lo.Close()
	var logs lockedBuffer
	h2, start2, err := Build(ctx, source("loopback", lo.URL+"/api/v3/"), testutil.NewWho(testCap, `{"read":["*"]}`),
		registry.Dial, slog.New(slog.NewTextHandler(&logs, nil)), Hooks{AllowPrivateUpstreams: true})
	if err != nil {
		t.Fatal(err)
	}
	go start2(ctx)
	refused := "upstream address forbidden: " + strings.TrimPrefix(lo.URL, "http://")
	for !strings.Contains(logs.String(), refused) {
		if ctx.Err() != nil {
			t.Fatalf("no refused dial to the loopback server in:\n%s", logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if w := do(h2, "GET", "/pypi/simple/acme-lib/", nil); w.Code == http.StatusOK {
		t.Fatalf("index from loopback = %d %s", w.Code, w.Body)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the loopback server got %d requests", n)
	}
}

// lockedBuffer is a bytes.Buffer safe for a logger writing while the test
// reads.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
