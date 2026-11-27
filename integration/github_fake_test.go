//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
)

// fakeGitHub is a GitHub Enterprise Server API whose App installation sees
// one repository, acme/lib, with one release, v1.0, and a separate download
// host the API redirects asset downloads to. The download host refuses any
// request carrying Authorization, as GitHub's signed asset URLs do not take
// the API token.
type fakeGitHub struct {
	api, dl *httptest.Server
	mu      sync.Mutex
	assets  []fakeAsset
	served  map[int64][]byte // bytes the download host serves instead
	hits    map[int64]int    // downloads per asset
}

type fakeAsset struct {
	id     int64
	name   string
	body   []byte
	digest bool // whether the API declares the asset's sha256
}

const fakeGitHubToken = "ghs_fake"

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{served: map[int64][]byte{}, hits: map[int64]int{}}
	g.dl = httptest.NewServer(http.HandlerFunc(g.download))
	t.Cleanup(g.dl.Close)
	g.api = httptest.NewServer(http.StripPrefix("/api/v3", http.HandlerFunc(g.serveAPI)))
	t.Cleanup(g.api.Close)
	return g
}

// add publishes body as an asset of the release and returns its ID.
func (g *fakeGitHub) add(name string, body []byte, digest bool) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	id := int64(100 + len(g.assets))
	g.assets = append(g.assets, fakeAsset{id: id, name: name, body: body, digest: digest})
	return id
}

// tamper makes the download host serve body for asset id.
func (g *fakeGitHub) tamper(id int64, body []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.served[id] = body
}

func (g *fakeGitHub) downloads(id int64) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hits[id]
}

// source is a pypi github source for the fake, polling every 100ms.
func (g *fakeGitHub) source(t *testing.T, name string, claims ...string) config.Source {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return config.Source{
		Name: name, Type: "github", Claims: claims, URL: g.api.URL + "/api/v3/",
		AppID: 1, InstallationID: 2,
		PrivateKey:   string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})),
		PollInterval: 100 * time.Millisecond,
		FetchHosts:   []string{strings.TrimPrefix(g.dl.URL, "http://")},
	}
}

func (g *fakeGitHub) serveAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/app/installations/2/access_tokens" {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ey") {
			http.Error(w, "no app JWT", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"token":%q,"expires_at":%q}`, fakeGitHubToken, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+fakeGitHubToken {
		http.Error(w, "no installation token", http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/installation/repositories":
		fmt.Fprint(w, `{"total_count":1,"repositories":[{"id":10,"full_name":"acme/lib"}]}`)
	case r.URL.Path == "/repos/acme/lib/releases":
		g.releases(w)
	case strings.HasPrefix(r.URL.Path, "/repos/acme/lib/releases/assets/"):
		if r.Header.Get("Accept") != "application/octet-stream" {
			http.Error(w, "asset JSON is not served", http.StatusNotAcceptable)
			return
		}
		http.Redirect(w, r, g.dl.URL+"/assets/"+strings.TrimPrefix(r.URL.Path, "/repos/acme/lib/releases/assets/"), http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

func (g *fakeGitHub) releases(w http.ResponseWriter) {
	g.mu.Lock()
	defer g.mu.Unlock()
	assets := []map[string]any{}
	for _, a := range g.assets {
		var digest any
		if a.digest {
			digest = "sha256:" + sum256(a.body)
		}
		assets = append(assets, map[string]any{
			"id": a.id, "name": a.name, "state": "uploaded", "digest": digest, "size": len(a.body),
			"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
		})
	}
	json.NewEncoder(w).Encode([]map[string]any{{
		"id": 1, "tag_name": "v1.0", "draft": false, "prerelease": false,
		"created_at": "2026-01-01T00:00:00Z", "assets": assets,
	}})
}

func (g *fakeGitHub) download(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		http.Error(w, "the download host takes no Authorization", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/assets/"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, a := range g.assets {
		if a.id != id {
			continue
		}
		g.hits[id]++
		body := a.body
		if b, ok := g.served[id]; ok {
			body = b
		}
		w.Write(body)
		return
	}
	http.NotFound(w, r)
}

// tailnetConn reports a Tailscale address as its remote end, as a tsnet
// connection to a tailnet host does.
type tailnetConn struct{ net.Conn }

func (tailnetConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 443}
}

// loopbackTailnet dials over loopback but looks like a tailnet dial, so a
// fake GitHub Enterprise Server on loopback passes the tailnet address check.
func loopbackTailnet(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return tailnetConn{c}, nil
}
