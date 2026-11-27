package githubapp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/upstream"
)

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClock() *clock { return &clock{t: time.Unix(1_700_000_000, 0).UTC()} }

// fakeAPI serves token POSTs and delegates everything else to h.
type fakeAPI struct {
	*httptest.Server
	mu       sync.Mutex
	posts    int
	jwts     []string
	lifetime time.Duration
	clk      *clock
}

func newFakeAPI(t *testing.T, clk *clock, h http.HandlerFunc) *fakeAPI {
	t.Helper()
	f := &fakeAPI{clk: clk, lifetime: time.Hour}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/app/installations/7/access_tokens" {
			f.mu.Lock()
			f.posts++
			n := f.posts
			f.jwts = append(f.jwts, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			exp := clk.now().Add(f.lifetime)
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token":      "tok-" + string(rune('0'+n)),
				"expires_at": exp.Format(time.RFC3339),
			})
			return
		}
		h(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAPI) postCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posts
}

func (f *fakeAPI) app(t *testing.T, clk *clock) *App {
	t.Helper()
	u, _ := url.Parse(f.URL)
	c := upstream.New(upstream.Options{FetchHosts: []string{u.Hostname()}, AllowPrivateForTesting: true})
	return New(c, f.URL+"/", 123, 7, testKey, clk.now)
}

func TestJWT(t *testing.T) {
	clk := newClock()
	f := newFakeAPI(t, clk, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total_count":0,"repositories":[]}`))
	})
	a := f.app(t, clk)
	if _, err := a.Repositories(t.Context()); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(f.jwts[0], ".")
	if len(parts) != 3 {
		t.Fatalf("jwt = %q", f.jwts[0])
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if got := string(dec(parts[0])); got != `{"alg":"RS256","typ":"JWT"}` {
		t.Errorf("header = %s", got)
	}
	var claims struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(dec(parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	now := clk.now().Unix()
	if claims.Iss != "123" || claims.Iat != now-60 || claims.Exp != now+540 {
		t.Errorf("claims = %+v (now %d)", claims, now)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, sum[:], dec(parts[2])); err != nil {
		t.Errorf("signature: %v", err)
	}
}

func TestInstallationTokenCached(t *testing.T) {
	clk := newClock()
	f := newFakeAPI(t, clk, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"repositories":[]}`))
	})
	a := f.app(t, clk)
	for range 2 {
		if _, err := a.Repositories(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.postCount(); n != 1 {
		t.Fatalf("posts = %d, want 1", n)
	}
	clk.advance(time.Hour - 4*time.Minute)
	if _, err := a.Repositories(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.postCount(); n != 2 {
		t.Fatalf("posts = %d, want 2", n)
	}
}

func TestTokenRenewedOnce401(t *testing.T) {
	clk := newClock()
	var mu sync.Mutex
	var seen []string
	reject := 1
	f := newFakeAPI(t, clk, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		rej := reject > 0
		if rej {
			reject--
		}
		mu.Unlock()
		if rej {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"repositories":[{"id":1,"full_name":"o/r"}]}`))
	})
	a := f.app(t, clk)
	repos, err := a.Repositories(t.Context())
	if err != nil || len(repos) != 1 {
		t.Fatalf("repos = %v, err = %v", repos, err)
	}
	mu.Lock()
	ok := f.postCount() == 2 && len(seen) == 2 && seen[0] != seen[1]
	mu.Unlock()
	if !ok {
		t.Fatalf("posts = %d, seen = %v", f.postCount(), seen)
	}
	mu.Lock()
	reject = 2
	mu.Unlock()
	clk.advance(2 * time.Hour)
	if _, err := a.Repositories(t.Context()); err == nil {
		t.Fatal("want error after a second 401")
	}
}

func TestTokenNeverInErrors(t *testing.T) {
	clk := newClock()
	f := newFakeAPI(t, clk, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom "+r.Header.Get("Authorization"), http.StatusInternalServerError)
	})
	a := f.app(t, clk)
	_, err := a.Repositories(t.Context())
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "tok-") || strings.Contains(err.Error(), "Bearer") {
		t.Errorf("error leaks the token: %v", err)
	}
	_, _, err = a.OpenAsset(t.Context(), Repo{FullName: "o/r"}, 5, 10)
	if err == nil || strings.Contains(err.Error(), "tok-") {
		t.Errorf("OpenAsset error = %v", err)
	}
	// A failing token request carries neither the JWT nor a token.
	g := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope "+r.Header.Get("Authorization"), http.StatusForbidden)
	}))
	defer g.Close()
	u, _ := url.Parse(g.URL)
	b := New(upstream.New(upstream.Options{FetchHosts: []string{u.Hostname()}, AllowPrivateForTesting: true}),
		g.URL, 123, 7, testKey, clk.now)
	_, err = b.Repositories(t.Context())
	if err == nil || strings.Contains(err.Error(), "eyJ") || strings.Contains(err.Error(), "Bearer") {
		t.Errorf("token error = %v", err)
	}
}

func TestParseKey(t *testing.T) {
	p1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)})
	der8, err := x509.MarshalPKCS8PrivateKey(testKey)
	if err != nil {
		t.Fatal(err)
	}
	p8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8})
	for name, p := range map[string][]byte{"pkcs1": p1, "pkcs8": p8} {
		k, err := ParseKey(string(p))
		if err != nil || !k.Equal(testKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseKey("not pem"); err == nil {
		t.Error("want error")
	}
}
