package upstream

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/resolve"
)

func testClient(o Options) *Client {
	o.AllowPrivateForTesting = true
	return New(o)
}

func TestRejectsHostNotInAllowlist(t *testing.T) {
	c := testClient(Options{FetchHosts: []string{"example.com"}})
	_, err := c.Get(context.Background(), "http://127.0.0.1:1/x")
	if !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("err = %v", err)
	}
}

func TestHostAllowlistPortAndCase(t *testing.T) {
	c := testClient(Options{FetchHosts: []string{"Example.com", "other.test:8443"}})
	for url, want := range map[string]bool{
		"https://EXAMPLE.com:9/x":   true,
		"https://other.test:8443/x": true,
		"https://other.test/x":      false,
		"https://other.test:1/x":    false,
		"https://evil.test/x":       false,
		"https://example.com.evil/": false,
	} {
		got := c.hostAllowed(mustParse(t, url))
		if got != want {
			t.Errorf("%s: got %v want %v", url, got, want)
		}
	}
}

func TestRejectsHTTPUnlessTesting(t *testing.T) {
	c := New(Options{FetchHosts: []string{"example.com"}})
	if _, err := c.Get(context.Background(), "http://example.com/x"); err == nil || errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("err = %v", err)
	}
}

func TestRejectsPrivateAddress(t *testing.T) {
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server must not be reached")
	}))
	defer tls.Close()
	c := New(Options{FetchHosts: []string{"127.0.0.1"}})
	_, err := c.Get(context.Background(), tls.URL)
	if !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("err = %v", err)
	}
}

func TestForbiddenAddrs(t *testing.T) {
	for s, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "172.16.0.1": true, "172.31.255.255": true,
		"192.168.1.1": true, "169.254.169.254": true, "100.64.0.1": true, "100.127.255.255": true,
		"0.0.0.0": true, "224.0.0.1": true, "::1": true, "fc00::1": true, "fd12::1": true,
		"fe80::1": true, "::": true, "ff02::1": true,
		"::ffff:127.0.0.1": true, "::ffff:10.0.0.1": true, "::ffff:100.64.0.1": true, "::ffff:169.254.169.254": true,
		"8.8.8.8": false, "172.32.0.1": false, "100.128.0.1": false, "2606:4700::1": false, "::ffff:8.8.8.8": false,
	} {
		if got := forbiddenAddr(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: got %v want %v", s, got, want)
		}
	}
}

func TestCredentialsOnlyForExactHost(t *testing.T) {
	var gotB string
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotB = r.Header.Get("Authorization")
	}))
	defer b.Close()
	var gotA string
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotA = r.Header.Get("Authorization")
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, b.URL+"/x", http.StatusFound)
		}
	}))
	defer a.Close()
	hostA := strings.TrimPrefix(a.URL, "http://")
	hostB := strings.TrimPrefix(b.URL, "http://")

	c := testClient(Options{
		FetchHosts:  []string{"127.0.0.1"},
		Credentials: map[string]config.Credential{hostA: {Bearer: "tok"}},
	})
	resp, err := c.Get(context.Background(), a.URL+"/direct")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotA != "Bearer tok" {
		t.Fatalf("A got %q", gotA)
	}

	gotA, gotB = "", ""
	resp, err = c.Get(context.Background(), a.URL+"/redir")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotA != "Bearer tok" || gotB != "" {
		t.Fatalf("A=%q B=%q", gotA, gotB)
	}

	// Credential for B must still not be attached on a redirect hop.
	c = testClient(Options{
		FetchHosts:  []string{"127.0.0.1"},
		Credentials: map[string]config.Credential{hostA: {Bearer: "tok"}, hostB: {Bearer: "btok"}},
	})
	gotB = ""
	resp, err = c.Get(context.Background(), a.URL+"/redir")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotB != "" {
		t.Fatalf("credential attached after redirect: %q", gotB)
	}
}

func TestBasicCredentials(t *testing.T) {
	var u, p string
	var ok bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok = r.BasicAuth()
	}))
	defer s.Close()
	c := testClient(Options{
		FetchHosts:  []string{"127.0.0.1"},
		Credentials: map[string]config.Credential{strings.TrimPrefix(s.URL, "http://"): {Username: "me", Password: "pw"}},
	})
	resp, err := c.Get(context.Background(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !ok || u != "me" || p != "pw" {
		t.Fatalf("basic = %v %q %q", ok, u, p)
	}
}

func TestRedirectToDisallowedHost(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.test/x", http.StatusFound)
	}))
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	_, err := c.Get(context.Background(), s.URL)
	if !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("err = %v", err)
	}
}

func TestTooManyRedirects(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	if _, err := c.Get(context.Background(), s.URL); err == nil {
		t.Fatal("want error")
	}
}

func hexSum(b []byte) (string, string) {
	a := sha1.Sum(b)
	s := sha256.Sum256(b)
	return hex.EncodeToString(a[:]), hex.EncodeToString(s[:])
}

func bodyServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
}

func TestFetchVerifiedOK(t *testing.T) {
	s := bodyServer("hello")
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	wantSHA1, wantSHA256 := hexSum([]byte("hello"))
	for _, want := range []*Digest{nil, {"sha1", strings.ToUpper(wantSHA1)}, {"sha256", wantSHA256}} {
		body, s1, s2, err := c.FetchVerified(context.Background(), s.URL, want, 100)
		if err != nil || string(body) != "hello" || s1 != wantSHA1 || s2 != wantSHA256 {
			t.Fatalf("%v: %q %q %q %v", want, body, s1, s2, err)
		}
	}
}

func TestFetchVerifiedMismatch(t *testing.T) {
	s := bodyServer("hello")
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	body, _, _, err := c.FetchVerified(context.Background(), s.URL, &Digest{"sha256", strings.Repeat("0", 64)}, 100)
	if !errors.Is(err, ErrDigestMismatch) || body != nil {
		t.Fatalf("%q %v", body, err)
	}
	_, want256 := hexSum([]byte("hello"))
	if !strings.Contains(err.Error(), want256) || !strings.Contains(err.Error(), strings.Repeat("0", 64)) {
		t.Fatalf("message lacks hashes: %v", err)
	}
	if _, _, _, err := c.FetchVerified(context.Background(), s.URL, &Digest{"md5", "x"}, 100); err == nil {
		t.Fatal("unknown algo must fail")
	}
}

func TestFetchTooLarge(t *testing.T) {
	s := bodyServer("0123456789")
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	if _, _, _, err := c.FetchVerified(context.Background(), s.URL, nil, 9); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, _, _, err := c.FetchVerified(context.Background(), s.URL, nil, 10); err != nil {
		t.Fatalf("exactly max must pass: %v", err)
	}
}

func Test404IsNotFound(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	_, _, _, err := c.FetchVerified(context.Background(), s.URL+"/p?token=secret", nil, 100)
	if !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 404 || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v", err)
	}
}

func TestOtherStatusNotNotFound(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	_, _, _, err := c.FetchVerified(context.Background(), s.URL, nil, 100)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 500 || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func mustParse(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
