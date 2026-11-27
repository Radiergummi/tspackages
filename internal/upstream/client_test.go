package upstream

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

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
		got := config.HostAllowed(c.hosts, mustParse(t, url))
		if got != want {
			t.Errorf("%s: got %v want %v", url, got, want)
		}
	}
}

func TestRejectsHTTPUnlessTesting(t *testing.T) {
	c := New(Options{FetchHosts: []string{"example.com"}})
	if _, err := c.Get(context.Background(), "http://example.com/x"); !errors.Is(err, ErrSchemeNotAllowed) {
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
		"0.1.2.3": true, "198.18.0.1": true, "198.19.255.255": true, "198.20.0.1": false,
		"240.0.0.1": true, "255.255.255.255": true, "239.255.255.255": true,
		"64:ff9b::7f00:1": true, "64:ff9b::a9fe:a9fe": true, "64:ff9b::808:808": false,
		"64:ff9b:1::1": true, "2002:7f00:1::": true, "2002:a00:1::": true, "2002:808:808::": false,
		"::7f00:1": true, "::a00:1": true, "::808:808": false,
		"192.0.0.1": true, "192.0.2.1": true, "198.51.100.1": true, "203.0.113.1": true, "192.88.99.1": true,
		"192.0.3.1": false, "198.51.101.1": false, "203.0.114.1": false,
		"2001:db8::1": true, "2001::1": true, "2001:0:ffff::1": true, "100::1": true, "100:0:0:1::1": false,
		"2001:4860::8888": false, "fec0::1": true, "3fff::1": true,
		"::ffff:0:7f00:1": true, "::ffff:0:a00:1": true, "::ffff:0:808:808": false,
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
	for _, want := range []string{"", strings.ToUpper(wantSHA1), wantSHA1} {
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
	body, _, _, err := c.FetchVerified(context.Background(), s.URL, strings.Repeat("0", 40), 100)
	if !errors.Is(err, ErrDigestMismatch) || body != nil {
		t.Fatalf("%q %v", body, err)
	}
	want1, _ := hexSum([]byte("hello"))
	if !strings.Contains(err.Error(), want1) || !strings.Contains(err.Error(), strings.Repeat("0", 40)) {
		t.Fatalf("message lacks hashes: %v", err)
	}
}

func TestFetchTooLarge(t *testing.T) {
	s := bodyServer("0123456789")
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	if _, _, _, err := c.FetchVerified(context.Background(), s.URL, "", 9); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, _, _, err := c.FetchVerified(context.Background(), s.URL, "", 10); err != nil {
		t.Fatalf("exactly max must pass: %v", err)
	}
}

func Test404IsNotFound(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	_, _, _, err := c.FetchVerified(context.Background(), s.URL+"/p?token=secret", "", 100)
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
	_, _, _, err := c.FetchVerified(context.Background(), s.URL, "", 100)
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

func TestRejectsUserinfo(t *testing.T) {
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	if _, err := c.Get(context.Background(), "http://u:p@127.0.0.1/a"); !errors.Is(err, ErrUserinfo) {
		t.Fatalf("initial: %v", err)
	}
	var got []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path+":"+r.Header.Get("Authorization"))
		if r.URL.Path == "/a" {
			http.Redirect(w, r, "http://u:p@"+r.Host+"/b", http.StatusFound)
		}
	}))
	defer s.Close()
	_, err := c.Get(context.Background(), s.URL+"/a")
	if !errors.Is(err, ErrUserinfo) {
		t.Fatalf("redirect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("redirect target was requested: %v", got)
	}
}

func TestSameHostRedirectDropsCredentialsAndReferer(t *testing.T) {
	type seen struct{ auth, referer string }
	got := map[string]seen{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got[r.URL.Path] = seen{r.Header.Get("Authorization"), r.Header.Get("Referer")}
		if r.URL.Path == "/a" {
			http.Redirect(w, r, "/b", http.StatusFound)
		}
	}))
	defer s.Close()
	host := strings.TrimPrefix(s.URL, "http://")
	c := testClient(Options{
		FetchHosts:  []string{"127.0.0.1"},
		Credentials: map[string]config.Credential{host: {Bearer: "tok"}},
	})
	resp, err := c.Get(context.Background(), s.URL+"/a?secret=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got["/a"].auth != "Bearer tok" || got["/b"].auth != "" || got["/b"].referer != "" {
		t.Fatalf("got %+v", got)
	}
}

func TestCredentialHostCaseInsensitive(t *testing.T) {
	var auth string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
	}))
	defer s.Close()
	port := strings.TrimPrefix(s.URL, "http://127.0.0.1:")
	c := testClient(Options{
		FetchHosts:  []string{"localhost"},
		Credentials: map[string]config.Credential{"LocalHost:" + port: {Bearer: "tok"}},
	})
	// "localhost" may resolve to ::1 first; the server listens on 127.0.0.1.
	c.http.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}
	resp, err := c.Get(context.Background(), "http://LOCALHOST:"+port+"/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if auth != "Bearer tok" {
		t.Fatalf("auth = %q", auth)
	}
}

func TestErrorsRedactQuery(t *testing.T) {
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	_, err := c.Get(context.Background(), "http://127.0.0.1:1/p?token=secret#frag")
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "frag") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := errors.AsType[*url.Error](err); !ok {
		t.Fatalf("lost cause: %v", err)
	}
}

func TestParseErrorRedactsURL(t *testing.T) {
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	_, err := c.Get(context.Background(), "http://u:pw-secret@127.0.0.1:bad/p?token=s3cret")
	if err == nil || strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "pw-secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestMaxBytesValidation(t *testing.T) {
	s := bodyServer("x")
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	for _, n := range []int64{0, -1} {
		if _, _, _, err := c.FetchVerified(context.Background(), s.URL, "", n); err == nil {
			t.Fatalf("maxBytes %d accepted", n)
		}
	}
	if _, _, _, err := c.FetchVerified(context.Background(), s.URL, "", math.MaxInt64); err != nil {
		t.Fatalf("MaxInt64: %v", err)
	}
}

func TestContentLengthRefusedEarly(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done() // never sends the body
	}))
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, _, _, err := c.FetchVerified(ctx, s.URL, "", 10)
	if !errors.Is(err, ErrTooLarge) || time.Since(start) > 2*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
}

func TestTimeoutBoundsHeadersNotBody(t *testing.T) {
	slowHeaders := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slowHeaders.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}, Timeout: 100 * time.Millisecond})
	if _, err := c.Get(context.Background(), slowHeaders.URL); err == nil {
		t.Fatal("slow headers must time out")
	}

	slowBody := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(400 * time.Millisecond)
		w.Write([]byte("late"))
	}))
	defer slowBody.Close()
	body, _, _, err := c.FetchVerified(context.Background(), slowBody.URL, "", 100)
	if err != nil || string(body) != "late" {
		t.Fatalf("%q %v", body, err)
	}
}

// Open returns as soon as the headers arrive, so bytes reach the caller while
// the upstream is still sending.
func TestOpenStreams(t *testing.T) {
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, 1024))
		w.(http.Flusher).Flush()
		<-release
		w.Write([]byte("tail"))
	}))
	defer s.Close()
	defer close(release)
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	body, size, err := c.Open(context.Background(), s.URL, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	if size != -1 {
		t.Errorf("size = %d, want -1 (no Content-Length)", size)
	}
	if _, err := io.ReadFull(body, make([]byte, 1024)); err != nil {
		t.Fatalf("first KiB: %v", err)
	}
}

func TestOpenTooLargeMidStream(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for range 2 {
			w.Write(make([]byte, 1<<20))
			w.(http.Flusher).Flush() // chunked: no Content-Length up front
		}
	}))
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	body, _, err := c.Open(context.Background(), s.URL, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	if _, err := io.ReadAll(body); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestOpenDeclaredTooLarge(t *testing.T) {
	s := bodyServer("0123456789")
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	if _, _, err := c.Open(context.Background(), s.URL, 9); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	body, size, err := c.Open(context.Background(), s.URL, 10)
	if err != nil || size != 10 {
		t.Fatalf("exactly max: size %d, %v", size, err)
	}
	body.Close()
}

func TestOpenStatus(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	if _, _, err := c.Open(context.Background(), s.URL, 100); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestGetAcceptSendsHeader(t *testing.T) {
	var got string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get("Accept") }))
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	resp, err := c.GetAccept(context.Background(), s.URL, "application/vnd.pypi.simple.v1+json")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got != "application/vnd.pypi.simple.v1+json" {
		t.Fatalf("Accept = %q", got)
	}
}

func TestAllowed(t *testing.T) {
	c := New(Options{FetchHosts: []string{"files.example.org"}})
	for u, want := range map[string]bool{
		"https://files.example.org/a.whl": true,
		"https://FILES.example.org/a.whl": true,
		"https://evil.example.org/a.whl":  false,
		"http://files.example.org/a.whl":  false,
		"https://u:p@files.example.org/a": false,
		"::not a url":                     false,
	} {
		if got := c.Allowed(u); got != want {
			t.Errorf("Allowed(%q) = %v", u, got)
		}
	}
}

func TestOpenWithHeader(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Last-Modified", "Fri, 20 Nov 2026 08:00:00 GMT")
		io.WriteString(w, "0123456789")
	}))
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	ctx := context.Background()
	body, size, hdr, err := c.OpenWithHeader(ctx, s.URL+"/f", 10)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(body)
	body.Close()
	if err != nil || string(b) != "0123456789" || size != 10 || hdr.Get("Last-Modified") != "Fri, 20 Nov 2026 08:00:00 GMT" {
		t.Fatalf("%q %d %v %v", b, size, hdr, err)
	}
	if _, _, _, err := c.OpenWithHeader(ctx, s.URL+"/f", 9); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over cap: %v", err)
	}
	if _, _, _, err := c.OpenWithHeader(ctx, s.URL+"/f", 0); err == nil {
		t.Fatal("maxBytes 0 accepted")
	}
	_, _, _, err = c.OpenWithHeader(ctx, s.URL+"/missing?X-Amz-Signature=secret", 10)
	var se *StatusError
	if !errors.Is(err, resolve.ErrNotFound) || !errors.As(err, &se) || strings.Contains(se.URL, "secret") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestDoSendsCallerHeaders(t *testing.T) {
	var gotAuth, gotAccept string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotAccept = r.Header.Get("Authorization"), r.Header.Get("Accept")
	}))
	defer s.Close()
	c := testClient(Options{
		FetchHosts:  []string{"127.0.0.1"},
		Credentials: map[string]config.Credential{strings.TrimPrefix(s.URL, "http://"): {Bearer: "static"}},
	})
	req, _ := http.NewRequest(http.MethodGet, s.URL, nil)
	req.Header.Set("Authorization", "Bearer mine")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer mine" || gotAccept != "application/vnd.github+json" {
		t.Fatalf("auth=%q accept=%q", gotAuth, gotAccept)
	}

	bad, _ := http.NewRequest(http.MethodGet, "http://other.test/x", nil)
	if _, err := c.Do(bad); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("err = %v", err)
	}
}

func TestDoRedirectDropsAuthorization(t *testing.T) {
	var gotAuth string
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer b.Close()
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL, http.StatusFound)
	}))
	defer a.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})
	req, _ := http.NewRequest(http.MethodGet, a.URL, nil)
	req.Header.Set("Authorization", "Bearer mine")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotAuth != "" {
		t.Fatalf("redirect carried Authorization %q", gotAuth)
	}
}

func TestOpenRequestCapsBody(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/declared" {
			w.Header().Set("Content-Length", "11")
		}
		if r.URL.Path == "/chunked" {
			w.(http.Flusher).Flush() // no Content-Length
		}
		_, _ = w.Write([]byte("12345678901"))
	}))
	defer s.Close()
	c := testClient(Options{FetchHosts: []string{"127.0.0.1"}})

	req, _ := http.NewRequest(http.MethodGet, s.URL+"/chunked", nil)
	rc, _, _, err := c.OpenRequest(req, 10)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(rc)
	rc.Close()
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("read err = %v", err)
	}

	req, _ = http.NewRequest(http.MethodGet, s.URL+"/declared", nil)
	if _, _, _, err := c.OpenRequest(req, 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("declared err = %v", err)
	}
}

// remoteConn reports a chosen remote address, as a tsnet connection would.
type remoteConn struct {
	net.Conn
	remote net.Addr
	closed bool
}

func (c *remoteConn) RemoteAddr() net.Addr { return c.remote }
func (c *remoteConn) Close() error         { c.closed = true; return c.Conn.Close() }

// tailnetDial returns a dial func that serves one HTTP answer per connection
// and records the addresses it was asked for and the conns it returned.
func tailnetDial(remote string, addrs *[]string, conns *[]*remoteConn) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, _, addr string) (net.Conn, error) {
		*addrs = append(*addrs, addr)
		cl, sv := net.Pipe()
		go func() {
			defer sv.Close()
			if _, err := http.ReadRequest(bufio.NewReader(sv)); err != nil {
				return
			}
			_, _ = io.WriteString(sv, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		}()
		rc := &remoteConn{Conn: cl, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(remote))}
		*conns = append(*conns, rc)
		return rc, nil
	}
}

func TestTailnetHostDialsThroughTailnetDial(t *testing.T) {
	var addrs []string
	var conns []*remoteConn
	c := testClient(Options{
		FetchHosts:   []string{"ghe.example", "127.0.0.1"},
		TailnetHosts: []string{"GHE.example"},
		TailnetDial:  tailnetDial("100.101.102.103:443", &addrs, &conns),
	})
	resp, err := c.Get(context.Background(), "http://ghe.example/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(addrs) != 1 || addrs[0] != "ghe.example:80" {
		t.Fatalf("dialled %v", addrs)
	}

	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer s.Close()
	resp, err = c.Get(context.Background(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(addrs) != 1 {
		t.Fatalf("a non-tailnet host used TailnetDial: %v", addrs)
	}
}

func TestTailnetDialRejectsNonTailscaleAddress(t *testing.T) {
	for _, remote := range []string{"10.0.0.5:443", "192.168.1.1:443", "[fd00::1]:443"} {
		var addrs []string
		var conns []*remoteConn
		c := testClient(Options{
			FetchHosts:   []string{"ghe.example"},
			TailnetHosts: []string{"ghe.example"},
			TailnetDial:  tailnetDial(remote, &addrs, &conns),
		})
		_, err := c.Get(context.Background(), "http://ghe.example/x")
		if !errors.Is(err, ErrForbiddenAddress) {
			t.Fatalf("%s: err = %v", remote, err)
		}
		if len(conns) != 1 || !conns[0].closed {
			t.Fatalf("%s: connection not closed", remote)
		}
	}

	var addrs []string
	var conns []*remoteConn
	c := testClient(Options{
		FetchHosts:   []string{"ghe.example"},
		TailnetHosts: []string{"ghe.example"},
		TailnetDial:  tailnetDial("[fd7a:115c:a1e0::1]:443", &addrs, &conns),
	})
	resp, err := c.Get(context.Background(), "http://ghe.example/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestTailnetHostWithoutDialer(t *testing.T) {
	c := testClient(Options{FetchHosts: []string{"ghe.example"}, TailnetHosts: []string{"ghe.example"}})
	if _, err := c.Get(context.Background(), "http://ghe.example/x"); !errors.Is(err, ErrTailnetDialer) {
		t.Fatalf("err = %v", err)
	}
}

func TestTailnetAddressStillForbiddenForOtherHosts(t *testing.T) {
	c := New(Options{FetchHosts: []string{"100.64.0.1"}})
	_, err := c.Get(context.Background(), "https://100.64.0.1/x")
	if !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("err = %v", err)
	}
}
