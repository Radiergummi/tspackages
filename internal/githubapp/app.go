// Package githubapp talks to the GitHub REST API as a GitHub App
// installation: it signs the App's JWT, exchanges it for an installation
// token and lists repositories, releases and release assets. It is the only
// code that talks to the GitHub API.
package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/radiergummi/tspackages/internal/upstream"
)

const (
	apiVersion = "2022-11-28"
	acceptJSON = "application/vnd.github+json"
	// tokenRenewBefore is how long before expires_at an installation token
	// stops being reused.
	tokenRenewBefore = 5 * time.Minute
	maxJSONBytes     = 64 << 20
)

// errUnauthorized is a 401 from the API: the installation token is no longer
// valid.
var errUnauthorized = errors.New("github: unauthorized (status 401)")

// App is one GitHub App installation. It is safe for concurrent use.
type App struct {
	c              *upstream.Client
	api            *url.URL
	appID          int64
	installationID int64
	key            *rsa.PrivateKey
	now            func() time.Time

	// tokMu guards the token and is held across its renewal request; it is
	// separate from mu so rate limits and pages never wait on the network.
	tokMu    sync.Mutex
	token    string
	tokenExp time.Time

	mu        sync.Mutex
	remaining int
	reset     time.Time
	pages     map[string]cachedPage

	onResponse atomic.Pointer[func(status int)]
}

// New returns an App that sends every request through c. apiURL is the API
// root, https://api.github.com/ or a GitHub Enterprise Server .../api/v3/.
// A malformed apiURL makes every call fail.
func New(c *upstream.Client, apiURL string, appID, installationID int64, key *rsa.PrivateKey, now func() time.Time) *App {
	u, _ := url.Parse(apiURL)
	return &App{
		c: c, api: u, appID: appID, installationID: installationID, key: key, now: now,
		remaining: -1,
		pages:     map[string]cachedPage{},
	}
}

// ParseKey parses a PEM-encoded RSA private key, PKCS#1 or PKCS#8.
func ParseKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("private key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("private key is neither PKCS#1 nor PKCS#8")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rk, nil
}

// apiURL joins a path (already escaped) and query onto the API root.
func (a *App) apiURL(path, query string) (string, error) {
	if a.api == nil || a.api.Host == "" {
		return "", errors.New("github: invalid API URL")
	}
	u := *a.api
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawPath = ""
	if ep := a.api.EscapedPath(); ep != "" {
		u.RawPath = strings.TrimSuffix(ep, "/") + path
	}
	u.RawQuery = query
	return u.String(), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwt signs the App's RS256 JWT: iss = app ID, iat 60s back for clock skew,
// exp 9 minutes ahead (GitHub allows 10).
func (a *App) jwt() (string, error) {
	now := a.now().Unix()
	claims, err := json.Marshal(struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}{now - 60, now + 540, strconv.FormatInt(a.appID, 10)})
	if err != nil {
		return "", err
	}
	signing := b64([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("github: signing JWT: %w", err)
	}
	return signing + "." + b64(sig), nil
}

// ErrAuthFailed wraps a failed exchange of the App's JWT for an
// installation token.
var ErrAuthFailed = errors.New("github: App authentication failed")

// InstallationID is the installation the App acts as.
func (a *App) InstallationID() int64 { return a.installationID }

// installationToken returns the cached token while it has more than
// tokenRenewBefore left, else a new one.
func (a *App) installationToken(ctx context.Context) (string, error) {
	a.tokMu.Lock()
	defer a.tokMu.Unlock()
	if a.token != "" && a.now().Before(a.tokenExp.Add(-tokenRenewBefore)) {
		return a.token, nil
	}
	a.token = ""
	tok, exp, err := a.fetchToken(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	a.token, a.tokenExp = tok, exp
	return tok, nil
}

func (a *App) fetchToken(ctx context.Context) (string, time.Time, error) {
	j, err := a.jwt()
	if err != nil {
		return "", time.Time{}, err
	}
	target, err := a.apiURL("/app/installations/"+strconv.FormatInt(a.installationID, 10)+"/access_tokens", "")
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, http.NoBody)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+j)
	req.Header.Set("Accept", acceptJSON)
	req.Header.Set("X-Github-Api-Version", apiVersion)
	resp, err := a.c.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("github: installation token request: %w", err)
	}
	defer resp.Body.Close()
	a.observe(resp.StatusCode)
	a.noteRate(resp.Header)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("github: installation token request: status %d", resp.StatusCode)
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil || out.Token == "" {
		return "", time.Time{}, errors.New("github: installation token response is malformed")
	}
	return out.Token, out.ExpiresAt, nil
}

// forget drops tok if it is still the cached token.
func (a *App) forget(tok string) {
	a.tokMu.Lock()
	if a.token == tok {
		a.token = ""
	}
	a.tokMu.Unlock()
}

// withToken runs fn with an installation token. On a 401 it renews the token
// and runs fn once more.
func (a *App) withToken(ctx context.Context, fn func(token string) error) error {
	for attempt := 0; ; attempt++ {
		tok, err := a.installationToken(ctx)
		if err != nil {
			return err
		}
		err = fn(tok)
		if !errors.Is(err, errUnauthorized) || attempt > 0 {
			return err
		}
		a.forget(tok)
	}
}

// newAPIRequest builds a request to an API URL carrying the token.
func newAPIRequest(ctx context.Context, target, token, accept string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-Github-Api-Version", apiVersion)
	return req, nil
}

// RateLimitError reports an exhausted rate limit. Reset is when it lifts and
// is zero when GitHub did not say.
type RateLimitError struct{ Reset time.Time }

func (e *RateLimitError) Error() string {
	if e.Reset.IsZero() {
		return "github: rate limited"
	}
	return "github: rate limited until " + e.Reset.UTC().Format(time.RFC3339)
}

func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// ErrRateLimited matches every *RateLimitError.
var ErrRateLimited = errors.New("github: rate limited")

// RateLimit returns the remaining requests and the reset time from the last
// response that carried them; remaining is -1 before any did.
func (a *App) RateLimit() (remaining int, reset time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.remaining, a.reset
}

// OnResponse sets f to be called with the status of every answered API
// request; a downloaded asset counts as 200. f must be safe for concurrent use.
func (a *App) OnResponse(f func(status int)) { a.onResponse.Store(&f) }

func (a *App) observe(status int) {
	if f := a.onResponse.Load(); f != nil {
		(*f)(status)
	}
}

func (a *App) noteRate(h http.Header) {
	rem, err := strconv.Atoi(h.Get("X-Ratelimit-Remaining"))
	if err != nil {
		return
	}
	a.mu.Lock()
	a.remaining = rem
	if ts, err := strconv.ParseInt(h.Get("X-Ratelimit-Reset"), 10, 64); err == nil {
		a.reset = time.Unix(ts, 0).UTC()
	}
	a.mu.Unlock()
}

// statusError turns a non-success answer into an error: a 401 into
// errUnauthorized, an exhausted limit (429, or 403 with no requests left) into
// *RateLimitError, anything else into a plain status error. The URL's query is
// left out.
func (a *App) statusError(resp *http.Response) error {
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return errUnauthorized
	case resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-Ratelimit-Remaining") == "0":
		rl := &RateLimitError{}
		if ts, err := strconv.ParseInt(resp.Header.Get("X-Ratelimit-Reset"), 10, 64); err == nil {
			rl.Reset = time.Unix(ts, 0).UTC()
		} else if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			rl.Reset = a.now().Add(time.Duration(s) * time.Second)
		}
		return rl
	}
	return fmt.Errorf("github: status %d for %s", resp.StatusCode, resp.Request.URL.Path)
}

// OpenAsset opens a release asset's bytes. GitHub redirects the API URL to a
// signed download host; the token is not sent there. The caller closes the
// body. The size is the declared one, -1 if unknown. A body above maxBytes
// fails with upstream.ErrTooLarge.
func (a *App) OpenAsset(ctx context.Context, r Repo, assetID int64, maxBytes int64) (io.ReadCloser, int64, error) {
	path, err := repoPath(r)
	if err != nil {
		return nil, 0, err
	}
	target, err := a.apiURL(path+"/releases/assets/"+strconv.FormatInt(assetID, 10), "")
	if err != nil {
		return nil, 0, err
	}
	var body io.ReadCloser
	var size int64
	err = a.withToken(ctx, func(tok string) error {
		req, err := newAPIRequest(ctx, target, tok, "application/octet-stream")
		if err != nil {
			return err
		}
		b, n, _, err := a.c.OpenRequest(req, maxBytes)
		if err == nil {
			a.observe(http.StatusOK)
		}
		if se, ok := errors.AsType[*upstream.StatusError](err); ok {
			a.observe(se.Code)
			switch se.Code {
			case http.StatusUnauthorized:
				return errUnauthorized
			case http.StatusTooManyRequests:
				return &RateLimitError{}
			}
		}
		body, size = b, n
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return body, size, nil
}

// repoPath is "/repos/<owner>/<repo>" for r.FullName.
func repoPath(r Repo) (string, error) {
	owner, name, ok := strings.Cut(r.FullName, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("github: invalid repository name %q", r.FullName)
	}
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name), nil
}
