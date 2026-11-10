// Package upstream is the only way the server fetches from upstream
// registries. It is the SSRF and credential-leak boundary: requests go only to
// allowlisted hosts, never to internal addresses, and credentials are sent
// only to the exact host they were configured for.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/digest"
	"github.com/radiergummi/tspackages/internal/resolve"
)

var (
	ErrHostNotAllowed   = errors.New("upstream host not allowed")
	ErrForbiddenAddress = errors.New("upstream address forbidden")
	ErrTooLarge         = errors.New("upstream response too large")
	ErrDigestMismatch   = errors.New("upstream digest mismatch")
	ErrUserinfo         = errors.New("upstream url must not contain userinfo")
	ErrSchemeNotAllowed = errors.New("upstream scheme not allowed")
)

const (
	defaultTimeout = 30 * time.Second
	maxRedirects   = 5
)

// redactURL drops query, fragment and userinfo so errors and logs cannot leak
// tokens carried in them.
func redactURL(u *url.URL) string {
	c := *u
	c.RawQuery, c.ForceQuery, c.Fragment, c.RawFragment, c.User = "", false, "", "", nil
	return c.String()
}

// StatusError is returned for non-2xx responses. A 404 also matches
// resolve.ErrNotFound via errors.Is.
type StatusError struct {
	Code int
	URL  string // query string stripped
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("upstream returned status %d for %s", e.Code, e.URL)
}

func (e *StatusError) Is(target error) bool {
	return e.Code == http.StatusNotFound && target == resolve.ErrNotFound
}

type Options struct {
	// FetchHosts is the allowlist. An entry is compared with the URL's
	// hostname, case-insensitively and exactly (no wildcards). An entry
	// written as host:port additionally requires that port.
	FetchHosts []string
	// Credentials are keyed by the exact URL host as configured, including
	// the port if one is part of the URL ("host" or "host:port").
	Credentials map[string]config.Credential
	// Timeout (default 30s) bounds dialing, the TLS handshake and waiting
	// for response headers. It does not bound the body read: that is limited
	// by the caller's context and, in FetchVerified, by maxBytes.
	Timeout time.Duration
	// AllowPrivateForTesting permits the http scheme and loopback/private
	// addresses. For tests only; never set it from configuration.
	AllowPrivateForTesting bool
}

type Client struct {
	hosts        []string
	creds        map[string]config.Credential
	allowPrivate bool
	http         *http.Client
}

func New(o Options) *Client {
	c := &Client{
		hosts:        o.FetchHosts,
		allowPrivate: o.AllowPrivateForTesting,
	}
	c.creds = make(map[string]config.Credential, len(o.Credentials))
	for h, cr := range o.Credentials {
		c.creds[strings.ToLower(h)] = cr
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	dialer := &net.Dialer{Timeout: timeout, Control: c.control}
	c.http = &http.Client{
		Transport: &http.Transport{
			// No proxy: it would connect on our behalf and bypass the
			// dial-time address check.
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			MaxIdleConns:          20,
			IdleConnTimeout:       90 * time.Second,
		},
		CheckRedirect: c.checkRedirect,
	}
	return c
}

// control runs on the resolved IP right before connecting, so a hostname that
// resolves (or rebinds) to an internal address is refused.
func (c *Client) control(_, address string, _ syscall.RawConn) error {
	if c.allowPrivate {
		return nil
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrForbiddenAddress, address)
	}
	if forbiddenAddr(ap.Addr()) {
		return fmt.Errorf("%w: %s", ErrForbiddenAddress, ap.Addr())
	}
	return nil
}

func forbiddenAddr(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return forbiddenV4(a)
	}
	b := a.As16()
	switch {
	case nat64LocalUse.Contains(a):
		return true // embedding position varies; block the whole range
	case nat64.Contains(a):
		return forbiddenV4(netip.AddrFrom4([4]byte(b[12:])))
	case sixToFour.Contains(a):
		return forbiddenV4(netip.AddrFrom4([4]byte(b[2:6])))
	case v4Translated.Contains(a):
		return forbiddenV4(netip.AddrFrom4([4]byte(b[12:])))
	case v4Compat.Contains(a) && !a.IsUnspecified():
		if forbiddenV4(netip.AddrFrom4([4]byte(b[12:]))) {
			return true
		}
	}
	return documentation6.Contains(a) || documentation6b.Contains(a) || teredo.Contains(a) ||
		discard6.Contains(a) || siteLocal.Contains(a) || nonUnicast(a)
}

func forbiddenV4(a netip.Addr) bool {
	return nonUnicast(a) || thisNetwork.Contains(a) ||
		cgnat.Contains(a) || benchmark.Contains(a) || reserved.Contains(a) ||
		ietfProtocol.Contains(a) || testNet1.Contains(a) || testNet2.Contains(a) ||
		testNet3.Contains(a) || relay6to4.Contains(a)
}

// nonUnicast reports loopback, private, link-local, multicast (which includes
// link- and interface-local multicast) and unspecified addresses.
func nonUnicast(a netip.Addr) bool {
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified()
}

var (
	cgnat           = netip.MustParsePrefix("100.64.0.0/10")
	thisNetwork     = netip.MustParsePrefix("0.0.0.0/8")
	benchmark       = netip.MustParsePrefix("198.18.0.0/15")
	reserved        = netip.MustParsePrefix("240.0.0.0/4") // incl. 255.255.255.255
	ietfProtocol    = netip.MustParsePrefix("192.0.0.0/24")
	testNet1        = netip.MustParsePrefix("192.0.2.0/24")
	testNet2        = netip.MustParsePrefix("198.51.100.0/24")
	testNet3        = netip.MustParsePrefix("203.0.113.0/24")
	relay6to4       = netip.MustParsePrefix("192.88.99.0/24")
	documentation6  = netip.MustParsePrefix("2001:db8::/32")
	documentation6b = netip.MustParsePrefix("3fff::/20")
	siteLocal       = netip.MustParsePrefix("fec0::/10")       // deprecated, but still routable on some networks
	v4Translated    = netip.MustParsePrefix("::ffff:0:0:0/96") // SIIT
	teredo          = netip.MustParsePrefix("2001::/32")
	discard6        = netip.MustParsePrefix("100::/64")
	nat64           = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalUse   = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour       = netip.MustParsePrefix("2002::/16")
	v4Compat        = netip.MustParsePrefix("::/96")
)

func (c *Client) checkURL(u *url.URL) error {
	if u.Scheme != "https" && (u.Scheme != "http" || !c.allowPrivate) {
		return fmt.Errorf("%w: %q", ErrSchemeNotAllowed, u.Scheme)
	}
	if u.User != nil {
		return ErrUserinfo
	}
	if !config.HostAllowed(c.hosts, u) {
		return fmt.Errorf("%w: %s", ErrHostNotAllowed, u.Host)
	}
	return nil
}

func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if err := c.checkURL(req.URL); err != nil {
		return err
	}
	req.Header.Del("Authorization")
	req.Header.Del("Referer")
	return nil
}

// Get fetches rawURL. The caller must close the response body.
func (c *Client) Get(ctx context.Context, rawURL string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		// The parse error quotes the whole URL; keep only its cause.
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		return nil, fmt.Errorf("parse upstream url: %w", err)
	}
	if err := c.checkURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if cr, ok := c.creds[strings.ToLower(u.Host)]; ok {
		switch {
		case cr.Bearer != "":
			req.Header.Set("Authorization", "Bearer "+cr.Bearer)
		case cr.Username != "" || cr.Password != "":
			req.SetBasicAuth(cr.Username, cr.Password)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ue, ok := errors.AsType[*url.Error](err); ok {
			// Keep the cause (errors.Is/As) but drop query/userinfo from the text.
			if pu, perr := url.Parse(ue.URL); perr == nil {
				ue.URL = redactURL(pu)
			} else {
				ue.URL = "(unparseable)"
			}
		}
		return nil, err
	}
	return resp, nil
}

// FetchVerified downloads at most maxBytes and returns the body with its
// SHA-1 and SHA-256. If wantSHA1 is set and differs (case-insensitively), it
// returns ErrDigestMismatch and no body.
func (c *Client) FetchVerified(ctx context.Context, rawURL, wantSHA1 string, maxBytes int64) (body []byte, sha1Hex, sha256Hex string, err error) {
	if maxBytes <= 0 {
		return nil, "", "", fmt.Errorf("maxBytes must be positive, got %d", maxBytes)
	}
	resp, err := c.Get(ctx, rawURL)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, "", "", &StatusError{Code: resp.StatusCode, URL: redactURL(resp.Request.URL)}
	}
	if resp.ContentLength > maxBytes {
		return nil, "", "", ErrTooLarge
	}
	limit := maxBytes
	if limit < math.MaxInt64 {
		limit++ // one extra byte detects overflow
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, "", "", err
	}
	if int64(len(body)) > maxBytes {
		return nil, "", "", ErrTooLarge
	}
	sha1Hex, sha256Hex = digest.Of(body)
	if wantSHA1 != "" && !strings.EqualFold(sha1Hex, wantSHA1) {
		return nil, "", "", fmt.Errorf("%w: sha1 want %s, got %s", ErrDigestMismatch, wantSHA1, sha1Hex)
	}
	return body, sha1Hex, sha256Hex, nil
}
