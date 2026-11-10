// Package identity derives the request's caller from Tailscale WhoIs.
package identity

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/radiergummi/tspackages/internal/authz"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
)

type Caller struct {
	Login        string
	Tags         []string
	NodeName     string
	NodeStableID string
	Rules        []authz.Rule
}

// String is the login, or the tags joined with ",".
func (c Caller) String() string {
	if c.Login != "" {
		return c.Login
	}
	return strings.Join(c.Tags, ",")
}

// Whoiser is satisfied by *local.Client.
type Whoiser interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// FromWhoIs builds a Caller from a WhoIs response and the app capability.
func FromWhoIs(r *apitype.WhoIsResponse, capName peercap.Cap) (Caller, error) {
	if r == nil || r.Node == nil {
		return Caller{}, errors.New("whois response has no node")
	}
	c := Caller{
		NodeName:     strings.TrimSuffix(r.Node.Name, "."),
		NodeStableID: string(r.Node.StableID),
	}
	if r.Node.IsTagged() {
		c.Tags = slices.Clone(r.Node.Tags)
	} else {
		if r.UserProfile == nil {
			return Caller{}, errors.New("whois response has no user profile")
		}
		if strings.TrimSpace(r.UserProfile.LoginName) == "" {
			return Caller{}, errors.New("whois response has empty login name")
		}
		c.Login = r.UserProfile.LoginName
	}
	rules, err := tailcfg.UnmarshalCapJSON[authz.Rule](r.CapMap, capName)
	if err != nil {
		return Caller{}, err
	}
	c.Rules = rules
	return c, nil
}

type ctxKey struct{}

func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

func FromContext(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(ctxKey{}).(Caller)
	return c, ok
}

// failureLogInterval is the least time between two identity-failure warnings.
const failureLogInterval = 10 * time.Second

// Middleware strips client credentials, resolves the caller via WhoIs and
// stores it in the request context. Any failure is a 403.
func Middleware(w Whoiser, capName peercap.Cap, log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	// Failures run before rate limiting, so one warning per interval at most;
	// the rest go to debug.
	var lastWarn atomic.Int64
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			r.Header.Del("Authorization")
			r.Header.Del("Proxy-Authorization")
			resp, err := w.WhoIs(r.Context(), r.RemoteAddr)
			var c Caller
			if err == nil {
				c, err = FromWhoIs(resp, capName)
			}
			if err != nil {
				level, now, last := slog.LevelDebug, time.Now().UnixNano(), lastWarn.Load()
				if now-last >= int64(failureLogInterval) && lastWarn.CompareAndSwap(last, now) {
					level = slog.LevelWarn
				}
				log.Log(r.Context(), level, "tailnet identity unavailable", "remote", r.RemoteAddr, "err", err)
				rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
				rw.WriteHeader(http.StatusForbidden)
				_, _ = rw.Write([]byte("tailnet identity unavailable"))
				return
			}
			next.ServeHTTP(rw, r.WithContext(WithCaller(r.Context(), c)))
		})
	}
}
