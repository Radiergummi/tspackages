// Package limits enforces per-identity request and upstream-fetch rate limits,
// so one tailnet member cannot exhaust the server or a shared upstream quota.
package limits

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/identity"
)

const (
	idleTTL       = 10 * time.Minute
	sweepInterval = time.Minute
)

type entry struct {
	req      *rate.Limiter
	upstream *rate.Limiter
	lastSeen time.Time
}

// Limiter holds one request limiter and one upstream-fetch limiter per node.
// Rates must be positive; config validation enforces it.
type Limiter struct {
	cfg      config.Limits
	now      func() time.Time
	mu       sync.Mutex
	entries  map[string]*entry
	rejected atomic.Uint64
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// New returns a Limiter and starts its idle-eviction janitor; call Close to stop it.
func New(l config.Limits) *Limiter { return newLimiter(l, time.Now, sweepInterval) }

func newLimiter(l config.Limits, now func() time.Time, sweep time.Duration) *Limiter {
	lim := &Limiter{
		cfg:     l,
		now:     now,
		entries: map[string]*entry{},
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go lim.janitor(sweep)
	return lim
}

// Close stops the janitor.
func (l *Limiter) Close() {
	l.stopOnce.Do(func() { close(l.stop) })
	<-l.done
}

// Rejected returns the number of requests answered with 429.
func (l *Limiter) Rejected() uint64 { return l.rejected.Load() }

func (l *Limiter) janitor(every time.Duration) {
	defer close(l.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.sweep()
		}
	}
}

func (l *Limiter) sweep() {
	cutoff := l.now().Add(-idleTTL)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range l.entries {
		if e.lastSeen.Before(cutoff) {
			delete(l.entries, k)
		}
	}
}

func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func (l *Limiter) get(key string) *entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		upBurst := max(1, int(2*l.cfg.UpstreamFetchesPerSecond))
		e = &entry{
			req:      newRate(l.cfg.RequestsPerSecond, l.cfg.Burst),
			upstream: newRate(l.cfg.UpstreamFetchesPerSecond, upBurst),
		}
		l.entries[key] = e
	}
	e.lastSeen = l.now()
	return e
}

func (l *Limiter) touch(e *entry) {
	l.mu.Lock()
	e.lastSeen = l.now()
	l.mu.Unlock()
}

func newRate(perSecond float64, burst int) *rate.Limiter {
	return rate.NewLimiter(rate.Limit(perSecond), max(1, burst))
}

type ctxKey struct{}

// Middleware must run after identity.Middleware. Requests without a caller
// get 403; there is no shared anonymous bucket.
func (l *Limiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := identity.FromContext(r.Context())
			if !ok || c.NodeStableID == "" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			e := l.get(c.NodeStableID)
			if !e.req.Allow() {
				l.rejected.Add(1)
				w.Header().Set("Retry-After", "1")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, e.upstream)))
			l.touch(e) // a long request keeps its entry from idle eviction
		})
	}
}

// UpstreamWait blocks until the caller's upstream limiter grants a token, or
// ctx ends. Without a limiter in ctx it returns nil immediately.
func UpstreamWait(ctx context.Context) error {
	lim, ok := ctx.Value(ctxKey{}).(*rate.Limiter)
	if !ok {
		return nil
	}
	return lim.Wait(ctx)
}
