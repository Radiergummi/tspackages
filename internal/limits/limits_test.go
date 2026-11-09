package limits

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/identity"
)

func do(h http.Handler, node string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/", nil)
	if node != "" {
		r = r.WithContext(identity.WithCaller(r.Context(), identity.Caller{NodeStableID: node}))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var ok = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})

func TestRequestLimitPerIdentity(t *testing.T) {
	l := New(config.Limits{RequestsPerSecond: 0.001, Burst: 2, UpstreamFetchesPerSecond: 10})
	defer l.Close()
	h := l.Middleware()(ok)
	for i := 0; i < 2; i++ {
		if w := do(h, "A"); w.Code != 200 {
			t.Fatalf("req %d = %d", i, w.Code)
		}
	}
	w := do(h, "A")
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" || strings.TrimSpace(w.Body.String()) != "rate limit exceeded" {
		t.Fatalf("third = %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	if w := do(h, "B"); w.Code != 200 {
		t.Fatalf("B = %d", w.Code)
	}
	if l.Rejected() != 1 {
		t.Fatalf("rejected = %d", l.Rejected())
	}
}

func TestMissingIdentityForbidden(t *testing.T) {
	l := New(config.Limits{RequestsPerSecond: 1, Burst: 1, UpstreamFetchesPerSecond: 1})
	defer l.Close()
	h := l.Middleware()(ok)
	if w := do(h, ""); w.Code != 403 {
		t.Fatalf("no caller = %d", w.Code)
	}
}

func TestUpstreamWaitHonoursContext(t *testing.T) {
	l := New(config.Limits{RequestsPerSecond: 1, Burst: 1, UpstreamFetchesPerSecond: 0.001})
	defer l.Close()
	var got context.Context
	h := l.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Context() }))
	do(h, "A")
	if err := UpstreamWait(got); err != nil { // burst 1 token
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(got)
	cancel()
	if err := UpstreamWait(ctx); err == nil {
		t.Fatal("expected error")
	}
	if err := UpstreamWait(context.Background()); err != nil {
		t.Fatalf("no limiter: %v", err)
	}
}

func TestIdleEviction(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	l := newLimiter(config.Limits{RequestsPerSecond: 1, Burst: 1, UpstreamFetchesPerSecond: 1}, clock)
	defer l.Close()
	do(l.Middleware()(ok), "A")
	if l.size() != 1 {
		t.Fatal("not tracked")
	}
	mu.Lock()
	now = now.Add(idleTTL + time.Second)
	mu.Unlock()
	l.sweep()
	if l.size() != 0 {
		t.Fatal("idle entry kept")
	}
}

func TestZeroRateUnlimited(t *testing.T) {
	l := New(config.Limits{})
	defer l.Close()
	h := l.Middleware()(ok)
	for i := 0; i < 500; i++ {
		if w := do(h, "A"); w.Code != 200 {
			t.Fatalf("req %d = %d", i, w.Code)
		}
	}
}
