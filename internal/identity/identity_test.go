package identity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

const capName tailcfg.PeerCapability = "github.com/radiergummi/tspackages"

func capMap(raw ...string) tailcfg.PeerCapMap {
	var vals []tailcfg.RawMessage
	for _, r := range raw {
		vals = append(vals, tailcfg.RawMessage(r))
	}
	return tailcfg.PeerCapMap{capName: vals}
}

func TestFromWhoIsTagged(t *testing.T) {
	c, err := FromWhoIs(&apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			Name:     "ci-1.tail.ts.net.",
			StableID: "nStable",
			Tags:     []string{"tag:ci-sdk-php"},
		},
		UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"},
		CapMap:      capMap(`{"read":["*"],"write":["composer:matchory/sdk-php"]}`),
	}, capName)
	if err != nil {
		t.Fatal(err)
	}
	if c.Login != "" || !slices.Equal(c.Tags, []string{"tag:ci-sdk-php"}) {
		t.Fatalf("caller = %+v", c)
	}
	if c.NodeName != "ci-1.tail.ts.net" || c.NodeStableID != "nStable" {
		t.Fatalf("node = %q %q", c.NodeName, c.NodeStableID)
	}
	if len(c.Rules) != 1 ||
		!slices.Equal(c.Rules[0].Read, []string{"*"}) ||
		!slices.Equal(c.Rules[0].Write, []string{"composer:matchory/sdk-php"}) {
		t.Fatalf("rules = %+v", c.Rules)
	}
	if c.String() != "tag:ci-sdk-php" {
		t.Fatalf("String = %q", c.String())
	}
}

func TestFromWhoIsTaggedTwoRules(t *testing.T) {
	c, err := FromWhoIs(&apitype.WhoIsResponse{
		Node:   &tailcfg.Node{Tags: []string{"tag:a"}},
		CapMap: capMap(`{"read":["*"]}`, `{"write":["composer:x/*"]}`),
	}, capName)
	if err != nil || len(c.Rules) != 2 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestFromWhoIsUser(t *testing.T) {
	c, err := FromWhoIs(&apitype.WhoIsResponse{
		Node:        &tailcfg.Node{},
		UserProfile: &tailcfg.UserProfile{LoginName: "a@example.com"},
	}, capName)
	if err != nil || c.Login != "a@example.com" || c.String() != "a@example.com" || len(c.Rules) != 0 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestFromWhoIsErrors(t *testing.T) {
	if _, err := FromWhoIs(nil, capName); err == nil {
		t.Error("nil response accepted")
	}
	if _, err := FromWhoIs(&apitype.WhoIsResponse{}, capName); err == nil {
		t.Error("nil node accepted")
	}
	if _, err := FromWhoIs(&apitype.WhoIsResponse{
		Node:        &tailcfg.Node{},
		UserProfile: &tailcfg.UserProfile{LoginName: "a@example.com"},
		CapMap:      capMap(`{"read":`),
	}, capName); err == nil {
		t.Error("malformed cap accepted")
	}
	if _, err := FromWhoIs(&apitype.WhoIsResponse{Node: &tailcfg.Node{}, UserProfile: &tailcfg.UserProfile{}}, capName); err == nil {
		t.Error("empty login accepted")
	}
	if _, err := FromWhoIs(&apitype.WhoIsResponse{Node: &tailcfg.Node{}}, capName); err == nil {
		t.Error("untagged node without user profile accepted")
	}
}

type fakeWho struct {
	resp *apitype.WhoIsResponse
	err  error
	addr string
}

func (f *fakeWho) WhoIs(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
	f.addr = addr
	return f.resp, f.err
}

var quiet = slog.New(slog.NewJSONHandler(io.Discard, nil))

func TestMiddlewareStripsAuthorization(t *testing.T) {
	who := &fakeWho{resp: &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{},
		UserProfile: &tailcfg.UserProfile{LoginName: "a@example.com"},
	}}
	var seen http.Header
	var caller Caller
	var ok bool
	h := Middleware(who, capName, quiet)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header
		caller, ok = FromContext(r.Context())
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "100.64.0.1:1234"
	req.Header.Set("Authorization", "Bearer x")
	req.Header.Set("Proxy-Authorization", "Basic x")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if seen == nil {
		t.Fatal("handler not called")
	}
	if seen.Get("Authorization") != "" || seen.Get("Proxy-Authorization") != "" {
		t.Fatalf("headers leaked: %v", seen)
	}
	if !ok || caller.Login != "a@example.com" || who.addr != "100.64.0.1:1234" {
		t.Fatalf("caller=%+v ok=%v addr=%q", caller, ok, who.addr)
	}
}

func TestMiddlewareWhoIsFails(t *testing.T) {
	called := false
	h := Middleware(&fakeWho{err: errors.New("boom")}, capName, quiet)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 403 || called || rec.Body.String() != "tailnet identity unavailable" {
		t.Fatalf("code=%d called=%v body=%q", rec.Code, called, rec.Body.String())
	}
}

func TestMiddlewareMalformedCap(t *testing.T) {
	called := false
	who := &fakeWho{resp: &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{},
		UserProfile: &tailcfg.UserProfile{LoginName: "a@example.com"},
		CapMap:      capMap(`not json`),
	}}
	h := Middleware(who, capName, quiet)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 403 || called {
		t.Fatalf("code=%d called=%v", rec.Code, called)
	}
}

func TestWithCallerRoundTrip(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("empty context has caller")
	}
	c := Caller{Login: "x"}
	got, ok := FromContext(WithCaller(context.Background(), c))
	if !ok || got.Login != "x" {
		t.Fatal("round trip failed")
	}
}

func TestFromWhoIsClonesTags(t *testing.T) {
	tags := []string{"tag:a"}
	c, err := FromWhoIs(&apitype.WhoIsResponse{Node: &tailcfg.Node{Tags: tags}}, capName)
	if err != nil {
		t.Fatal(err)
	}
	tags[0] = "tag:evil"
	if c.Tags[0] != "tag:a" {
		t.Fatal("tags alias the response")
	}
}

func TestMiddlewareNilLogger(t *testing.T) {
	h := Middleware(&fakeWho{err: errors.New("boom")}, capName, nil)(http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 403 {
		t.Fatalf("code = %d", rec.Code)
	}
}
