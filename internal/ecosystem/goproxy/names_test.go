package goproxy

import (
	"strings"
	"testing"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/storage"
)

func TestRouteSpellings(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Route
	}{
		{"github.com/!acme/x/@v/list", Route{"github.com/Acme/x", "", KindList}},
		{"github.com/acme/x/v2/@v/v2.0.0.info", Route{"github.com/acme/x/v2", "v2.0.0", KindInfo}},
		{"github.com/acme/x/@v/v1.0.0-!r!c1.mod", Route{"github.com/acme/x", "v1.0.0-RC1", KindMod}},
		{"github.com/acme/x/@v/v1.0.0.zip", Route{"github.com/acme/x", "v1.0.0", KindZip}},
		{"github.com/acme/x/@latest", Route{"github.com/acme/x", "", KindLatest}},
	} {
		got, err := ParseRoute(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ParseRoute(%q) = %+v, %v; want %+v", tc.in, got, err, tc.want)
		}
	}
	for _, in := range []string{
		"github.com/Acme/x/@v/list",
		"github.com/!!acme/x/@v/list",
		"github.com/acme/x/@v/",
		"github.com/acme/x/@v/.info",
		"github.com/acme/x/@v/v1.0.0.tar",
		"github.com/acme/x/@v/a/b.info",
		"github.com/acme/x@v1/@v/list",
		"acme/x/@v/list",
		"sumdb/sum.golang.org/supported",
		"",
	} {
		if got, err := ParseRoute(in); err == nil {
			t.Errorf("ParseRoute(%q) = %+v; want an error", in, got)
		}
	}
}

func TestMatchAgreesWithConfig(t *testing.T) {
	patterns := []string{"*", "go.acme.dev/sdk", "go.acme.dev/*", "go.acme.dev/a*/x", "github.com/acme/*", "github.com/ac*/x", "gopkg.in/yaml", "a/b/*", "A/b", "a//b", "", "a/**", "a?"}
	paths := []string{"go.acme.dev/sdk", "go.acme.dev/sdk/v2", "go.acme.dev/sdk/v10", "go.acme.dev/sdk/v1", "go.acme.dev/x/v2", "github.com/acme/x", "github.com/Acme/x", "github.com/acme", "gopkg.in/yaml.v3", "a/b/c/v3", "a/b"}
	n := 0
	for _, pat := range patterns {
		if ValidPattern(pat) != config.ValidGoPattern(pat) {
			t.Errorf("ValidPattern(%q) disagrees with config", pat)
		}
		for _, p := range paths {
			n++
			if Match(pat, p) != config.GoMatch(strings.ToLower(pat), strings.ToLower(p)) && ValidPattern(pat) {
				t.Errorf("Match(%q, %q) = %v disagrees with config", pat, p, Match(pat, p))
			}
		}
	}
	if n < 40 {
		t.Fatalf("only %d pairs", n)
	}
}

func TestMatchMajorSuffix(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"go.acme.dev/sdk", "go.acme.dev/sdk/v2", true},
		{"go.acme.dev/sdk", "go.acme.dev/sdk/v10", true},
		{"go.acme.dev/sdk", "go.acme.dev/sdk/v1", false},
		{"go.acme.dev/sdk", "go.acme.dev/sdk/v2x", false},
		{"go.acme.dev/sdk", "go.acme.dev/sdkv2", false},
		{"go.acme.dev/*", "go.acme.dev/x/v2", true},
		{"go.acme.dev/sdk", "Go.Acme.Dev/SDK/V2", true},
		{"go.acme.dev/sdk", "Go.Acme.Dev/SDK/v2", true},
		{"gopkg.in/yaml", "gopkg.in/yaml.v3", false},
	} {
		if got := Match(tc.pattern, tc.path); got != tc.want {
			t.Errorf("Match(%q, %q) = %v", tc.pattern, tc.path, got)
		}
	}
}

func TestMatchLowercases(t *testing.T) {
	if !Match("github.com/acme/*", "github.com/Acme/x") {
		t.Error("path not lowercased")
	}
	if Match("github.com/Acme/*", "github.com/acme/x") {
		t.Error("an uppercase pattern is invalid and matches nothing")
	}
}

func TestKeySegmentsInjective(t *testing.T) {
	a, ok1 := pathSeg("github.com/Acme/x")
	b, ok2 := pathSeg("github.com/acme/x")
	if !ok1 || !ok2 || a == b {
		t.Errorf("segments %q %q", a, b)
	}
	if _, ok := pathSeg("github.com/" + strings.Repeat("a", 200)); ok {
		t.Error("a 200-byte path must not fit a segment")
	}
	if _, ok := versionSeg(strings.Repeat("v", storage.MaxSegment)); ok {
		t.Error("an over-long version must not fit a segment")
	}
	if s, ok := versionSeg("v1.0.0-RC1"); !ok || s != storage.EscapeSegment("v1.0.0-RC1") {
		t.Errorf("versionSeg = %q, %v", s, ok)
	}
}
