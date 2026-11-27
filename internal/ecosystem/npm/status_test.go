package npm_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/ecosystem/npm"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/web"
)

type fakeEco struct{}

func (fakeEco) Name() string         { return "npm" }
func (fakeEco) Mount(*http.ServeMux) {}

var _ ecosystem.Ecosystem = fakeEco{}

func statusPage(t *testing.T, read ...string) string {
	t.Helper()
	w := web.New(web.Options{
		Hostname:   "fallback",
		Ecosystems: []ecosystem.Ecosystem{fakeEco{}},
		Sections: []web.Section{npm.StatusSection(func() []npm.ChangedTarball {
			return []npm.ChangedTarball{
				{Package: "@acme/core", Version: "1.0.0", Source: "npmjs", FirstSHA256: "aaaa", NowSHA256: "bbbb", Seen: time.Unix(0, 0).UTC()},
				{Package: "JSONStream", Version: "1.3.5", Source: "npmjs", FirstSHA256: "cccc", NowSHA256: "dddd", Seen: time.Unix(0, 0).UTC()},
			}
		})},
	})
	mux := http.NewServeMux()
	w.Mount(mux)
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "pkgs.tail.ts.net"
	r = r.WithContext(identity.WithCaller(r.Context(), identity.Caller{Login: "a@b", Rules: []authz.Rule{{Read: read}}}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status page = %d", rec.Code)
	}
	return strings.ReplaceAll(rec.Body.String(), "&#34;", `"`)
}

func TestStatusSectionNPM(t *testing.T) {
	body := statusPage(t, "npm:@acme/*")
	for _, want := range []string{
		"registry=https://pkgs.tail.ts.net/npm/",
		"//pkgs.tail.ts.net/npm/:_authToken=tailscale",
		`"publishConfig": {"registry": "https://pkgs.tail.ts.net/npm/"}`,
		"npm publish --registry https://pkgs.tail.ts.net/npm/",
		"Changed tarballs", "@acme/core", "bbbb",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "{{host}}") {
		t.Error("host placeholder left in the page")
	}
	// The npm: rule does not match this package, so its row stays hidden.
	if body := statusPage(t, "npm:@other/*"); strings.Contains(body, "@acme/core") {
		t.Error("changed tarball shown to a caller without a matching rule")
	}
	// Rules match the normalised name; the row keeps the exact one.
	if body := statusPage(t, "npm:jsonstream"); !strings.Contains(body, "JSONStream") || !strings.Contains(body, "dddd") {
		t.Error("changed tarball of JSONStream hidden from npm:jsonstream")
	}
}
