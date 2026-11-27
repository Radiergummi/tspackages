package maven_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/ecosystem/maven"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/web"
)

type fakeEco struct{}

func (fakeEco) Name() string         { return "maven" }
func (fakeEco) Mount(*http.ServeMux) {}

var _ ecosystem.Ecosystem = fakeEco{}

func statusPage(t *testing.T, read ...string) string {
	t.Helper()
	w := web.New(web.Options{
		Hostname:   "fallback",
		Ecosystems: []ecosystem.Ecosystem{fakeEco{}},
		Sections: []web.Section{maven.StatusSection(func() []maven.ChangedFile {
			return []maven.ChangedFile{
				{Package: "Com.Acme.Core:Lib", Version: "1.0", File: "core-1.0.jar", Source: "central", FirstSHA256: "aaaa", NowSHA256: "bbbb", Seen: time.Unix(0, 0).UTC()},
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
	return rec.Body.String()
}

func TestStatusSectionMaven(t *testing.T) {
	body := statusPage(t, "maven:com.acme.*")
	for _, want := range []string{
		"https://pkgs.tail.ts.net/maven/", "mirrorOf", "distributionManagement",
		"gradlePluginPortal()", "exclusiveContent", "Changed artifacts", "core-1.0.jar", "bbbb",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "{{host}}") {
		t.Error("host placeholder left in the page")
	}
	if body := statusPage(t, "maven:org.other.*"); strings.Contains(body, "core-1.0.jar") {
		t.Error("changed file shown to a caller without a matching rule")
	}
}
