package apt_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/ecosystem/apt"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/testutil"
	"github.com/radiergummi/tspackages/internal/web"
)

type fakeEco struct{}

func (fakeEco) Name() string         { return "apt" }
func (fakeEco) Mount(*http.ServeMux) {}

var _ ecosystem.Ecosystem = fakeEco{}

func statusPage(t *testing.T, signer *apt.Signer, read ...string) string {
	t.Helper()
	w := web.New(web.Options{
		Hostname:   "fallback",
		Ecosystems: []ecosystem.Ecosystem{fakeEco{}},
		Sections: []web.Section{apt.StatusSection(
			[]string{"hosted"},
			[]apt.RegistryStanza{{Name: "debian", Suites: []string{"bookworm", "bookworm-updates"}, Components: []string{"main"}}},
			signer,
			func() []apt.ChangedFile {
				return []apt.ChangedFile{{Source: "debian", Package: "hello", Path: "pool/main/h/hello/hello_1.0_amd64.deb", First: "aaaa", Now: "bbbb"}}
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

func TestStatusSection(t *testing.T) {
	priv, _ := testutil.PGPKey(t, "status")
	signer, err := apt.LoadSigner(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	body := statusPage(t, signer, "apt:hello")
	for _, want := range []string{
		"Without this file a client is not protected against a claimed name being shadowed by another repository.",
		"https://pkgs.tail.ts.net/apt/hosted/", "https://pkgs.tail.ts.net/apt/debian/",
		"Suites: bookworm bookworm-updates", "/etc/apt/keyrings/tspackages.asc",
		"/usr/share/keyrings/debian-archive-keyring.gpg", "/apt/preferences",
		"curl -fT pkg.deb https://pkgs.tail.ts.net/apt/hosted/", signer.Fingerprint(),
		"Changed artifacts", "hello_1.0_amd64.deb", "bbbb",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if n := strings.Count(body, "Types: deb"); n != 2 {
		t.Errorf("%d .sources stanzas, want 2", n)
	}
	if strings.Contains(body, "{{host}}") {
		t.Error("host placeholder left in the page")
	}

	if body := statusPage(t, nil, "apt:other"); strings.Contains(body, "hello_1.0_amd64.deb") || strings.Contains(body, "signing key fingerprint") {
		t.Error("changed row shown without a read rule, or fingerprint without a signer")
	}
}
