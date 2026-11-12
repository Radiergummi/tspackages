package web_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/web"
)

type goEco struct{}

func (goEco) Name() string         { return "go" }
func (goEco) Mount(*http.ServeMux) {}

// goMatch is a test matcher: a trailing "*" is a prefix wildcard.
func goMatch(pattern, name string) bool {
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(name, p)
	}
	return pattern == name
}

func goReader(patterns ...string) *identity.Caller {
	return &identity.Caller{Login: "a@b", Rules: []authz.Rule{{Read: patterns}}}
}

func goSection(rows func() []web.Row, snippets ...web.Snippet) web.Section {
	return web.Section{
		Ecosystem: "go", Title: "Go", Match: goMatch, Snippets: snippets,
		Tables: []web.Table{{Title: "Things", Level: 3, Empty: "Nothing.", Columns: []string{"Name"}, Rows: rows}},
	}
}

func TestSectionRowsFilteredByAnyPackage(t *testing.T) {
	rows := func() []web.Row {
		return []web.Row{
			{Packages: []string{"github.com/acme/a", "github.com/other/b"}, Cells: []web.Cell{{Lines: []string{"multi-row"}}}},
			{Cells: []web.Cell{{Lines: []string{"no-packages-row"}}}},
		}
	}
	w := web.New(web.Options{Hostname: "h", Ecosystems: []ecosystem.Ecosystem{goEco{}}, Sections: []web.Section{goSection(rows)}})
	body := serve(t, w, "/", goReader("go:github.com/acme/*")).Body.String()
	if !strings.Contains(body, "multi-row") {
		t.Error("row with a readable package hidden")
	}
	if strings.Contains(body, "no-packages-row") {
		t.Error("row without packages shown")
	}
	body = serve(t, w, "/", goReader("go:github.com/x/*")).Body.String()
	if strings.Contains(body, "multi-row") || strings.Contains(body, "no-packages-row") {
		t.Error("row shown to a caller who may not read any of its packages")
	}
	if !strings.Contains(body, "Nothing.") {
		t.Error("empty text missing")
	}
}

func TestScopedHealthUsesItsEcosystemMatcher(t *testing.T) {
	src := fakeSource{{Name: "go-remote", Ecosystem: "go", Scoped: true, OK: true, Packages: []string{"github.com/acme/x"}}}
	w := web.New(web.Options{Hostname: "h", Ecosystems: []ecosystem.Ecosystem{goEco{}},
		Sources: []web.StatusSource{src}, Sections: []web.Section{goSection(nil)}})
	if body := serve(t, w, "/", goReader("go:github.com/acme/*")).Body.String(); !strings.Contains(body, "go-remote") {
		t.Error("row hidden from a go reader of the package")
	}
	if body := serve(t, w, "/", goReader("composer:*")).Body.String(); strings.Contains(body, "go-remote") {
		t.Error("go row shown to a composer-only reader")
	}
}

func TestTableLevels(t *testing.T) {
	sec := goSection(nil)
	sec.Tables = append(sec.Tables, web.Table{Title: "Shared", Level: 2, Empty: "None.", Columns: []string{"X"}})
	w := web.New(web.Options{Hostname: "h", Ecosystems: []ecosystem.Ecosystem{goEco{}}, Sections: []web.Section{sec}})
	body := serve(t, w, "/", goReader("*")).Body.String()
	shared, heading, things := strings.Index(body, "<h2>Shared</h2>"), strings.Index(body, "<h2>Go</h2>"), strings.Index(body, "<h3>Things</h3>")
	if shared < 0 || heading < 0 || things < 0 || shared >= heading || heading >= things {
		t.Fatalf("shared %d, heading %d, things %d\n%s", shared, heading, things, body)
	}
}

func TestSectionHiddenWhenEcosystemNotMounted(t *testing.T) {
	w := web.New(web.Options{Hostname: "h", Ecosystems: []ecosystem.Ecosystem{fakeEco{}}, Sections: []web.Section{goSection(nil)}})
	if body := serve(t, w, "/", goReader("*")).Body.String(); strings.Contains(body, "Go</h2>") || strings.Contains(body, "Things") {
		t.Error("section of an unmounted ecosystem rendered")
	}
}

func TestSnippetHostEscaped(t *testing.T) {
	sec := goSection(nil, web.Snippet{Intro: "Set <code>GOPROXY</code>:", Code: "GOPROXY=https://{{host}}/go"}, web.Snippet{Intro: "Only intro."})
	w := web.New(web.Options{Hostname: "h", Ecosystems: []ecosystem.Ecosystem{goEco{}}, Sections: []web.Section{sec}})
	r := serveHost(t, w, "a<b", goReader("*"))
	body := r.Body.String()
	for _, want := range []string{"GOPROXY=https://a&lt;b/go", "Set <code>GOPROXY</code>:", "<p>Only intro.</p>"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	if strings.Contains(body, "a<b") {
		t.Error("host not escaped")
	}
	if strings.Count(body, "<pre>") != 1 {
		t.Error("a snippet without code rendered a pre block")
	}
}
