package pypi

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWantJSON(t *testing.T) {
	for accept, want := range map[string]bool{
		"application/vnd.pypi.simple.v1+json":     true,
		"application/vnd.pypi.simple.latest+json": true,
		"text/html": false,
		"":          false,
		"*/*":       false,
		"application/vnd.pypi.simple.v1+json;q=0.1, text/html":         false,
		"application/vnd.pypi.simple.v1+json, text/html;q=0.01":        true,
		"application/vnd.pypi.simple.v1+html, application/json;q=0.9":  false,
		"application/vnd.pypi.simple.v1+json; q=0, text/html; q=0.001": false,
	} {
		if got := WantJSON(accept); got != want {
			t.Errorf("WantJSON(%q) = %v", accept, got)
		}
	}
}

var sampleProject = Project{
	Name:     "matchory-core",
	Versions: []string{"1.0.0"},
	Files: []File{{
		Filename: "matchory_core-1.0.0-py3-none-any.whl", URL: "https://reg/pypi/files/hosted/matchory-core/matchory_core-1.0.0-py3-none-any.whl",
		SHA256: "aa", RequiresPython: ">=3.10", Yanked: false, UploadTime: time.Date(2026, 11, 11, 9, 30, 0, 0, time.UTC),
		Size: 1234, CoreMetadata: "bb", HasProvenance: true, ProvenanceURL: "https://reg/pypi/integrity/x",
	}, {
		Filename: "matchory_core-1.0.0.tar.gz", URL: "https://reg/f/<x>.tar.gz", SHA256: "cc", Yanked: "broken <build>",
	}},
}

func TestWriteProjectHTML(t *testing.T) {
	w := httptest.NewRecorder()
	WriteProject(w, sampleProject, false)
	body := w.Body.String()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type %q", ct)
	}
	for _, want := range []string{
		`<meta name="pypi:repository-version" content="1.4">`,
		`<a href="https://reg/pypi/files/hosted/matchory-core/matchory_core-1.0.0-py3-none-any.whl#sha256=aa" data-requires-python="&gt;=3.10" data-core-metadata="sha256=bb" data-dist-info-metadata="sha256=bb" data-provenance="https://reg/pypi/integrity/x">matchory_core-1.0.0-py3-none-any.whl</a>`,
		`data-yanked="broken &lt;build&gt;"`,
		`href="https://reg/f/%3cx%3e.tar.gz#sha256=cc"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %s\n%s", want, body)
		}
	}
	if strings.Contains(body, "<build>") || strings.Contains(body, "<x>") {
		t.Error("unescaped value")
	}
}

func TestWriteProjectJSON(t *testing.T) {
	w := httptest.NewRecorder()
	WriteProject(w, sampleProject, true)
	if ct := w.Header().Get("Content-Type"); ct != "application/vnd.pypi.simple.v1+json" {
		t.Errorf("content type %q", ct)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["meta"].(map[string]any)["api-version"] != "1.4" || got["name"] != "matchory-core" {
		t.Fatalf("head: %v", got)
	}
	files := got["files"].([]any)
	f0, f1 := files[0].(map[string]any), files[1].(map[string]any)
	if f0["hashes"].(map[string]any)["sha256"] != "aa" || f0["requires-python"] != ">=3.10" || f0["size"] != 1234.0 ||
		f0["upload-time"] != "2026-11-11T09:30:00Z" || f0["core-metadata"].(map[string]any)["sha256"] != "bb" ||
		f0["provenance"] != "https://reg/pypi/integrity/x" || f0["yanked"] != false {
		t.Fatalf("file 0: %v", f0)
	}
	if f1["core-metadata"] != false || f1["yanked"] != "broken <build>" || f1["provenance"] != nil || f1["upload-time"] != nil {
		t.Fatalf("file 1: %v", f1)
	}
	if _, ok := got["project-status"]; ok {
		t.Error("project-status without a status")
	}
}

func TestWriteIndex(t *testing.T) {
	w := httptest.NewRecorder()
	WriteIndex(w, []string{"b-pkg", "a&b"}, false)
	if !strings.Contains(w.Body.String(), `<a href="a&amp;b/">a&amp;b</a>`) {
		t.Fatalf("html: %s", w.Body)
	}
	w = httptest.NewRecorder()
	WriteIndex(w, []string{"b-pkg"}, true)
	if !strings.Contains(w.Body.String(), `"projects":[{"name":"b-pkg"}]`) {
		t.Fatalf("json: %s", w.Body)
	}
}
