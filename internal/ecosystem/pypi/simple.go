package pypi

import (
	"encoding/json"
	"html/template"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// apiVersion is the simple API version served: PEP 691 JSON with PEP 700
// (size, upload-time, versions), PEP 714 (core-metadata), PEP 740
// (provenance) and PEP 792 (project status).
const apiVersion = "1.4"

const (
	jsonType = "application/vnd.pypi.simple.v1+json"
	htmlType = "text/html; charset=utf-8"
)

// File is one distribution file of a project.
type File struct {
	Filename       string
	URL            string // filled by the handler
	SHA256         string
	RequiresPython string
	Yanked         any       // false, true or a reason (PEP 592)
	UploadTime     time.Time // zero = omitted
	Size           int64     // 0 = omitted
	CoreMetadata   string    // sha256 of the .metadata file; "" = none
	HasProvenance  bool
	ProvenanceURL  string // filled by the handler
}

// Project is a project's page in the simple API.
type Project struct {
	Name     string
	Versions []string
	Files    []File
	Status   string // PEP 792; "" = omitted
}

// WantJSON reports whether accept prefers the JSON simple API over HTML
// (PEP 691). Equal preference goes to JSON; no preference to HTML.
func WantJSON(accept string) bool {
	bestJSON, bestHTML := -1.0, -1.0
	for part := range strings.SplitSeq(accept, ",") {
		mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		q := 1.0
		if v, ok := params["q"]; ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				q = f
			}
		}
		if q <= 0 {
			continue
		}
		switch mt {
		case "application/vnd.pypi.simple.v1+json", "application/vnd.pypi.simple.latest+json":
			bestJSON = max(bestJSON, q)
		case "application/vnd.pypi.simple.v1+html", "application/vnd.pypi.simple.latest+html", "text/html", "*/*":
			bestHTML = max(bestHTML, q)
		}
	}
	return bestJSON > 0 && bestJSON >= bestHTML
}

type jsonFile struct {
	Filename       string            `json:"filename"`
	URL            string            `json:"url"`
	Hashes         map[string]string `json:"hashes"`
	RequiresPython string            `json:"requires-python,omitempty"`
	CoreMetadata   any               `json:"core-metadata"`
	DistInfo       any               `json:"dist-info-metadata"`
	Yanked         any               `json:"yanked"`
	Size           int64             `json:"size,omitempty"`
	UploadTime     string            `json:"upload-time,omitempty"`
	Provenance     *string           `json:"provenance"`
}

type jsonMeta struct {
	APIVersion string `json:"api-version"`
}

// WriteProject writes p as an HTML (PEP 503) or JSON (PEP 691) page.
func WriteProject(w http.ResponseWriter, p Project, asJSON bool) {
	if !asJSON {
		w.Header().Set("Content-Type", htmlType)
		_ = projectTmpl.Execute(w, htmlProject(p))
		return
	}
	files := make([]jsonFile, 0, len(p.Files))
	for _, f := range p.Files {
		jf := jsonFile{
			Filename: f.Filename, URL: f.URL, Hashes: map[string]string{"sha256": f.SHA256},
			RequiresPython: f.RequiresPython, Yanked: yanked(f.Yanked), Size: f.Size,
			CoreMetadata: false, DistInfo: false,
		}
		if f.CoreMetadata != "" {
			jf.CoreMetadata = map[string]string{"sha256": f.CoreMetadata}
			jf.DistInfo = jf.CoreMetadata
		}
		if !f.UploadTime.IsZero() {
			jf.UploadTime = f.UploadTime.UTC().Format(time.RFC3339Nano)
		}
		if f.HasProvenance {
			jf.Provenance = &f.ProvenanceURL
		}
		files = append(files, jf)
	}
	doc := struct {
		Meta     jsonMeta          `json:"meta"`
		Name     string            `json:"name"`
		Versions []string          `json:"versions"`
		Files    []jsonFile        `json:"files"`
		Status   map[string]string `json:"project-status,omitempty"`
	}{Meta: jsonMeta{apiVersion}, Name: p.Name, Versions: p.Versions, Files: files}
	if doc.Versions == nil {
		doc.Versions = []string{}
	}
	if p.Status != "" {
		doc.Status = map[string]string{"status": p.Status}
	}
	writeJSON(w, doc)
}

// WriteIndex writes the list of project names as HTML or JSON.
func WriteIndex(w http.ResponseWriter, names []string, asJSON bool) {
	if !asJSON {
		w.Header().Set("Content-Type", htmlType)
		_ = indexTmpl.Execute(w, names)
		return
	}
	type entry struct {
		Name string `json:"name"`
	}
	projects := make([]entry, 0, len(names))
	for _, n := range names {
		projects = append(projects, entry{n})
	}
	writeJSON(w, struct {
		Meta     jsonMeta `json:"meta"`
		Projects []entry  `json:"projects"`
	}{jsonMeta{apiVersion}, projects})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", jsonType)
	_ = json.NewEncoder(w).Encode(v)
}

// yanked normalises a PEP 592 value: a non-empty reason, true or false.
func yanked(v any) any {
	switch y := v.(type) {
	case string:
		if y == "" {
			return true
		}
		return y
	case bool:
		return y
	}
	return false
}

type htmlFile struct {
	Href, Filename, RequiresPython, Metadata, Provenance string
	Yanked                                               *string
}

func htmlProject(p Project) struct {
	Name  string
	Files []htmlFile
} {
	out := struct {
		Name  string
		Files []htmlFile
	}{Name: p.Name}
	for _, f := range p.Files {
		hf := htmlFile{Href: f.URL + "#sha256=" + f.SHA256, Filename: f.Filename, RequiresPython: f.RequiresPython}
		if f.CoreMetadata != "" {
			hf.Metadata = "sha256=" + f.CoreMetadata
		}
		if f.HasProvenance {
			hf.Provenance = f.ProvenanceURL
		}
		switch y := yanked(f.Yanked).(type) {
		case string:
			hf.Yanked = &y
		case bool:
			if y {
				empty := ""
				hf.Yanked = &empty
			}
		}
		out.Files = append(out.Files, hf)
	}
	return out
}

var projectTmpl = template.Must(template.New("project").Parse(`<!DOCTYPE html>
<html>
<head><meta name="pypi:repository-version" content="` + apiVersion + `"><title>Links for {{.Name}}</title></head>
<body>
<h1>Links for {{.Name}}</h1>
{{range .Files}}<a href="{{.Href}}"{{if .RequiresPython}} data-requires-python="{{.RequiresPython}}"{{end}}{{if .Metadata}} data-core-metadata="{{.Metadata}}" data-dist-info-metadata="{{.Metadata}}"{{end}}{{if .Yanked}} data-yanked="{{.Yanked}}"{{end}}{{if .Provenance}} data-provenance="{{.Provenance}}"{{end}}>{{.Filename}}</a><br>
{{end}}</body>
</html>
`))

var indexTmpl = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html>
<head><meta name="pypi:repository-version" content="` + apiVersion + `"><title>Simple index</title></head>
<body>
{{range .}}<a href="{{.}}/">{{.}}</a><br>
{{end}}</body>
</html>
`))
