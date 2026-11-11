package pypi

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/textproto"
	"path"
	"slices"
	"strings"
)

// Metadata is the part of a distribution's core metadata (wheel METADATA,
// sdist PKG-INFO) that tspackages checks and serves.
type Metadata struct {
	MetadataVersion, Name, Version, RequiresPython string
	RequiresDist, Dynamic                          []string
}

// ParseMetadata reads core metadata: RFC 822 style headers, as Python's
// email.parser reads them, up to the first blank line.
func ParseMetadata(b []byte) (Metadata, error) {
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(b))).ReadMIMEHeader()
	// Metadata without a body ends at EOF instead of a blank line.
	if err != nil && !errors.Is(err, io.EOF) {
		return Metadata{}, fmt.Errorf("invalid core metadata: %w", err)
	}
	m := Metadata{
		MetadataVersion: h.Get("Metadata-Version"),
		Name:            h.Get("Name"),
		Version:         h.Get("Version"),
		RequiresPython:  h.Get("Requires-Python"),
		RequiresDist:    h.Values("Requires-Dist"),
		Dynamic:         h.Values("Dynamic"),
	}
	if m.MetadataVersion == "" || m.Name == "" || m.Version == "" {
		return Metadata{}, errors.New("core metadata lacks Metadata-Version, Name or Version")
	}
	return m, nil
}

// WritePKGINFO generates an sdist's PKG-INFO (core metadata 2.2) from the
// package's static [project] table; read fetches the readme. Fields [project]
// marks dynamic are listed as Dynamic. License fields are always Dynamic:
// backends add License-File entries of their own, so a static value here
// would promise something the built wheel does not keep (PEP 643).
func WritePKGINFO(p Package, read func(path string) ([]byte, error)) ([]byte, error) {
	proj := p.Project
	dynamic := stringList(proj["dynamic"])
	isDynamic := func(key string) bool { return slices.Contains(dynamic, key) }
	var b bytes.Buffer
	field := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%s: %s\n", k, strings.ReplaceAll(v, "\n", " "))
		}
	}
	field("Metadata-Version", "2.2")
	rawName, _ := proj["name"].(string)
	field("Name", rawName)
	field("Version", p.Version.String())
	if s, ok := proj["description"].(string); ok {
		field("Summary", s)
	}
	if s, ok := proj["requires-python"].(string); ok {
		field("Requires-Python", s)
	}
	if kw := stringList(proj["keywords"]); len(kw) > 0 {
		field("Keywords", strings.Join(kw, ","))
	}
	writePeople(&b, "Author", proj["authors"])
	writePeople(&b, "Maintainer", proj["maintainers"])
	for _, c := range stringList(proj["classifiers"]) {
		field("Classifier", c)
	}
	if urls, ok := proj["urls"].(map[string]any); ok {
		for _, label := range slices.Sorted(maps.Keys(urls)) {
			if u, ok := urls[label].(string); ok {
				field("Project-URL", label+", "+u)
			}
		}
	}
	// An extra's requirements are Requires-Dist lines: dynamic extras make
	// the whole field dynamic, and it is then left out.
	depsDynamic := isDynamic("dependencies") || isDynamic("optional-dependencies")
	if !depsDynamic {
		for _, d := range stringList(proj["dependencies"]) {
			field("Requires-Dist", d)
		}
	}
	if extras, ok := proj["optional-dependencies"].(map[string]any); ok {
		for _, extra := range slices.Sorted(maps.Keys(extras)) {
			norm, err := Normalize(extra)
			if err != nil {
				return nil, fmt.Errorf("invalid extra %q", extra)
			}
			field("Provides-Extra", norm)
			for _, d := range stringList(extras[extra]) {
				field("Requires-Dist", withExtra(d, norm))
			}
		}
	}
	var desc []byte
	if p.Readme != "" {
		var err error
		if desc, err = read(p.Readme); err != nil {
			return nil, fmt.Errorf("read readme %s: %w", p.Readme, err)
		}
		field("Description-Content-Type", readmeType(proj, p.Readme))
	}
	for _, d := range []struct{ key, field string }{
		{"dependencies", "Requires-Dist"}, {"optional-dependencies", "Provides-Extra"},
		{"description", "Summary"}, {"readme", "Description"}, {"requires-python", "Requires-Python"},
		{"keywords", "Keywords"}, {"classifiers", "Classifier"}, {"urls", "Project-URL"},
		{"authors", "Author"}, {"maintainers", "Maintainer"},
	} {
		if isDynamic(d.key) || d.field == "Requires-Dist" && depsDynamic {
			field("Dynamic", d.field)
		}
	}
	for _, f := range []string{"License", "License-Expression", "License-File"} {
		field("Dynamic", f)
	}
	if desc != nil {
		b.WriteString("\n")
		b.Write(desc)
	}
	return b.Bytes(), nil
}

// withExtra adds an extra marker to a requirement, keeping its own marker.
func withExtra(req, extra string) string {
	spec, marker, ok := strings.Cut(req, ";")
	if !ok || strings.TrimSpace(marker) == "" {
		return strings.TrimSpace(req) + `; extra == "` + extra + `"`
	}
	return strings.TrimSpace(spec) + "; (" + strings.TrimSpace(marker) + `) and extra == "` + extra + `"`
}

// writePeople writes Author/Author-email (or Maintainer...) from a list of
// {name, email} tables, as the core metadata spec maps them.
func writePeople(b *bytes.Buffer, field string, v any) {
	people, _ := v.([]any)
	var names, emails []string
	for _, p := range people {
		m, _ := p.(map[string]any)
		name, _ := m["name"].(string)
		email, _ := m["email"].(string)
		switch {
		case email != "" && name != "":
			emails = append(emails, name+" <"+email+">")
		case email != "":
			emails = append(emails, email)
		case name != "":
			names = append(names, name)
		}
	}
	if len(names) > 0 {
		fmt.Fprintf(b, "%s: %s\n", field, strings.Join(names, ", "))
	}
	if len(emails) > 0 {
		fmt.Fprintf(b, "%s-email: %s\n", field, strings.Join(emails, ", "))
	}
}

func readmeType(proj map[string]any, file string) string {
	if r, ok := proj["readme"].(map[string]any); ok {
		if ct, ok := r["content-type"].(string); ok {
			return ct
		}
	}
	switch strings.ToLower(path.Ext(file)) {
	case ".md":
		return "text/markdown"
	case ".rst":
		return "text/x-rst"
	}
	return "text/plain"
}
