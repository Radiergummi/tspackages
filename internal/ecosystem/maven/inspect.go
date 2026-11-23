package maven

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// maxModule is the largest Gradle .module file accepted, in bytes.
	maxModule = 1 << 20
	// maxModuleDepth is the deepest nesting of JSON arrays and objects in a
	// .module file.
	maxModuleDepth = 32
)

// POMInfo is what a deployed POM records about its version.
type POMInfo struct {
	Packaging string // "jar" when the POM declares none
}

// MetadataLevel is the level an uploaded maven-metadata.xml addresses.
type MetadataLevel int

const (
	// LevelArtifact is artifact- or version-level metadata, naming
	// Path.Coords.
	LevelArtifact MetadataLevel = iota
	// LevelGroup is group-level plugin metadata, naming Path.Group.
	LevelGroup
)

func badRequest(format string, args ...any) *RequestError {
	return &RequestError{Status: 400, Title: "Bad Request", Detail: fmt.Sprintf(format, args...)}
}

// readUpload reads r, which must be at most limit bytes; size names the
// limit in the error.
func readUpload(r io.Reader, limit int64, what, size string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, badRequest("reading %s: %v", what, err)
	}
	if int64(len(b)) > limit {
		return nil, &RequestError{Status: 413, Title: "Payload Too Large", Detail: what + " larger than " + size}
	}
	return b, nil
}

// decodeUploadXML decodes an uploaded XML document into v with UploadXML.
func decodeUploadXML(r io.Reader, what string, v any) error {
	b, err := readUpload(r, UploadXML.MaxBytes, what, "1 MiB")
	if err != nil {
		return err
	}
	if err := DecodeXML(bytes.NewReader(b), UploadXML, v); err != nil {
		if xe, ok := errors.AsType[*XMLError](err); ok {
			return badRequest("invalid %s: %s", what, xe.Reason)
		}
		return badRequest("invalid %s: %v", what, err)
	}
	return nil
}

// single returns the trimmed text of an element that occurs at most once
// (Maven trims element text); "" when it is absent.
func single(what, field string, vals []string) (string, error) {
	if len(vals) > 1 {
		return "", badRequest("%s has more than one <%s>", what, field)
	}
	if len(vals) == 0 {
		return "", nil
	}
	return strings.TrimSpace(vals[0]), nil
}

// matchField checks a coordinate read from an upload against the path's.
func matchField(what, field, got, want string) error {
	if strings.Contains(got, "${") {
		return badRequest("unresolved property in %s; deploy a flattened POM", field)
	}
	if got != want {
		return badRequest("%s %s %q does not match the path's %q", what, field, got, want)
	}
	return nil
}

type pomDoc struct {
	XMLName    xml.Name
	GroupID    []string `xml:"groupId"`
	ArtifactID []string `xml:"artifactId"`
	Version    []string `xml:"version"`
	Packaging  []string `xml:"packaging"`
	Parent     []struct {
		GroupID []string `xml:"groupId"`
		Version []string `xml:"version"`
	} `xml:"parent"`
}

// InspectPOM checks that a deployed POM names p's coordinates in their exact
// case: groupId (or parent/groupId), artifactId, and version (or
// parent/version), which for a SNAPSHOT path is the "-SNAPSHOT" version of
// the directory. A coordinate with an unresolved "${" property is refused.
// Errors are *RequestError.
func InspectPOM(r io.Reader, p Path) (POMInfo, error) {
	const what = "POM"
	var doc pomDoc
	if err := decodeUploadXML(r, what, &doc); err != nil {
		return POMInfo{}, err
	}
	if doc.XMLName.Local != "project" {
		return POMInfo{}, badRequest("POM root is <%s>, want <project>", doc.XMLName.Local)
	}
	if len(doc.Parent) > 1 {
		return POMInfo{}, badRequest("POM has more than one <parent>")
	}
	var parentGroup, parentVersion []string
	if len(doc.Parent) == 1 {
		parentGroup, parentVersion = doc.Parent[0].GroupID, doc.Parent[0].Version
	}
	for _, c := range []struct {
		field, parentField string
		own, parent        []string
		want               string
	}{
		{"groupId", "parent/groupId", doc.GroupID, parentGroup, p.Coords.Group},
		{"artifactId", "", doc.ArtifactID, nil, p.Coords.Artifact},
		{"version", "parent/version", doc.Version, parentVersion, p.Coords.Version},
	} {
		field := c.field
		got, err := single(what, c.field, c.own)
		if err != nil {
			return POMInfo{}, err
		}
		if got == "" && c.parentField != "" {
			field = c.parentField
			if got, err = single(what, c.parentField, c.parent); err != nil {
				return POMInfo{}, err
			}
		}
		if err := matchField(what, field, got, c.want); err != nil {
			return POMInfo{}, err
		}
	}
	packaging, err := single(what, "packaging", doc.Packaging)
	if err != nil {
		return POMInfo{}, err
	}
	if packaging == "" {
		packaging = "jar"
	}
	return POMInfo{Packaging: packaging}, nil
}

// InspectModule checks a deployed Gradle .module file: JSON of at most 1 MiB
// nested at most 32 deep, with formatVersion, component.group, .module and
// .version equal to p's coordinates in their exact case, and every
// variants[].files[].url naming a file in the same directory. Its listed
// hashes are not checked. Keys match exactly, as Gradle reads them.
// Errors are *RequestError.
func InspectModule(r io.Reader, p Path) error {
	b, err := readUpload(r, maxModule, ".module", "1 MiB")
	if err != nil {
		return err
	}
	if err := checkJSON(b); err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil || doc == nil {
		return badRequest(".module is not a JSON object")
	}
	if v, ok := doc["formatVersion"]; !ok || string(v) == "null" {
		return badRequest(".module has no formatVersion")
	}
	component, ok := jsonField[map[string]json.RawMessage](doc, "component")
	if !ok || component == nil {
		return badRequest(".module has no component object")
	}
	for _, c := range []struct{ key, want string }{
		{"group", p.Coords.Group}, {"module", p.Coords.Artifact}, {"version", p.Coords.Version},
	} {
		got, ok := jsonField[string](component, c.key)
		if !ok {
			return badRequest(".module component.%s is missing or not a string", c.key)
		}
		if got != c.want {
			return badRequest(".module component.%s %q does not match the path's %q", c.key, got, c.want)
		}
	}
	if _, present := doc["variants"]; !present {
		return nil
	}
	variants, ok := jsonField[[]map[string]json.RawMessage](doc, "variants")
	if !ok {
		return badRequest(".module variants is not a list of objects")
	}
	for i, v := range variants {
		if _, present := v["files"]; !present {
			continue
		}
		files, ok := jsonField[[]map[string]json.RawMessage](v, "files")
		if !ok {
			return badRequest(".module variants[%d].files is not a list of objects", i)
		}
		for j, f := range files {
			url, ok := jsonField[string](f, "url")
			if !ok || url == "" || url == "." || url == ".." || strings.Contains(url, "/") {
				return badRequest(".module variants[%d].files[%d].url must name a file in the same directory", i, j)
			}
		}
	}
	return nil
}

// jsonField decodes m[key] into a T; false if the key is absent or holds
// another type.
func jsonField[T any](m map[string]json.RawMessage, key string) (T, bool) {
	var v T
	raw, ok := m[key]
	if !ok {
		return v, false
	}
	return v, json.Unmarshal(raw, &v) == nil
}

// checkJSON checks that b is one JSON value nested at most maxModuleDepth
// deep.
func checkJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	depth := 0
	for {
		tok, err := d.Token()
		if err != nil {
			return badRequest("invalid .module JSON: %v", err)
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if depth++; depth > maxModuleDepth {
				return badRequest(".module JSON is nested deeper than %d levels", maxModuleDepth)
			}
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			break
		}
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return badRequest("invalid .module JSON: data after the top-level value")
	}
	return nil
}

type metadataDoc struct {
	XMLName    xml.Name
	GroupID    []string   `xml:"groupId"`
	ArtifactID []string   `xml:"artifactId"`
	Plugins    []struct{} `xml:"plugins"`
}

// InspectMetadataUpload checks an uploaded maven-metadata.xml, which is
// discarded afterwards, and returns the level its content addresses: a root
// <artifactId> is artifact or version level and must name p.Coords' group
// and artifact; <plugins> without <artifactId> is group level (maven-plugin
// deploys) and a <groupId>, if any, must equal p.Group. Errors are
// *RequestError.
func InspectMetadataUpload(r io.Reader, p Path) (MetadataLevel, error) {
	const what = "maven-metadata.xml"
	var doc metadataDoc
	if err := decodeUploadXML(r, what, &doc); err != nil {
		return 0, err
	}
	if doc.XMLName.Local != "metadata" {
		return 0, badRequest("maven-metadata.xml root is <%s>, want <metadata>", doc.XMLName.Local)
	}
	group, err := single(what, "groupId", doc.GroupID)
	if err != nil {
		return 0, err
	}
	artifact, err := single(what, "artifactId", doc.ArtifactID)
	if err != nil {
		return 0, err
	}
	switch {
	case len(doc.ArtifactID) > 0:
		if err := matchField(what, "groupId", group, p.Coords.Group); err != nil {
			return 0, err
		}
		if err := matchField(what, "artifactId", artifact, p.Coords.Artifact); err != nil {
			return 0, err
		}
		return LevelArtifact, nil
	case len(doc.Plugins) > 0:
		if p.Kind != KindArtifactMetadata {
			return 0, badRequest("group-level maven-metadata.xml is not accepted in a version directory")
		}
		if len(doc.GroupID) > 0 {
			if err := matchField(what, "groupId", group, p.Group); err != nil {
				return 0, err
			}
		}
		return LevelGroup, nil
	}
	return 0, badRequest("maven-metadata.xml has neither <artifactId> nor <plugins>")
}

// InspectChecksumUpload checks an uploaded checksum file for alg ("sha1",
// "md5", "sha256" or "sha512"): at most 1 KiB, read as Maven reads it, and
// equal to want.Get(alg). An empty want (an uploaded maven-metadata.xml's
// checksum) checks only the form. Errors are *RequestError.
func InspectChecksumUpload(r io.Reader, alg string, want Digests) error {
	b, err := readUpload(r, maxChecksumFile, "checksum file", "1 KiB")
	if err != nil {
		return err
	}
	got, err := ParseChecksumFile(bytes.NewReader(b), alg)
	if err != nil {
		return badRequest("invalid checksum file: %v", err)
	}
	if want != (Digests{}) && got != want.Get(alg) {
		return badRequest("checksum mismatch")
	}
	return nil
}
