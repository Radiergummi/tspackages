package maven

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// wantRequestError checks that err is a *RequestError with status and a
// Detail containing detail.
func wantRequestError(t *testing.T, name string, err error, status int, detail string) {
	t.Helper()
	re, ok := errors.AsType[*RequestError](err)
	if !ok {
		t.Errorf("%s: err = %v (%T), want *RequestError", name, err, err)
		return
	}
	if re.Status != status || re.Title == "" || !strings.Contains(re.Detail, detail) {
		t.Errorf("%s: err = %+v, want status %d and detail containing %q", name, re, status, detail)
	}
}

func pom(inner string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>` + inner + `</project>`
}

func TestInspectPOM(t *testing.T) {
	release := mustPath(t, "com/matchory/lib/1.0/lib-1.0.pom")
	snapshot := mustPath(t, "com/matchory/lib/1.0-SNAPSHOT/lib-1.0-20261123.101010-3.pom")

	for name, tc := range map[string]struct {
		doc       string
		p         Path
		packaging string
	}{
		"gradle":    {readTestdata(t, "lib-1.0.pom"), release, "jar"},
		"direct":    {pom(`<groupId>com.matchory</groupId><artifactId>lib</artifactId><version>1.0</version><packaging>bundle</packaging>`), release, "bundle"},
		"inherited": {pom(`<parent><groupId>com.matchory</groupId><artifactId>parent</artifactId><version>1.0</version></parent><artifactId>lib</artifactId>`), release, "jar"},
		"own wins":  {pom(`<parent><groupId>org.other</groupId><artifactId>parent</artifactId><version>9</version></parent><groupId>com.matchory</groupId><artifactId>lib</artifactId><version>1.0</version>`), release, "jar"},
		"trimmed":   {pom("<groupId>\n  com.matchory\n</groupId><artifactId> lib </artifactId><version>1.0</version>"), release, "jar"},
		"snapshot":  {pom(`<groupId>com.matchory</groupId><artifactId>lib</artifactId><version>1.0-SNAPSHOT</version>`), snapshot, "jar"},
	} {
		info, err := InspectPOM(strings.NewReader(tc.doc), tc.p)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if info.Packaging != tc.packaging {
			t.Errorf("%s: packaging = %q, want %q", name, info.Packaging, tc.packaging)
		}
	}

	for name, tc := range map[string]struct {
		doc    string
		p      Path
		status int
		detail string
	}{
		"artifactId mismatch": {pom(`<groupId>com.matchory</groupId><artifactId>other</artifactId><version>1.0</version>`), release, 400, "artifactId"},
		"groupId mismatch":    {pom(`<groupId>com.other</groupId><artifactId>lib</artifactId><version>1.0</version>`), release, 400, "groupId"},
		"version mismatch":    {pom(`<groupId>com.matchory</groupId><artifactId>lib</artifactId><version>1.1</version>`), release, 400, "version"},
		"no version":          {pom(`<groupId>com.matchory</groupId><artifactId>lib</artifactId>`), release, 400, "version"},
		"mixed case":          {pom(`<groupId>com.Matchory</groupId><artifactId>lib</artifactId><version>1.0</version>`), release, 400, "groupId"},
		"revision":            {pom(`<groupId>com.matchory</groupId><artifactId>lib</artifactId><version>${revision}</version>`), release, 400, "unresolved property in version; deploy a flattened POM"},
		"parent revision":     {pom(`<parent><groupId>com.matchory</groupId><artifactId>p</artifactId><version>${revision}</version></parent><artifactId>lib</artifactId>`), release, 400, "unresolved property in parent/version; deploy a flattened POM"},
		"property groupId":    {pom(`<groupId>${g}</groupId><artifactId>lib</artifactId><version>1.0</version>`), release, 400, "unresolved property in groupId"},
		"timestamped version": {pom(`<groupId>com.matchory</groupId><artifactId>lib</artifactId><version>1.0-20261123.101010-3</version>`), snapshot, 400, "version"},
		"doctype":             {`<!DOCTYPE project SYSTEM "file:///etc/passwd">` + pom(`<groupId>com.matchory</groupId><artifactId>lib</artifactId><version>1.0</version>`), release, 400, "DOCTYPE"},
		"not a project":       {`<metadata><groupId>com.matchory</groupId><artifactId>lib</artifactId><version>1.0</version></metadata>`, release, 400, "project"},
		"too large":           {pom(strings.Repeat(" ", 1<<20)), release, 413, "1 MiB"},
	} {
		_, err := InspectPOM(strings.NewReader(tc.doc), tc.p)
		wantRequestError(t, name, err, tc.status, tc.detail)
	}
}

func TestInspectModule(t *testing.T) {
	release := mustPath(t, "com/matchory/lib/1.0/lib-1.0.module")
	gradle := readTestdata(t, "lib-1.0.module")
	if err := InspectModule(strings.NewReader(gradle), release); err != nil {
		t.Fatalf("gradle: %v", err)
	}

	snapshot := mustPath(t, "com/matchory/lib/1.0-SNAPSHOT/lib-1.0-20261123.101010-3.module")
	snapDoc := strings.Replace(gradle, `"version": "1.0"`, `"version": "1.0-SNAPSHOT"`, 1)
	snapDoc = strings.ReplaceAll(snapDoc, `"url": "lib-1.0.jar"`, `"url": "lib-1.0-20261123.101010-3.jar"`)
	if err := InspectModule(strings.NewReader(snapDoc), snapshot); err != nil {
		t.Errorf("snapshot: %v", err)
	}

	const deep32 = `{"formatVersion":"1.1","component":{"group":"com.matchory","module":"lib","version":"1.0"},"x":`
	if err := InspectModule(strings.NewReader(deep32+strings.Repeat("[", 31)+strings.Repeat("]", 31)+"}"), release); err != nil {
		t.Errorf("depth 32: %v", err)
	}

	for name, tc := range map[string]struct {
		doc    string
		status int
		detail string
	}{
		"wrong version":     {strings.Replace(gradle, `"version": "1.0"`, `"version": "1.1"`, 1), 400, "component.version"},
		"wrong group":       {strings.Replace(gradle, `"group": "com.matchory"`, `"group": "com.Matchory"`, 1), 400, "component.group"},
		"wrong module":      {strings.Replace(gradle, `"module": "lib"`, `"module": "other"`, 1), 400, "component.module"},
		"url with slash":    {strings.Replace(gradle, `"url": "lib-1.0.jar"`, `"url": "../../other/1.0/other-1.0.jar"`, 1), 400, "url"},
		"url dotdot":        {strings.Replace(gradle, `"url": "lib-1.0.jar"`, `"url": ".."`, 1), 400, "url"},
		"no formatVersion":  {strings.Replace(gradle, `"formatVersion": "1.1",`, ``, 1), 400, "formatVersion"},
		"no component":      {`{"formatVersion":"1.1"}`, 400, "component"},
		"case-folded key":   {strings.Replace(gradle, `"component"`, `"Component"`, 1), 400, "component"},
		"depth 33":          {deep32 + strings.Repeat("[", 32) + strings.Repeat("]", 32) + "}", 400, "32"},
		"not JSON":          {`<project/>`, 400, "JSON"},
		"trailing data":     {gradle + "{}", 400, "JSON"},
		"array top level":   {`[]`, 400, "JSON object"},
		"url not a string":  {strings.Replace(gradle, `"url": "lib-1.0.jar"`, `"url": 1`, 1), 400, "url"},
		"variants not list": {strings.Replace(gradle, `"variants": [`, `"variants": {"a": [`, 1) + "}", 400, ""},
		"too large":         {gradle + strings.Repeat(" ", 1<<20), 413, "1 MiB"},
	} {
		wantRequestError(t, name, InspectModule(strings.NewReader(tc.doc), release), tc.status, tc.detail)
	}
}

func TestInspectMetadataUpload(t *testing.T) {
	artifact := mustPath(t, "com/matchory/lib/maven-metadata.xml")
	group := mustPath(t, "com/matchory/maven-metadata.xml")
	version := mustPath(t, "com/matchory/lib/1.0-SNAPSHOT/maven-metadata.xml")
	plugin := readTestdata(t, "plugin-group-metadata.xml")
	const versionDoc = `<?xml version="1.0" encoding="UTF-8"?>
<metadata modelVersion="1.1.0">
  <groupId>com.matchory</groupId>
  <artifactId>lib</artifactId>
  <version>1.0-SNAPSHOT</version>
  <versioning>
    <snapshot><timestamp>20261123.101010</timestamp><buildNumber>3</buildNumber></snapshot>
    <lastUpdated>20261123101010</lastUpdated>
  </versioning>
</metadata>`

	for name, tc := range map[string]struct {
		doc  string
		p    Path
		want MetadataLevel
	}{
		"artifact":         {readTestdata(t, "artifact-metadata.xml"), artifact, LevelArtifact},
		"version":          {versionDoc, version, LevelArtifact},
		"plugin group":     {plugin, group, LevelGroup},
		"plugin group id":  {strings.Replace(plugin, "<plugins>", "<groupId>com.matchory</groupId><plugins>", 1), group, LevelGroup},
		"plugin group sub": {plugin, mustPath(t, "com/matchory/plugins/maven-metadata.xml"), LevelGroup},
	} {
		got, err := InspectMetadataUpload(strings.NewReader(tc.doc), tc.p)
		if err != nil || got != tc.want {
			t.Errorf("%s: = %v, %v; want %v", name, got, err, tc.want)
		}
	}

	for name, tc := range map[string]struct {
		doc    string
		p      Path
		status int
		detail string
	}{
		"group mismatch":        {strings.Replace(readTestdata(t, "artifact-metadata.xml"), "com.matchory", "com.other", 1), artifact, 400, "groupId"},
		"artifact mismatch":     {strings.Replace(readTestdata(t, "artifact-metadata.xml"), "<artifactId>lib", "<artifactId>other", 1), artifact, 400, "artifactId"},
		"no groupId":            {`<metadata><artifactId>lib</artifactId></metadata>`, artifact, 400, "groupId"},
		"plugin group mismatch": {strings.Replace(plugin, "<plugins>", "<groupId>com.other</groupId><plugins>", 1), group, 400, "groupId"},
		"project root":          {pom(`<groupId>com.matchory</groupId><artifactId>lib</artifactId><version>1.0</version>`), artifact, 400, "metadata"},
		"neither":               {`<metadata><groupId>com.matchory</groupId></metadata>`, artifact, 400, "artifactId"},
		"doctype":               {`<!DOCTYPE metadata []>` + plugin, group, 400, "DOCTYPE"},
		"too large":             {plugin + strings.Repeat(" ", 1<<20), group, 413, "1 MiB"},
	} {
		_, err := InspectMetadataUpload(strings.NewReader(tc.doc), tc.p)
		wantRequestError(t, name, err, tc.status, tc.detail)
	}
}

func TestInspectChecksumUpload(t *testing.T) {
	want := Digests{SHA1: "5510650b8a84603866b4232dc54ace475521c15a", MD5: "f5d037c0833250b621fc69e871bea672"}
	for name, tc := range map[string]struct {
		body, alg string
		want      Digests
	}{
		"sha1":            {"5510650b8a84603866b4232dc54ace475521c15a", "sha1", want},
		"upper with name": {"5510650B8A84603866B4232DC54ACE475521C15A  lib-1.0.jar\n", "sha1", want},
		"md5":             {"f5d037c0833250b621fc69e871bea672", "md5", want},
		"form only":       {"0123456789abcdef0123456789abcdef01234567", "sha1", Digests{}},
	} {
		if err := InspectChecksumUpload(strings.NewReader(tc.body), tc.alg, tc.want); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		body, alg string
		want      Digests
		status    int
		detail    string
	}{
		"mismatch":       {"0123456789abcdef0123456789abcdef01234567", "sha1", want, 400, "checksum mismatch"},
		"unknown digest": {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "sha256", want, 400, "checksum mismatch"},
		"form only bad":  {"xyz", "sha1", Digests{}, 400, "checksum"},
		"wrong length":   {"f5d037c0833250b621fc69e871bea672", "sha1", Digests{}, 400, "checksum"},
		"too large":      {strings.Repeat("a", 1025), "sha1", Digests{}, 413, "1 KiB"},
	} {
		wantRequestError(t, name, InspectChecksumUpload(strings.NewReader(tc.body), tc.alg, tc.want), tc.status, tc.detail)
	}
}
