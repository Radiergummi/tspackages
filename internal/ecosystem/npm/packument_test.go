package npm

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const testBase = "https://tsp.example/npm/"

// distFromInput builds the Dist a source would render for an input version.
func distFromInput(t *testing.T, name Name, version string, in map[string]json.RawMessage) Dist {
	t.Helper()
	var src struct {
		Integrity, Shasum string
		FileCount         int64
		UnpackedSize      int64
		Signatures        json.RawMessage `json:"signatures"`
		NPMSignature      json.RawMessage `json:"npm-signature"`
		Attestations      *struct {
			URL        string
			Provenance json.RawMessage
		}
	}
	if err := json.Unmarshal(in["dist"], &src); err != nil {
		t.Fatal(err)
	}
	d := Dist{
		Tarball: BaseToken + name.Exact + "/-/" + name.TarballFile(version), Integrity: src.Integrity, Shasum: src.Shasum,
		FileCount: src.FileCount, UnpackedSize: src.UnpackedSize, Signatures: src.Signatures, NPMSignature: src.NPMSignature,
	}
	if src.Attestations != nil {
		d.AttestationsURL = BaseToken + "-/npm/v1/attestations/" + name.Exact + "@" + version
		d.AttestationsProvenance = src.Attestations.Provenance
	}
	return d
}

func renderFixture(t *testing.T, file string) (full, corgi []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := json.Unmarshal(doc["name"], &name); err != nil {
		t.Fatal(err)
	}
	n, err := ParseName(name)
	if err != nil {
		t.Fatal(err)
	}
	var fb, cb bytes.Buffer
	w := NewDocWriter(&fb, &cb)
	for k, v := range doc {
		w.Top(k, v)
	}
	var versions map[string]map[string]json.RawMessage
	if err := json.Unmarshal(doc["versions"], &versions); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(versions))
	for k := range versions {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int {
		va, _ := ParseVersion(a)
		vb, _ := ParseVersion(b)
		return Compare(va, vb)
	})
	for _, v := range keys {
		f, c, err := RenderVersion(versions[v], distFromInput(t, n, v, versions[v]))
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Version(v, f, c); err != nil {
			t.Fatal(err)
		}
	}
	var tags, times map[string]string
	if err := json.Unmarshal(doc["dist-tags"], &tags); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(doc["time"], &times); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(tags, times); err != nil {
		t.Fatal(err)
	}
	return expandAll(t, fb.Bytes()), expandAll(t, cb.Bytes())
}

func expandAll(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	e := Expand(&out, testBase)
	if _, err := e.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func indent(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, b)
	}
	out.WriteByte('\n')
	return out.Bytes()
}

func TestRenderGolden(t *testing.T) {
	for _, base := range []string{"left-pad", "scoped"} {
		full, corgi := renderFixture(t, "packument-"+base+".json")
		for kind, got := range map[string][]byte{"full": full, "corgi": corgi} {
			path := filepath.Join("testdata", "packument-"+base+"."+kind+".golden.json")
			got = indent(t, got)
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s differs from %s (run with -update):\n%s", kind, path, got)
			}
		}
	}
}

func decode(t *testing.T, b []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return m
}

func versionsOf(t *testing.T, doc map[string]json.RawMessage) map[string]map[string]json.RawMessage {
	t.Helper()
	var v map[string]map[string]json.RawMessage
	if err := json.Unmarshal(doc["versions"], &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFullDropsReadmeAndInternals(t *testing.T) {
	full, _ := renderFixture(t, "packument-left-pad.json")
	doc := decode(t, full)
	for _, k := range []string{"readme", "readmeFilename", "users", "_rev", "_attachments"} {
		if _, ok := doc[k]; ok {
			t.Errorf("full has %s", k)
		}
	}
	for v, obj := range versionsOf(t, doc) {
		for _, k := range droppedVersionFields {
			if _, ok := obj[k]; ok {
				t.Errorf("%s has %s", v, k)
			}
		}
	}
	if strings.Contains(string(full), "registry.npmjs.org") {
		t.Errorf("upstream URL leaked:\n%s", full)
	}
}

func TestCorgiFields(t *testing.T) {
	_, corgi := renderFixture(t, "packument-scoped.json")
	doc := decode(t, corgi)
	var keys []string
	for k := range doc {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"dist-tags", "modified", "name", "time", "versions"}; !slices.Equal(keys, want) {
		t.Errorf("top = %v, want %v", keys, want)
	}
	v := versionsOf(t, doc)["2.0.0-beta.1"]
	if _, ok := v["hasInstallScript"]; !ok {
		t.Error("hasInstallScript missing")
	}
	for _, k := range []string{"scripts", "readme", "description"} {
		if _, ok := v[k]; ok {
			t.Errorf("corgi version has %s", k)
		}
	}
	for _, k := range []string{"bin", "peerDependencies", "dist", "name", "version", "license"} {
		if _, ok := v[k]; !ok {
			t.Errorf("corgi version lacks %s", k)
		}
	}
}

// distFields are the keys a rendered dist may have (spec §2).
var distFields = []string{"tarball", "integrity", "shasum", "fileCount", "unpackedSize", "signatures", "npm-signature", "attestations"}

func TestDistAllowlist(t *testing.T) {
	obj := map[string]json.RawMessage{
		"name": json.RawMessage(`"p"`), "version": json.RawMessage(`"1.0.0"`),
		"dist": json.RawMessage(`{"tarball":"https://up/p.tgz","noattachment":{},"fileCount":3}`),
	}
	full, corgi, err := RenderVersion(obj, Dist{Tarball: BaseToken + "p/-/p-1.0.0.tgz", FileCount: 3})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{expandAll(t, full), expandAll(t, corgi)} {
		var v struct{ Dist map[string]json.RawMessage }
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		for k := range v.Dist {
			if !slices.Contains(distFields, k) {
				t.Errorf("dist key %q not allowed", k)
			}
		}
		if string(v.Dist["tarball"]) != `"`+testBase+`p/-/p-1.0.0.tgz"` {
			t.Errorf("tarball not replaced: %s", b)
		}
		if strings.Contains(string(b), "https://up") || strings.Contains(string(b), "noattachment") {
			t.Errorf("input dist leaked: %s", b)
		}
	}
}

func TestRenderDeterministic(t *testing.T) {
	a1, b1 := renderFixture(t, "packument-left-pad.json")
	a2, b2 := renderFixture(t, "packument-left-pad.json")
	if !bytes.Equal(a1, a2) || !bytes.Equal(b1, b2) {
		t.Error("rendering differs between runs")
	}
}

func TestTopCap(t *testing.T) {
	var fb, cb bytes.Buffer
	w := NewDocWriter(&fb, &cb)
	big, _ := json.Marshal(strings.Repeat("x", 1<<20+1))
	w.Top("description", big)
	if err := w.Close(nil, nil); err == nil {
		t.Error("expected error for oversized top fields")
	}
}

func TestExpand(t *testing.T) {
	doc := `{"a":"` + BaseToken + `x/-/x-1.tgz","d":"literal \u0001base\u0001 text","b":"` + BaseToken + `y","c":"` + BaseToken + `"}`
	want := strings.ReplaceAll(doc, BaseToken, testBase)
	var out bytes.Buffer
	e := Expand(&out, testBase)
	for i := 0; i < len(doc); i++ {
		if _, err := e.Write([]byte{doc[i]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if out.String() != want {
		t.Errorf("got %q\nwant %q", out.String(), want)
	}
	if n := ExpandedSize(int64(len(doc)), 3, testBase); n != int64(out.Len()) {
		t.Errorf("ExpandedSize = %d, want %d", n, out.Len())
	}
}

func TestExpandFlushesPartialToken(t *testing.T) {
	var out bytes.Buffer
	e := Expand(&out, testBase)
	e.Write([]byte("ab\x01ba"))
	if out.String() != "ab" {
		t.Errorf("held bytes written early: %q", out.String())
	}
	e.Close()
	if out.String() != "ab\x01ba" {
		t.Errorf("got %q", out.String())
	}
}

func TestTokensCounted(t *testing.T) {
	var fb, cb bytes.Buffer
	w := NewDocWriter(&fb, &cb)
	n, _ := ParseName("p")
	obj := map[string]json.RawMessage{"name": json.RawMessage(`"p"`), "version": json.RawMessage(`"1.0.0"`)}
	f, c, _ := RenderVersion(obj, Dist{Tarball: BaseToken + "p/-/" + n.TarballFile("1.0.0")})
	w.Version("1.0.0", f, c)
	w.Close(map[string]string{"latest": "1.0.0"}, nil)
	tf, tc := w.Tokens()
	if tf != 1 || tc != 1 {
		t.Errorf("tokens = %d, %d", tf, tc)
	}
	if got := ExpandedSize(int64(fb.Len()), tf, testBase); got != int64(len(expandAll(t, fb.Bytes()))) {
		t.Errorf("size mismatch")
	}
}

func TestRenderDistTags(t *testing.T) {
	if got := string(RenderDistTags(map[string]string{"next": "2.0.0", "latest": "1.0.0"})); got != `{"latest":"1.0.0","next":"2.0.0"}` {
		t.Errorf("got %s", got)
	}
}

func TestTokenLookalikesStayEscaped(t *testing.T) {
	fake := "\x01base\x01x" // decoded from upstream JSON "\u0001base\u0001x"
	var fb, cb bytes.Buffer
	w := NewDocWriter(&fb, &cb)
	obj := map[string]json.RawMessage{
		"name": json.RawMessage(`"p"`), "version": json.RawMessage(`"1.0.0"`),
		fake: json.RawMessage(`"v"`),
	}
	f, c, err := RenderVersion(obj, Dist{Tarball: BaseToken + "p/-/p-1.0.0.tgz"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Version(fake, f, c); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(map[string]string{fake: "1.0.0"}, map[string]string{fake: fake, "modified": fake}); err != nil {
		t.Fatal(err)
	}
	tf, tc := w.Tokens()
	if tf != 1 || tc != 1 {
		t.Errorf("tokens = %d, %d, want 1, 1", tf, tc)
	}
	for _, b := range [][]byte{fb.Bytes(), cb.Bytes()} {
		out := string(expandAll(t, b))
		if n := strings.Count(out, testBase); n != 1 {
			t.Errorf("%d substitutions, want 1:\n%s", n, out)
		}
		decode(t, []byte(out))
	}
}
