package pypi

import (
	"bytes"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// FuzzPyprojectScan: what the pyproject.toml pre-scan accepts decodes to
// no deeper a value than its caps allow, so the decoder's quadratic cost
// stays bounded.
func FuzzPyprojectScan(f *testing.F) {
	for _, seed := range []string{
		"[project]\nname = \"a\"\n",
		"b = [\"\"\"y\"\"\"\", {a={a={a=1}}}]\n",
		"b = ['''y''''', [[[1]]]]\n",
		"[a.b.c]\nd.e = \"#[{\"\n# [{\n",
		"x = \"\"\"\\\"\"\"\" \nk = {a=[1]}\n",
		"[h.h.h]\nx = {a.a.a={a.a.a={a.a.a=1}}}\n",
		// The scan once ended this string a quote early and missed the rest
		// of the line.
		"b = [\"\"\"y\"\"\"\", " + strings.Repeat("{a=", 80) + "1" + strings.Repeat("}", 80) + "]\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxPyprojectBytes || tomlTooComplex(b) {
			return
		}
		var doc map[string]any
		if _, err := toml.NewDecoder(bytes.NewReader(b)).Decode(&doc); err != nil {
			return
		}
		// Headers, dotted keys, brackets and braces together nest at most
		// maxTOMLDepth levels below the document (and one for a slice of
		// tables).
		if d := depthOf(doc); d > maxTOMLDepth+2 {
			t.Fatalf("decoded depth %d from %q", d, b)
		}
	})
}

func depthOf(v any) int {
	d := 0
	switch v := v.(type) {
	case map[string]any:
		for _, x := range v {
			d = max(d, depthOf(x))
		}
	case []map[string]any:
		for _, x := range v {
			d = max(d, depthOf(x))
		}
	case []any:
		for _, x := range v {
			d = max(d, depthOf(x))
		}
	default:
		return 0
	}
	return d + 1
}
