package pypi

import (
	"slices"
	"testing"
)

func TestParseMetadata(t *testing.T) {
	raw := []byte("Metadata-Version: 2.2\r\nName: Matchory_Core\nVersion: 1.0.0\nRequires-Python: >=3.10\nRequires-Dist: requests>=2\nRequires-Dist: rich; extra == \"cli\"\nDynamic: Classifier\nDescription: first line\n        |second line\n\nLong body text\n")
	m, err := ParseMetadata(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.MetadataVersion != "2.2" || m.Name != "Matchory_Core" || m.Version != "1.0.0" || m.RequiresPython != ">=3.10" ||
		!slices.Equal(m.Dynamic, []string{"Classifier"}) || len(m.RequiresDist) != 2 {
		t.Fatalf("%+v", m)
	}
	for _, bad := range []string{"", "Version: 1.0\n", "Name: x\n", "not a header line\n"} {
		if _, err := ParseMetadata([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
