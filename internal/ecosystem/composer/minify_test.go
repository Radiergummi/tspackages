package composer

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The example from Composer's MetadataMinifier docs.
func TestExpand(t *testing.T) {
	in := `[
	{"name":"foo/bar","version":"2.0.0","version_normalized":"2.0.0.0","type":"library","scripts":{"x":"y"}},
	{"version":"1.2.0","version_normalized":"1.2.0.0","license":["MIT"],"homepage":"https://example.org"},
	{"version":"1.0.0","version_normalized":"1.0.0.0","homepage":"__unset","scripts":"__unset"}
	]`
	want := `[
	{"name":"foo/bar","version":"2.0.0","version_normalized":"2.0.0.0","type":"library","scripts":{"x":"y"}},
	{"name":"foo/bar","version":"1.2.0","version_normalized":"1.2.0.0","type":"library","scripts":{"x":"y"},"license":["MIT"],"homepage":"https://example.org"},
	{"name":"foo/bar","version":"1.0.0","version_normalized":"1.0.0.0","type":"library","license":["MIT"]}
	]`
	var a, b []map[string]any
	if err := json.Unmarshal([]byte(in), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatal(err)
	}
	got := Expand(a)
	if !reflect.DeepEqual(got, b) {
		gj, _ := json.Marshal(got)
		t.Fatalf("got %s", gj)
	}
	if _, ok := a[1]["name"]; ok {
		t.Fatal("input was modified")
	}
}
