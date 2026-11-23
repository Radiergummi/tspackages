package npm

import (
	"strings"
	"testing"
)

func TestParseName(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
		norm    string
		escaped string
	}{
		{in: "@scope/name", norm: "@scope/name", escaped: "@scope%2fname"},
		{in: "@SCOPE/Name", norm: "@scope/name", escaped: "@SCOPE%2fName"},
		{in: "name", norm: "name", escaped: "name"},
		{in: "Name", norm: "name", escaped: "Name"},
		{in: "JSONStream", norm: "jsonstream", escaped: "JSONStream"},
		{in: "@scope", wantErr: true},
		{in: "@/x", wantErr: true},
		{in: "@scope/", wantErr: true},
		{in: "", wantErr: true},
		{in: ".x", wantErr: true},
		{in: "_x", wantErr: true},
		{in: "@s/.x", wantErr: true},
		{in: "@._/x", wantErr: true},
		{in: "a/b", wantErr: true},
		{in: "@a/b/c", wantErr: true},
		{in: "a!b", wantErr: true},
		{in: "a*b", wantErr: true},
		{in: "a b", wantErr: true},
		{in: strings.Repeat("a", 156), norm: strings.Repeat("a", 156), escaped: strings.Repeat("a", 156)},
		{in: strings.Repeat("a", 157), wantErr: true},
		{in: strings.Repeat("a", 215), wantErr: true},
	}
	for _, tt := range tests {
		n, err := ParseName(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseName(%.20q) = %+v, want error", tt.in, n)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseName(%.20q): %v", tt.in, err)
			continue
		}
		if n.Exact != tt.in || n.Norm != tt.norm || n.Escaped() != tt.escaped {
			t.Errorf("ParseName(%.20q) = %+v, escaped %.20q", tt.in, n, n.Escaped())
		}
		for _, p := range []string{"@scope/*", "*", "name*"} {
			want := p == "*" || (p == "@scope/*" && strings.HasPrefix(tt.norm, "@scope/")) || (p == "name*" && strings.HasPrefix(tt.norm, "name"))
			if got := Match(p, n.Norm); got != want {
				t.Errorf("Match(%q, %.20q) = %v, want %v", p, n.Norm, got, want)
			}
		}
	}
}

func TestNameParts(t *testing.T) {
	n, err := ParseName("@Sc/Base")
	if err != nil || n.Scope != "Sc" || n.Base != "Base" || n.TarballFile("1.0.0") != "Base-1.0.0.tgz" {
		t.Fatalf("%+v %v", n, err)
	}
	n, err = ParseName("Plain")
	if err != nil || n.Scope != "" || n.Base != "Plain" || n.TarballFile("1.0.0") != "Plain-1.0.0.tgz" {
		t.Fatalf("%+v %v", n, err)
	}
}

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"foo*", "@foo/x", false},
		{"foo*", "foobar", true},
		{"@foo*/x", "@foobar/x", true},
		{"@foo/*", "@foo/x", true},
		{"@foo/*", "@foo", false},
		{"*", "@a/b", true},
		{"*", "a", true},
		{"@A/x", "@a/x", false},
		{"@A/x", "@A/x", false},
		{"a/b", "a/b", false},
		{"[a]", "a", false},
	}
	for _, tt := range tests {
		if got := Match(tt.pattern, tt.name); got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

func TestValidTag(t *testing.T) {
	tests := []struct {
		tag  string
		want bool
	}{
		{"latest", true}, {"next", true}, {"beta.1", true}, {"1.x", false}, {"v1", false},
		{"vnext", true}, {"1abc", false}, {"Beta", false}, {strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false}, {"", false},
	}
	for _, tt := range tests {
		if got := ValidTag(tt.tag); got != tt.want {
			t.Errorf("ValidTag(%.20q) = %v, want %v", tt.tag, got, tt.want)
		}
	}
}
