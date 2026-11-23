package npm

import (
	"slices"
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
		want    Version
	}{
		{in: "1.2.3", want: Version{Major: 1, Minor: 2, Patch: 3}},
		{in: "1.2.3-alpha.1+build.5", want: Version{1, 2, 3, []string{"alpha", "1"}, "build.5"}},
		{in: "1.0.0-Beta", want: Version{1, 0, 0, []string{"Beta"}, ""}},
		{in: "0.0.0", want: Version{}},
		{in: "1.0.0-0", want: Version{1, 0, 0, []string{"0"}, ""}},
		{in: "1.0.0-x-y.0a", want: Version{1, 0, 0, []string{"x-y", "0a"}, ""}},
		{in: "1.0.0+001", want: Version{1, 0, 0, nil, "001"}},
		{in: "01.2.3", wantErr: true},
		{in: "1.02.3", wantErr: true},
		{in: "1.2.3-01", wantErr: true},
		{in: "1.2", wantErr: true},
		{in: "1.2.3.4", wantErr: true},
		{in: "v1.2.3", wantErr: true},
		{in: "=1.2.3", wantErr: true},
		{in: " 1.2.3", wantErr: true},
		{in: "1.2.3-", wantErr: true},
		{in: "1.2.3-a..b", wantErr: true},
		{in: "1.2.3+", wantErr: true},
		{in: "1.2.3-a_b", wantErr: true},
		{in: "", wantErr: true},
		{in: "18446744073709551616.0.0", wantErr: true},
		{in: "18446744073709551615.0.0", want: Version{Major: 18446744073709551615}},
		{in: "1.0.0-" + strings.Repeat("a", 150), want: Version{1, 0, 0, []string{strings.Repeat("a", 150)}, ""}},
		{in: "1.0.0-" + strings.Repeat("a", 151), wantErr: true}, // 157 bytes
	}
	for _, tt := range tests {
		v, err := ParseVersion(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseVersion(%.30q) = %+v, want error", tt.in, v)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseVersion(%.30q): %v", tt.in, err)
			continue
		}
		if v.Major != tt.want.Major || v.Minor != tt.want.Minor || v.Patch != tt.want.Patch ||
			!slices.Equal(v.Pre, tt.want.Pre) || v.Build != tt.want.Build {
			t.Errorf("ParseVersion(%.30q) = %+v, want %+v", tt.in, v, tt.want)
		}
		if v.String() != tt.in {
			t.Errorf("String() = %.30q, want %.30q", v.String(), tt.in)
		}
	}
}

func TestPrerelease(t *testing.T) {
	for in, want := range map[string]bool{"1.0.0": false, "1.0.0+b": false, "1.0.0-rc.1": true} {
		v, _ := ParseVersion(in)
		if v.Prerelease() != want {
			t.Errorf("Prerelease(%q) = %v", in, !want)
		}
	}
}

func TestCompareOrdering(t *testing.T) {
	ordered := []string{
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0",
	}
	for i := range ordered {
		for j := range ordered {
			a, _ := ParseVersion(ordered[i])
			b, _ := ParseVersion(ordered[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := Compare(a, b); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	a, _ := ParseVersion("1.0.0+a")
	b, _ := ParseVersion("1.0.0+b")
	if Compare(a, b) != 0 {
		t.Error("build metadata must not affect order")
	}
	upper, _ := ParseVersion("1.0.0-B")
	lower, _ := ParseVersion("1.0.0-a")
	if Compare(upper, lower) >= 0 {
		t.Error("1.0.0-B must sort before 1.0.0-a (ASCII)")
	}
}
