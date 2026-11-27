package maven

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func readLines(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for l := range strings.SplitSeq(string(b), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// TestCompareGolden sorts testdata/versions.txt and compares the result with
// the order Maven's ComparableVersion produced (testdata/Gen.java).
func TestCompareGolden(t *testing.T) {
	in := readLines(t, "testdata/versions.txt")
	want := readLines(t, "testdata/versions.golden")
	got := slices.Clone(in)
	slices.SortStableFunc(got, CompareVersions)
	if len(got) != len(want) {
		t.Fatalf("got %d versions, golden has %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("line %d: got %q, golden %q", i+1, got[i], want[i])
		}
	}
	// Every earlier golden line sorts at or before every later one.
	for i := range want {
		for j := i + 1; j < len(want); j++ {
			if CompareVersions(want[i], want[j]) > 0 || CompareVersions(want[j], want[i]) < 0 {
				t.Errorf("%q sorts after %q", want[i], want[j])
			}
		}
	}
}

func TestCompareEqual(t *testing.T) {
	for _, pair := range [][2]string{
		{"1.0", "1"}, {"1", "1.0.0"}, {"1.0", "1.0.0"},
		{"1.0-ga", "1.0"}, {"1.0-final", "1.0"}, {"1.0.RELEASE", "1"},
		{"1.0-cr1", "1.0-rc1"}, {"1.0-a1", "1.0-alpha-1"}, {"1.0-SNAPSHOT", "1.0-snapshot"},
		{"010", "10"},
	} {
		if c := CompareVersions(pair[0], pair[1]); c != 0 {
			t.Errorf("CompareVersions(%q, %q) = %d, want 0", pair[0], pair[1], c)
		}
	}
	for _, pair := range [][2]string{
		{"1.0-alpha-1", "1.0-beta-1"}, {"1.0-rc1", "1.0-SNAPSHOT"}, {"1.0-SNAPSHOT", "1.0"},
		{"1.0", "1.0-sp"}, {"1.0-sp", "1.0-1"}, {"1.0-1", "1.0.1"}, {"1.9", "1.10"},
	} {
		if c := CompareVersions(pair[0], pair[1]); c >= 0 {
			t.Errorf("CompareVersions(%q, %q) = %d, want < 0", pair[0], pair[1], c)
		}
		if c := CompareVersions(pair[1], pair[0]); c <= 0 {
			t.Errorf("CompareVersions(%q, %q) = %d, want > 0", pair[1], pair[0], c)
		}
	}
}

func TestIsSnapshot(t *testing.T) {
	if !IsSnapshot("1.0-SNAPSHOT") || IsSnapshot("1.0") || IsSnapshot("1.0-snapshot") {
		t.Error("IsSnapshot")
	}
}

func TestParseTimestamped(t *testing.T) {
	got, ok := ParseTimestamped("1.0-20261123.101010-3")
	if want := (Timestamped{"1.0", "20261123.101010", 3}); !ok || got != want {
		t.Errorf("got %+v, %v; want %+v", got, ok, want)
	}
	got, ok = ParseTimestamped("1.0-beta-1-20261123.101010-12")
	if want := (Timestamped{"1.0-beta-1", "20261123.101010", 12}); !ok || got != want {
		t.Errorf("got %+v, %v; want %+v", got, ok, want)
	}
	for _, v := range []string{"1.0-SNAPSHOT", "1.0", "-20261123.101010-3", "1.0-20261123.10101-3", "1.0-20261123.101010-", "1.0-20261123.101010-99999999999999999999"} {
		if got, ok := ParseTimestamped(v); ok {
			t.Errorf("ParseTimestamped(%q) = %+v, true", v, got)
		}
	}
}
