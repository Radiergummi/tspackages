package maven

import (
	"os"
	"testing"
	"time"
)

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	want, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("%s:\n got:\n%s\nwant:\n%s", name, got, want)
	}
}

func TestMetadataGolden(t *testing.T) {
	at := func(s string) time.Time {
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	art := RenderArtifactMetadata("com.matchory", "lib", []VersionInfo{
		{Version: "1.10", POM: at("2026-11-20T08:00:00Z")},
		{Version: "2.0-SNAPSHOT", POM: at("2026-11-23T10:15:00+01:00")},
		{Version: "1.9", POM: at("2026-11-21T08:00:00Z")},
		{Version: "1.10-rc1", POM: at("2026-11-19T08:00:00Z")},
	})
	checkGolden(t, "storage-artifact-metadata.xml", art)

	snap := RenderArtifactMetadata("com.matchory", "lib", []VersionInfo{{Version: "1.0-SNAPSHOT", POM: at("2026-11-23T10:15:00Z")}})
	checkGolden(t, "storage-snapshot-only-metadata.xml", snap)

	ver := RenderVersionMetadata("com.matchory", "lib", "1.0-SNAPSHOT", []SnapshotFile{
		{Extension: "jar", Value: "1.0-20261123.101010-1", Updated: at("2026-11-23T10:10:11Z")},
		{Extension: "pom", Value: "1.0-20261123.101500-2", Updated: at("2026-11-23T10:15:01Z")},
		{Extension: "jar", Value: "1.0-20261123.101500-2", Updated: at("2026-11-23T10:15:02Z")},
		{Classifier: "sources", Extension: "jar", Value: "1.0-20261123.101010-1", Updated: at("2026-11-23T10:10:12Z")},
		{Extension: "pom", Value: "1.0-20261123.101010-1", Updated: at("2026-11-23T10:10:10Z")},
		{Extension: "jar.asc", Value: "1.0-20261123.101500-2", Updated: at("2026-11-23T10:15:03Z")},
	})
	checkGolden(t, "storage-version-metadata.xml", ver)

	// The same input in another order renders the same bytes.
	again := RenderArtifactMetadata("com.matchory", "lib", []VersionInfo{
		{Version: "1.10-rc1", POM: at("2026-11-19T08:00:00Z")},
		{Version: "1.9", POM: at("2026-11-21T08:00:00Z")},
		{Version: "2.0-SNAPSHOT", POM: at("2026-11-23T09:15:00Z")},
		{Version: "1.10", POM: at("2026-11-20T08:00:00Z")},
	})
	if string(again) != string(art) {
		t.Errorf("artifact metadata depends on input order:\n%s", again)
	}
}
