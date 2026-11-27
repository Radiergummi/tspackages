package maven

import (
	"strings"
	"testing"
)

func TestParsePath(t *testing.T) {
	long := strings.Repeat("a", MaxPart+1)
	for _, tc := range []struct {
		in   string
		want Path
	}{
		{"com/matchory/lib/1.0/lib-1.0.jar", Path{Kind: KindFile, Coords: Coords{"com.matchory", "lib", "1.0"}, File: "lib-1.0.jar"}},
		{"com/matchory/lib/1.0/lib-1.0-sources.jar", Path{Kind: KindFile, Coords: Coords{"com.matchory", "lib", "1.0"}, File: "lib-1.0-sources.jar"}},
		{"com/matchory/lib/1.0/lib-1.0.pom.asc", Path{Kind: KindFile, Coords: Coords{"com.matchory", "lib", "1.0"}, File: "lib-1.0.pom.asc"}},
		{"com/matchory/lib/1.0/lib-1.0.tar.gz", Path{Kind: KindFile, Coords: Coords{"com.matchory", "lib", "1.0"}, File: "lib-1.0.tar.gz"}},
		{"com/matchory/lib/1.0/lib-1.0.jar.sha1", Path{Kind: KindFile, Coords: Coords{"com.matchory", "lib", "1.0"}, File: "lib-1.0.jar", Checksum: "sha1"}},
		{"com/matchory/lib/1.0/lib-1.0.pom.sha512", Path{Kind: KindFile, Coords: Coords{"com.matchory", "lib", "1.0"}, File: "lib-1.0.pom", Checksum: "sha512"}},
		{"Com/Matchory/Lib/1.0/Lib-1.0.jar", Path{Kind: KindFile, Coords: Coords{"Com.Matchory", "Lib", "1.0"}, File: "Lib-1.0.jar"}},
		{"com/matchory/lib/1.0-SNAPSHOT/lib-1.0-20261123.101010-3.jar", Path{Kind: KindFile, Coords: Coords{"com.matchory", "lib", "1.0-SNAPSHOT"}, File: "lib-1.0-20261123.101010-3.jar"}},
		{"com/matchory/lib/1.0-SNAPSHOT/lib-1.0-20261123.101010-3-sources.jar", Path{Kind: KindFile, Coords: Coords{"com.matchory", "lib", "1.0-SNAPSHOT"}, File: "lib-1.0-20261123.101010-3-sources.jar"}},
		{"com/matchory/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.pom", Path{Kind: KindFile, Coords: Coords{"com.matchory", "lib", "1.0-SNAPSHOT"}, File: "lib-1.0-SNAPSHOT.pom"}},
		{"com/matchory/lib/maven-metadata.xml", Path{Kind: KindArtifactMetadata, Coords: Coords{"com.matchory", "lib", ""}, File: "maven-metadata.xml"}},
		{"com/matchory/lib/maven-metadata.xml.md5", Path{Kind: KindArtifactMetadata, Coords: Coords{"com.matchory", "lib", ""}, File: "maven-metadata.xml", Checksum: "md5"}},
		{"com/matchory/lib/1.0-SNAPSHOT/maven-metadata.xml.sha1", Path{Kind: KindVersionMetadata, Coords: Coords{"com.matchory", "lib", "1.0-SNAPSHOT"}, File: "maven-metadata.xml", Checksum: "sha1"}},
		{"org/apache/maven/plugins/maven-metadata.xml", Path{Kind: KindArtifactMetadata, Coords: Coords{"org.apache.maven", "plugins", ""}, File: "maven-metadata.xml"}},
		{"acme/maven-metadata.xml", Path{Kind: KindGroupMetadata, Coords: Coords{"acme", "", ""}, File: "maven-metadata.xml"}},
		{"acme/maven-metadata.xml.sha1", Path{Kind: KindGroupMetadata, Coords: Coords{"acme", "", ""}, File: "maven-metadata.xml", Checksum: "sha1"}},
	} {
		got, err := ParsePath(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.in, got, tc.want)
		}
		if s := got.String(); s != tc.in {
			t.Errorf("%s: String() = %q", tc.in, s)
		}
		if again, err := ParsePath(got.String()); err != nil || again != got {
			t.Errorf("%s: round trip = %+v, %v", tc.in, again, err)
		}
	}
	for _, in := range []string{
		"com/matchory/lib/1.0/other-1.0.jar",
		"com/matchory/lib/1.0/lib-2.0.jar",
		"com/../lib/1.0/lib-1.0.jar",
		"com/./lib/1.0/lib-1.0.jar",
		"com//lib/1.0/lib-1.0.jar",
		"com/matchory/lib/1.0/lib-1.0.jar/",
		"/com/matchory/lib/1.0/lib-1.0.jar",
		"com/matchory/" + long + "/1.0/" + long + "-1.0.jar",
		"com/" + long + "/lib/1.0/lib-1.0.jar",
		".meta/prefixes.txt",
		"lib/1.0/lib-1.0.jar",
		"com/matchory/lib/1.0/lib-1.0",
		"com/matchory/lib/1.0/lib-1.0.",
		"com/matchory/lib/1.0/lib-1.0..jar",
		"com/matchory/lib/1.0/lib-1.0.jar.sha1.sha1",
		"com/matchory/lib/1.0/lib-1.0x.jar",
		"com/matchory/lib/1.0/lib-1.0-.jar",
		"com/matchory/lib/1.0-SNAPSHOT/lib-1.0-2026.101010-3.jar",
		"com/matchory/lib/1.0-SNAPSHOT/lib-1.0-20261123.101010-.jar",
		"com/matchory/lib/1.0-SNAPSHOT/lib-1.1-20261123.101010-3.jar",
		"com/Matchory_x!/lib/1.0/lib-1.0.jar",
		"com/matchory/li:b/1.0/li:b-1.0.jar",
		"com/matchory/lib/1:0/lib-1:0.jar",
		"com/matchory/lib/.hidden/lib-.hidden.jar",
		"com/matchory/lib/1.0/lib-1.0.ja r",
		"maven-metadata.xml",
		"acme.x/maven-metadata.xml",
		"Ac!me/maven-metadata.xml",
		"com/matchory/lib/maven-metadata.xml.sha1.sha1",
		"com/matchory/lib/maven-metadata.xml.asc",
		"com/maven-metadata.xml.sha3",
		"",
	} {
		if got, err := ParsePath(in); err == nil {
			t.Errorf("%q parsed: %+v", in, got)
		}
	}
}

func TestPartLimits(t *testing.T) {
	art := strings.Repeat("a", MaxPart)
	if _, err := ParsePath("g/" + art + "/1/" + art + "-1.jar"); err == nil {
		t.Error("file name longer than MaxPart accepted")
	}
	if _, err := ParsePath("g/" + art + "/1/" + art + "-1.jar.sha1"); err == nil {
		t.Error("file name longer than MaxPart accepted with checksum")
	}
	if _, err := ParsePath(strings.Repeat("g/", MaxPart/2+1) + "a/1/a-1.jar"); err == nil {
		t.Error("group longer than MaxPart accepted")
	}
	if _, err := ParsePath("g/a/1/a-1-" + strings.Repeat("c", 65) + ".jar"); err == nil {
		t.Error("classifier longer than 64 accepted")
	}
	if _, err := ParsePath("g/a/1/a-1." + strings.Repeat("e", 33)); err == nil {
		t.Error("extension longer than 32 accepted")
	}
}

func TestKey(t *testing.T) {
	if got := (Coords{"Com.Matchory", "Lib", "1"}).Key(); got != "com.matchory:lib" {
		t.Errorf("Key = %q", got)
	}
}

func TestSegmentCap(t *testing.T) {
	path := func(groupSegs int) string { return strings.Repeat("g/", groupSegs) + "a/1/a-1.jar" }
	if _, err := ParsePath(path(61)); err != nil {
		t.Errorf("64 segments refused: %v", err)
	}
	if _, err := ParsePath(path(62)); err == nil {
		t.Error("65 segments accepted")
	}
	// A dotted group segment counts once per part.
	if _, err := ParsePath(strings.Repeat("g.", 61) + "g/a/1/a-1.jar"); err == nil {
		t.Error("65 canonical segments accepted")
	}
}

func TestImmutable(t *testing.T) {
	for path, want := range map[string]bool{
		"com/matchory/lib/1.0/lib-1.0.jar":                                 true,
		"com/matchory/lib/1.0-SNAPSHOT/lib-1.0-20261123.101010-3.jar":      true,
		"com/matchory/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar":               false,
		"com/matchory/lib/1.0-SNAPSHOT/maven-metadata.xml":                 false,
		"com/matchory/lib/maven-metadata.xml":                              false,
		"com/matchory/lib/1.0-SNAPSHOT/lib-1.0-20261123.101010-3.jar.sha1": true,
	} {
		p, err := ParsePath(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Immutable(); got != want {
			t.Errorf("%s: Immutable() = %v, want %v", path, got, want)
		}
	}
}

func TestPathGroup(t *testing.T) {
	for in, want := range map[string]string{
		"com/matchory/plugins/maven-metadata.xml": "com.matchory.plugins",
		"acme/maven-metadata.xml":                 "acme",
	} {
		if got := mustPath(t, in).Group(); got != want {
			t.Errorf("%s: Group() = %q, want %q", in, got, want)
		}
	}
}
