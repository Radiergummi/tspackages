package maven

import "testing"

func FuzzParsePath(f *testing.F) {
	for _, s := range []string{
		"com/matchory/lib/1.0/lib-1.0.jar", "com/matchory/lib/1.0/lib-1.0-sources.jar.sha1",
		"com/matchory/lib/1.0-SNAPSHOT/lib-1.0-20261123.101010-3.jar", "com/matchory/lib/maven-metadata.xml",
		"com/matchory/lib/1.0-SNAPSHOT/maven-metadata.xml.sha1", ".meta/prefixes.txt", "a/b/c/d", "lib/1.0-SNAPSHOT/maven-metadata.xml",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParsePath(s)
		if err != nil {
			return
		}
		again, err := ParsePath(p.String())
		if err != nil || again != p {
			t.Fatalf("re-parse of %q = %+v, %v; want %+v", p.String(), again, err, p)
		}
	})
}
