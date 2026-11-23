package maven

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

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

func FuzzDecodeXML(f *testing.F) {
	for _, s := range []string{
		plainPOM, "\uFEFF" + plainPOM, "<project/>", `<!DOCTYPE x SYSTEM "file:///etc/passwd"><project/>`,
		`<?xml version="1.0" encoding="ISO-8859-1"?><project/>`, "<project>" + nested(40) + "</project>",
		"<metadata><versioning><versions><version>1.0</version></versions></versioning></metadata>",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var p testPOM
		err := DecodeXML(bytes.NewReader(b), XMLLimits{MaxBytes: 64 << 10, MaxDepth: 32, MaxElements: 1000}, &p)
		if _, ok := errors.AsType[*XMLError](err); err != nil && !ok {
			t.Fatalf("err = %v (%T), want *XMLError", err, err)
		}
		cerr := CheckXML(bytes.NewReader(b), XMLLimits{MaxBytes: 64 << 10, MaxDepth: 32, MaxElements: 1000}, "project")
		if _, ok := errors.AsType[*XMLError](cerr); cerr != nil && !ok {
			t.Fatalf("CheckXML err = %v (%T), want *XMLError", cerr, cerr)
		}
	})
}

func FuzzParseChecksumFile(f *testing.F) {
	for _, s := range []string{
		"8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12", "8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12  junit-4.13.2.jar\n",
		"SHA1 (junit-4.13.2.jar) = 8AC9E16D933B6FB43BC7F576336B8F4D7EB5BA12", "\n\n", "x= y",
	} {
		f.Add([]byte(s), "sha1")
	}
	f.Fuzz(func(t *testing.T, b []byte, alg string) {
		sum, err := ParseChecksumFile(bytes.NewReader(b), alg)
		if err != nil {
			return
		}
		want := map[string]int{"sha1": 40, "sha256": 64, "sha512": 128, "md5": 32}[alg]
		if len(sum) != want || strings.ToLower(sum) != sum {
			t.Fatalf("%q (%s) = %q", b, alg, sum)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			t.Fatalf("%q: not hex: %q", b, sum)
		}
	})
}

func FuzzInspectPOM(f *testing.F) {
	for _, s := range []string{
		plainPOM, pom(`<groupId>com.matchory</groupId><artifactId>lib</artifactId><version>1.0</version>`),
		pom(`<parent><groupId>com.matchory</groupId><version>${revision}</version></parent><artifactId>lib</artifactId>`),
		`<!DOCTYPE project []><project/>`,
		smuggledPOM,
	} {
		f.Add([]byte(s))
	}
	p := mustPath(f, "com/matchory/lib/1.0/lib-1.0.pom")
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := InspectPOM(bytes.NewReader(b), p); err != nil {
			if _, ok := errors.AsType[*RequestError](err); !ok {
				t.Fatalf("err = %v (%T), want *RequestError", err, err)
			}
		}
	})
}

func FuzzInspectModule(f *testing.F) {
	for _, s := range []string{
		`{"formatVersion":"1.1","component":{"group":"com.matchory","module":"lib","version":"1.0"},"variants":[{"files":[{"url":"lib-1.0.jar"}]}]}`,
		`{"formatVersion":"1.1","component":{"group":"com.matchory","module":"lib","version":"1.0"},"variants":[{"files":[{"url":"a/b"}]}]}`,
		`[[[[]]]]`, `{"a":1}{}`, `null`,
	} {
		f.Add([]byte(s))
	}
	p := mustPath(f, "com/matchory/lib/1.0/lib-1.0.module")
	f.Fuzz(func(t *testing.T, b []byte) {
		err := InspectModule(bytes.NewReader(b), p)
		if err == nil {
			if !json.Valid(b) {
				t.Fatalf("accepted invalid JSON %q", b)
			}
			return
		}
		if _, ok := errors.AsType[*RequestError](err); !ok {
			t.Fatalf("err = %v (%T), want *RequestError", err, err)
		}
	})
}
