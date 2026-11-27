package maven

import (
	"errors"
	"strings"
	"testing"
)

type testPOM struct {
	GroupID      string `xml:"groupId"`
	ArtifactID   string `xml:"artifactId"`
	Version      string `xml:"version"`
	Packaging    string `xml:"packaging"`
	Dependencies []struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"dependencies>dependency"`
}

const plainPOM = `<?xml version="1.0" encoding="UTF-8"?>
<!-- a comment -->
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.matchory</groupId>
  <artifactId>lib</artifactId>
  <version>1.0 &amp; more</version>
  <dependencies>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version></dependency>
  </dependencies>
</project>
`

func nested(depth int) string {
	return strings.Repeat("<a>", depth) + strings.Repeat("</a>", depth)
}

func wantXMLError(t *testing.T, name string, err error) {
	t.Helper()
	if _, ok := errors.AsType[*XMLError](err); !ok {
		t.Errorf("%s: err = %v (%T), want *XMLError", name, err, err)
	}
}

func TestXMLRejects(t *testing.T) {
	big := "<project>" + strings.Repeat(" ", 1<<20) + "</project>"
	big = big[:1<<20-len("</project>")] + "</project>" // exactly 1 MiB
	for name, doc := range map[string]string{
		"billion laughs": `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><project>&lol2;</project>`,
		"doctype system": `<!DOCTYPE x SYSTEM "file:///etc/passwd"><project/>`,
		"entity":         `<project><!ENTITY x "y"></project>`,
		"undefined ref":  `<project>&lol;</project>`,
		"stylesheet":     `<?xml version="1.0"?><?xml-stylesheet href="x.xsl"?><project/>`,
		"pi in body":     `<project><?php echo 1; ?></project>`,
		"late decl":      `<project/><?xml version="1.0"?>`,
		"decl not first": ` <?xml version="1.0"?><project/>`,
		"depth 33":       "<project>" + nested(32) + "</project>",
		"10001 elements": "<project>" + strings.Repeat("<a/>", 10000) + "</project>",
		"1 MiB + 1":      big + " ",
		"unclosed":       "<project><a></project>",
		"truncated":      "<project><a>",
		"empty":          "",
		"text only":      "hello",
		"two roots":      "<project/><project/>",
		"text after":     "<project/>junk",
		"bad utf-8":      "<project>\xff</project>",
	} {
		var p testPOM
		wantXMLError(t, name+" decode", DecodeXML(strings.NewReader(doc), UploadXML, &p))
		wantXMLError(t, name+" check", CheckXML(strings.NewReader(doc), UploadXML, "project"))
	}
	for name, doc := range map[string]string{
		"depth 32":       "<project>" + nested(31) + "</project>",
		"10000 elements": "<project>" + strings.Repeat("<a/>", 9999) + "</project>",
		"1 MiB":          big,
		"comment":        "<project><!-- x --></project>\n",
	} {
		var p testPOM
		if err := DecodeXML(strings.NewReader(doc), UploadXML, &p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if err := CheckXML(strings.NewReader(doc), UploadXML, "project"); err != nil {
			t.Errorf("%s check: %v", name, err)
		}
	}
}

func TestXMLDecodesPOM(t *testing.T) {
	var p testPOM
	if err := DecodeXML(strings.NewReader(plainPOM), UploadXML, &p); err != nil {
		t.Fatal(err)
	}
	if p.GroupID != "com.matchory" || p.ArtifactID != "lib" || p.Version != "1.0 & more" ||
		len(p.Dependencies) != 1 || p.Dependencies[0].Version != "4.13.2" {
		t.Errorf("got %+v", p)
	}
	if err := CheckXML(strings.NewReader(plainPOM), UploadXML, "project"); err != nil {
		t.Error(err)
	}
	wantXMLError(t, "wrong root", CheckXML(strings.NewReader(plainPOM), UploadXML, "metadata"))
}

func TestXMLEncodings(t *testing.T) {
	var p testPOM
	if err := DecodeXML(strings.NewReader("\uFEFF"+plainPOM), UploadXML, &p); err != nil || p.ArtifactID != "lib" {
		t.Errorf("UTF-8 BOM: %+v, %v", p, err)
	}
	if err := CheckXML(strings.NewReader("\uFEFF"+plainPOM), UploadXML, "project"); err != nil {
		t.Errorf("UTF-8 BOM check: %v", err)
	}
	for _, enc := range []string{"UTF-8", "utf-8"} {
		doc := `<?xml version="1.0" encoding="` + enc + `"?><project><artifactId>lib</artifactId></project>`
		if err := DecodeXML(strings.NewReader(doc), UploadXML, &p); err != nil {
			t.Errorf("%s: %v", enc, err)
		}
	}
	doc := `<?xml version="1.0" encoding="ISO-8859-1"?><project><artifactId>lib</artifactId></project>`
	err := DecodeXML(strings.NewReader(doc), UploadXML, &p)
	wantXMLError(t, "ISO-8859-1", err)
	if err == nil || !strings.Contains(err.Error(), "ISO-8859-1") {
		t.Errorf("ISO-8859-1: %v", err)
	}
	wantXMLError(t, "ISO-8859-1 check", CheckXML(strings.NewReader(doc), UploadXML, "project"))
	for name, bom := range map[string]string{"UTF-16BE": "\xfe\xff", "UTF-16LE": "\xff\xfe"} {
		wantXMLError(t, name, DecodeXML(strings.NewReader(bom+"<\x00p\x00/\x00>\x00"), UploadXML, &p))
		wantXMLError(t, name+" check", CheckXML(strings.NewReader(bom+"<\x00p\x00/\x00>\x00"), UploadXML, "p"))
	}
}

func TestXMLDecodeErrorIsXMLError(t *testing.T) {
	var v struct {
		N int `xml:"n"`
	}
	wantXMLError(t, "type mismatch", DecodeXML(strings.NewReader("<p><n>x</n></p>"), UploadXML, &v))
}

// TestXMLASCIIEncodingLabel: UpstreamXML accepts another declared encoding
// when every byte is ASCII; UploadXML never does.
func TestXMLASCIIEncodingLabel(t *testing.T) {
	ascii := `<?xml version="1.0" encoding="ISO-8859-1"?><metadata><groupId>com.matchory</groupId></metadata>`
	if err := CheckXML(strings.NewReader(ascii), UpstreamXML, "metadata"); err != nil {
		t.Errorf("upstream ASCII: %v", err)
	}
	wantXMLError(t, "upload ASCII", CheckXML(strings.NewReader(ascii), UploadXML, "metadata"))
	latin := `<?xml version="1.0" encoding="ISO-8859-1"?><metadata><groupId>caf` + "\xe9" + `</groupId></metadata>`
	wantXMLError(t, "upstream non-ASCII", CheckXML(strings.NewReader(latin), UpstreamXML, "metadata"))
}
