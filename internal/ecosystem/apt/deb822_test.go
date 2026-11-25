package apt

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const descStanza = "Package: acme\nVersion: 1.0-1\nDescription: short\n long text\n .\n second paragraph\n\ttabbed\nHomepage: https://example.org\n"

func TestParseStanza(t *testing.T) {
	s, err := ParseStanza([]byte(descStanza), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := s.Get("description"); !ok || v != "short\n long text\n .\n second paragraph\n\ttabbed" {
		t.Fatalf("Description = %q, %v", v, ok)
	}
	if _, ok := s.Get("Missing"); ok {
		t.Fatal("Get found a missing field")
	}
	var buf bytes.Buffer
	if err := WriteStanza(&buf, s); err != nil {
		t.Fatal(err)
	}
	if buf.String() != descStanza {
		t.Fatalf("round trip = %q", buf.String())
	}

	if _, err := ParseStanza([]byte("Package: a\nVersion: 1"), 1024); err != nil {
		t.Fatalf("missing final newline: %v", err)
	}

	for name, in := range map[string]string{
		"empty input":         "",
		"empty line inside":   "Package: a\n\nVersion: 1\n",
		"trailing blank":      "Package: a\n\n",
		"crlf":                "Package: a\r\nVersion: 1\r\n",
		"nul":                 "Package: a\x00b\n",
		"invalid utf-8":       "Package: a\xffb\n",
		"bad name":            "Bad Name: x\n",
		"empty name":          ": x\n",
		"no colon":            "Package: a\nnocolon\n",
		"leading continued":   " cont\nPackage: a\n",
		"duplicate":           "Package: a\npackage: b\n",
		"comment":             "# c\nPackage: a\n",
		"whitespace-only":     "Package: a\n \n",
		"field over maxField": "Package: " + strings.Repeat("a", 100) + "\n",
	} {
		if _, err := ParseStanza([]byte(in), 50); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestWriteStanzaRejectsInjection(t *testing.T) {
	for _, v := range []string{"x\n\nPackage: evil", "x\nPackage: evil", "x\n", "x\n \nPackage: evil", "x\r", "\n\n", " lead", "a\x00"} {
		var buf bytes.Buffer
		if err := WriteStanza(&buf, Stanza{{"Description", v}}); err == nil {
			t.Errorf("value %q accepted", v)
		}
		if buf.Len() != 0 {
			t.Errorf("value %q: wrote %q before failing", v, buf.String())
		}
	}
	if err := WriteStanza(&bytes.Buffer{}, Stanza{{"Bad Name", "x"}}); err == nil {
		t.Error("bad name accepted")
	}
	// A first line that is empty is fine: the value continues on the next lines.
	var buf bytes.Buffer
	if err := WriteStanza(&buf, Stanza{{"Files", "\n a 1 x"}}); err != nil || buf.String() != "Files:\n a 1 x\n" {
		t.Fatalf("empty first line: %q, %v", buf.String(), err)
	}
}

func collect(t *testing.T, in string, max int) ([]Stanza, error) {
	t.Helper()
	var out []Stanza
	for s, err := range Stanzas(strings.NewReader(in), max) {
		if err != nil {
			return out, err
		}
		out = append(out, s)
	}
	return out, nil
}

func TestStanzas(t *testing.T) {
	in := "\n# lead\nPackage: a\n# inner\nVersion: 1\n\n\n\nPackage: b\nDescription: x\n y\n\nPackage: c\nVersion: 3"
	got, err := collect(t, in, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d stanzas: %+v", len(got), got)
	}
	if v, _ := got[0].Get("Version"); v != "1" || len(got[0]) != 2 {
		t.Errorf("stanza 0 = %+v", got[0])
	}
	if v, _ := got[1].Get("Description"); v != "x\n y" {
		t.Errorf("stanza 1 = %+v", got[1])
	}
	if v, _ := got[2].Get("Version"); v != "3" {
		t.Errorf("stanza 2 = %+v", got[2])
	}

	// Real indexes are not held to upload hygiene: duplicates and unusual UTF-8 pass.
	if got, err := collect(t, "Package: a\nPackage: b\nX: \xff\n", 1024); err != nil || len(got) != 1 {
		t.Errorf("lenient: %v, %v", got, err)
	}

	if _, err := collect(t, "Package: a\r\n", 1024); err == nil {
		t.Error("CRLF accepted")
	}
	if _, err := collect(t, "Package: a\nnocolon\n", 1024); err == nil {
		t.Error("line without colon accepted")
	}
	if _, err := collect(t, "Package: a\nX: \x00\n", 1024); err == nil {
		t.Error("NUL accepted")
	}

	big := "Package: a\nVersion: 1\n\nPackage: b\nDescription: " + strings.Repeat("x", 200) + "\n"
	got, err = collect(t, big, 64)
	if err == nil || !errors.Is(err, ErrStanzaTooLarge) {
		t.Fatalf("oversize stanza: err = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("stanzas before the oversize one = %d", len(got))
	}

	// A line without a newline longer than the cap must not be buffered whole.
	if _, err := collect(t, "Package: "+strings.Repeat("x", 1<<20), 64); !errors.Is(err, ErrStanzaTooLarge) {
		t.Errorf("long line: err = %v", err)
	}

	// PGP armor is not special-cased: the header line has no colon.
	if _, err := collect(t, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSuite: x\n", 1024); err == nil {
		t.Error("armor header accepted")
	}
}

func TestParseStanzaLinear(t *testing.T) {
	long := "A: x\n" + strings.Repeat(" a\n", 350000)
	names := new(strings.Builder)
	for i := 0; names.Len() < 1<<20; i++ {
		fmt.Fprintf(names, "N%d: x\n", i)
	}
	start := time.Now()
	if _, err := ParseStanza([]byte(long), 256<<10); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("long field: err = %v", err)
	}
	if s, err := ParseStanza([]byte(names.String()), 256<<10); err != nil || len(s) < 100000 {
		t.Fatalf("many fields: %d, %v", len(s), err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestStanzasLenientNamesAndSeparators(t *testing.T) {
	got, err := collect(t, "X-Foo_Bar.Baz: 1\nA@b~: 2\n", 1024)
	if err != nil || len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("names: %+v, %v", got, err)
	}
	if v, _ := got[0].Get("x-foo_bar.baz"); v != "1" {
		t.Errorf("value = %q", v)
	}
	for _, in := range []string{"-a: 1\n", "a b: 1\n", "\xc3\xa4: 1\n"} {
		if _, err := collect(t, in, 1024); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	sep := strings.Repeat("\n# c\n", 100)
	got, err = collect(t, "A: 1\n"+sep+"B: 2\n", 64)
	if err != nil || len(got) != 2 {
		t.Fatalf("separators: %d, %v", len(got), err)
	}
	start := time.Now()
	if got, err = collect(t, "A:\n"+strings.Repeat(" a\n", 350000), 2<<20); err != nil || len(got) != 1 || time.Since(start) > time.Second {
		t.Fatalf("long continuation: %v, %v", err, time.Since(start))
	}
}
