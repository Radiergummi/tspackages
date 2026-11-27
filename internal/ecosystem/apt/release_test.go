package apt

import (
	"bytes"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func readRelease(t *testing.T, name string) ReleaseDoc {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseRelease(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestParseRelease(t *testing.T) {
	d := readRelease(t, "debian-bookworm-Release.txt")
	if want := time.Date(2026, 7, 11, 10, 16, 37, 0, time.UTC); !d.Date.Equal(want) {
		t.Fatalf("Date = %v, want %v", d.Date, want)
	}
	if !d.ValidUntil.IsZero() || !d.ByHash {
		t.Fatalf("ValidUntil = %v, ByHash = %v", d.ValidUntil, d.ByHash)
	}
	fh, ok := d.Lookup("main/binary-amd64/Packages.xz")
	if !ok || fh.Size != 8790396 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fh.SHA256) ||
		fh.SHA256 != "9e0b5aabb2465b3d2e7a7fe27f9913846277833f7a2826e7767acccff5b588c5" {
		t.Fatalf("Lookup = %+v, %v", fh, ok)
	}
	if _, ok := d.Lookup("main/binary-amd64/Packages.zz"); ok {
		t.Fatal("Lookup found a path that is not listed")
	}
	if d.Fields[0] != (Field{"Origin", "Debian"}) {
		t.Fatalf("Fields[0] = %+v", d.Fields[0])
	}
	for _, n := range []string{"MD5Sum", "SHA1", "SHA256", "SHA512"} {
		if _, ok := d.Fields.Get(n); ok {
			t.Fatalf("Fields holds %s", n)
		}
	}
	if v, _ := d.Fields.Get("Components"); v != "main contrib non-free-firmware non-free" {
		t.Fatalf("Components = %q", v)
	}

	sec := readRelease(t, "debian-security-Release.txt")
	if want := time.Date(2026, 12, 2, 7, 43, 37, 0, time.UTC); !sec.ValidUntil.Equal(want) {
		t.Fatalf("ValidUntil = %v, want %v", sec.ValidUntil, want)
	}
	if fh, ok := sec.Lookup("main/binary-amd64/Packages.xz"); !ok || fh.Size == 0 {
		t.Fatalf("security Lookup = %+v, %v", fh, ok)
	}
}

func TestParseReleaseDates(t *testing.T) {
	want := time.Date(2026, 11, 9, 10, 12, 43, 0, time.UTC)
	for _, s := range []string{
		"Mon, 09 Nov 2026 10:12:43 UTC", "Mon, 09 Nov 2026 10:12:43 GMT", "Mon, 09 Nov 2026 10:12:43 +0000",
		"Mon, 09 Nov 2026 10:12:43 Z", "Mon, 9 Nov 2026 10:12:43 UTC",
	} {
		d, err := ParseRelease([]byte("Origin: x\nDate: " + s + "\nValid-Until: " + s + "\n"))
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if !d.Date.Equal(want) || !d.ValidUntil.Equal(want) || d.Date.Location() != time.UTC {
			t.Fatalf("%q: Date = %v, ValidUntil = %v", s, d.Date, d.ValidUntil)
		}
	}
	for _, s := range []string{
		"", "Mon, 09 Nov 2026 10:12:43", "Mon, 09 Nov 2026 10:12:43 +0100", "Mon, 09 Nov 2026 10:12:43 CEST",
		"2026-11-09T10:12:43Z", "Mon, 09 Nov 2026 25:12:43 UTC", "Mon, 09 Nov 2026 10:12:43 UTC extra",
	} {
		if _, err := ParseRelease([]byte("Date: " + s + "\n")); err == nil {
			t.Fatalf("Date %q accepted", s)
		}
		if _, err := ParseRelease([]byte("Date: Mon, 09 Nov 2026 10:12:43 UTC\nValid-Until: " + s + "\n")); err == nil {
			t.Fatalf("Valid-Until %q accepted", s)
		}
	}
}

func TestParseReleaseRejects(t *testing.T) {
	const date = "Date: Mon, 09 Nov 2026 10:12:43 UTC\n"
	const h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for name, in := range map[string]string{
		"empty":           "",
		"no Date":         "Origin: x\n",
		"two stanzas":     date + "\nOrigin: y\n",
		"duplicate field": date + "Origin: x\norigin: y\n",
		"short hash":      date + "SHA256:\n e3b0 0 a\n",
		"bad size":        date + "SHA256:\n " + h + " x a\n",
		"negative size":   date + "SHA256:\n " + h + " -1 a\n",
		"no path":         date + "SHA256:\n " + h + " 0\n",
		"extra column":    date + "SHA256:\n " + h + " 0 a b\n",
		"duplicate path":  date + "SHA256:\n " + h + " 0 a\n " + h + " 1 a\n",
		"absolute path":   date + "SHA256:\n " + h + " 0 /a\n",
		"dotdot path":     date + "SHA256:\n " + h + " 0 main/../../a\n",
		"unclean path":    date + "SHA256:\n " + h + " 0 main//a\n",
		"CR":              "Date: Mon, 09 Nov 2026 10:12:43 UTC\r\n",
		"too large":       date + "X: " + strings.Repeat("a", 4<<20) + "\n",
	} {
		if _, err := ParseRelease([]byte(in)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	d, err := ParseRelease([]byte(date + "SHA256:\n " + h + "        0 a\n\t" + strings.ToUpper(h) + " 12 b/c\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []FileHash{{"a", 0, h}, {"b/c", 12, h}}; !reflect.DeepEqual(d.SHA256, want) {
		t.Fatalf("SHA256 = %+v", d.SHA256)
	}
}

func TestRenderRelease(t *testing.T) {
	const h1 = "1111111111111111111111111111111111111111111111111111111111111111"
	const h2 = "2222222222222222222222222222222222222222222222222222222222222222"
	date := time.Date(2026, 11, 9, 11, 12, 43, 0, time.FixedZone("CET", 3600))
	d := ReleaseDoc{
		Fields: Stanza{
			{"Origin", "tspackages"}, {"Label", "hosted"}, {"Suite", "bookworm"}, {"Codename", "bookworm"},
			{"Date", ""}, {"Architectures", "amd64 all"}, {"Components", "main"}, {"Acquire-By-Hash", ""},
		},
		Date:   date,
		ByHash: true,
		SHA256: []FileHash{
			{"main/binary-amd64/Packages.gz", 20, h2},
			{"main/binary-all/Packages", 0, h1},
			{"main/binary-amd64/Packages", 100, h1},
		},
	}
	want := "Origin: tspackages\nLabel: hosted\nSuite: bookworm\nCodename: bookworm\n" +
		"Date: Mon, 09 Nov 2026 10:12:43 UTC\nArchitectures: amd64 all\nComponents: main\nAcquire-By-Hash: yes\n" +
		"SHA256:\n " + h1 + " 0 main/binary-all/Packages\n " + h1 + " 100 main/binary-amd64/Packages\n " +
		h2 + " 20 main/binary-amd64/Packages.gz\n"
	got := d.Render()
	if string(got) != want {
		t.Fatalf("Render =\n%s\nwant\n%s", got, want)
	}
	if again := d.Render(); !bytes.Equal(again, got) {
		t.Fatal("Render is not stable")
	}
	if d.SHA256[0].Path != "main/binary-amd64/Packages.gz" {
		t.Fatal("Render reordered the caller's SHA256 slice")
	}
	back, err := ParseRelease(got)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Date.Equal(date) || !back.ByHash || len(back.SHA256) != 3 {
		t.Fatalf("round trip: %+v", back)
	}
	if !bytes.Equal(back.Render(), got) {
		t.Fatal("Render(ParseRelease(Render)) differs")
	}

	// A parsed upstream Release renders back to its fields and SHA256 list.
	deb := readRelease(t, "debian-bookworm-Release.txt")
	again, err := ParseRelease(deb.Render())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again.Fields, deb.Fields) || len(again.SHA256) != len(deb.SHA256) {
		t.Fatal("Debian Release does not round-trip through Render")
	}
}
