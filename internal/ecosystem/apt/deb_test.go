package apt

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/radiergummi/tspackages/internal/testutil"
)

const testControl = "Package: acme\nVersion: 1.0-1\nArchitecture: amd64\nMaintainer: A <a@example.com>\nDepends: libc6 (>= 2.36)\nX-Secret: s\nFilename: pool/evil.deb\nDescription: short\n long\n"

func inspect(t *testing.T, b []byte) (Control, error) {
	t.Helper()
	return Inspect(bytes.NewReader(b), int64(len(b)))
}

func TestInspect(t *testing.T) {
	for _, c := range []string{"gz", "xz", "zst", "none", ""} {
		t.Run(c, func(t *testing.T) {
			got, err := inspect(t, testutil.Deb(t, testControl, testutil.DebOptions{Compression: c}))
			if err != nil {
				t.Fatal(err)
			}
			if want := (Deb{"acme", "1.0-1", "amd64"}); got.Deb != want {
				t.Fatalf("Deb = %+v, want %+v", got.Deb, want)
			}
			if v, ok := got.Fields.Get("Depends"); !ok || v != "libc6 (>= 2.36)" {
				t.Fatalf("Depends = %q, %v", v, ok)
			}
			for _, n := range []string{"X-Secret", "Filename"} {
				if _, ok := got.Fields.Get(n); ok {
					t.Fatalf("%s kept", n)
				}
			}
			if got.Fields[0].Name != "Package" || got.Fields[len(got.Fields)-1].Name != "Description" {
				t.Fatalf("order: %+v", got.Fields)
			}
		})
	}
}

func TestInspectZstdEpoch(t *testing.T) {
	got, err := inspect(t, testutil.Deb(t, "Package: acme\nVersion: 1:2.0-1ubuntu1\nArchitecture: amd64\n", testutil.DebOptions{Compression: "zst"}))
	if err != nil {
		t.Fatal(err)
	}
	if want := (Deb{"acme", "1:2.0-1ubuntu1", "amd64"}); got.Deb != want {
		t.Fatalf("Deb = %+v, want %+v", got.Deb, want)
	}
}

func TestInspectRejects(t *testing.T) {
	good := "Package: acme\nVersion: 1.0\nArchitecture: amd64\n"
	ctl := string(testutil.Gzip(t, testutil.Tar(t, map[string]string{"./control": good})))
	data := string(testutil.Gzip(t, testutil.Tar(t, map[string]string{"./x": "x"})))
	ar := func(m ...[2]string) []byte { return testutil.Ar(t, m) }
	bin := [2]string{"debian-binary", "2.0\n"}
	ctlM := [2]string{"control.tar.gz", ctl}
	dataM := [2]string{"data.tar.gz", data}
	many := [][2]string{bin, ctlM}
	for i := range 14 {
		many = append(many, [2]string{fmt.Sprintf("_x%d", i), "x"})
	}
	many = append(many, dataM)
	bomb := string(testutil.Gzip(t, testutil.Tar(t, map[string]string{"./pad": strings.Repeat("\x00", 5<<20)})))

	cases := map[string][]byte{
		"not ar":            []byte("hello world, definitely not an archive"),
		"debian-binary 3.0": ar([2]string{"debian-binary", "3.0\n"}, ctlM, dataM),
		"data before ctrl":  ar(bin, dataM, ctlM),
		"slash in name":     ar(bin, ctlM, [2]string{"a/b", "x"}, dataM),
		"17 members":        testutil.Ar(t, many),
		"control too big":   testutil.Deb(t, "Package: acme\nVersion: 1.0\nArchitecture: amd64\nDescription: "+strings.Repeat("a", 256<<10)+"\n", testutil.DebOptions{}),
		"gzip bomb":         ar(bin, [2]string{"control.tar.gz", bomb}, dataM),
		"blank line":        testutil.Deb(t, "Package: acme\n\nVersion: 1.0\nArchitecture: amd64\n", testutil.DebOptions{}),
		"no architecture":   testutil.Deb(t, "Package: acme\nVersion: 1.0\n", testutil.DebOptions{}),
		"bad package":       testutil.Deb(t, "Package: A\nVersion: 1.0\nArchitecture: amd64\n", testutil.DebOptions{}),
		"no data":           ar(bin, ctlM),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := inspect(t, b)
			var re *RequestError
			if !errors.As(err, &re) || re.Status != 400 {
				t.Fatalf("err = %v, want 400 RequestError", err)
			}
		})
	}
	_, err := inspect(t, cases["no architecture"])
	if err == nil || !strings.Contains(err.Error(), "Architecture") {
		t.Fatalf("err = %v, want it to name Architecture", err)
	}
}

func TestInspectBombMessage(t *testing.T) {
	bomb := testutil.Gzip(t, testutil.Tar(t, map[string]string{"./pad": strings.Repeat("\x00", 5<<20)}))
	b := testutil.Ar(t, [][2]string{{"debian-binary", "2.0\n"}, {"control.tar.gz", string(bomb)}, {"data.tar.gz", "x"}})
	if _, err := inspect(t, b); err == nil || !strings.Contains(err.Error(), "decompressed") {
		t.Fatalf("err = %v", err)
	}
}

// GNU ar ends member names with "/"; dpkg strips one.
func TestInspectGNUMemberNames(t *testing.T) {
	ctl := string(testutil.Gzip(t, testutil.Tar(t, map[string]string{"./control": "Package: acme\nVersion: 1.0\nArchitecture: amd64\n"})))
	data := string(testutil.Gzip(t, testutil.Tar(t, map[string]string{"./x": "x"})))
	b := testutil.Ar(t, [][2]string{{"debian-binary/", "2.0\n"}, {"control.tar.gz/", ctl}, {"data.tar.gz/", data}})
	got, err := inspect(t, b)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Deb{"acme", "1.0", "amd64"}); got.Deb != want {
		t.Fatalf("Deb = %+v, want %+v", got.Deb, want)
	}
	for _, name := range []string{"debian-binary//", "/", "a/b/"} {
		b := testutil.Ar(t, [][2]string{{name, "2.0\n"}, {"control.tar.gz", ctl}, {"data.tar.gz", data}})
		var re *RequestError
		if _, err := inspect(t, b); !errors.As(err, &re) || re.Status != 400 {
			t.Errorf("%q: err = %v, want 400 RequestError", name, err)
		}
	}
}
