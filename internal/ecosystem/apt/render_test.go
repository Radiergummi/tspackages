package apt

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

func accFor(pattern string) ReadAccess {
	return ReadAccess{Any: true, Name: func(n string) bool { return Match(pattern, n) }}
}

func (e *stEnv) uploadArch(suite, name, arch string) {
	e.t.Helper()
	ctl := fmt.Sprintf("Package: %s\nVersion: 1.0\nArchitecture: %s\nMaintainer: A <a@example.com>\nDescription: d\n", name, arch)
	if _, _, err := e.uploadBytes(suite, "main", testutil.Deb(e.t, ctl, testutil.DebOptions{})); err != nil {
		e.t.Fatal(err)
	}
}

func blobBytes(t *testing.T, b Blob, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Body.Close()
	got, err := io.ReadAll(b.Body)
	if err != nil {
		t.Fatal(err)
	}
	if b.Size != int64(len(got)) {
		t.Errorf("Size = %d, read %d bytes", b.Size, len(got))
	}
	if sum := sha256.Sum256(got); b.ETag != `"`+hex.EncodeToString(sum[:])+`"` {
		t.Errorf("ETag = %s", b.ETag)
	}
	return got
}

// release fetches suite's InRelease as acc sees it, checks its signature and
// that Release and Release.gpg agree with it, and parses it.
func (e *stEnv) release(t *testing.T, acc ReadAccess, suite string) (ReleaseDoc, []byte) {
	t.Helper()
	ctx := context.Background()
	b, err := e.src.Release(ctx, acc, suite, "InRelease")
	in := blobBytes(t, b, err)
	if b.Immutable {
		t.Error("InRelease is immutable")
	}
	kr := keyring(t, e.entity)
	text, err := kr.VerifyInRelease(in, time.Now())
	if err != nil {
		t.Fatalf("InRelease: %v", err)
	}
	b, err = e.src.Release(ctx, acc, suite, "Release")
	rel := blobBytes(t, b, err)
	if !bytes.Equal(rel, text) {
		t.Errorf("Release differs from the signed text of InRelease:\n%s\n---\n%s", rel, text)
	}
	b, err = e.src.Release(ctx, acc, suite, "Release.gpg")
	if err := kr.VerifyDetached(rel, blobBytes(t, b, err), time.Now()); err != nil {
		t.Errorf("Release.gpg: %v", err)
	}
	doc, err := ParseRelease(rel)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Modified.Equal(doc.Date) {
		t.Errorf("Modified = %v, Date %v", b.Modified, doc.Date)
	}
	return doc, in
}

// checkIndexes fetches every index doc lists, checks its size and hash, that
// each Packages has a Packages.gz of the same text, and returns the package
// names of each Packages file.
func (e *stEnv) checkIndexes(t *testing.T, acc ReadAccess, suite string, doc ReleaseDoc) map[string][]string {
	t.Helper()
	raw := map[string][]byte{}
	for _, h := range doc.SHA256 {
		b, err := e.src.Dist(context.Background(), acc, suite, h.Path)
		got := blobBytes(t, b, err)
		sum := sha256.Sum256(got)
		if int64(len(got)) != h.Size || hex.EncodeToString(sum[:]) != h.SHA256 {
			t.Errorf("%s: %d bytes %x, Release says %d %s", h.Path, len(got), sum, h.Size, h.SHA256)
		}
		if b.Immutable || !b.Modified.Equal(doc.Date) {
			t.Errorf("%s: Immutable %v Modified %v", h.Path, b.Immutable, b.Modified)
		}
		raw[h.Path] = got
	}
	out := map[string][]string{}
	for p, got := range raw {
		if strings.HasSuffix(p, ".gz") {
			continue
		}
		zr, err := gzip.NewReader(bytes.NewReader(raw[p+".gz"]))
		if err != nil {
			t.Fatalf("%s.gz: %v", p, err)
		}
		if unz, err := io.ReadAll(zr); err != nil || !bytes.Equal(unz, got) {
			t.Errorf("%s.gz does not hold %s (%v)", p, p, err)
		}
		pkgs := []string{}
		for s, err := range Stanzas(bytes.NewReader(got), 1<<20) {
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			n, _ := s.Get("Package")
			pkgs = append(pkgs, n)
		}
		out[p] = pkgs
	}
	return out
}

func signatures(t *testing.T) float64 {
	t.Helper()
	mfs, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "tspackages_apt_release_signatures_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "source" && l.GetValue() == "hosted" {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestRenderPerCaller(t *testing.T) {
	drivers(t, func(t *testing.T, newDriver func(*testing.T) storage.Driver) {
		e := newStEnv(t, newDriver(t))
		for _, n := range []string{"acme-a", "acme-b", "other"} {
			e.uploadArch("bookworm", n, "amd64")
		}
		for _, tc := range []struct {
			pattern string
			want    []string
		}{
			{"acme-*", []string{"acme-a", "acme-b"}},
			{"*", []string{"acme-a", "acme-b", "other"}},
		} {
			acc := accFor(tc.pattern)
			doc, _ := e.release(t, acc, "bookworm")
			idx := e.checkIndexes(t, acc, "bookworm", doc)
			if got := idx["main/binary-amd64/Packages"]; !slices.Equal(got, tc.want) {
				t.Errorf("%s: Packages lists %v, want %v", tc.pattern, got, tc.want)
			}
			if len(doc.SHA256) != 2 {
				t.Errorf("%s: SHA256 = %+v", tc.pattern, doc.SHA256)
			}
			wantFields := "Origin=tspackages Label=hosted Suite=bookworm Codename=bookworm Date= Architectures=all amd64 Components=main Acquire-By-Hash=yes"
			var fields []string
			for _, f := range doc.Fields {
				v := f.Value
				if f.Name == "Date" {
					v = ""
				}
				fields = append(fields, f.Name+"="+v)
			}
			if got := strings.Join(fields, " "); got != wantFields {
				t.Errorf("%s: fields %s", tc.pattern, got)
			}
		}

		// Nothing visible: a signed Release with empty indexes.
		none := ReadAccess{Any: true, Name: func(string) bool { return false }}
		doc, in := e.release(t, none, "bookworm")
		if strings.Contains(string(in), "acme") || strings.Contains(string(in), "other") {
			t.Errorf("empty InRelease names packages:\n%s", in)
		}
		if v, _ := doc.Fields.Get("Architectures"); v != "all" {
			t.Errorf("Architectures = %q", v)
		}
		if !doc.Date.Equal(time.Unix(0, 0)) {
			t.Errorf("Date = %v, want the epoch", doc.Date)
		}
		idx := e.checkIndexes(t, none, "bookworm", doc)
		if pkgs, ok := idx["main/binary-all/Packages"]; !ok || len(pkgs) != 0 || len(idx) != 1 {
			t.Errorf("empty indexes = %v", idx)
		}

		ctx := context.Background()
		all := accFor("*")
		for _, f := range []func() error{
			func() error { _, err := e.src.Release(ctx, all, "trixie", "InRelease"); return err },
			func() error { _, err := e.src.Release(ctx, all, "bookworm", "Packages"); return err },
			func() error { _, err := e.src.Dist(ctx, all, "bookworm", "main/binary-arm64/Packages"); return err },
			func() error { _, err := e.src.Dist(ctx, all, "trixie", "main/binary-amd64/Packages"); return err },
			func() error { _, err := e.src.Dist(ctx, all, "bookworm", "main/binary-amd64/Packages.xz"); return err },
			func() error {
				_, err := e.src.ByHash(ctx, all, "bookworm", "main/binary-amd64/by-hash/SHA256/"+strings.Repeat("0", 64), strings.Repeat("0", 64))
				return err
			},
		} {
			if err := f(); !errors.Is(err, resolve.ErrNotFound) {
				t.Errorf("got %v, want ErrNotFound", err)
			}
		}
	})
}

func TestRenderStable(t *testing.T) {
	e := newStEnv(t, fsDriver(t))
	for _, n := range []string{"acme-a", "acme-b", "other"} {
		e.uploadArch("bookworm", n, "amd64")
	}
	acc := accFor("acme-*")
	before := signatures(t)
	doc, first := e.release(t, acc, "bookworm")
	_, second := e.release(t, acc, "bookworm")
	if !bytes.Equal(first, second) {
		t.Error("InRelease changed between two requests for the same set")
	}
	if got := signatures(t) - before; got != 1 {
		t.Errorf("signed %v times, want 1", got)
	}
	var newest time.Time
	for _, m := range e.members(t, "bookworm") {
		if strings.HasPrefix(m.Deb.Name, "acme-") && m.Uploaded.After(newest) {
			newest = m.Uploaded
		}
	}
	if !doc.Date.Equal(newest.Truncate(time.Second)) {
		t.Errorf("Date = %v, want %v", doc.Date, newest)
	}

	// A source that has not rendered the set yet serves the stored signature.
	cache, err := storage.NewCache(context.Background(), e.cacheD, 1<<30, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.src = NewStorageSource("hosted", []string{"acme*"}, e.d, cache, e.src.rec, e.src.signer, e.src.log)
	if _, third := e.release(t, acc, "bookworm"); !bytes.Equal(first, third) {
		t.Error("a fresh source signed again instead of serving the stored InRelease")
	}
	if got := signatures(t) - before; got != 1 {
		t.Errorf("signed %v times, want 1", got)
	}
}

func TestArchAll(t *testing.T) {
	e := newStEnv(t, fsDriver(t))
	e.uploadArch("bookworm", "acme-tool", "arm64")
	e.uploadArch("bookworm", "acme-data", "all")
	e.uploadArch("bookworm", "acme-tool", "amd64")
	acc := accFor("*")
	doc, _ := e.release(t, acc, "bookworm")
	if v, _ := doc.Fields.Get("Architectures"); v != "all amd64 arm64" {
		t.Errorf("Architectures = %q", v)
	}
	idx := e.checkIndexes(t, acc, "bookworm", doc)
	want := []string{"acme-data", "acme-tool"}
	for _, p := range []string{"main/binary-amd64/Packages", "main/binary-arm64/Packages"} {
		if !slices.Equal(idx[p], want) {
			t.Errorf("%s lists %v, want %v", p, idx[p], want)
		}
	}
	if len(idx) != 2 {
		t.Errorf("indexes = %v", idx)
	}
	b, err := e.src.Dist(context.Background(), acc, "bookworm", "main/binary-arm64/Packages")
	got := string(blobBytes(t, b, err))
	if !strings.Contains(got, "Filename: pool/acme-tool/acme-tool_1.0_arm64.deb\nSize: ") || strings.Contains(got, "_amd64.deb") {
		t.Errorf("arm64 Packages:\n%s", got)
	}
}

// byHash returns the by-hash path and hash of rel in doc.
func byHash(t *testing.T, doc ReleaseDoc, rel string) (string, string) {
	t.Helper()
	h, ok := doc.Lookup(rel)
	if !ok {
		t.Fatalf("%s not in Release", rel)
	}
	dir, _, _ := strings.Cut(rel, "/Packages")
	return dir + "/by-hash/SHA256/" + h.SHA256, h.SHA256
}

func TestByHashSurvivesUpload(t *testing.T) {
	drivers(t, func(t *testing.T, newDriver func(*testing.T) storage.Driver) {
		e := newStEnv(t, newDriver(t))
		e.uploadArch("bookworm", "acme-a", "amd64")
		acc := accFor("acme-*")
		ctx := context.Background()
		doc, _ := e.release(t, acc, "bookworm")
		b, err := e.src.Dist(ctx, acc, "bookworm", "main/binary-amd64/Packages.gz")
		old := blobBytes(t, b, err)

		e.uploadArch("bookworm", "acme-b", "amd64")
		newDoc, _ := e.release(t, acc, "bookworm")
		rel, h := byHash(t, doc, "main/binary-amd64/Packages.gz")
		if _, newH := byHash(t, newDoc, "main/binary-amd64/Packages.gz"); newH == h {
			t.Fatal("the upload did not change the index")
		}
		b, err = e.src.ByHash(ctx, acc, "bookworm", rel, h)
		if got := blobBytes(t, b, err); !bytes.Equal(got, old) {
			t.Error("by-hash bytes differ from the index served before the upload")
		}
		if !b.Immutable {
			t.Error("by-hash file is not immutable")
		}
		// Another suite's or another directory's by-hash path is a miss.
		if _, err := e.src.ByHash(ctx, acc, "trixie", rel, h); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("other suite: %v", err)
		}
		if _, err := e.src.ByHash(ctx, acc, "bookworm", "main/by-hash/SHA256/"+h, h); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("malformed directory: %v", err)
		}
	})
}

func TestByHashNotLeaked(t *testing.T) {
	e := newStEnv(t, fsDriver(t))
	for _, n := range []string{"acme-a", "other"} {
		e.uploadArch("bookworm", n, "amd64")
	}
	ctx := context.Background()
	doc, _ := e.release(t, accFor("*"), "bookworm")
	acme := accFor("acme-*")
	for _, p := range []string{"main/binary-amd64/Packages", "main/binary-amd64/Packages.gz"} {
		rel, h := byHash(t, doc, p)
		if _, err := e.src.ByHash(ctx, acme, "bookworm", rel, h); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("%s: %v, want ErrNotFound", p, err)
		}
	}
	own, _ := e.release(t, acme, "bookworm")
	rel, h := byHash(t, own, "main/binary-amd64/Packages")
	b, err := e.src.ByHash(ctx, acme, "bookworm", rel, h)
	if got := blobBytes(t, b, err); bytes.Contains(got, []byte("other")) {
		t.Errorf("own by-hash index:\n%s", got)
	}
}

func TestRevokedRuleShrinksIndex(t *testing.T) {
	e := newStEnv(t, fsDriver(t))
	for _, n := range []string{"acme-a", "other"} {
		e.uploadArch("bookworm", n, "amd64")
	}
	other := Deb{"other", "1.0", "amd64"}
	for _, tc := range []struct {
		pattern string
		want    []string
	}{{"*", []string{"acme-a", "other"}}, {"acme-*", []string{"acme-a"}}} {
		acc := accFor(tc.pattern)
		doc, _ := e.release(t, acc, "bookworm")
		if got := e.checkIndexes(t, acc, "bookworm", doc)["main/binary-amd64/Packages"]; !slices.Equal(got, tc.want) {
			t.Errorf("%s: lists %v, want %v", tc.pattern, got, tc.want)
		}
	}
	_, err := e.src.Pool(context.Background(), accFor("acme-*"), Path{Kind: KindPool, Rel: "pool/other/" + other.FileName()})
	if !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("pool: %v", err)
	}
}

func TestIndexNoInjection(t *testing.T) {
	var logs bytes.Buffer
	d := fsDriver(t)
	e := newStEnvLog(t, d, slog.New(slog.NewTextHandler(&logs, nil)))
	e.uploadArch("bookworm", "acme-a", "amd64")
	e.uploadArch("bookworm", "acme-b", "s390x")
	ctx := context.Background()
	key := poolPrefix("hosted", Deb{"acme-b", "1.0", "s390x"}) + "deb.json"
	sc, _, err := e.src.readSidecar(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range sc.Fields {
		if f[0] == "Description" {
			sc.Fields[i][1] = "x\n\nPackage: evil"
		}
	}
	future := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	sc.Uploaded = future
	b, _ := json.Marshal(sc)
	if _, err := d.Put(ctx, key, bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(ctx, suitePrefix("hosted", "bookworm")+"index.json"); err != nil {
		t.Fatal(err)
	}
	acc := accFor("*")
	doc, _ := e.release(t, acc, "bookworm")
	if got := e.checkIndexes(t, acc, "bookworm", doc)["main/binary-amd64/Packages"]; !slices.Equal(got, []string{"acme-a"}) {
		t.Errorf("Packages lists %v", got)
	}
	// The skipped member adds neither its architecture nor its date.
	if v, _ := doc.Fields.Get("Architectures"); v != "all amd64" {
		t.Errorf("Architectures = %q", v)
	}
	if doc.Date.Equal(future) {
		t.Error("Date is the skipped member's upload time")
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "acme-b") {
		t.Errorf("no error logged for the skipped member:\n%s", logs.String())
	}
}

func TestByHashKeptAcrossRenderings(t *testing.T) {
	e := newStEnv(t, fsDriver(t))
	for _, n := range []string{"acme-a", "other"} {
		e.uploadArch("bookworm", n, "amd64")
	}
	ctx := context.Background()
	all := accFor("*")
	doc, _ := e.release(t, all, "bookworm")
	rel, sum := byHash(t, doc, "main/binary-amd64/Packages")
	// 20 other visible sets, each its own rendering.
	for i := range 20 {
		e.uploadArch("bookworm", fmt.Sprintf("acme-x%d", i), "amd64")
		e.release(t, accFor(fmt.Sprintf("acme-x%d", i)), "bookworm")
	}
	b, err := e.src.ByHash(ctx, all, "bookworm", rel, sum)
	if got := blobBytes(t, b, err); hexSHA256(got) != sum {
		t.Error("by-hash bytes differ from their hash")
	}
	if _, err := e.src.ByHash(ctx, accFor("acme-*"), "bookworm", rel, sum); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("caller without other: %v, want ErrNotFound", err)
	}
}

func TestByHashRestoredAfterEviction(t *testing.T) {
	e := newStEnv(t, fsDriver(t))
	e.uploadArch("bookworm", "acme-a", "amd64")
	ctx := context.Background()
	acc := accFor("acme-*")
	doc, _ := e.release(t, acc, "bookworm")
	rel, sum := byHash(t, doc, "main/binary-amd64/Packages.gz")
	key := e.src.byHashKey("bookworm", sum)
	if err := e.cacheD.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	b, err := e.src.ByHash(ctx, acc, "bookworm", rel, sum)
	if got := blobBytes(t, b, err); hexSHA256(got) != sum || !b.Immutable {
		t.Errorf("served %d bytes, Immutable %v", len(got), b.Immutable)
	}
	if _, err := e.cacheD.Stat(ctx, key); err != nil {
		t.Errorf("entry not stored again: %v", err)
	}
	// A caller whose rendering lacks the hash still misses.
	if _, err := e.src.ByHash(ctx, ReadAccess{Any: true, Name: func(string) bool { return false }}, "bookworm", rel, sum); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("caller without acme-a: %v", err)
	}
}

func TestSignatureBoundToKey(t *testing.T) {
	e := newStEnv(t, fsDriver(t))
	e.uploadArch("bookworm", "acme-a", "amd64")
	acc := accFor("*")
	before := signatures(t)
	e.release(t, acc, "bookworm")
	cache, err := storage.NewCache(context.Background(), e.cacheD, 1<<30, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.entity = newEntity(t, "rotated", nil)
	e.src = NewStorageSource("hosted", []string{"acme*"}, e.d, cache, e.src.rec, signer(t, e.entity), e.src.log)
	e.release(t, acc, "bookworm") // verifies with the new key
	if got := signatures(t) - before; got != 2 {
		t.Errorf("signed %v times, want 2", got)
	}
}
