package composer

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

var caller = identity.Caller{Login: "ci@example.com", Tags: []string{"tag:ci"}, NodeName: "runner", NodeStableID: "nstable1"}

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(w, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func pkgZip(t *testing.T, composerJSON string) []byte {
	return zipOf(t, map[string]string{"composer.json": composerJSON, "src/a.php": "<?php"})
}

func newSource(t *testing.T) (*StorageSource, storage.Driver) {
	t.Helper()
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l := archive.Limits{MaxBytes: 1 << 20, MaxDecompressed: 16 << 20, MaxEntries: 1000}
	return NewStorageSource("internal", []string{"matchory-internal/*"}, d, records.New(d), l), d
}

func keys(t *testing.T, d storage.Driver, prefix string) []string {
	t.Helper()
	var out []string
	for info, err := range d.List(context.Background(), prefix) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, info.Key)
	}
	return out
}

const fooJSON = `{"name":"Matchory-Internal/Foo","require":{"php":">=8.2"}}`

func TestUploadAndVersions(t *testing.T) {
	s, d := newSource(t)
	ctx := context.Background()
	data := pkgZip(t, fooJSON)

	v, err := s.Upload(ctx, caller, "matchory-internal/foo", "1.2.0", data)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	wantRef := hex.EncodeToString(sum[:])
	if v.Reference != wantRef || v.Version != "1.2.0" || v.Dev {
		t.Fatalf("bad version %+v", v)
	}

	vs, err := s.Versions(ctx, "Matchory-Internal/Foo")
	if err != nil || len(vs) != 1 {
		t.Fatalf("Versions: %v %v", vs, err)
	}
	p := vs[0].Package
	if p["version_normalized"] != "1.2.0.0" || p["version"] != "1.2.0" || p["name"] != "matchory-internal/foo" {
		t.Fatalf("package %v", p)
	}
	sha1sum := sha1.Sum(data)
	dist, _ := p["dist"].(map[string]any)
	if dist["shasum"] != hex.EncodeToString(sha1sum[:]) || dist["reference"] != wantRef || dist["type"] != "zip" {
		t.Fatalf("dist %v", dist)
	}
	if _, ok := p["require"]; !ok {
		t.Fatal("composer.json fields lost")
	}

	if _, err := records.New(d).GetProvenance(ctx, "composer", "matchory-internal/foo", "1.2.0", wantRef); err != nil {
		t.Fatalf("provenance: %v", err)
	}
	if got := keys(t, d, "audit/"); len(got) != 1 {
		t.Fatalf("audit records: %v", got)
	}
	for _, k := range keys(t, d, "composer/") {
		if err := storage.ValidKey(k); err != nil {
			t.Fatal(err)
		}
	}

	art, err := s.Dist(ctx, "matchory-internal/foo", "1.2.0", wantRef)
	if err != nil {
		t.Fatal(err)
	}
	defer art.Body.Close()
	got, _ := io.ReadAll(art.Body)
	if !bytes.Equal(got, data) || art.Size != int64(len(data)) || art.SHA1 != hex.EncodeToString(sha1sum[:]) {
		t.Fatal("dist bytes/size/sha1 mismatch")
	}
	// the spelling of the version does not matter, the reference does
	if a, err := s.Dist(ctx, "matchory-internal/foo", "v1.2.0", wantRef); err != nil {
		t.Fatalf("v-prefixed: %v", err)
	} else {
		a.Body.Close()
	}
	if _, err := s.Dist(ctx, "matchory-internal/foo", "1.2.0", wantRef[:63]+"0"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("wrong reference: %v", err)
	}
	if _, err := s.Dist(ctx, "matchory-internal/foo", "9.9.9", wantRef); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("wrong version: %v", err)
	}
}

func TestVersionsUnknown(t *testing.T) {
	s, _ := newSource(t)
	for _, n := range []string{"matchory-internal/nope", "not a name"} {
		if _, err := s.Versions(context.Background(), n); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("%q: %v", n, err)
		}
	}
}

func TestUploadRejects(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name, pkg, version string
		data               []byte
		wantUpload         bool
		wantArchive        bool
	}{
		{"name mismatch", "matchory-internal/foo", "1.0.0", pkgZip(t, `{"name":"matchory-internal/bar"}`), true, false},
		{"invalid url name", "nope", "1.0.0", pkgZip(t, fooJSON), true, false},
		{"invalid version", "matchory-internal/foo", "banana", pkgZip(t, fooJSON), true, false},
		{"dev version", "matchory-internal/foo", "1.0.x-dev", pkgZip(t, fooJSON), true, false},
		{"dev branch", "matchory-internal/foo", "dev-main", pkgZip(t, fooJSON), true, false},
		{"no composer.json", "matchory-internal/foo", "1.0.0", zipOf(t, map[string]string{"a": "b"}), true, false},
		{"bad composer.json", "matchory-internal/foo", "1.0.0", pkgZip(t, `{`), true, false},
		{"version mismatch", "matchory-internal/foo", "1.0.0", pkgZip(t, `{"name":"matchory-internal/foo","version":"2.0.0"}`), true, false},
		{"not a zip", "matchory-internal/foo", "1.0.0", []byte("nope"), false, true},
		{"too big", "matchory-internal/foo", "1.0.0", make([]byte, 2<<20), false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, d := newSource(t)
			_, err := s.Upload(ctx, caller, tc.pkg, tc.version, tc.data)
			var ue *UploadError
			var ae *archive.Error
			if tc.wantUpload && !errors.As(err, &ue) || tc.wantArchive && !errors.As(err, &ae) {
				t.Fatalf("got %T %v", err, err)
			}
			if n := keys(t, d, ""); len(n) != 0 {
				t.Fatalf("stored something: %v", n)
			}
		})
	}
}

func TestUploadNameMismatch(t *testing.T) {
	s, d := newSource(t)
	_, err := s.Upload(context.Background(), caller, "matchory-internal/foo", "1.0.0", pkgZip(t, `{"name":"x/y"}`))
	var ue *UploadError
	if !errors.As(err, &ue) || ue.Reason != `composer.json name "x/y" does not match "matchory-internal/foo"` {
		t.Fatalf("got %v", err)
	}
	if n := keys(t, d, "composer/"); len(n) != 0 {
		t.Fatalf("stored: %v", n)
	}
}

func TestUploadMatchingVersionInComposerJSON(t *testing.T) {
	s, _ := newSource(t)
	v, err := s.Upload(context.Background(), caller, "matchory-internal/foo", "v1.0.0", pkgZip(t, `{"name":"matchory-internal/foo","version":"1.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	if v.Package["version"] != "v1.0.0" {
		t.Fatalf("version key must be the uploaded one: %v", v.Package["version"])
	}
}

func TestUploadDuplicate(t *testing.T) {
	s, _ := newSource(t)
	ctx := context.Background()
	if _, err := s.Upload(ctx, caller, "matchory-internal/foo", "1.2.0", pkgZip(t, fooJSON)); err != nil {
		t.Fatal(err)
	}
	// same normalised version, different spelling and bytes
	_, err := s.Upload(ctx, caller, "matchory-internal/foo", "v1.2", pkgZip(t, `{"name":"matchory-internal/foo","extra":1}`))
	if !errors.Is(err, ErrVersionExists) {
		t.Fatalf("got %v", err)
	}
}

func TestUploadConcurrentSameVersion(t *testing.T) {
	s, _ := newSource(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.Upload(ctx, caller, "matchory-internal/foo", "1.0.0", pkgZip(t, fooJSON))
		}()
	}
	wg.Wait()
	ok, exists := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrVersionExists):
			exists++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1 || exists != 1 {
		t.Fatalf("ok=%d exists=%d", ok, exists)
	}
	vs, err := s.Versions(ctx, "matchory-internal/foo")
	if err != nil || len(vs) != 1 {
		t.Fatalf("%v %v", vs, err)
	}
}

func TestUploadConcurrentDifferentVersions(t *testing.T) {
	s, _ := newSource(t)
	ctx := context.Background()
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.Upload(ctx, caller, "matchory-internal/foo", fmt.Sprintf("1.%d.0", i), pkgZip(t, fooJSON))
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	vs, err := s.Versions(ctx, "matchory-internal/foo")
	if err != nil || len(vs) != n {
		t.Fatalf("want %d versions, got %d (%v)", n, len(vs), err)
	}
	if vs[0].Version != "1.7.0" || vs[n-1].Version != "1.0.0" {
		t.Fatalf("not sorted descending: %s ... %s", vs[0].Version, vs[n-1].Version)
	}
}

func TestVersionsSortOrder(t *testing.T) {
	s, _ := newSource(t)
	ctx := context.Background()
	for _, v := range []string{"1.9.0", "1.10.0", "2.0.0-beta1", "1.10.0-RC1", "2.0.0"} {
		if _, err := s.Upload(ctx, caller, "matchory-internal/foo", v, pkgZip(t, fooJSON)); err != nil {
			t.Fatal(err)
		}
	}
	vs, _ := s.Versions(ctx, "matchory-internal/foo")
	var got []string
	for _, v := range vs {
		got = append(got, v.Version)
	}
	want := []string{"2.0.0", "2.0.0-beta1", "1.10.0", "1.10.0-RC1", "1.9.0"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestRebuildIndex(t *testing.T) {
	s, d := newSource(t)
	ctx := context.Background()
	for _, v := range []string{"1.0.0", "2.0.0-beta1"} {
		if _, err := s.Upload(ctx, caller, "matchory-internal/foo", v, pkgZip(t, fooJSON)); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := s.Versions(ctx, "matchory-internal/foo")
	if err := d.Delete(ctx, "composer/matchory-internal/foo/index.json"); err != nil {
		t.Fatal(err)
	}
	after, err := s.Versions(ctx, "matchory-internal/foo")
	if err != nil || len(after) != 2 {
		t.Fatalf("%v %v", after, err)
	}
	for i := range before {
		if before[i].Version != after[i].Version || before[i].Reference != after[i].Reference ||
			before[i].Package["version_normalized"] != after[i].Package["version_normalized"] {
			t.Fatalf("rebuilt entry differs:\n%+v\n%+v", before[i], after[i])
		}
	}
	// the rebuilt index is persisted and later uploads extend it
	if _, err := s.Upload(ctx, caller, "matchory-internal/foo", "3.0.0", pkgZip(t, fooJSON)); err != nil {
		t.Fatal(err)
	}
	if vs, _ := s.Versions(ctx, "matchory-internal/foo"); len(vs) != 3 {
		t.Fatalf("got %d", len(vs))
	}
}

func TestUploadAfterIndexLoss(t *testing.T) {
	s, d := newSource(t)
	ctx := context.Background()
	s.Upload(ctx, caller, "matchory-internal/foo", "1.0.0", pkgZip(t, fooJSON))
	d.Delete(ctx, "composer/matchory-internal/foo/index.json")
	if _, err := s.Upload(ctx, caller, "matchory-internal/foo", "1.1.0", pkgZip(t, fooJSON)); err != nil {
		t.Fatal(err)
	}
	if vs, _ := s.Versions(ctx, "matchory-internal/foo"); len(vs) != 2 {
		t.Fatalf("index must keep the earlier version, got %d", len(vs))
	}
}

func TestPackages(t *testing.T) {
	s, _ := newSource(t)
	ctx := context.Background()
	s.Upload(ctx, caller, "matchory-internal/foo", "1.0.0", pkgZip(t, fooJSON))
	s.Upload(ctx, caller, "matchory-internal/bar", "1.0.0", pkgZip(t, `{"name":"matchory-internal/bar"}`))
	names, enumerable, err := s.Packages(ctx)
	if err != nil || !enumerable || fmt.Sprint(names) != "[matchory-internal/bar matchory-internal/foo]" {
		t.Fatalf("%v %v %v", names, enumerable, err)
	}
	if s.Type() != "storage" || s.Name() != "internal" || fmt.Sprint(s.Claims()) != "[matchory-internal/*]" {
		t.Fatal("identity")
	}
}
