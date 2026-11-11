package pypi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

var testLimits = archive.Limits{MaxBytes: 16 << 20, MaxDecompressed: 64 << 20, MaxEntries: 1000}

func metadataFor(name, version string, extra ...string) string {
	m := "Metadata-Version: 2.2\nName: " + name + "\nVersion: " + version + "\nRequires-Python: >=3.10\nRequires-Dist: requests\n"
	for _, e := range extra {
		m += e + "\n"
	}
	return m
}

// wheelOf builds a wheel whose dist-info directory holds METADATA.
func wheelOf(t *testing.T, name, version, metadata string) []byte {
	t.Helper()
	dist := name + "-" + version + ".dist-info/"
	return testutil.ZipOf(t, map[string]string{
		name + "/__init__.py": "", dist + "METADATA": metadata, dist + "WHEEL": "Wheel-Version: 1.0\n", dist + "RECORD": "",
	})
}

// sdistOf builds an sdist whose top directory holds PKG-INFO.
func sdistOf(t *testing.T, top, pkgInfo string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{top + "/PKG-INFO": pkgInfo, top + "/pyproject.toml": "[project]\n"} {
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

type storeEnv struct {
	src *StorageSource
	d   storage.Driver
	rec *records.Store
	dir string
}

func newStoreEnv(t *testing.T) *storeEnv {
	t.Helper()
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sd, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := records.New(sd)
	return &storeEnv{src: NewStorageSource("hosted", []string{"acme-*"}, d, rec, testLimits, nil), d: d, rec: rec, dir: t.TempDir()}
}

var uploader = identity.Caller{Login: "ci@example.com", NodeName: "ci", NodeStableID: "n1"}

func (e *storeEnv) upload(t *testing.T, name, version, filename string, content []byte, sha string) (File, error) {
	t.Helper()
	f, err := os.CreateTemp(e.dir, "up")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write(content)
	f.Seek(0, io.SeekStart)
	return e.src.Upload(context.Background(), uploader, Upload{Name: name, Version: version, Filename: filename, Content: f, Size: int64(len(content)), SHA256: sha})
}

func TestUploadWheelThenProject(t *testing.T) {
	e := newStoreEnv(t)
	meta := metadataFor("acme_core", "1.2.0")
	whl := wheelOf(t, "acme_core", "1.2.0", meta)
	fn := "acme_core-1.2.0-py3-none-any.whl"
	if _, err := e.upload(t, "acme-core", "1.2.0", fn, whl, sum256(whl)); err != nil {
		t.Fatal(err)
	}
	p, err := e.src.Project(context.Background(), "acme-core")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Files) != 1 {
		t.Fatalf("files = %+v", p.Files)
	}
	f := p.Files[0]
	if f.Filename != fn || f.SHA256 != sum256(whl) || f.RequiresPython != ">=3.10" || f.UploadTime.IsZero() ||
		f.Size != int64(len(whl)) || f.CoreMetadata != sum256([]byte(meta)) || f.HasProvenance {
		t.Fatalf("file = %+v", f)
	}
	got, err := readAllArtifact(e.src.Metadata(context.Background(), "acme-core", fn))
	if err != nil || string(got) != meta {
		t.Fatalf("metadata = %q %v", got, err)
	}
	got, err = readAllArtifact(e.src.File(context.Background(), "acme-core", fn))
	if err != nil || !bytes.Equal(got, whl) {
		t.Fatalf("file bytes: %v", err)
	}
	if _, err := e.rec.GetProvenance(context.Background(), "pypi", "acme-core", "1.2.0", sum256(whl)); err != nil {
		t.Fatalf("provenance: %v", err)
	}
	names, err := e.src.Names(context.Background())
	if err != nil || len(names) != 1 || names[0] != "acme-core" {
		t.Fatalf("names = %v %v", names, err)
	}
}

func TestUploadSdist(t *testing.T) {
	e := newStoreEnv(t)
	sd := sdistOf(t, "acme_core-1.0.0", metadataFor("acme-core", "1.0.0"))
	if _, err := e.upload(t, "acme-core", "1.0.0", "acme_core-1.0.0.tar.gz", sd, ""); err != nil {
		t.Fatal(err)
	}
	p, _ := e.src.Project(context.Background(), "acme-core")
	if len(p.Files) != 1 || p.Files[0].CoreMetadata == "" {
		t.Fatalf("sdist with static metadata 2.2: %+v", p.Files)
	}
}

func TestUploadRejections(t *testing.T) {
	e := newStoreEnv(t)
	whl := wheelOf(t, "acme_core", "1.0.0", metadataFor("acme-core", "1.0.0"))
	cases := []struct {
		name, form, version, filename string
		content                       []byte
		sha                           string
	}{
		{"form name differs from file", "acme-other", "1.0.0", "acme_core-1.0.0-py3-none-any.whl", whl, ""},
		{"filename version differs", "acme-core", "1.0.0", "acme_core-1.0.1-py3-none-any.whl", whl, ""},
		{"metadata name differs", "acme-x", "1.0.0", "acme_x-1.0.0-py3-none-any.whl", wheelOf(t, "acme_x", "1.0.0", metadataFor("acme-core", "1.0.0")), ""},
		{"metadata version differs", "acme-core", "2.0", "acme_core-2.0-py3-none-any.whl", wheelOf(t, "acme_core", "2.0", metadataFor("acme-core", "1.0.0")), ""},
		{"digest mismatch", "acme-core", "1.0.0", "acme_core-1.0.0-py3-none-any.whl", whl, sum256([]byte("other"))},
		{"zip sdist", "acme-core", "1.0.0", "acme_core-1.0.0.zip", whl, ""},
		{"not a wheel", "acme-core", "1.0.0", "acme_core-1.0.0-py3-none-any.whl", []byte("garbage"), ""},
		{"wheel without METADATA", "acme-core", "1.0.0", "acme_core-1.0.0-py3-none-any.whl", testutil.ZipOf(t, map[string]string{"a.py": ""}), ""},
	}
	for _, c := range cases {
		_, err := e.upload(t, c.form, c.version, c.filename, c.content, c.sha)
		if err == nil || errors.Is(err, ErrFileExists) || (!errors.As(err, new(*UploadError)) && !errors.As(err, new(*archive.Error))) {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
	if _, err := e.src.Project(context.Background(), "acme-core"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("a rejected upload left a project: %v", err)
	}
}

func TestUploadVersionMismatchCanonicalOK(t *testing.T) {
	e := newStoreEnv(t)
	whl := wheelOf(t, "acme_core", "1.0.0", metadataFor("acme-core", "1.0.0"))
	if _, err := e.upload(t, "acme-core", "1.0", "acme_core-1.0.0-py3-none-any.whl", whl, ""); err != nil {
		t.Fatalf("form 1.0 for file 1.0.0: %v", err)
	}
}

func TestUploadDuplicates(t *testing.T) {
	e := newStoreEnv(t)
	whl := wheelOf(t, "acme_core", "1.0.0", metadataFor("acme-core", "1.0.0"))
	if _, err := e.upload(t, "acme-core", "1.0.0", "acme_core-1.0.0-py3-none-any.whl", whl, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.upload(t, "acme-core", "1.0.0", "acme_core-1.0.0-py3-none-any.whl", whl, ""); !errors.Is(err, ErrFileExists) {
		t.Errorf("same filename, same bytes: %v", err)
	}
	whl2 := wheelOf(t, "acme_core", "1.0", metadataFor("acme-core", "1.0"))
	if _, err := e.upload(t, "acme-core", "1.0", "acme_core-1.0-py3-none-any.whl", whl2, ""); !errors.Is(err, ErrFileExists) {
		t.Errorf("same tags under another version spelling: %v", err)
	}
	other := wheelOf(t, "acme_core", "1.0.0", metadataFor("acme-core", "1.0.0"))
	if _, err := e.upload(t, "acme-core", "1.0.0", "acme_core-1.0.0-cp312-cp312-manylinux_2_28_x86_64.whl", other, ""); err != nil {
		t.Errorf("a wheel for another platform: %v", err)
	}
	sd := sdistOf(t, "acme_core-1.0.0", metadataFor("acme-core", "1.0.0"))
	if _, err := e.upload(t, "acme-core", "1.0.0", "acme_core-1.0.0.tar.gz", sd, ""); err != nil {
		t.Fatal(err)
	}
	sd2 := sdistOf(t, "acme_core-1.0", metadataFor("acme-core", "1.0"))
	if _, err := e.upload(t, "acme-core", "1.0", "acme_core-1.0.tar.gz", sd2, ""); !errors.Is(err, ErrFileExists) {
		t.Errorf("second sdist under another spelling: %v", err)
	}
	p, _ := e.src.Project(context.Background(), "acme-core")
	if len(p.Files) != 3 {
		t.Fatalf("files = %d", len(p.Files))
	}
}

func TestUploadConcurrentDifferentFiles(t *testing.T) {
	e := newStoreEnv(t)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range 8 {
		wg.Go(func() {
			v := fmt.Sprintf("1.%d.0", i)
			whl := wheelOf(t, "acme_core", v, metadataFor("acme-core", v))
			_, errs[i] = e.upload(t, "acme-core", v, "acme_core-"+v+"-py3-none-any.whl", whl, "")
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("upload %d: %v", i, err)
		}
	}
	p, err := e.src.Project(context.Background(), "acme-core")
	if err != nil || len(p.Files) != 8 {
		t.Fatalf("files = %d %v", len(p.Files), err)
	}
}

func TestUploadConcurrentSdistSpellings(t *testing.T) {
	e := newStoreEnv(t)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, v := range []string{"2.0", "2.0.0"} {
		wg.Go(func() {
			sd := sdistOf(t, "acme_core-"+v, metadataFor("acme-core", v))
			_, errs[i] = e.upload(t, "acme-core", v, "acme_core-"+v+".tar.gz", sd, "")
		})
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("exactly one sdist must win: %v", errs)
	}
}

func TestAttestationsStoredNotServed(t *testing.T) {
	e := newStoreEnv(t)
	whl := wheelOf(t, "acme_core", "1.0.0", metadataFor("acme-core", "1.0.0"))
	f, _ := os.CreateTemp(e.dir, "up")
	f.Write(whl)
	f.Seek(0, io.SeekStart)
	if _, err := e.src.Upload(context.Background(), uploader, Upload{Name: "acme-core", Version: "1.0.0", Filename: "acme_core-1.0.0-py3-none-any.whl", Content: f, Attestations: []byte(`[{"x":1}]`)}); err != nil {
		t.Fatal(err)
	}
	found := false
	for info, err := range e.d.List(context.Background(), "pypi/") {
		if err == nil && filepath.Ext(info.Key) == ".attestations" {
			found = true
		}
	}
	if !found {
		t.Error("attestations not stored")
	}
	if _, err := e.src.Provenance(context.Background(), "acme-core", "acme_core-1.0.0-py3-none-any.whl"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("attestations served: %v", err)
	}
}

func TestIndexRebuilt(t *testing.T) {
	e := newStoreEnv(t)
	for _, v := range []string{"1.0.0", "1.1.0"} {
		whl := wheelOf(t, "acme_core", v, metadataFor("acme-core", v))
		if _, err := e.upload(t, "acme-core", v, "acme_core-"+v+"-py3-none-any.whl", whl, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.d.Delete(context.Background(), "pypi/acme-core/index.json"); err != nil {
		t.Fatal(err)
	}
	p, err := e.src.Project(context.Background(), "acme-core")
	if err != nil || len(p.Files) != 2 {
		t.Fatalf("after losing the index: %d %v", len(p.Files), err)
	}
}
