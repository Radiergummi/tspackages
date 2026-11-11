package pypi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/relay"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
)

func sum256(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// fakeIndex serves simple-API pages and files.
type fakeIndex struct {
	srv   *httptest.Server
	mu    sync.Mutex
	pages map[string][]byte // path → body
	types map[string]string // path → Content-Type
	down  bool
	hits  map[string]int
}

func newFakeIndex(t *testing.T) *fakeIndex {
	t.Helper()
	f := &fakeIndex{pages: map[string][]byte{}, types: map[string]string{}, hits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits[r.URL.Path]++
		if f.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		b, ok := f.pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if ct := f.types[r.URL.Path]; ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.Write(b)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIndex) set(path string, body []byte, contentType string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pages[path], f.types[path] = body, contentType
}

func (f *fakeIndex) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

// page is a PEP 691 project page with files of the given bodies (filename →
// bytes); extra fields are merged into the first file.
func (f *fakeIndex) page(name string, files map[string][]byte, extra map[string]any) []byte {
	var entries []map[string]any
	for fn, b := range files {
		e := map[string]any{
			"filename": fn, "url": f.srv.URL + "/files/" + fn, "hashes": map[string]string{"sha256": sum256(b)},
			"requires-python": ">=3.9", "yanked": false, "size": len(b), "upload-time": "2026-01-02T03:04:05.000000Z",
		}
		entries = append(entries, e)
		f.set("/files/"+fn, b, "application/octet-stream")
	}
	maps.Copy(entries[0], extra)
	doc, _ := json.Marshal(map[string]any{"meta": map[string]string{"api-version": "1.1"}, "name": name, "versions": []string{"1.0"}, "files": entries})
	return doc
}

type regEnv struct {
	idx   *fakeIndex
	src   *RegistrySource
	cache *storage.Cache
	rec   *records.Store
	clock time.Time
}

func newRegEnv(t *testing.T) *regEnv {
	t.Helper()
	idx := newFakeIndex(t)
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := storage.NewCache(context.Background(), d, 1<<30, nil)
	if err != nil {
		t.Fatal(err)
	}
	rl, err := relay.New(cache, filepath.Join(t.TempDir(), "relay"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rl.Wait) // the test's directories must outlast cache writes
	sd, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := records.New(sd)
	c := upstream.New(upstream.Options{FetchHosts: []string{"127.0.0.1"}, AllowPrivateForTesting: true})
	e := &regEnv{idx: idx, cache: cache, rec: rec, clock: time.Now()}
	e.src = NewRegistrySource("pypi", nil, idx.srv.URL+"/simple/", c, cache, rl, rec, time.Minute, 1<<20, nil, nil)
	e.src.now = func() time.Time { return e.clock }
	return e
}

func readAllArtifact(a Artifact, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	defer a.Body.Close()
	return io.ReadAll(a.Body)
}

const jsonCT = "application/vnd.pypi.simple.v1+json"

func TestRegistryProjectAllowlist(t *testing.T) {
	e := newRegEnv(t)
	wheel := []byte("WHEEL")
	page := e.idx.page("requests", map[string][]byte{"requests-2.0.0-py3-none-any.whl": wheel}, map[string]any{
		"core-metadata": map[string]string{"sha256": strings.Repeat("c", 64)}, "provenance": e.idx.srv.URL + "/prov", "data-extra": "x", "gpg-sig": true,
	})
	var doc map[string]any
	json.Unmarshal(page, &doc)
	doc["files"] = append(doc["files"].([]any),
		map[string]any{"filename": "requests-2.0.1.tar.gz", "url": e.idx.srv.URL + "/files/x", "hashes": map[string]string{"md5": "00"}},
		map[string]any{"filename": "requests-2.0.2.tar.gz", "url": "https://elsewhere.example/x", "hashes": map[string]string{"sha256": "aa"}},
		map[string]any{"filename": "other-1.0.tar.gz", "url": e.idx.srv.URL + "/files/y", "hashes": map[string]string{"sha256": "bb"}},
		map[string]any{"filename": "requests-2.0.3-py3-none-any#x.whl", "url": e.idx.srv.URL + "/files/z", "hashes": map[string]string{"sha256": strings.Repeat("d", 64)}},
	)
	doc["unknown-top-level"] = "x"
	page, _ = json.Marshal(doc)
	e.idx.set("/simple/requests/", page, jsonCT)
	p, err := e.src.Project(context.Background(), "requests")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Files) != 1 {
		t.Fatalf("files = %+v (no sha256, foreign host, other project and unsafe filename must be dropped)", p.Files)
	}
	f := p.Files[0]
	if f.Filename != "requests-2.0.0-py3-none-any.whl" || f.SHA256 != sum256(wheel) || f.RequiresPython != ">=3.9" ||
		f.CoreMetadata != strings.Repeat("c", 64) || !f.HasProvenance || f.Size != 5 || f.UploadTime.IsZero() || f.URL != "" {
		t.Fatalf("file = %+v", f)
	}
	if len(p.Versions) != 1 {
		t.Fatalf("versions = %v", p.Versions)
	}
}

// Review Focus 3: a 200 that is not the JSON simple API is a failed fetch.
func TestRegistryHTMLErrorPageIsAFailure(t *testing.T) {
	e := newRegEnv(t)
	e.idx.set("/simple/requests/", []byte("<html>maintenance</html>"), "text/html")
	if _, err := e.src.Project(context.Background(), "requests"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	good := e.idx.page("requests", map[string][]byte{"requests-1.0.tar.gz": []byte("S")}, nil)
	e.idx.set("/simple/requests/", good, jsonCT)
	if _, err := e.src.Project(context.Background(), "requests"); err != nil {
		t.Fatal(err)
	}
	e.clock = e.clock.Add(time.Hour)
	e.idx.set("/simple/requests/", []byte("<html>maintenance</html>"), "text/html")
	p, err := e.src.Project(context.Background(), "requests")
	if err != nil || len(p.Files) != 1 {
		t.Fatalf("stale copy not served: %+v %v", p, err)
	}
}

func TestRegistryNotFound(t *testing.T) {
	e := newRegEnv(t)
	if _, err := e.src.Project(context.Background(), "nope"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestRegistryFileVerifiedAndCached(t *testing.T) {
	e := newRegEnv(t)
	body := []byte("SDIST-BYTES")
	e.idx.set("/simple/requests/", e.idx.page("requests", map[string][]byte{"requests-1.0.tar.gz": body}, nil), jsonCT)
	for range 2 {
		got, err := readAllArtifact(e.src.File(context.Background(), "requests", "requests-1.0.tar.gz"))
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("%q %v", got, err)
		}
	}
	if n := e.idx.count("/files/requests-1.0.tar.gz"); n != 1 {
		t.Fatalf("file fetched %d times", n)
	}
	if _, err := e.rec.GetProvenance(context.Background(), "pypi", "requests", "1.0", sum256(body)); err != nil {
		t.Fatalf("provenance: %v", err)
	}
	if _, err := e.src.File(context.Background(), "requests", "requests-9.9.tar.gz"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("unlisted file: %v", err)
	}
}

func TestRegistryFileMismatch(t *testing.T) {
	e := newRegEnv(t)
	e.idx.set("/simple/requests/", e.idx.page("requests", map[string][]byte{"requests-1.0.tar.gz": []byte("declared")}, nil), jsonCT)
	e.idx.set("/files/requests-1.0.tar.gz", []byte("tampered"), "application/octet-stream")
	if _, err := readAllArtifact(e.src.File(context.Background(), "requests", "requests-1.0.tar.gz")); !errors.Is(err, relay.ErrDigestMismatch) {
		t.Fatalf("err = %v", err)
	}
	if _, err := readAllArtifact(e.src.File(context.Background(), "requests", "requests-1.0.tar.gz")); !errors.Is(err, relay.ErrDigestMismatch) {
		t.Fatalf("second read must refetch and fail again: %v", err)
	}
	if n := e.idx.count("/files/requests-1.0.tar.gz"); n != 2 {
		t.Fatalf("fetched %d times; a mismatching file must not be cached", n)
	}
}

func TestRegistryMetadataVerified(t *testing.T) {
	e := newRegEnv(t)
	meta := []byte("Metadata-Version: 2.1\nName: requests\n")
	whl := "requests-1.0-py3-none-any.whl"
	e.idx.set("/simple/requests/", e.idx.page("requests", map[string][]byte{whl: []byte("W")}, map[string]any{"core-metadata": map[string]string{"sha256": sum256(meta)}}), jsonCT)
	e.idx.set("/files/"+whl+".metadata", meta, "application/octet-stream")
	got, err := readAllArtifact(e.src.Metadata(context.Background(), "requests", whl))
	if err != nil || !bytes.Equal(got, meta) {
		t.Fatalf("%q %v", got, err)
	}
	e.idx.set("/simple/requests/", e.idx.page("requests", map[string][]byte{whl: []byte("W")}, map[string]any{"core-metadata": map[string]string{"sha256": strings.Repeat("0", 64)}}), jsonCT)
	e.clock = e.clock.Add(time.Hour)
	if _, err := readAllArtifact(e.src.Metadata(context.Background(), "requests", whl)); !errors.Is(err, relay.ErrDigestMismatch) {
		t.Fatalf("mismatching metadata: %v", err)
	}
}

func TestRegistryStaleOnUpstreamDown(t *testing.T) {
	e := newRegEnv(t)
	e.idx.set("/simple/requests/", e.idx.page("requests", map[string][]byte{"requests-1.0.tar.gz": []byte("S")}, nil), jsonCT)
	if _, err := e.src.Project(context.Background(), "requests"); err != nil {
		t.Fatal(err)
	}
	e.idx.mu.Lock()
	e.idx.down = true
	e.idx.mu.Unlock()
	e.clock = e.clock.Add(time.Hour)
	if _, err := e.src.Project(context.Background(), "requests"); err != nil {
		t.Fatalf("stale: %v", err)
	}
	if h := e.src.Health(context.Background()); h[0].OK || h[0].Detail != "serving stale" {
		t.Fatalf("health = %+v", h)
	}
	if _, err := e.src.Project(context.Background(), "uncached"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("uncached while down: %v", err)
	}
}
