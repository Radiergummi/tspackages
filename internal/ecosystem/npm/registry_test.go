package npm

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // npm's shasum is sha1; tests build fixtures with it
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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

// fakeNPM serves packuments, tarballs, keys and attestations by escaped
// path.
type fakeNPM struct {
	srv      *httptest.Server
	mu       sync.Mutex
	bodies   map[string][]byte
	handlers map[string]http.HandlerFunc
	status   int // when not 0, every request answers it
	hits     map[string]int
	accept   map[string]string
}

func newFakeNPM(t *testing.T) *fakeNPM {
	t.Helper()
	f := &fakeNPM{bodies: map[string][]byte{}, handlers: map[string]http.HandlerFunc{}, hits: map[string]int{}, accept: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.EscapedPath()
		f.mu.Lock()
		f.hits[p]++
		f.accept[p] = r.Header.Get("Accept")
		status, h := f.status, f.handlers[p]
		body, ok := f.bodies[p]
		f.mu.Unlock()
		switch {
		case status != 0:
			http.Error(w, "down", status)
		case h != nil:
			h(w, r)
		case ok:
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNPM) set(path string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies[path] = body
}

func (f *fakeNPM) handle(path string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[path] = h
}

func (f *fakeNPM) setStatus(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = code
}

func (f *fakeNPM) acceptOf(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accept[path]
}

func (f *fakeNPM) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

type npmEnv struct {
	up    *fakeNPM
	src   *RegistrySource
	cache *storage.Cache
	relay *relay.Relay
	rec   *records.Store
	clock time.Time
	tmp   string // the source's tmpDir
}

// wantTmpEmpty fails t when a refresh left files in the source's tmpDir.
func (e *npmEnv) wantTmpEmpty(t *testing.T) {
	t.Helper()
	ents, err := os.ReadDir(e.tmp)
	if err != nil || len(ents) != 0 {
		t.Fatalf("tmpDir holds %v (%v)", ents, err)
	}
}

func newNPMEnv(t *testing.T) *npmEnv {
	t.Helper()
	up := newFakeNPM(t)
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
	c := upstream.New(upstream.Options{FetchHosts: []string{"127.0.0.1", "registry.npmjs.org"}, AllowPrivateForTesting: true})
	tmp := t.TempDir()
	e := &npmEnv{up: up, cache: cache, relay: rl, rec: rec, clock: time.Now(), tmp: tmp}
	e.src = NewRegistrySource("npmjs", []string{"*"}, up.srv.URL+"/", c, cache, rl, rec, time.Minute, 1<<20, nil, tmp, slog.New(slog.DiscardHandler))
	e.src.now = func() time.Time { return e.clock }
	return e
}

func mustName(t *testing.T, s string) Name {
	t.Helper()
	n, err := ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func sriSHA512(b []byte) string {
	s := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}
func hexSHA512(b []byte) string { s := sha512.Sum512(b); return hex.EncodeToString(s[:]) }
func hexSHA1(b []byte) string   { s := sha1.Sum(b); return hex.EncodeToString(s[:]) } //nolint:gosec // npm shasum
func hexSHA256(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// version is an upstream version object whose tarball, at file on the fake
// upstream, is body.
func (e *npmEnv) version(name, v, file string, body []byte) map[string]any {
	e.up.set("/"+name+"/-/"+file, body)
	return map[string]any{
		"name": name, "version": v, "description": "d",
		"dist": map[string]any{
			"tarball": e.up.srv.URL + "/" + name + "/-/" + file, "integrity": sriSHA512(body), "shasum": hexSHA1(body),
		},
	}
}

// packument is an upstream packument of versions (by their "version").
func packument(name string, tags map[string]string, times map[string]string, versions ...map[string]any) []byte {
	vs := map[string]any{}
	for _, v := range versions {
		vs[v["version"].(string)] = v
	}
	doc := map[string]any{"_id": name, "name": name, "versions": vs, "dist-tags": tags, "readme": "long"}
	if times != nil {
		doc["time"] = times
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return b
}

// readDoc returns a reader of a Packument result that fails t on error.
func readDoc(t *testing.T) func(Doc, error) []byte {
	return func(d Doc, err error) []byte {
		t.Helper()
		return readDocBody(t, d, err)
	}
}

func readDocBody(t *testing.T, d Doc, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Body.Close()
	b, err := io.ReadAll(d.Body)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) != d.Size {
		t.Fatalf("size %d, read %d bytes", d.Size, len(b))
	}
	return b
}

func readArtifact(a Artifact, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	defer a.Body.Close()
	return io.ReadAll(a.Body)
}

func TestPackumentPassThrough(t *testing.T) {
	e := newNPMEnv(t)
	for _, tc := range []struct{ fixture, name, path string }{
		{"left-pad", "left-pad", "/left-pad"},
		{"scoped", "@acme/widget", "/@acme%2fwidget"},
	} {
		raw, err := os.ReadFile(filepath.Join("testdata", "packument-"+tc.fixture+".json"))
		if err != nil {
			t.Fatal(err)
		}
		e.up.set(tc.path, raw)
		n := mustName(t, tc.name)
		for kind, corgi := range map[string]bool{"full": false, "corgi": true} {
			d, err := e.src.Packument(context.Background(), n, corgi)
			stored := readDoc(t)(d, err)
			if d.SHA256 != hexSHA256(stored) {
				t.Errorf("%s %s: SHA256 %s is not of the stored bytes", tc.name, kind, d.SHA256)
			}
			if want := bytes.Count(stored, []byte(BaseToken)); d.Tokens != want || want == 0 {
				t.Errorf("%s %s: Tokens = %d, stored has %d", tc.name, kind, d.Tokens, want)
			}
			got := indent(t, expandAll(t, stored))
			want, err := os.ReadFile(filepath.Join("testdata", "packument-"+tc.fixture+"."+kind+".golden.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s %s differs from the golden:\n%s", tc.name, kind, got)
			}
		}
		if n := e.up.count(tc.path); n != 1 {
			t.Errorf("%s fetched %d times", tc.name, n)
		}
		if a := e.up.acceptOf(tc.path); a != "application/json" {
			t.Errorf("Accept = %q", a)
		}
	}

	n := mustName(t, "left-pad")
	tags, err := e.src.DistTags(context.Background(), n)
	if err != nil || len(tags) != 1 || tags["latest"] != "1.3.0" {
		t.Fatalf("tags = %v, %v", tags, err)
	}
	full := readDoc(t)(e.src.Packument(context.Background(), n, false))
	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(expandAll(t, full), &doc); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"1.3.0", "latest"} {
		v, err := e.src.Version(context.Background(), n, spec)
		if err != nil {
			t.Fatalf("Version(%s): %v", spec, err)
		}
		if got := expandAll(t, v); !bytes.Equal(got, doc.Versions["1.3.0"]) {
			t.Errorf("Version(%s) = %s, want %s", spec, got, doc.Versions["1.3.0"])
		}
	}
	if _, err := e.src.Version(context.Background(), n, "9.9.9"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("absent version: %v", err)
	}
	if _, err := e.src.Packument(context.Background(), mustName(t, "nope"), false); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("absent package: %v", err)
	}
}

func TestTarballVerifiedAndCached(t *testing.T) {
	e := newNPMEnv(t)
	body := []byte("TARBALL-BYTES")
	e.up.set("/left-pad", packument("left-pad", map[string]string{"latest": "1.0.0"}, nil, e.version("left-pad", "1.0.0", "left-pad-1.0.0.tgz", body)))
	n := mustName(t, "left-pad")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Go(func() {
			got, err := readArtifact(e.src.Tarball(context.Background(), n, "left-pad-1.0.0.tgz"))
			if err == nil && !bytes.Equal(got, body) {
				err = fmt.Errorf("got %q", got)
			}
			errs[i] = err
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if c := e.up.count("/left-pad/-/left-pad-1.0.0.tgz"); c != 1 {
		t.Fatalf("tarball fetched %d times", c)
	}
	e.relay.Wait()
	p, err := e.rec.GetProvenance(context.Background(), "npm", "left-pad", "1.0.0", hexSHA256(body))
	if err != nil {
		t.Fatal(err)
	}
	if p.DeclaredDigest != "sha512:"+hexSHA512(body) || p.SHA1 != hexSHA1(body) || p.Source != "npmjs" || p.SourceType != "registry" ||
		p.UpstreamURL != e.up.srv.URL+"/left-pad/-/left-pad-1.0.0.tgz" {
		t.Fatalf("provenance = %+v", p)
	}
	if _, _, err := e.cache.Open(context.Background(), "npm/npmjs/tarballs/sha512-"+hexSHA512(body)); err != nil {
		t.Fatalf("cache: %v", err)
	}
	if _, err := e.src.Tarball(context.Background(), n, "left-pad-9.9.9.tgz"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("unlisted file: %v", err)
	}
}

func TestTamperedTarball(t *testing.T) {
	e := newNPMEnv(t)
	declared := []byte("declared")
	e.up.set("/left-pad", packument("left-pad", nil, nil, e.version("left-pad", "1.0.0", "left-pad-1.0.0.tgz", declared)))
	e.up.set("/left-pad/-/left-pad-1.0.0.tgz", []byte("tampered"))
	n := mustName(t, "left-pad")
	if _, err := readArtifact(e.src.Tarball(context.Background(), n, "left-pad-1.0.0.tgz")); !errors.Is(err, relay.ErrDigestMismatch) {
		t.Fatalf("err = %v", err)
	}
	e.relay.Wait()
	if _, _, err := e.cache.Open(context.Background(), "npm/npmjs/tarballs/sha512-"+hexSHA512(declared)); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("cached: %v", err)
	}
	if ds, err := e.rec.ProvenanceDigests(context.Background(), "npm", "left-pad", "1.0.0"); err != nil || len(ds) != 0 {
		t.Fatalf("provenance %v %v", ds, err)
	}
}

func TestSHA1OnlyVersion(t *testing.T) {
	e := newNPMEnv(t)
	body := []byte("OLD-TARBALL")
	v := e.version("left-pad", "0.0.1", "left-pad-0.0.1.tgz", body)
	delete(v["dist"].(map[string]any), "integrity")
	e.up.set("/left-pad", packument("left-pad", nil, nil, v))
	got, err := readArtifact(e.src.Tarball(context.Background(), mustName(t, "left-pad"), "left-pad-0.0.1.tgz"))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("%q %v", got, err)
	}
	e.relay.Wait()
	if _, _, err := e.cache.Open(context.Background(), "npm/npmjs/tarballs/sha1-"+hexSHA1(body)); err != nil {
		t.Fatalf("cache: %v", err)
	}
	p, err := e.rec.GetProvenance(context.Background(), "npm", "left-pad", "0.0.1", hexSHA256(body))
	if err != nil || p.DeclaredDigest != "sha1:"+hexSHA1(body) {
		t.Fatalf("provenance %+v %v", p, err)
	}
}

// docParts decodes an expanded document's versions, dist-tags and time.
func docParts(t *testing.T, stored []byte) (versions []string, tags, times map[string]string) {
	t.Helper()
	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
		Tags     map[string]string          `json:"dist-tags"`
		Time     map[string]string          `json:"time"`
	}
	if err := json.Unmarshal(expandAll(t, stored), &doc); err != nil {
		t.Fatalf("%v\n%s", err, stored)
	}
	for v := range doc.Versions {
		versions = append(versions, v)
	}
	slices.Sort(versions)
	return versions, doc.Tags, doc.Time
}

func TestDroppedVersions(t *testing.T) {
	e := newNPMEnv(t)
	good := e.version("left-pad", "1.0.0", "left-pad-1.0.0.tgz", []byte("A"))
	noDigest := e.version("left-pad", "1.0.1", "left-pad-1.0.1.tgz", []byte("B"))
	delete(noDigest["dist"].(map[string]any), "integrity")
	delete(noDigest["dist"].(map[string]any), "shasum")
	wrongKey := e.version("left-pad", "1.0.3", "left-pad-1.0.3.tgz", []byte("C"))
	foreign := e.version("left-pad", "1.0.4", "left-pad-1.0.4.tgz", []byte("D"))
	foreign["name"] = "right-pad"
	offHost := e.version("left-pad", "1.0.5", "left-pad-1.0.5.tgz", []byte("E"))
	offHost["dist"].(map[string]any)["tarball"] = "https://evil.example/left-pad-1.0.5.tgz"
	huge := e.version("left-pad", "1.0.6", "left-pad-1.0.6.tgz", []byte("F"))
	huge["description"] = strings.Repeat("x", MaxVersionBytes+1)
	times := map[string]string{"created": "c", "modified": "m", "0.9.0": "unpublished", "1.0.0": "t0", "1.0.1": "t1",
		"1.0.2": "t2", "1.0.4": "t4", "1.0.5": "t5", "1.0.6": "t6"}
	tags := map[string]string{"latest": "1.0.0", "beta": "1.0.1", "rc": "1.0.2", "next": "1.0.6", "gone": "7.0.0"}
	raw := packument("left-pad", tags, times, good, noDigest, foreign, offHost, huge)
	// Key 1.0.2 holds the object of 1.0.3.
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	doc["versions"].(map[string]any)["1.0.2"] = wrongKey
	raw, _ = json.Marshal(doc)
	e.up.set("/left-pad", raw)

	n := mustName(t, "left-pad")
	for _, corgi := range []bool{false, true} {
		vs, gotTags, gotTimes := docParts(t, readDoc(t)(e.src.Packument(context.Background(), n, corgi)))
		if !slices.Equal(vs, []string{"1.0.0"}) {
			t.Errorf("corgi=%v: versions = %v", corgi, vs)
		}
		if len(gotTags) != 1 || gotTags["latest"] != "1.0.0" {
			t.Errorf("corgi=%v: tags = %v", corgi, gotTags)
		}
		wantTimes := map[string]string{"created": "c", "modified": "m", "0.9.0": "unpublished", "1.0.0": "t0"}
		if fmt.Sprint(gotTimes) != fmt.Sprint(wantTimes) {
			t.Errorf("corgi=%v: time = %v", corgi, gotTimes)
		}
	}
	for _, v := range []string{"1.0.1", "1.0.2", "1.0.4", "1.0.5", "1.0.6"} {
		if _, err := e.src.Tarball(context.Background(), n, n.TarballFile(v)); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("tarball of dropped %s: %v", v, err)
		}
	}
}

func TestFileNameCollision(t *testing.T) {
	e := newNPMEnv(t)
	// 1.0.1's upstream file is named like 1.0.0's canonical one; 2.0.0 and
	// 2.0.1 share an alias.
	a := e.version("left-pad", "1.0.0", "left-pad-1.0.0.tgz", []byte("A"))
	b := e.version("left-pad", "1.0.1", "left-pad-1.0.0.tgz", []byte("A"))
	c := e.version("left-pad", "2.0.0", "shared.tgz", []byte("C"))
	d := e.version("left-pad", "2.0.1", "shared.tgz", []byte("C"))
	ok := e.version("left-pad", "3.0.0", "left-pad-3.0.0.tgz", []byte("OK"))
	e.up.set("/left-pad", packument("left-pad", map[string]string{"latest": "3.0.0"}, nil, a, b, c, d, ok))
	n := mustName(t, "left-pad")
	for _, corgi := range []bool{false, true} {
		if vs, _, _ := docParts(t, readDoc(t)(e.src.Packument(context.Background(), n, corgi))); !slices.Equal(vs, []string{"3.0.0"}) {
			t.Errorf("corgi=%v: versions = %v", corgi, vs)
		}
	}
	for _, f := range []string{"left-pad-1.0.0.tgz", "left-pad-1.0.1.tgz", "shared.tgz", "left-pad-2.0.0.tgz"} {
		if _, err := e.src.Tarball(context.Background(), n, f); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("%s: %v", f, err)
		}
	}
	if got, err := readArtifact(e.src.Tarball(context.Background(), n, "left-pad-3.0.0.tgz")); err != nil || string(got) != "OK" {
		t.Errorf("3.0.0: %q %v", got, err)
	}
}

func TestAliasFileName(t *testing.T) {
	e := newNPMEnv(t)
	body := []byte("LEGACY")
	e.up.set("/left-pad", packument("left-pad", nil, nil, e.version("left-pad", "1.0.0", "left-pad-1.0.0-legacy.tgz", body)))
	n := mustName(t, "left-pad")
	for _, f := range []string{"left-pad-1.0.0-legacy.tgz", "left-pad-1.0.0.tgz"} {
		if got, err := readArtifact(e.src.Tarball(context.Background(), n, f)); err != nil || !bytes.Equal(got, body) {
			t.Errorf("%s: %q %v", f, got, err)
		}
	}
	stored := readDoc(t)(e.src.Packument(context.Background(), n, false))
	if !bytes.Contains(expandAll(t, stored), []byte(`"tarball":"https://tsp.example/npm/left-pad/-/left-pad-1.0.0.tgz"`)) {
		t.Errorf("served tarball URL is not canonical:\n%s", stored)
	}
}

// Review Focus 1: an unpublished package is a definite, cached miss.
func TestUnpublishedIsMiss(t *testing.T) {
	e := newNPMEnv(t)
	e.up.set("/x", []byte(`{"name":"x","time":{"unpublished":{}}}`))
	e.up.set("/y", []byte(`{"name":"y","versions":{},"time":{"modified":"m"}}`))
	for _, name := range []string{"x", "y"} {
		for range 2 {
			if _, err := e.src.Packument(context.Background(), mustName(t, name), false); !errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if c := e.up.count("/" + name); c != 1 {
			t.Fatalf("%s fetched %d times", name, c)
		}
	}
}

func TestStaleOnError(t *testing.T) {
	e := newNPMEnv(t)
	e.up.set("/left-pad", packument("left-pad", nil, nil, e.version("left-pad", "1.0.0", "left-pad-1.0.0.tgz", []byte("A"))))
	n := mustName(t, "left-pad")
	first := readDoc(t)(e.src.Packument(context.Background(), n, false))
	if h := e.src.Health(context.Background()); !h[0].OK {
		t.Fatalf("health = %+v", h)
	}
	e.up.setStatus(http.StatusInternalServerError)
	e.clock = e.clock.Add(time.Hour)
	stale := readDoc(t)(e.src.Packument(context.Background(), n, false))
	if !bytes.Equal(stale, first) {
		t.Fatal("stale document differs")
	}
	if c := e.up.count("/left-pad"); c != 2 {
		t.Fatalf("fetched %d times; the expired copy must be refreshed", c)
	}
	if h := e.src.Health(context.Background()); h[0].OK || h[0].Detail != "serving stale" || h[0].Ecosystem != "npm" {
		t.Fatalf("health = %+v", h)
	}
	if _, err := e.src.Packument(context.Background(), mustName(t, "uncached"), false); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("uncached while down: %v", err)
	}
}

// serveStream answers with what gen writes.
func serveStream(gen func(w io.Writer)) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		gen(w)
	}
}

func wantBadGateway(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil || errors.Is(err, resolve.ErrNotFound) || resolve.HTTPStatus(resolve.Wrap("npmjs", err)) != http.StatusBadGateway {
		t.Fatalf("%s: err = %v", what, err)
	}
}

func TestCaps(t *testing.T) {
	e := newNPMEnv(t)
	e.up.handle("/many", serveStream(func(w io.Writer) {
		io.WriteString(w, `{"name":"many","versions":{`)
		for i := range maxVersions + 1 {
			if i > 0 {
				io.WriteString(w, ",")
			}
			fmt.Fprintf(w, `"0.0.%d":{}`, i)
		}
		io.WriteString(w, `}}`)
	}))
	_, err := e.src.Packument(context.Background(), mustName(t, "many"), false)
	wantBadGateway(t, "too many versions", err)

	deep := func(levels int) []byte {
		return fmt.Appendf(nil, `{"name":"deep","versions":{"1.0.0":{}},"x":%s%s}`, strings.Repeat("[", levels), strings.Repeat("]", levels))
	}
	e.up.set("/deep", deep(64)) // 65 levels with the document itself
	_, err = e.src.Packument(context.Background(), mustName(t, "deep"), false)
	wantBadGateway(t, "nesting 65", err)
	e.up.set("/deep", deep(63))
	e.clock = e.clock.Add(time.Hour)
	if _, err := e.src.Packument(context.Background(), mustName(t, "deep"), false); err != nil {
		t.Fatalf("nesting 64: %v", err)
	}
	e.up.set("/longkey", []byte(`{"name":"longkey","versions":{"1.0.0":{}},"`+strings.Repeat("k", maxKeyBytes+1)+`":1}`))
	_, err = e.src.Packument(context.Background(), mustName(t, "longkey"), false)
	wantBadGateway(t, "long key", err)
	for _, name := range []string{"many", "longkey"} {
		if _, _, err := e.cache.Open(context.Background(), e.src.key(mustName(t, name), "files.json")); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("%s cached: %v", name, err)
		}
	}
}

// TestCapsMemory streams a 200 MiB packument: an 80 MiB readme, 100 MiB in
// oversized versions and 20 MiB in versions within the per-version cap.
func TestCapsMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("streams 200 MiB")
	}
	e := newNPMEnv(t)
	chunk := bytes.Repeat([]byte("x"), 1<<20)
	e.up.handle("/big", serveStream(func(w io.Writer) {
		io.WriteString(w, `{"name":"big","readme":"`)
		for range 80 {
			w.Write(chunk)
		}
		io.WriteString(w, `","versions":{`)
		for i := range 20 {
			fmt.Fprintf(w, `"1.0.%d":{"name":"big","version":"1.0.%d","dist":{"shasum":"%s","tarball":"%s/big/-/big-1.0.%d.tgz"},"description":"`,
				i, i, strings.Repeat("a", 40), e.up.srv.URL, i)
			w.Write(chunk)
			io.WriteString(w, `"},`)
		}
		for i := range 20 {
			fmt.Fprintf(w, `"2.0.%d":{"name":"big","version":"2.0.%d","description":"`, i, i)
			for range 5 {
				w.Write(chunk)
			}
			io.WriteString(w, `"},`)
		}
		io.WriteString(w, `"3.0.0":{}},"dist-tags":{"latest":"1.0.19"}}`)
	}))
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	done := make(chan struct{})
	peak := make(chan uint64)
	go func() {
		var maxHeap uint64
		var m runtime.MemStats
		for {
			select {
			case <-done:
				peak <- maxHeap
				return
			case <-time.After(5 * time.Millisecond):
				runtime.ReadMemStats(&m)
				maxHeap = max(maxHeap, m.HeapAlloc)
			}
		}
	}()
	d, err := e.src.Packument(context.Background(), mustName(t, "big"), true)
	close(done)
	if err == nil {
		if vs, tags, _ := docParts(t, readDocBody(t, d, nil)); len(vs) != 20 || tags["latest"] != "1.0.19" {
			t.Errorf("versions %v, tags %v", vs, tags)
		}
	}
	growth := int64(<-peak) - int64(base.HeapAlloc)
	if err != nil {
		t.Fatal(err)
	}
	if growth > 64<<20 {
		t.Fatalf("heap grew by %d MiB", growth>>20)
	}
	t.Logf("heap growth %d MiB", growth>>20)
}

func TestChangedTarball(t *testing.T) {
	e := newNPMEnv(t)
	body := []byte("NOW")
	old := strings.Repeat("0", 64)
	other := strings.Repeat("1", 64)
	for _, p := range []records.Provenance{
		{Ecosystem: "npm", Package: "a", Version: "1.0.0", Source: "npmjs", SourceType: "registry", SHA256: old, Created: time.Now().Add(-time.Hour)},
		{Ecosystem: "npm", Package: "b", Version: "1.0.0", Source: "elsewhere", SourceType: "registry", SHA256: other, Created: time.Now().Add(-time.Hour)},
	} {
		if err := e.rec.PutProvenance(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	e.up.set("/a", packument("a", nil, nil, e.version("a", "1.0.0", "a-1.0.0.tgz", body)))
	e.up.set("/b", packument("b", nil, nil, e.version("b", "1.0.0", "b-1.0.0.tgz", append([]byte("B"), body...))))
	for _, name := range []string{"a", "b"} {
		if _, err := readArtifact(e.src.Tarball(context.Background(), mustName(t, name), name+"-1.0.0.tgz")); err != nil {
			t.Fatalf("%s: changed bytes must still be served: %v", name, err)
		}
	}
	e.relay.Wait()
	got := e.src.Changed()
	if len(got) != 1 {
		t.Fatalf("changed = %+v", got)
	}
	c := got[0]
	if c.Package != "a" || c.Version != "1.0.0" || c.Source != "npmjs" || c.FirstSHA256 != old || c.NowSHA256 != hexSHA256(body) || c.Seen.IsZero() {
		t.Fatalf("changed = %+v", c)
	}
}

func TestKeysCached(t *testing.T) {
	e := newNPMEnv(t)
	if _, err := e.src.Keys(context.Background()); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("no upstream keys: %v", err)
	}
	keys := []byte(`{"keys":[{"keyid":"SHA256:x"}]}`)
	e.up.set("/-/npm/v1/keys", keys)
	for range 2 {
		if got, err := readArtifact(e.src.Keys(context.Background())); err != nil || !bytes.Equal(got, keys) {
			t.Fatalf("%q %v", got, err)
		}
	}
	if c := e.up.count("/-/npm/v1/keys"); c != 2 {
		t.Fatalf("keys fetched %d times (one miss, then one fetch cached for ttl)", c)
	}
	e.up.setStatus(http.StatusBadGateway)
	e.clock = e.clock.Add(time.Hour)
	if got, err := readArtifact(e.src.Keys(context.Background())); err != nil || !bytes.Equal(got, keys) {
		t.Fatalf("stale keys: %q %v", got, err)
	}
}

func TestAttestationsRewritten(t *testing.T) {
	e := newNPMEnv(t)
	bundle := []byte(`{"attestations":[{"predicateType":"https://slsa.dev/provenance/v1"}]}`)
	e.up.set("/-/npm/v1/attestations/@acme%2fwidget@1.0.0", bundle)
	v := e.version("@acme/widget", "1.0.0", "widget-1.0.0.tgz", []byte("W"))
	v["dist"].(map[string]any)["attestations"] = map[string]any{
		"url": e.up.srv.URL + "/-/npm/v1/attestations/@acme%2fwidget@1.0.0", "provenance": map[string]string{"predicateType": "https://slsa.dev/provenance/v1"},
	}
	plain := e.version("@acme/widget", "1.0.1", "widget-1.0.1.tgz", []byte("X"))
	e.up.set("/@acme%2fwidget", packument("@acme/widget", nil, nil, v, plain))
	n := mustName(t, "@acme/widget")
	doc := expandAll(t, readDoc(t)(e.src.Packument(context.Background(), n, false)))
	if !bytes.Contains(doc, []byte(`"url":"https://tsp.example/npm/-/npm/v1/attestations/@acme/widget@1.0.0"`)) || bytes.Contains(doc, []byte(e.up.srv.URL)) {
		t.Fatalf("attestations url not rewritten:\n%s", doc)
	}
	for range 2 {
		if got, err := readArtifact(e.src.Attestations(context.Background(), n, "1.0.0")); err != nil || !bytes.Equal(got, bundle) {
			t.Fatalf("%q %v", got, err)
		}
	}
	e.relay.Wait()
	if c := e.up.count("/-/npm/v1/attestations/@acme%2fwidget@1.0.0"); c != 1 {
		t.Fatalf("attestations fetched %d times", c)
	}
	for _, version := range []string{"1.0.1", "9.9.9"} {
		if _, err := e.src.Attestations(context.Background(), n, version); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("%s: %v", version, err)
		}
	}
}

func TestRefreshLeavesTmpDirEmpty(t *testing.T) {
	e := newNPMEnv(t)
	e.up.set("/left-pad", packument("left-pad", nil, nil, e.version("left-pad", "1.0.0", "left-pad-1.0.0.tgz", []byte("A"))))
	readDoc(t)(e.src.Packument(context.Background(), mustName(t, "left-pad"), false))
	e.wantTmpEmpty(t)

	chunk := bytes.Repeat([]byte("x"), 1<<20)
	e.up.handle("/huge", serveStream(func(w io.Writer) {
		io.WriteString(w, `{"name":"huge","readme":"`)
		for range maxPackumentBytes>>20 + 1 {
			w.Write(chunk)
		}
		io.WriteString(w, `"}`)
	}))
	_, err := e.src.Packument(context.Background(), mustName(t, "huge"), false)
	wantBadGateway(t, "oversized packument", err)
	e.wantTmpEmpty(t)

	e.up.set("/bad", []byte(`{"name":"bad","versions":{"1.0.0":`))
	_, err = e.src.Packument(context.Background(), mustName(t, "bad"), false)
	wantBadGateway(t, "truncated packument", err)
	e.wantTmpEmpty(t)
}
