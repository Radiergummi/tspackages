package maven

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

const (
	upJar   = "/com/matchory/lib/1.0/lib-1.0.jar"
	upAsc   = "/com/matchory/lib/1.0/lib-1.0.jar.asc"
	upMeta  = "/com/matchory/lib/maven-metadata.xml"
	jarData = "PK\x03\x04 jar bytes"
)

var upModified = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)

// fakeRepo is a Maven repository in Central's layout, serving bodies by
// path and recording every request.
type fakeRepo struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies map[string]string
	mods   map[string]time.Time // Last-Modified by path; upModified when unset
	status int                  // when not 0, every request answers it
	paths  []string
}

func newFakeRepo(t *testing.T) *fakeRepo {
	t.Helper()
	f := &fakeRepo{bodies: map[string]string{}, mods: map[string]time.Time{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.Method+" "+r.URL.EscapedPath())
		status := f.status
		body, ok := f.bodies[r.URL.EscapedPath()]
		mod, set := f.mods[r.URL.EscapedPath()]
		f.mu.Unlock()
		if !set {
			mod = upModified
		}
		switch {
		case status != 0:
			http.Error(w, "down", status)
		case ok:
			w.Header().Set("Last-Modified", mod.Format(http.TimeFormat))
			io.WriteString(w, body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRepo) set(path, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies[path] = body
}

func (f *fakeRepo) setStatus(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = code
}

// requests returns the requests so far as "METHOD path".
func (f *fakeRepo) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.paths)
}

func (f *fakeRepo) count(path string) int {
	n := 0
	for _, r := range f.requests() {
		if strings.HasSuffix(r, " "+path) {
			n++
		}
	}
	return n
}

type regEnv struct {
	up    *fakeRepo
	src   *RegistrySource
	cache *storage.Cache
	cd    storage.Driver // the cache's driver
	relay *relay.Relay
	rec   *records.Store
	clock time.Time
}

func newRegEnv(t *testing.T) *regEnv {
	t.Helper()
	up := newFakeRepo(t)
	cd, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := storage.NewCache(context.Background(), cd, 1<<30, nil)
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
	e := &regEnv{up: up, cache: cache, cd: cd, relay: rl, rec: rec, clock: time.Now()}
	e.src = NewRegistrySource("central", []string{"*"}, up.srv.URL+"/", c, cache, rl, rec, time.Minute, 1<<20, nil, slog.New(slog.DiscardHandler))
	e.src.now = func() time.Time { return e.clock }
	return e
}

func mustPath(t testing.TB, s string) Path {
	t.Helper()
	p, err := ParsePath(strings.TrimPrefix(s, "/"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// readFile reads a File result to its end.
func readFile(f File, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	defer f.Body.Close()
	return io.ReadAll(f.Body)
}

// keys lists the cache keys under prefix.
func (e *regEnv) keys(t *testing.T, prefix string) []string {
	t.Helper()
	var out []string
	for info, err := range e.cd.List(context.Background(), prefix) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, info.Key)
	}
	return out
}

func allDigests(s string) Digests {
	h := NewHasher()
	io.WriteString(h, s)
	return h.Digests()
}

func TestFileVerifiedAndCached(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	e.up.set(upJar, jarData)
	e.up.set(upJar+".sha1", sha1Hex(jarData)+"  lib-1.0.jar\n")
	p := mustPath(t, upJar)

	var wg sync.WaitGroup
	got := make([][]byte, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Go(func() { got[i], errs[i] = readFile(e.src.File(ctx, p)) })
	}
	wg.Wait()
	for i := range 2 {
		if errs[i] != nil || string(got[i]) != jarData {
			t.Fatalf("call %d: %q, %v", i, got[i], errs[i])
		}
	}
	e.relay.Wait()
	if n := e.up.count(upJar); n != 1 {
		t.Fatalf("jar fetched %d times", n)
	}

	want := allDigests(jarData)
	provs, err := e.rec.FileProvenance(ctx, "maven", "com.matchory:lib", "1.0", "lib-1.0.jar")
	if err != nil || len(provs) != 1 {
		t.Fatalf("provenance = %+v, %v", provs, err)
	}
	prov := provs[0]
	if prov.File != "lib-1.0.jar" || prov.Source != "central" || prov.SourceType != "registry" ||
		prov.DeclaredDigest != "sha1:"+want.SHA1 || prov.SHA1 != want.SHA1 || prov.UpstreamURL != e.up.srv.URL+upJar {
		t.Fatalf("provenance = %+v", prov)
	}
	if keys := e.keys(t, "maven/central/digests/"); !slices.Equal(keys, []string{e.src.digestsKey(mustPath(t, upJar), want.SHA1)}) {
		t.Fatalf("digests objects = %v", keys)
	}

	// A cache hit carries all four digests and the upstream Last-Modified.
	f, err := e.src.File(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := readFile(f, nil)
	if err != nil || string(b) != jarData {
		t.Fatalf("hit: %q, %v", b, err)
	}
	if f.Digests != want || !f.Modified.Equal(upModified) || !f.Immutable || f.Size != int64(len(jarData)) {
		t.Fatalf("hit = %+v", f)
	}
	d, err := e.src.Digests(ctx, p)
	if err != nil || d != want {
		t.Fatalf("digests = %+v, %v; want %+v", d, err, want)
	}
	if n := e.up.count(upJar); n != 1 {
		t.Fatalf("jar fetched %d times", n)
	}
}

func TestTamperedFile(t *testing.T) {
	e := newRegEnv(t)
	e.up.set(upJar, jarData+" tampered")
	e.up.set(upJar+".sha1", sha1Hex(jarData))
	_, err := readFile(e.src.File(context.Background(), mustPath(t, upJar)))
	if !errors.Is(err, relay.ErrDigestMismatch) {
		t.Fatalf("err = %v", err)
	}
	e.relay.Wait()
	if keys := e.keys(t, "maven/central/files/"); len(keys) != 0 {
		t.Fatalf("cached %v", keys)
	}
	if keys := e.keys(t, "maven/central/digests/"); len(keys) != 0 {
		t.Fatalf("digests cached %v", keys)
	}
}

func TestNoChecksumMissingFile(t *testing.T) {
	e := newRegEnv(t)
	p := mustPath(t, "/com/matchory/lib/1.0/lib-1.0-sources.jar")
	for i := range 2 {
		if _, err := e.src.File(context.Background(), p); !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("call %d: err = %v", i, err)
		}
		if n := len(e.up.requests()); n != 2 {
			t.Fatalf("call %d: requests %v", i, e.up.requests())
		}
	}
	if _, err := e.src.Digests(context.Background(), p); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("digests err = %v", err)
	}
	if n := len(e.up.requests()); n != 2 {
		t.Fatalf("requests %v", e.up.requests())
	}
}

func TestUncheckedSignature(t *testing.T) {
	e := newRegEnv(t)
	sig := "-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----\n"
	e.up.set(upAsc, sig)
	f, err := e.src.File(context.Background(), mustPath(t, upAsc))
	b, rerr := readFile(f, err)
	if rerr != nil || string(b) != sig {
		t.Fatalf("got %q, %v", b, rerr)
	}
	if f.Digests != (Digests{}) {
		t.Fatalf("digests = %+v", f.Digests)
	}
	e.relay.Wait()
	if keys := e.keys(t, "maven/"); len(keys) != 0 {
		t.Fatalf("cached %v", keys)
	}

	e.up.set(upAsc, strings.Repeat("a", 64<<10+1))
	if _, err := readFile(e.src.File(context.Background(), mustPath(t, upAsc))); err == nil {
		t.Fatal("oversized signature served")
	}
}

func TestNoChecksumOtherFile(t *testing.T) {
	e := newRegEnv(t)
	e.up.set(upJar, jarData)
	_, err := e.src.File(context.Background(), mustPath(t, upJar))
	if err == nil || errors.Is(err, resolve.ErrNotFound) || !strings.Contains(err.Error(), "upstream declares no checksum for lib-1.0.jar") {
		t.Fatalf("err = %v", err)
	}
	if s := resolve.HTTPStatus(resolve.Wrap("central", err)); s != http.StatusBadGateway {
		t.Fatalf("status = %d", s)
	}
}

func TestMetadataPassThrough(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	doc := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\r\n  <groupId>com.matchory</groupId>  \n</metadata>\n"
	e.up.set(upMeta, doc)
	p := mustPath(t, upMeta)
	for i := range 2 {
		b, err := e.src.Metadata(ctx, p)
		if err != nil || string(b) != doc {
			t.Fatalf("call %d: %q, %v", i, b, err)
		}
	}
	if n := e.up.count(upMeta); n != 1 {
		t.Fatalf("fetched %d times", n)
	}

	// After the TTL a failing upstream leaves the cached bytes served.
	e.clock = e.clock.Add(2 * time.Minute)
	e.up.setStatus(http.StatusInternalServerError)
	if b, err := e.src.Metadata(ctx, p); err != nil || string(b) != doc {
		t.Fatalf("stale: %q, %v", b, err)
	}
	if h := e.src.Health(ctx); len(h) != 1 || h[0].OK || h[0].Detail != "serving stale" {
		t.Fatalf("health = %+v", h)
	}
	e.up.setStatus(0)
	e.clock = time.Now()

	bad := mustPath(t, "/com/matchory/other/maven-metadata.xml")
	e.up.set("/com/matchory/other/maven-metadata.xml", `<!DOCTYPE metadata [<!ENTITY x "y">]><metadata/>`)
	_, err := e.src.Metadata(ctx, bad)
	if err == nil || resolve.HTTPStatus(resolve.Wrap("central", err)) != http.StatusBadGateway {
		t.Fatalf("doctype: err = %v", err)
	}
	e.up.set("/com/matchory/other/maven-metadata.xml", "<metadata/>")
	if b, err := e.src.Metadata(ctx, bad); err != nil || string(b) != "<metadata/>" {
		t.Fatalf("after doctype: %q, %v", b, err)
	}

	missing := mustPath(t, "/com/matchory/none/maven-metadata.xml")
	for range 2 {
		if _, err := e.src.Metadata(ctx, missing); !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("missing: err = %v", err)
		}
	}
	if n := e.up.count("/com/matchory/none/maven-metadata.xml"); n != 1 {
		t.Fatalf("miss fetched %d times", n)
	}
}

func TestUpstreamURLCanonical(t *testing.T) {
	e := newRegEnv(t)
	e.up.set(upJar, jarData)
	e.up.set(upJar+".sha1", sha1Hex(jarData))
	p := mustPath(t, "com/matchory/lib/1.0/lib-1.0.jar.md5")
	if _, err := readFile(e.src.File(context.Background(), p)); err != nil {
		t.Fatal(err)
	}
	want := []string{"GET " + upJar + ".sha1", "GET " + upJar}
	if got := e.up.requests(); !slices.Equal(got, want) {
		t.Fatalf("requests = %v, want %v", got, want)
	}
}

func TestChangedFile(t *testing.T) {
	ctx := context.Background()
	other := strings.Repeat("e", 64)
	for _, tc := range []struct {
		name   string
		prior  records.Provenance
		listed bool
	}{
		{"same source", records.Provenance{Source: "central", File: "lib-1.0.jar"}, true},
		{"other source", records.Provenance{Source: "mirror", File: "lib-1.0.jar"}, false},
		{"other file", records.Provenance{Source: "central", File: "lib-1.0.pom"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newRegEnv(t)
			pr := tc.prior
			pr.Ecosystem, pr.Package, pr.Version, pr.SourceType, pr.SHA256 = "maven", "com.matchory:lib", "1.0", "registry", other
			pr.Created = time.Now().Add(-time.Hour)
			if err := e.rec.PutProvenance(ctx, pr); err != nil {
				t.Fatal(err)
			}
			e.up.set(upJar, jarData)
			e.up.set(upJar+".sha1", sha1Hex(jarData))
			if b, err := readFile(e.src.File(ctx, mustPath(t, upJar))); err != nil || string(b) != jarData {
				t.Fatalf("got %q, %v", b, err)
			}
			e.relay.Wait()
			got := e.src.Changed()
			if !tc.listed {
				if len(got) != 0 {
					t.Fatalf("changed = %+v", got)
				}
				return
			}
			now := sha256.Sum256([]byte(jarData))
			if len(got) != 1 || got[0] != (ChangedFile{
				Package: "com.matchory:lib", Version: "1.0", File: "lib-1.0.jar", Source: "central",
				FirstSHA256: other, NowSHA256: hex.EncodeToString(now[:]), Seen: e.clock,
			}) {
				t.Fatalf("changed = %+v", got)
			}
		})
	}
}

func TestDigestsOfUncachedFile(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	e.up.set(upJar, jarData)
	e.up.set(upJar+".sha1", sha1Hex(jarData))
	p := mustPath(t, upJar)
	want := allDigests(jarData)
	if want.MD5 != md5Hex(jarData) {
		t.Fatal("hasher disagrees with crypto/md5")
	}
	d, err := e.src.Digests(ctx, p)
	if err != nil || d != want {
		t.Fatalf("digests = %+v, %v", d, err)
	}
	e.relay.Wait()

	// The digests object gone, the cached file is read again; the upstream
	// is not asked.
	for _, k := range e.keys(t, "maven/central/digests/") {
		if err := e.cache.Delete(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	if d, err := e.src.Digests(ctx, p); err != nil || d != want {
		t.Fatalf("re-read: %+v, %v", d, err)
	}
	if n := e.up.count(upJar); n != 1 {
		t.Fatalf("jar fetched %d times", n)
	}

	// An unchecked signature's digests are computed from the streamed
	// bytes and never cached.
	sig := "signature"
	e.up.set(upAsc, sig)
	for range 2 {
		if d, err := e.src.Digests(ctx, mustPath(t, upAsc)); err != nil || d != allDigests(sig) {
			t.Fatalf("signature: %+v, %v", d, err)
		}
	}
	if n := e.up.count(upAsc); n != 2 {
		t.Fatalf("signature fetched %d times", n)
	}
	if len(e.keys(t, "maven/central/digests/")) != 1 {
		t.Fatalf("digests objects = %v", e.keys(t, "maven/central/digests/"))
	}
}

// TestChangedFileBackToFirst: bytes A, then B, then A again are not changed
// on the third fetch, as they equal the first record.
func TestChangedFileBackToFirst(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	p := mustPath(t, upJar)
	for i, body := range []string{jarData, jarData + " B", jarData} {
		e.up.set(upJar, body)
		e.up.set(upJar+".sha1", sha1Hex(body))
		// A release's .sha1 is cached for good: drop it and the file, so
		// both are fetched again.
		for _, k := range append(e.keys(t, "maven/central/paths/"), e.keys(t, "maven/central/files/")...) {
			if err := e.cache.Delete(ctx, k); err != nil {
				t.Fatal(err)
			}
		}
		if b, err := readFile(e.src.File(ctx, p)); err != nil || string(b) != body {
			t.Fatalf("fetch %d: %q, %v", i, b, err)
		}
		e.relay.Wait()
		got := e.src.Changed()
		switch i {
		case 0:
			if len(got) != 0 {
				t.Fatalf("fetch 0: changed = %+v", got)
			}
		case 1:
			if len(got) != 1 || got[0].FirstSHA256 != allDigests(jarData).SHA256 {
				t.Fatalf("fetch 1: changed = %+v", got)
			}
		case 2:
			// A again: equal to the first record, so not newly listed.
			if len(got) != 1 || got[0].NowSHA256 != allDigests(jarData+" B").SHA256 {
				t.Fatalf("fetch 2: changed = %+v", got)
			}
		}
	}
}

// TestChangedIdenticalFiles: two files of one version with the same bytes
// each keep a first record, so a later change of either is listed.
func TestChangedIdenticalFiles(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	sources, javadoc := "/com/matchory/lib/1.0/lib-1.0-sources.jar", "/com/matchory/lib/1.0/lib-1.0-javadoc.jar"
	for _, f := range []string{sources, javadoc} {
		e.up.set(f, jarData)
		e.up.set(f+".sha1", sha1Hex(jarData))
		if _, err := readFile(e.src.File(ctx, mustPath(t, f))); err != nil {
			t.Fatal(err)
		}
		e.relay.Wait()
	}
	changed := jarData + " changed"
	e.up.set(javadoc, changed)
	e.up.set(javadoc+".sha1", sha1Hex(changed))
	for _, k := range append(e.keys(t, "maven/central/paths/"), e.keys(t, "maven/central/files/")...) {
		if err := e.cache.Delete(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := readFile(e.src.File(ctx, mustPath(t, javadoc))); err != nil {
		t.Fatal(err)
	}
	e.relay.Wait()
	if got := e.src.Changed(); len(got) != 1 || got[0].File != "lib-1.0-javadoc.jar" || got[0].FirstSHA256 != allDigests(jarData).SHA256 {
		t.Fatalf("changed = %+v", got)
	}
}

// TestModifiedPerFile: files with the same bytes keep their own
// Last-Modified on cache hits.
func TestModifiedPerFile(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	a, b := "/com/matchory/lib/1.0/lib-1.0-sources.jar", "/com/matchory/lib/1.0/lib-1.0-javadoc.jar"
	modA, modB := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for f, mod := range map[string]time.Time{a: modA, b: modB} {
		e.up.set(f, jarData)
		e.up.set(f+".sha1", sha1Hex(jarData))
		e.up.mu.Lock()
		e.up.mods[f] = mod
		e.up.mu.Unlock()
	}
	for _, f := range []string{a, b} {
		if _, err := readFile(e.src.File(ctx, mustPath(t, f))); err != nil {
			t.Fatal(err)
		}
		e.relay.Wait()
	}
	f, err := e.src.File(ctx, mustPath(t, a))
	if err != nil {
		t.Fatal(err)
	}
	f.Body.Close()
	if !f.Modified.Equal(modA) {
		t.Errorf("cache hit of %s: Modified %v, want %v", a, f.Modified, modA)
	}
}

// TestSnapshotFilesFromRegistry: a timestamped SNAPSHOT file's checksum is
// kept for good, as it is served immutable; a non-timestamped one that
// changes upstream is refreshed and not reported as changed.
func TestSnapshotFilesFromRegistry(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	stamped := "/com/matchory/lib/1.0-SNAPSHOT/lib-1.0-20261123.101010-1.jar"
	plain := "/com/matchory/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar"
	for _, f := range []string{stamped, plain} {
		e.up.set(f, jarData)
		e.up.set(f+".sha1", sha1Hex(jarData))
		if _, err := readFile(e.src.File(ctx, mustPath(t, f))); err != nil {
			t.Fatal(err)
		}
		e.relay.Wait()
	}
	rebuilt := jarData + " rebuilt"
	e.up.set(plain, rebuilt)
	e.up.set(plain+".sha1", sha1Hex(rebuilt))
	e.clock = e.clock.Add(2 * time.Minute)
	if _, err := readFile(e.src.File(ctx, mustPath(t, stamped))); err != nil {
		t.Fatal(err)
	}
	if n := e.up.count(stamped + ".sha1"); n != 1 {
		t.Errorf("timestamped .sha1 fetched %d times, want 1", n)
	}
	if b, err := readFile(e.src.File(ctx, mustPath(t, plain))); err != nil || string(b) != rebuilt {
		t.Fatalf("plain SNAPSHOT: %q, %v", b, err)
	}
	e.relay.Wait()
	if got := e.src.Changed(); len(got) != 0 {
		t.Errorf("changed = %+v, want none", got)
	}
}

// TestUpstreamURLEscaped: every segment of an upstream request path is
// escaped, so "?", "#" and "%" in a version stay part of the path.
func TestUpstreamURLEscaped(t *testing.T) {
	for _, tc := range []struct{ version, escaped string }{
		{"1.0?x", "1.0%3Fx"},
		{"1.0#x", "1.0%23x"},
		{"%2e%2e", "%252e%252e"},
	} {
		t.Run(tc.escaped, func(t *testing.T) {
			e := newRegEnv(t)
			ctx := context.Background()
			jar := "/org/foo/bar/" + tc.escaped + "/bar-" + tc.escaped + ".jar"
			e.up.set(jar, jarData)
			e.up.set(jar+".sha1", sha1Hex(jarData))
			p := mustPath(t, "org/foo/bar/"+tc.version+"/bar-"+tc.version+".jar")
			if b, err := readFile(e.src.File(ctx, p)); err != nil || string(b) != jarData {
				t.Fatalf("file: %q, %v", b, err)
			}
			e.relay.Wait()
			meta := "/org/foo/bar/" + tc.escaped + "-SNAPSHOT/maven-metadata.xml"
			e.up.set(meta, "<metadata/>")
			if b, err := e.src.Metadata(ctx, mustPath(t, "org/foo/bar/"+tc.version+"-SNAPSHOT/maven-metadata.xml")); err != nil || string(b) != "<metadata/>" {
				t.Fatalf("metadata: %q, %v", b, err)
			}
			want := []string{"GET " + jar + ".sha1", "GET " + jar, "GET " + meta}
			if got := e.up.requests(); !slices.Equal(got, want) {
				t.Fatalf("requests = %v, want %v", got, want)
			}
		})
	}
}

// TestReleaseChecksumPermanent: a release file's .sha1 is fetched once;
// a non-timestamped SNAPSHOT file's is refreshed after the TTL.
func TestReleaseChecksumPermanent(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	snapJar := "/com/matchory/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar"
	for _, path := range []string{upJar, snapJar} {
		e.up.set(path, jarData)
		e.up.set(path+".sha1", sha1Hex(jarData))
	}
	for range 2 {
		for _, path := range []string{upJar, snapJar} {
			if b, err := readFile(e.src.File(ctx, mustPath(t, path))); err != nil || string(b) != jarData {
				t.Fatalf("%s: %q, %v", path, b, err)
			}
			e.relay.Wait()
		}
		e.clock = e.clock.Add(2 * time.Minute)
	}
	if n := e.up.count(upJar + ".sha1"); n != 1 {
		t.Errorf("release .sha1 fetched %d times, want 1", n)
	}
	if n := e.up.count(snapJar + ".sha1"); n != 2 {
		t.Errorf("SNAPSHOT .sha1 fetched %d times, want 2", n)
	}
}

// TestLongCoordinates: a groupId:artifactId too long for a provenance
// record is served and cached without one.
func TestLongCoordinates(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	g, a := strings.Repeat("g", 100), strings.Repeat("a", 100)
	path := "/" + g + "/" + a + "/1.0/" + a + "-1.0.jar"
	e.up.set(path, jarData)
	e.up.set(path+".sha1", sha1Hex(jarData))
	for i := range 2 {
		if b, err := readFile(e.src.File(ctx, mustPath(t, path))); err != nil || string(b) != jarData {
			t.Fatalf("call %d: %q, %v", i, b, err)
		}
		e.relay.Wait()
	}
	if n := e.up.count(path); n != 1 {
		t.Fatalf("jar fetched %d times", n)
	}
	if d, err := e.src.Digests(ctx, mustPath(t, path)); err != nil || d != allDigests(jarData) {
		t.Fatalf("digests = %+v, %v", d, err)
	}
}

// TestMetadataASCIIEncodingLabel: upstream metadata labelled with another
// encoding is accepted while every byte is ASCII.
func TestMetadataASCIIEncodingLabel(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	doc := `<?xml version="1.0" encoding="ISO-8859-1"?><metadata><groupId>com.matchory</groupId></metadata>`
	e.up.set(upMeta, doc)
	if b, err := e.src.Metadata(ctx, mustPath(t, upMeta)); err != nil || string(b) != doc {
		t.Fatalf("ASCII: %q, %v", b, err)
	}
	other := "/com/matchory/other/maven-metadata.xml"
	e.up.set(other, `<?xml version="1.0" encoding="ISO-8859-1"?><metadata><groupId>caf`+"\xe9"+`</groupId></metadata>`)
	if _, err := e.src.Metadata(ctx, mustPath(t, other)); err == nil || resolve.HTTPStatus(resolve.Wrap("central", err)) != http.StatusBadGateway {
		t.Fatalf("non-ASCII: err = %v", err)
	}
}
