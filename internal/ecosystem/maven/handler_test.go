package maven

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // test oracle for the .md5 route
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/testutil"
	"github.com/radiergummi/tspackages/internal/upstream"
	"tailscale.com/tailcfg/peercap"
)

const hCap peercap.Cap = "github.com/radiergummi/tspackages"

const (
	readAll  = `{"read":["maven:*"]}`
	writeAll = `{"read":["maven:*"],"write":["maven:*"]}`

	jarPath  = "/maven/com/matchory/lib/1.0/lib-1.0.jar"
	snapPath = "/maven/com/matchory/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar"
	metaPath = "/maven/com/matchory/lib/maven-metadata.xml"
	jarBody  = "JAR BYTES"
	metaBody = `<metadata><groupId>com.matchory</groupId></metadata>`
)

var modified = time.Date(2026, 11, 23, 10, 10, 10, 0, time.UTC)

// fakeSource serves files and metadata keyed by their path without a
// checksum suffix.
type fakeSource struct {
	name      string
	claims    []string
	files     map[string]string
	meta      map[string]string
	immutable bool
	noDigests bool // File reports no digests (an uncached signature)
	err       error

	calls atomic.Int32
	log   *callLog
}

// callLog records which sources were asked, in order.
type callLog struct {
	mu    sync.Mutex
	names []string
}

func (l *callLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.names = nil
}

func (l *callLog) add(name string) {
	l.mu.Lock()
	l.names = append(l.names, name)
	l.mu.Unlock()
}

func (f *fakeSource) Name() string     { return f.name }
func (f *fakeSource) Claims() []string { return f.claims }

func (f *fakeSource) record() error {
	f.calls.Add(1)
	if f.log != nil {
		f.log.add(f.name)
	}
	return f.err
}

func keyOf(p Path) string {
	p.Checksum = ""
	return p.String()
}

func digestsOf(s string) Digests {
	h := NewHasher()
	_, _ = io.WriteString(h, s)
	return h.Digests()
}

func (f *fakeSource) File(_ context.Context, p Path) (File, error) {
	if err := f.record(); err != nil {
		return File{}, err
	}
	s, ok := f.files[keyOf(p)]
	if !ok {
		return File{}, resolve.ErrNotFound
	}
	file := File{Body: io.NopCloser(strings.NewReader(s)), Size: int64(len(s)), Modified: modified, Immutable: f.immutable}
	if !f.noDigests {
		file.Digests = digestsOf(s)
		file.Digests.SHA256, file.Digests.SHA512 = "", ""
	}
	return file, nil
}

func (f *fakeSource) Digests(_ context.Context, p Path) (Digests, error) {
	if err := f.record(); err != nil {
		return Digests{}, err
	}
	s, ok := f.files[keyOf(p)]
	if !ok {
		return Digests{}, resolve.ErrNotFound
	}
	return digestsOf(s), nil
}

func (f *fakeSource) Metadata(_ context.Context, p Path) ([]byte, error) {
	if err := f.record(); err != nil {
		return nil, err
	}
	s, ok := f.meta[keyOf(p)]
	if !ok {
		return nil, resolve.ErrNotFound
	}
	return []byte(s), nil
}

type fakeDeployer struct {
	*fakeSource
	deployErr error
	deployed  []string
	paths     []Path
}

func (d *fakeDeployer) Deploy(_ context.Context, _ identity.Caller, p Path, body *os.File, size int64) error {
	d.calls.Add(1)
	if d.deployErr != nil {
		return d.deployErr
	}
	b, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(b)) != size {
		return fmt.Errorf("size %d, read %d", size, len(b))
	}
	d.deployed = append(d.deployed, string(b))
	d.paths = append(d.paths, p)
	return nil
}

func registryFake() *fakeSource {
	return &fakeSource{name: "central", immutable: true,
		files: map[string]string{"org/x/y/1.0/y-1.0.jar": "Y"},
		meta:  map[string]string{"org/x/y/maven-metadata.xml": "<metadata/>"},
	}
}

func storageFake() *fakeDeployer {
	return &fakeDeployer{fakeSource: &fakeSource{name: "hosted", claims: []string{"com.matchory", "com.matchory.*"}, immutable: true,
		files: map[string]string{"com/matchory/lib/1.0/lib-1.0.jar": jarBody},
		meta:  map[string]string{"com/matchory/lib/maven-metadata.xml": metaBody},
	}}
}

// serverIn mounts the handler behind the real identity middleware and
// returns the directory PUT bodies are spooled in.
func serverIn(t *testing.T, srcs []Source, maxUpload int64, rules ...string) (http.Handler, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(srcs, maxUpload, dir, slog.New(slog.DiscardHandler)).Mount(mux)
	return identity.Middleware(testutil.Who{Cap: hCap, Rules: rules}, hCap, nil)(CollapseSlashes(mux)), dir
}

func server(t *testing.T, srcs []Source, rules ...string) http.Handler {
	t.Helper()
	h, _ := serverIn(t, srcs, 1<<20, rules...)
	return h
}

func do(h http.Handler, method, path string, body io.Reader, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, body)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s)) //nolint:gosec // Maven's checksum, not a security digest
	return hex.EncodeToString(sum[:])
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // Maven's checksum, not a security digest
	return hex.EncodeToString(sum[:])
}

type problemBody struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func problemOf(t *testing.T, w *httptest.ResponseRecorder) problemBody {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != problemType {
		t.Fatalf("Content-Type %q, body %s", ct, w.Body)
	}
	var p problemBody
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("problem body %q: %v", w.Body, err)
	}
	if p.Title == "" || p.Detail == "" || p.Status != w.Code {
		t.Fatalf("problem %+v for %d", p, w.Code)
	}
	return p
}

func TestFileHeaders(t *testing.T) {
	st := storageFake()
	h := server(t, []Source{st}, readAll)
	w := do(h, "GET", jarPath, nil)
	if w.Code != 200 || w.Body.String() != jarBody {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	hd := w.Header()
	for k, v := range map[string]string{
		"ETag":                   `"{SHA1{` + sha1Hex(jarBody) + `}}"`,
		"X-Checksum-Sha1":        sha1Hex(jarBody),
		"X-Checksum-Md5":         md5Hex(jarBody),
		"Content-Length":         fmt.Sprint(len(jarBody)),
		"Last-Modified":          modified.Format(http.TimeFormat),
		"Cache-Control":          "private, max-age=31536000, immutable",
		"Content-Type":           "application/octet-stream",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := hd.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}

	// A file that may still change.
	st.immutable = false
	if w := do(h, "GET", jarPath, nil); w.Header().Get("Cache-Control") != "private, no-store" {
		t.Errorf("mutable: Cache-Control %q", w.Header().Get("Cache-Control"))
	}

	// A file without known digests (an uncached upstream signature).
	st.immutable, st.noDigests = true, true
	w = do(h, "GET", jarPath, nil)
	if w.Code != 200 || w.Body.String() != jarBody || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("no digests: %d %q %s", w.Code, w.Header().Get("Cache-Control"), w.Body)
	}
	for _, k := range []string{"ETag", "X-Checksum-Sha1", "X-Checksum-Md5"} {
		if v := w.Header().Values(k); v != nil {
			t.Errorf("no digests: %s = %q", k, v)
		}
	}
}

func TestHeadMatchesGet(t *testing.T) {
	st := storageFake()
	h := server(t, []Source{st}, readAll)
	for _, path := range []string{jarPath, jarPath + ".sha1", metaPath, metaPath + ".md5"} {
		get := do(h, "GET", path, nil)
		head := do(h, "HEAD", path, nil)
		if get.Code != 200 || head.Code != 200 {
			t.Fatalf("%s: GET %d HEAD %d", path, get.Code, head.Code)
		}
		if !maps.EqualFunc(get.Header(), head.Header(), slices.Equal) {
			t.Errorf("%s: GET %v\nHEAD %v", path, get.Header(), head.Header())
		}
		if head.Body.Len() != 0 {
			t.Errorf("%s: HEAD body %q", path, head.Body)
		}
	}
}

func TestChecksumRoutes(t *testing.T) {
	h := server(t, []Source{storageFake()}, readAll)
	want := digestsOf(jarBody)
	for _, alg := range []string{"sha1", "md5", "sha256", "sha512"} {
		w := do(h, "GET", jarPath+"."+alg, nil)
		if w.Code != 200 || w.Body.String() != want.Get(alg) {
			t.Errorf("%s: %d %q", alg, w.Code, w.Body)
		}
		if w.Header().Get("Content-Type") != "text/plain" || w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("ETag") == "" {
			t.Errorf("%s: headers %v", alg, w.Header())
		}
		if w.Header().Get("Content-Length") != fmt.Sprint(len(want.Get(alg))) {
			t.Errorf("%s: Content-Length %q", alg, w.Header().Get("Content-Length"))
		}
	}
	w := do(h, "GET", metaPath+".sha1", nil)
	if w.Code != 200 || w.Body.String() != sha1Hex(metaBody) {
		t.Fatalf("metadata sha1: %d %q", w.Code, w.Body)
	}
	w = do(h, "GET", metaPath+".md5", nil)
	if w.Code != 200 || w.Body.String() != md5Hex(metaBody) {
		t.Fatalf("metadata md5: %d %q", w.Code, w.Body)
	}
	if w := do(h, "GET", "/maven/com/matchory/lib/1.0/lib-1.0-sources.jar.sha1", nil); w.Code != 404 {
		t.Fatalf("checksum of a missing file: %d", w.Code)
	}
}

func TestMetadataConditional(t *testing.T) {
	h := server(t, []Source{storageFake()}, readAll)
	w := do(h, "GET", metaPath, nil)
	etag := w.Header().Get("ETag")
	if w.Code != 200 || w.Body.String() != metaBody || etag == "" || strings.HasPrefix(etag, "W/") {
		t.Fatalf("%d %q %s", w.Code, etag, w.Body)
	}
	if w.Header().Get("Content-Type") != "application/xml" || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("headers %v", w.Header())
	}
	if w.Header().Get("X-Checksum-Sha1") != sha1Hex(metaBody) || w.Header().Get("X-Checksum-Md5") != md5Hex(metaBody) {
		t.Fatalf("checksum headers %v", w.Header())
	}
	if w := do(h, "GET", metaPath, nil, "If-None-Match", etag); w.Code != 304 || w.Body.Len() != 0 || w.Header().Get("ETag") != etag {
		t.Fatalf("revalidation: %d %q %s", w.Code, w.Header().Get("ETag"), w.Body)
	}
	if w := do(h, "GET", metaPath, nil, "If-None-Match", `"other"`); w.Code != 200 {
		t.Fatalf("stale tag: %d", w.Code)
	}
	sum := do(h, "GET", metaPath+".sha1", nil)
	if w := do(h, "GET", metaPath+".sha1", nil, "If-None-Match", sum.Header().Get("ETag")); w.Code != 304 {
		t.Fatalf("checksum revalidation: %d", w.Code)
	}
}

func TestClaimsBothReadings(t *testing.T) {
	// com/matchory/plugins/maven-metadata.xml: artifact level of
	// com.matchory:plugins, group level of com.matchory.plugins.
	const plugins = "/maven/com/matchory/plugins/maven-metadata.xml"

	// Claimed only under the group-level reading: the unclaimed registry is
	// never asked.
	st := &fakeDeployer{fakeSource: &fakeSource{name: "hosted", claims: []string{"com.matchory.*"}}}
	reg := registryFake()
	h := server(t, []Source{st, reg}, readAll)
	if w := do(h, "GET", plugins, nil); w.Code != 404 || st.calls.Load() != 1 {
		t.Fatalf("group reading: %d, storage asked %d times", w.Code, st.calls.Load())
	}
	// The brief's path: com/matchory/maven-metadata.xml, group-level reading
	// com.matchory under a literal claim.
	lit := &fakeDeployer{fakeSource: &fakeSource{name: "hosted", claims: []string{"com.matchory"}}}
	h = server(t, []Source{lit, reg}, readAll)
	if w := do(h, "GET", "/maven/com/matchory/maven-metadata.xml", nil); w.Code != 404 || lit.calls.Load() != 1 {
		t.Fatalf("literal group: %d, storage asked %d times", w.Code, lit.calls.Load())
	}
	if n := reg.calls.Load(); n != 0 {
		t.Fatalf("registry asked %d times", n)
	}
	// Unclaimed under both readings: the registry answers.
	if w := do(h, "GET", "/maven/org/x/y/maven-metadata.xml", nil); w.Code != 200 || reg.calls.Load() != 1 {
		t.Fatalf("unclaimed: %d, registry asked %d times", w.Code, reg.calls.Load())
	}

	// Different sources per reading: the artifact level's first, then the
	// group level's, each once.
	var log callLog
	groupSrc := &fakeSource{name: "group", claims: []string{"com.matchory.plugins"}, log: &log}
	artSrc := &fakeSource{name: "artifact", claims: []string{"com.matchory:plugins"}, log: &log}
	both := &fakeSource{name: "both", claims: []string{"com.matchory.*", "com.matchory:*"}, log: &log}
	h = server(t, []Source{groupSrc, both, artSrc, reg}, readAll)
	if w := do(h, "GET", plugins, nil); w.Code != 404 {
		t.Fatalf("both readings: %d", w.Code)
	}
	if want := []string{"both", "artifact", "group"}; !slices.Equal(log.names, want) {
		t.Fatalf("order %v, want %v", log.names, want)
	}

	// Authz under the group-level reading needs a rule whose group part
	// matches the group.
	h = server(t, []Source{st, reg}, `{"read":["maven:com.matchory:plugins"]}`)
	if w := do(h, "GET", plugins, nil); w.Code != 403 || problemOf(t, w).Detail != "forbidden: no maven:com.matchory.plugins read rule" {
		t.Fatalf("artifact rule on a group reading: %d %s", w.Code, w.Body)
	}
	h = server(t, []Source{st, reg}, `{"read":["maven:com.matchory.*"]}`)
	if w := do(h, "GET", plugins, nil); w.Code != 404 {
		t.Fatalf("group rule: %d %s", w.Code, w.Body)
	}
	// A read rule that names an artifact never grants group-level metadata,
	// even when its group part matches the group.
	h = server(t, []Source{st, reg}, `{"read":["maven:com.matchory.plugins:x"]}`)
	if w := do(h, "GET", plugins, nil); w.Code != 403 {
		t.Fatalf("artifact rule on its own group: %d %s", w.Code, w.Body)
	}
	// Every artifact of the group ("g:*") covers its group-level metadata.
	h = server(t, []Source{st, reg}, `{"read":["maven:com.matchory.plugins:*"]}`)
	if w := do(h, "GET", plugins, nil); w.Code != 404 {
		t.Fatalf("g:* rule on its group: %d %s", w.Code, w.Body)
	}

	// With both readings claimed, a caller allowed only the artifact level
	// is answered by its sources alone; the group level's are not asked.
	log.reset()
	h = server(t, []Source{groupSrc, artSrc, reg}, `{"read":["maven:com.matchory:plugins"]}`)
	if w := do(h, "GET", plugins, nil); w.Code != 404 {
		t.Fatalf("artifact grant, both readings: %d %s", w.Code, w.Body)
	}
	if want := []string{"artifact"}; !slices.Equal(log.names, want) {
		t.Fatalf("asked %v, want %v", log.names, want)
	}
	log.reset()
	h = server(t, []Source{groupSrc, artSrc, reg}, `{"read":["maven:com.matchory:plugins","maven:com.matchory.plugins"]}`)
	if w := do(h, "GET", plugins, nil); w.Code != 404 {
		t.Fatalf("both grants: %d %s", w.Code, w.Body)
	}
	if want := []string{"artifact", "group"}; !slices.Equal(log.names, want) {
		t.Fatalf("asked %v, want %v", log.names, want)
	}
}

func TestForbiddenProblemJSON(t *testing.T) {
	h := server(t, []Source{storageFake()}, `{"read":["npm:*"]}`)
	w := do(h, "GET", jarPath, nil)
	if w.Code != 403 || problemOf(t, w).Detail != "forbidden: no maven:com.matchory:lib read rule" {
		t.Fatalf("read: %d %s", w.Code, w.Body)
	}
	h = server(t, []Source{storageFake()}, readAll)
	w = do(h, "PUT", jarPath, strings.NewReader("x"))
	if w.Code != 403 || problemOf(t, w).Detail != "forbidden: no maven:com.matchory:lib write rule" {
		t.Fatalf("write: %d %s", w.Code, w.Body)
	}
	// Mixed case can't dodge a rule: the detail names the lowercased key.
	h = server(t, []Source{storageFake()}, `{"read":["maven:org.x"]}`)
	w = do(h, "GET", "/maven/Com/Matchory/Lib/1.0/Lib-1.0.jar", nil)
	if w.Code != 403 || problemOf(t, w).Detail != "forbidden: no maven:com.matchory:lib read rule" {
		t.Fatalf("mixed case: %d %s", w.Code, w.Body)
	}
}

func Test404Plain(t *testing.T) {
	h := server(t, []Source{storageFake(), registryFake()}, readAll)
	for _, path := range []string{
		"/maven/com/matchory/lib/2.0/lib-2.0.jar", // a miss
		"/maven/org/x/y/2.0/y-2.0.pom",            // an upstream miss
		"/maven/.meta/prefixes.txt",
		"/maven/com/matchory/lib/1.0/other-1.0.jar", // names nothing
		"/maven/",
	} {
		w := do(h, "GET", path, nil)
		if w.Code != 404 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
			t.Errorf("%s: %d %q %s", path, w.Code, w.Header().Get("Content-Type"), w.Body)
		}
	}
	// A source's 404 RequestError is still plain text.
	st := storageFake()
	st.err = &RequestError{Status: 404, Title: "Not Found", Detail: "gone"}
	w := do(server(t, []Source{st}, readAll), "GET", jarPath, nil)
	if w.Code != 404 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("RequestError 404: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
}

// recordingReader records whether the body was read.
type recordingReader struct {
	r    io.Reader
	read atomic.Bool
}

func (r *recordingReader) Read(p []byte) (int, error) {
	r.read.Store(true)
	return r.r.Read(p)
}

func TestDeployRouting(t *testing.T) {
	put := func(h http.Handler, path, body string) *httptest.ResponseRecorder {
		return do(h, "PUT", path, strings.NewReader(body))
	}
	reg := registryFake()

	// No storage source claims the coordinates.
	h := server(t, []Source{storageFake(), reg}, writeAll)
	if w := put(h, "/maven/org/x/y/1.0/y-1.0.jar", "x"); w.Code != 403 || problemOf(t, w).Detail != "no storage source claims org.x:y" {
		t.Fatalf("unclaimed: %d %s", w.Code, w.Body)
	}
	// Claimed only by a registry.
	claimingReg := registryFake()
	claimingReg.claims = []string{"com.matchory"}
	h = server(t, []Source{claimingReg}, writeAll)
	if w := put(h, jarPath, "x"); w.Code != 403 || problemOf(t, w).Detail != "no storage source claims com.matchory:lib" {
		t.Fatalf("registry only: %d %s", w.Code, w.Body)
	}
	// A registry claiming the coordinates first.
	h = server(t, []Source{claimingReg, storageFake()}, writeAll)
	if w := put(h, jarPath, "x"); w.Code != 409 {
		t.Fatalf("registry first: %d %s", w.Code, w.Body)
	} else {
		problemOf(t, w)
	}

	// Refused PUTs never read the body (an Expect: 100-continue client
	// never sends it).
	for name, tc := range map[string]struct {
		srcs  []Source
		rules []string
	}{
		"no write rule":  {[]Source{storageFake()}, []string{readAll}},
		"unclaimed":      {[]Source{storageFake(), reg}, []string{writeAll}},
		"registry first": {[]Source{claimingReg, storageFake()}, []string{writeAll}},
	} {
		h := server(t, tc.srcs, tc.rules...)
		path := jarPath
		if name == "unclaimed" {
			path = "/maven/org/x/y/1.0/y-1.0.jar"
		}
		body := &recordingReader{r: strings.NewReader("JAR")}
		w := do(h, "PUT", path, body, "Expect", "100-continue")
		if w.Code < 400 || body.read.Load() {
			t.Errorf("%s: %d, body read %v", name, w.Code, body.read.Load())
		}
	}

	st := storageFake()
	h, dir := serverIn(t, []Source{st, reg}, 8, writeAll)
	// Caps by kind: artifact files max_upload, POM and metadata 1 MiB,
	// checksums 1 KiB, signatures 64 KiB.
	for _, tc := range []struct {
		path string
		cap  int
	}{
		{jarPath, 8},
		{"/maven/com/matchory/lib/1.0/lib-1.0.pom", 1 << 20},
		{"/maven/com/matchory/lib/1.0/lib-1.0.module", 1 << 20},
		{metaPath, 1 << 20},
		{"/maven/com/matchory/lib/1.0-SNAPSHOT/maven-metadata.xml", 1 << 20},
		{jarPath + ".sha1", 1 << 10},
		{metaPath + ".md5", 1 << 10},
		{"/maven/com/matchory/lib/1.0/lib-1.0.jar.asc", 64 << 10},
	} {
		if w := put(h, tc.path, strings.Repeat("x", tc.cap+1)); w.Code != 413 {
			t.Errorf("%s over cap: %d %s", tc.path, w.Code, w.Body)
		} else {
			problemOf(t, w)
		}
		// Without a declared length the cap holds while reading.
		r := httptest.NewRequest("PUT", tc.path, io.MultiReader(strings.NewReader(strings.Repeat("x", tc.cap+1))))
		r.ContentLength = -1
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 413 {
			t.Errorf("%s over cap, chunked: %d %s", tc.path, w.Code, w.Body)
		}
		if w := put(h, tc.path, strings.Repeat("y", tc.cap)); w.Code != 201 || w.Body.Len() != 0 {
			t.Errorf("%s at cap: %d %s", tc.path, w.Code, w.Body)
		}
	}
	if len(st.deployed) != 8 || st.deployed[0] != "yyyyyyyy" {
		t.Fatalf("deployed %d bodies", len(st.deployed))
	}
	if p := st.paths[5]; p.Checksum != "sha1" || p.File != "lib-1.0.jar" {
		t.Fatalf("checksum deploy path %+v", p)
	}

	for _, tc := range []struct {
		err    error
		status int
		title  string
		detail string
	}{
		{fmt.Errorf("com.matchory:lib:1.0 lib-1.0.jar: %w", ErrExists), 409, "Conflict", "com.matchory:lib:1.0 lib-1.0.jar: already exists with other content"},
		{&RequestError{Status: 400, Title: "Bad checksum", Detail: "checksum mismatch"}, 400, "Bad checksum", "checksum mismatch"},
		{&RequestError{Status: 409, Detail: "differs only in case"}, 409, "Conflict", "differs only in case"},
		{&RequestError{Status: 413, Title: "Too large", Detail: "jar too large"}, 413, "Too large", "jar too large"},
		{errors.New("disk full"), 500, "Internal Server Error", "internal server error"},
	} {
		st.deployErr = tc.err
		w := put(h, jarPath, "x")
		if w.Code != tc.status {
			t.Errorf("%v: %d %s", tc.err, w.Code, w.Body)
			continue
		}
		if p := problemOf(t, w); p.Title != tc.title || p.Detail != tc.detail {
			t.Errorf("%v: %+v", tc.err, p)
		}
	}
	if left, err := os.ReadDir(dir); err != nil || len(left) != 0 {
		t.Fatalf("spool dir: %v %v", left, err)
	}
}

// errReader fails every read.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("client went away") }

func TestDeploySpoolErrors(t *testing.T) {
	dir := t.TempDir()
	var logs bytes.Buffer
	st := storageFake()
	m := New([]Source{st}, 1<<20, dir, slog.New(slog.NewTextHandler(&logs, nil)))
	mux := http.NewServeMux()
	m.Mount(mux)
	srv := identity.Middleware(testutil.Who{Cap: hCap, Rules: []string{writeAll}}, hCap, nil)(mux)

	// A body the client fails to send is the client's fault.
	if w := do(srv, "PUT", jarPath, errReader{}); w.Code != 400 {
		t.Errorf("client read error: %d %s", w.Code, w.Body)
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("client read error logged as an error: %s", logs.String())
	}

	// A spool that cannot be written (a full disk) is ours.
	m.createTemp = func(dir, pattern string) (*os.File, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		f.Close()
		return os.Open(f.Name())
	}
	if w := do(srv, "PUT", jarPath, strings.NewReader("JAR")); w.Code != 500 {
		t.Errorf("spool write error: %d %s", w.Code, w.Body)
	} else {
		problemOf(t, w)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "spool") {
		t.Errorf("spool write error not logged: %s", logs.String())
	}
	if len(st.deployed) != 0 {
		t.Error("a body that failed to spool reached Deploy")
	}
	if left, err := os.ReadDir(dir); err != nil || len(left) != 0 {
		t.Errorf("spool dir: %v %v", left, err)
	}
}

func TestNever401(t *testing.T) {
	paths := []string{
		jarPath, jarPath + ".sha1", jarPath + ".md5", snapPath, metaPath, metaPath + ".sha256",
		"/maven/com/matchory/lib/1.0-SNAPSHOT/maven-metadata.xml", "/maven/com/matchory/maven-metadata.xml",
		"/maven/org/x/y/1.0/y-1.0.jar", "/maven/org/x/y/maven-metadata.xml.sha1",
		"/maven/.meta/prefixes.txt", "/maven/", "/maven", "/maven//com/matchory/lib/1.0/lib-1.0.jar",
	}
	errs := []error{
		nil,
		resolve.ErrNotFound,
		errors.New("boom"),
		&upstream.StatusError{Code: 401, URL: "https://repo.maven.apache.org/maven2/x"},
		context.DeadlineExceeded,
		&RequestError{Status: 401, Title: "Unauthorized", Detail: "log in"},
		ErrExists,
	}
	for _, rules := range [][]string{nil, {readAll}, {writeAll}} {
		for _, e := range errs {
			reg, st := registryFake(), storageFake()
			reg.err, st.err, st.deployErr = e, e, e
			h := server(t, []Source{st, reg}, rules...)
			for _, path := range paths {
				for _, method := range []string{"GET", "HEAD", "PUT", "DELETE", "POST"} {
					w := do(h, method, path, strings.NewReader("x"))
					if w.Code == http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "" {
						t.Errorf("rules %v, err %v: %s %s = %d", rules, e, method, path, w.Code)
					}
				}
			}
		}
	}
	// An upstream 401 and a 401 RequestError are gateway failures.
	reg := registryFake()
	reg.err = &upstream.StatusError{Code: 401, URL: "https://repo.maven.apache.org/maven2/x"}
	if w := do(server(t, []Source{reg}, readAll), "GET", "/maven/org/x/y/1.0/y-1.0.jar", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("upstream 401: %d", w.Code)
	}
	st := storageFake()
	st.deployErr = &RequestError{Status: 401, Title: "Unauthorized", Detail: "log in"}
	if w := do(server(t, []Source{st}, writeAll), "PUT", jarPath, strings.NewReader("x")); w.Code != http.StatusBadGateway {
		t.Fatalf("RequestError 401: %d", w.Code)
	}
}

func TestBaseWithoutSlash(t *testing.T) {
	st := storageFake()
	h := server(t, []Source{st}, writeAll)
	for _, method := range []string{"GET", "HEAD"} {
		w := do(h, method, "/maven", nil)
		if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "/maven/" {
			t.Fatalf("%s /maven: %d %q", method, w.Code, w.Header().Get("Location"))
		}
	}
	if w := do(h, "PUT", "/maven", strings.NewReader("x")); w.Code != 405 {
		t.Fatalf("PUT /maven: %d", w.Code)
	}
	w := do(h, "GET", "/maven//com/matchory/lib/1.0/lib-1.0.jar", nil)
	if w.Code != 200 || w.Body.String() != jarBody || w.Header().Get("ETag") != `"{SHA1{`+sha1Hex(jarBody)+`}}"` {
		t.Fatalf("doubled slash GET: %d %v %s", w.Code, w.Header(), w.Body)
	}
	if w := do(h, "PUT", "/maven//com/matchory//lib/1.0/lib-1.0.pom", strings.NewReader("POM")); w.Code != 201 {
		t.Fatalf("doubled slash PUT: %d %v %s", w.Code, w.Header(), w.Body)
	}
	if len(st.paths) != 1 || st.paths[0].String() != "com/matchory/lib/1.0/lib-1.0.pom" {
		t.Fatalf("deployed %+v", st.paths)
	}
}

func TestDelete405(t *testing.T) {
	h := server(t, []Source{storageFake()}, writeAll)
	for _, path := range []string{jarPath, metaPath, jarPath + ".sha1", "/maven/", "/maven/.meta/prefixes.txt"} {
		for _, method := range []string{"DELETE", "POST"} {
			w := do(h, method, path, nil)
			if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD, PUT" {
				t.Errorf("%s %s: %d %q", method, path, w.Code, w.Header().Get("Allow"))
				continue
			}
			problemOf(t, w)
		}
	}
}

func TestMalformedRulesMatchNothing(t *testing.T) {
	var buf bytes.Buffer
	mux := http.NewServeMux()
	New([]Source{storageFake()}, 1<<20, t.TempDir(), slog.New(slog.NewTextHandler(&buf, nil))).Mount(mux)
	h := identity.Middleware(testutil.Who{Cap: hCap, Rules: []string{`{"read":["maven:Com.Matchory","maven:*:lib","nocolon","npm:*"]}`}}, hCap, nil)(mux)
	if w := do(h, "GET", jarPath, nil); w.Code != 403 {
		t.Fatalf("%d", w.Code)
	}
	out := buf.String()
	if strings.Count(out, "malformed") != 1 || !strings.Contains(out, "maven:Com.Matchory") || !strings.Contains(out, "maven:*:lib") || !strings.Contains(out, "nocolon") || strings.Contains(out, "npm:*") {
		t.Fatalf("log: %s", out)
	}
}
