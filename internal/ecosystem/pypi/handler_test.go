package pypi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/testutil"
	"tailscale.com/tailcfg/peercap"
)

const hCap peercap.Cap = "github.com/radiergummi/tspackages"

const readAll = `{"read":["*"]}`

type fakeSource struct {
	name     string
	claims   []string
	projects map[string]Project
	files    map[string][]byte // by filename; "<filename>.metadata" for metadata
	err      error
	calls    atomic.Int32
	fileHits atomic.Int32
}

func (f *fakeSource) Name() string     { return f.name }
func (f *fakeSource) Claims() []string { return f.claims }

func (f *fakeSource) Project(_ context.Context, name string) (Project, error) {
	f.calls.Add(1)
	if f.err != nil {
		return Project{}, f.err
	}
	p, ok := f.projects[name]
	if !ok {
		return Project{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, name)
	}
	return p, nil
}

func (f *fakeSource) artifact(key string) (Artifact, error) {
	b, ok := f.files[key]
	if !ok {
		return Artifact{}, resolve.ErrNotFound
	}
	return Artifact{Body: io.NopCloser(bytes.NewReader(b)), Size: int64(len(b))}, nil
}

func (f *fakeSource) File(_ context.Context, _, filename string) (Artifact, error) {
	f.fileHits.Add(1)
	if f.err != nil {
		return Artifact{}, f.err
	}
	return f.artifact(filename)
}

func (f *fakeSource) Metadata(_ context.Context, _, filename string) (Artifact, error) {
	return f.artifact(filename + ".metadata")
}

func (f *fakeSource) Provenance(context.Context, string, string) (Artifact, error) {
	return Artifact{}, resolve.ErrNotFound
}

func (f *fakeSource) Names(context.Context) ([]string, error) {
	var out []string
	for n := range f.projects {
		out = append(out, n)
	}
	return out, nil
}

type fakeUploader struct {
	*fakeSource
	mu      sync.Mutex
	uploads []Upload
	content [][]byte
	err     error
}

func (u *fakeUploader) Upload(_ context.Context, _ identity.Caller, up Upload) (File, error) {
	if u.err != nil {
		return File{}, u.err
	}
	b, err := io.ReadAll(up.Content)
	if err != nil {
		return File{}, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.uploads = append(u.uploads, up)
	u.content = append(u.content, b)
	return File{Filename: up.Filename}, nil
}

func project(name string, files ...string) Project {
	p := Project{Name: name}
	for _, f := range files {
		p.Files = append(p.Files, File{Filename: f, SHA256: "ab"})
	}
	return p
}

func server(t *testing.T, srcs []Source, rules ...string) http.Handler {
	t.Helper()
	h, _ := serverIn(t, srcs, rules...)
	return h
}

// serverIn also returns the directory uploads are spooled in.
func serverIn(t *testing.T, srcs []Source, rules ...string) (http.Handler, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "uploads")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(srcs, 1<<20, dir, slog.New(slog.DiscardHandler)).Mount(mux)
	return identity.Middleware(testutil.Who{Cap: hCap, Rules: rules}, hCap, nil)(mux), dir
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

// hosted claims acme-*; public is the unclaimed pass-through.
func hostedAndPublic() (*fakeSource, *fakeSource) {
	hosted := &fakeSource{name: "hosted", claims: []string{"acme-*"},
		projects: map[string]Project{"acme-core": project("acme-core", "acme_core-1.0.0-py3-none-any.whl")},
		files:    map[string][]byte{"acme_core-1.0.0-py3-none-any.whl": []byte("WHEEL"), "acme_core-1.0.0-py3-none-any.whl.metadata": []byte("Metadata-Version: 2.1")}}
	public := &fakeSource{name: "public",
		projects: map[string]Project{"requests": project("requests", "requests-2.0.0.tar.gz"), "acme-core": project("acme-core", "acme_core-9.9.9.tar.gz")},
		files:    map[string][]byte{"requests-2.0.0.tar.gz": []byte("SDIST")}}
	return hosted, public
}

// Review Focus 1: unnormalised names and a missing slash redirect to the
// canonical page before any source is asked.
func TestSimpleRedirectsToNormalised(t *testing.T) {
	hosted, public := hostedAndPublic()
	h := server(t, []Source{hosted, public}, readAll)
	for _, path := range []string{"/pypi/simple/Acme_Core/", "/pypi/simple/acme.core", "/pypi/simple/acme-core"} {
		w := do(h, "GET", path, nil)
		if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/pypi/simple/acme-core/" {
			t.Errorf("%s: %d Location=%q", path, w.Code, w.Header().Get("Location"))
		}
	}
	if hosted.calls.Load()+public.calls.Load() != 0 {
		t.Fatal("a source was asked before the redirect")
	}
	if w := do(h, "GET", "/pypi/simple/-bad-/", nil); w.Code != http.StatusNotFound {
		t.Fatalf("invalid name: %d", w.Code)
	}
}

func TestSimpleServesProjectWithLocalURLs(t *testing.T) {
	hosted, public := hostedAndPublic()
	h := server(t, []Source{hosted, public}, readAll)
	w := do(h, "GET", "/pypi/simple/acme-core/", nil, "Accept", "application/vnd.pypi.simple.v1+json")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"url":"http://example.com/pypi/files/hosted/acme-core/acme_core-1.0.0-py3-none-any.whl"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w.Header().Get("Vary") == "" || !strings.Contains(w.Header().Get("Vary"), "Accept") {
		t.Errorf("Vary = %q", w.Header().Get("Vary"))
	}
}

// A claimed name never falls through to the unclaimed source.
func TestSimpleClaimedNeverFallsThrough(t *testing.T) {
	hosted, public := hostedAndPublic()
	h := server(t, []Source{hosted, public}, readAll)
	if w := do(h, "GET", "/pypi/simple/acme-other/", nil); w.Code != http.StatusNotFound {
		t.Fatalf("%d", w.Code)
	}
	if public.calls.Load() != 0 {
		t.Fatal("unclaimed source consulted for a claimed name")
	}
	hosted.err = errors.New("store down")
	if w := do(h, "GET", "/pypi/simple/acme-core/", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("failing claimed source: %d", w.Code)
	}
	if public.calls.Load() != 0 {
		t.Fatal("fell through on an error")
	}
}

func TestSimpleForbidden(t *testing.T) {
	hosted, public := hostedAndPublic()
	h := server(t, []Source{hosted, public}, `{"read":["pypi:requests"]}`)
	if w := do(h, "GET", "/pypi/simple/acme-core/", nil); w.Code != http.StatusForbidden {
		t.Fatalf("%d", w.Code)
	}
	if w := do(h, "GET", "/pypi/files/hosted/acme-core/acme_core-1.0.0-py3-none-any.whl", nil); w.Code != http.StatusForbidden {
		t.Fatalf("file: %d", w.Code)
	}
	if hosted.calls.Load()+hosted.fileHits.Load() != 0 {
		t.Fatal("source asked before authorization")
	}
}

func TestFileAndMetadata(t *testing.T) {
	hosted, public := hostedAndPublic()
	h := server(t, []Source{hosted, public}, readAll)
	w := do(h, "GET", "/pypi/files/hosted/acme-core/acme_core-1.0.0-py3-none-any.whl", nil)
	if w.Code != 200 || w.Body.String() != "WHEEL" || w.Header().Get("Content-Length") != "5" {
		t.Fatalf("file: %d %q %v", w.Code, w.Body, w.Header())
	}
	w = do(h, "GET", "/pypi/files/hosted/acme-core/acme_core-1.0.0-py3-none-any.whl.metadata", nil)
	if w.Code != 200 || w.Body.String() != "Metadata-Version: 2.1" {
		t.Fatalf("metadata: %d %q", w.Code, w.Body)
	}
	if w := do(h, "HEAD", "/pypi/files/hosted/acme-core/acme_core-1.0.0-py3-none-any.whl", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD: %d", w.Code)
	}
}

// With two candidates, a file is served only by the source the index
// resolves the name to.
func TestFileOnlyFromResolvingSource(t *testing.T) {
	hosted, public := hostedAndPublic()
	public.files["acme_core-9.9.9.tar.gz"] = []byte("DECOY")
	first := &fakeSource{name: "first", claims: []string{"acme-*"}, projects: map[string]Project{"acme-core": project("acme-core")}}
	second := &fakeSource{name: "second", claims: []string{"acme-*"}, projects: hosted.projects, files: hosted.files}
	h := server(t, []Source{first, second, public}, readAll)
	if w := do(h, "GET", "/pypi/files/second/acme-core/acme_core-1.0.0-py3-none-any.whl", nil); w.Code != http.StatusNotFound || second.fileHits.Load() != 0 {
		t.Fatalf("shadowed source served: %d", w.Code)
	}
	if w := do(h, "GET", "/pypi/files/public/acme-core/acme_core-9.9.9.tar.gz", nil); w.Code != http.StatusNotFound || public.fileHits.Load() != 0 {
		t.Fatalf("unclaimed source served a claimed name: %d", w.Code)
	}
}

type brokenBody struct{ n int }

func (b *brokenBody) Read(p []byte) (int, error) {
	if b.n > 0 {
		b.n--
		return copy(p, "data"), nil
	}
	return 0, errors.New("disk exploded")
}
func (b *brokenBody) Close() error { return nil }

type brokenSource struct{ *fakeSource }

func (b brokenSource) File(context.Context, string, string) (Artifact, error) {
	return Artifact{Body: &brokenBody{n: 2}, Size: 100}, nil
}

func TestFileAbortsOnMidStreamError(t *testing.T) {
	b := brokenSource{&fakeSource{name: "b", claims: []string{"acme-*"}, projects: map[string]Project{"acme-x": project("acme-x")}}}
	srv := httptest.NewServer(server(t, []Source{b}, readAll))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/pypi/files/b/acme-x/acme_x-1.0.tar.gz")
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("the client read a complete response")
	}
}

func TestIndexListsOnlyReadable(t *testing.T) {
	hosted := &fakeSource{name: "hosted", claims: []string{"*"}, projects: map[string]Project{"acme-a": {}, "other-b": {}}}
	h := server(t, []Source{hosted}, `{"read":["pypi:acme-*"]}`)
	w := do(h, "GET", "/pypi/simple/", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "acme-a") || strings.Contains(w.Body.String(), "other-b") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// multipartUpload builds a legacy upload request body.
func multipartUpload(t *testing.T, fields map[string]string, filename string, content []byte) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	if filename != "" {
		fw, err := mw.CreateFormFile("content", filename)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write(content)
	}
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func uploadFields(name, version string) map[string]string {
	return map[string]string{":action": "file_upload", "protocol_version": "1", "name": name, "version": version, "metadata_version": "2.1"}
}

func TestUploadRoutesToFirstClaimingUploader(t *testing.T) {
	hosted, public := hostedAndPublic()
	u := &fakeUploader{fakeSource: hosted}
	h, spool := serverIn(t, []Source{u, public}, `{"read":["*"],"write":["pypi:acme-*"]}`)
	body, ct := multipartUpload(t, uploadFields("Acme_Core", "1.1.0"), "acme_core-1.1.0.tar.gz", []byte("TARGZ"))
	w := do(h, "POST", "/pypi/legacy/", body, "Content-Type", ct)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(u.uploads) != 1 || u.uploads[0].Name != "Acme_Core" || u.uploads[0].Filename != "acme_core-1.1.0.tar.gz" || string(u.content[0]) != "TARGZ" {
		t.Fatalf("uploads = %+v", u.uploads)
	}
	if entries, _ := os.ReadDir(spool); len(entries) != 0 {
		t.Fatalf("spooled upload left behind: %v", entries)
	}
}

func TestUploadStatuses(t *testing.T) {
	hosted, public := hostedAndPublic()
	u := &fakeUploader{fakeSource: hosted}
	write := `{"read":["*"],"write":["pypi:acme-*"]}`
	h := server(t, []Source{u, public}, write)
	post := func(h http.Handler, fields map[string]string, filename string, content []byte) *httptest.ResponseRecorder {
		body, ct := multipartUpload(t, fields, filename, content)
		return do(h, "POST", "/pypi/legacy/", body, "Content-Type", ct)
	}
	if w := post(h, uploadFields("acme-core", "1.0"), "acme_core-1.0.tar.gz", bytes.Repeat([]byte("x"), 2<<20)); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("too large: %d", w.Code)
	}
	if w := post(server(t, []Source{u, public}, readAll), uploadFields("acme-core", "1.0"), "acme_core-1.0.tar.gz", []byte("x")); w.Code != http.StatusForbidden {
		t.Errorf("no write rule: %d", w.Code)
	}
	if w := post(h, uploadFields("requests", "1.0"), "requests-1.0.tar.gz", []byte("x")); w.Code != http.StatusForbidden {
		t.Errorf("unclaimed name: %d", w.Code)
	}
	bad := uploadFields("acme-core", "1.0")
	bad[":action"] = "submit"
	if w := post(h, bad, "acme_core-1.0.tar.gz", []byte("x")); w.Code != http.StatusBadRequest {
		t.Errorf("wrong action: %d", w.Code)
	}
	if w := post(h, uploadFields("acme-core", "1.0"), "", nil); w.Code != http.StatusBadRequest {
		t.Errorf("no content: %d", w.Code)
	}
	u.err = ErrFileExists
	if w := post(h, uploadFields("acme-core", "1.0"), "acme_core-1.0.tar.gz", []byte("x")); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "File already exists") {
		t.Errorf("exists: %d %s", w.Code, w.Body)
	}
	u.err = &UploadError{Reason: "name mismatch"}
	if w := post(h, uploadFields("acme-core", "1.0"), "acme_core-1.0.tar.gz", []byte("x")); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "name mismatch") {
		t.Errorf("upload error: %d %s", w.Code, w.Body)
	}
	// An earlier source also claims the name: the upload would never be served.
	other := &fakeSource{name: "git", claims: []string{"acme-*"}}
	h2 := server(t, []Source{other, &fakeUploader{fakeSource: &fakeSource{name: "hosted2", claims: []string{"acme-core"}}}}, write)
	if w := post(h2, uploadFields("acme-core", "1.0"), "acme_core-1.0.tar.gz", []byte("x")); w.Code != http.StatusConflict {
		t.Errorf("shadowed uploader: %d", w.Code)
	}
}
