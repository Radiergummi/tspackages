//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/sumdb/note"
	modzip "golang.org/x/mod/zip"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/server"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

// Private module paths. Their repositories live at <repos>/acme/<name>, so
// testutil.GoListModule resolves the same paths over direct VCS.
const (
	modM     = "git.test/acme/m.git" // root module, tags v1.0.0 and v1.1.0, plus main beyond them
	modTools = modM + "/tools"       // dir module "tools", tag tools/v0.1.0
	modMv2   = modM + "/v2"          // subdirectory style: v2/go.mod at tag v2.0.0
	modB     = "git.test/acme/b.git" // tags v1.0.0 and v2.0.0
	modBv2   = modB + "/v2"          // branch style: go.mod declares /v2 at tag v2.0.0
	modU     = "git.test/acme/u.git" // untagged

	modPub    = "example.com/pub"    // public, served by the fake GOPROXY
	modTamper = "example.com/tamper" // public, its zip can be tampered with
)

func needGo(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"go", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not on PATH")
		}
	}
}

// pubModule is a public module version as a GOPROXY serves it.
type pubModule struct {
	gomod, zip []byte
	record     string // the checksum database's go.sum lines
}

// diskFile is a modzip.File read from disk.
type diskFile struct{ name, path string }

func (f diskFile) Path() string                 { return f.name }
func (f diskFile) Lstat() (os.FileInfo, error)  { return os.Lstat(f.path) }
func (f diskFile) Open() (io.ReadCloser, error) { return os.Open(f.path) }

// newPubModule builds path@version holding a go.mod and files with
// modzip.Create, and its checksum database record.
func newPubModule(t *testing.T, path, version string, files map[string]string) pubModule {
	t.Helper()
	gomod := "module " + path + "\n\ngo 1.21\n"
	all := map[string]string{"go.mod": gomod}
	maps.Copy(all, files)
	dir := t.TempDir()
	writeTree(t, dir, all)
	var list []modzip.File
	for n := range all {
		list = append(list, diskFile{name: n, path: filepath.Join(dir, n)})
	}
	var buf bytes.Buffer
	if err := modzip.Create(&buf, module.Version{Path: path, Version: version}, list); err != nil {
		t.Fatal(err)
	}
	zipFile := filepath.Join(t.TempDir(), "m.zip")
	if err := os.WriteFile(zipFile, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	zh, err := dirhash.HashZip(zipFile, dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	mh, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(gomod)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return pubModule{
		gomod:  []byte(gomod),
		zip:    buf.Bytes(),
		record: fmt.Sprintf("%s %s %s\n%s %s/go.mod %s\n", path, version, zh, path, version, mh),
	}
}

// fakeGoProxy is proxy.golang.org for modPub and modTamper at v1.0.0. While
// tampered, modTamper's zip is a valid zip with one content byte flipped.
type fakeGoProxy struct {
	*httptest.Server
	mods     map[string]pubModule // path → v1.0.0
	tampered []byte
	mu       sync.Mutex
	tamper   bool
	paths    []string
}

func newFakeGoProxy(t *testing.T) *fakeGoProxy {
	t.Helper()
	f := &fakeGoProxy{mods: map[string]pubModule{
		modPub:    newPubModule(t, modPub, "v1.0.0", map[string]string{"pub.go": "package pub\n\nconst Name = \"pub\"\n"}),
		modTamper: newPubModule(t, modTamper, "v1.0.0", map[string]string{"t.go": "package tamper\n"}),
	}}
	f.tampered = newPubModule(t, modTamper, "v1.0.0", map[string]string{"t.go": "package tampes\n"}).zip
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeGoProxy) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	tamper := f.tamper
	f.mu.Unlock()
	esc, rest, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/@v/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	path, err := module.UnescapePath(esc)
	m, known := f.mods[path]
	if err != nil || !known {
		http.NotFound(w, r)
		return
	}
	switch rest {
	case "list":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "v1.0.0\n")
	case "v1.0.0.info":
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`)
	case "v1.0.0.mod":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(m.gomod)
	case "v1.0.0.zip":
		w.Header().Set("Content-Type", "application/zip")
		if tamper && path == modTamper {
			w.Write(f.tampered)
			return
		}
		w.Write(m.zip)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGoProxy) setTamper(v bool) { f.mu.Lock(); f.tamper = v; f.mu.Unlock() }

func (f *fakeGoProxy) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

// testSumDB is an offline sum.golang.org that knows the fake GOPROXY's
// modules and counts the requests it gets.
type testSumDB struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func newTestSumDB(t *testing.T, signer string, proxy *fakeGoProxy) *testSumDB {
	t.Helper()
	h := sumdb.NewServer(sumdb.NewTestServer(signer, func(path, vers string) ([]byte, error) {
		if m, ok := proxy.mods[path]; ok && vers == "v1.0.0" {
			return []byte(m.record), nil
		}
		return nil, os.ErrNotExist
	}))
	s := &testSumDB{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		s.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *testSumDB) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

// goRegistry is a fully wired tspackages whose Go endpoint has a git source
// "acme" for the private modules and a registry source "public" in front of
// a fake GOPROXY, verified against an offline checksum database.
type goRegistry struct {
	t     *testing.T
	root  string
	repos string
	cfg   *config.Config
	rules string
	key   string // the checksum database's verifier key
	proxy *fakeGoProxy
	sumdb *testSumDB
	URL   string
	stop  func()

	mu    sync.Mutex
	paths []string // requests tspackages received
}

// startGoRegistry creates the private repositories, waits for nothing and
// starts tspackages with rules for every caller ({"read":["go:*"]} if "").
func startGoRegistry(t *testing.T, rules string) *goRegistry {
	t.Helper()
	needGo(t)
	if rules == "" {
		rules = `{"read":["go:*"]}`
	}
	root := t.TempDir()
	r := &goRegistry{t: t, root: root, repos: filepath.Join(root, "repos"), rules: rules, proxy: newFakeGoProxy(t)}
	signer, verifier, err := note.GenerateKey(rand.Reader, "sum.golang.org")
	if err != nil {
		t.Fatal(err)
	}
	r.key = verifier
	r.sumdb = newTestSumDB(t, signer, r.proxy)

	m := r.newRepo("m.git")
	r.commit(m, map[string]string{
		"go.mod":       "module " + modM + "\n\ngo 1.21\n",
		"m.go":         "package m\n\nconst Version = \"v1.0.0\"\n",
		"tools/go.mod": "module " + modTools + "\n\ngo 1.21\n",
		"tools/t.go":   "package tools\n",
	})
	testutil.Git(t, m, "tag", "v1.0.0")
	testutil.Git(t, m, "tag", "tools/v0.1.0")
	r.commit(m, map[string]string{"m.go": "package m\n\nconst Version = \"between\"\n"})
	r.commit(m, map[string]string{
		"m.go":      "package m\n\nconst Version = \"v1.1.0\"\n",
		"v2/go.mod": "module " + modMv2 + "\n\ngo 1.21\n",
		"v2/m.go":   "package m\n",
	})
	testutil.Git(t, m, "tag", "v1.1.0")
	testutil.Git(t, m, "tag", "v2.0.0")
	r.commit(m, map[string]string{"m.go": "package m\n\nconst Version = \"main\"\n"})

	b := r.newRepo("b.git")
	r.commit(b, map[string]string{"go.mod": "module " + modB + "\n\ngo 1.21\n", "b.go": "package b\n"})
	testutil.Git(t, b, "tag", "v1.0.0")
	r.commit(b, map[string]string{"go.mod": "module " + modBv2 + "\n\ngo 1.21\n"})
	testutil.Git(t, b, "tag", "v2.0.0")

	u := r.newRepo("u.git")
	r.commit(u, map[string]string{"go.mod": "module " + modU + "\n\ngo 1.21\n", "u.go": "package u\n"})

	pu, _ := url.Parse(r.proxy.URL)
	su, _ := url.Parse(r.sumdb.URL)
	r.cfg = &config.Config{
		Tailscale: config.Tailscale{Hostname: "registry", Capability: capName, StateDir: filepath.Join(root, "ts")},
		Storage: config.Storage{
			WorkDir: filepath.Join(root, "work"),
			Cache:   config.StoreConfig{Driver: "fs", Path: filepath.Join(root, "cache"), MaxSize: 1 << 30},
			State:   config.StoreConfig{Driver: "fs", Path: filepath.Join(root, "state")},
		},
		Ecosystems: map[string]config.Ecosystem{"go": {Sources: []config.Source{
			{
				Name: "acme", Type: "git", Claims: []string{"git.test/acme", "git.test/acme/*"},
				Modules: map[string]config.GoModule{
					modM:     {Remote: m},
					modTools: {Remote: m, Dir: "tools"},
					modB:     {Remote: b},
					modU:     {Remote: u},
				},
				Branches: []string{"main"}, PollInterval: 200 * time.Millisecond,
			},
			{
				Name: "public", Type: "registry", URL: r.proxy.URL,
				FetchHosts: []string{"proxy.golang.org", "sum.golang.org", pu.Host, su.Host},
			},
		}}},
	}
	r.start()
	return r
}

// start builds tspackages on r.cfg's stores and serves it on a new URL.
func (r *goRegistry) start() {
	r.t.Helper()
	ctx, cancel := context.WithCancel(r.t.Context())
	handler, start, err := server.Build(ctx, r.cfg, testutil.NewWho(capName, r.rules), nil, slog.New(slog.DiscardHandler),
		server.Hooks{AllowPrivateUpstreams: true, AllowFileRemotes: true, GoSumDB: server.GoSumDB{URL: r.sumdb.URL, Key: r.key}})
	if err != nil {
		cancel()
		r.t.Fatal(err)
	}
	loops := make(chan struct{})
	go func() { start(ctx); close(loops) }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.paths = append(r.paths, req.URL.Path)
		r.mu.Unlock()
		handler.ServeHTTP(w, req)
	}))
	var once sync.Once
	// The git loop writes below root: stop it before TempDir cleanup.
	r.stop = func() { once.Do(func() { srv.Close(); cancel(); <-loops }) }
	r.t.Cleanup(r.stop)
	r.URL = srv.URL
}

func (r *goRegistry) newRepo(name string) string {
	r.t.Helper()
	dir := filepath.Join(r.repos, "acme", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	testutil.Git(r.t, dir, "init", "-q")
	return dir
}

// commit writes files into the repository at dir, commits them and returns
// the commit SHA.
func (r *goRegistry) commit(dir string, files map[string]string) string {
	r.t.Helper()
	writeTree(r.t, dir, files)
	testutil.Git(r.t, dir, "add", "-A")
	testutil.Git(r.t, dir, "commit", "-q", "-m", "c")
	return testutil.Git(r.t, dir, "rev-parse", "HEAD")
}

func (r *goRegistry) saw(path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.paths, path)
}

func (r *goRegistry) get(path string) (int, string) {
	r.t.Helper()
	resp, err := http.Get(r.URL + path)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// waitFor polls path until it answers 200 with a body containing want.
func (r *goRegistry) waitFor(path, want string) {
	r.t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; {
		if code, body := r.get(path); code == http.StatusOK && strings.Contains(body, want) {
			return
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("%s never contained %s", path, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitForVersion waits until the git source lists version of path.
func (r *goRegistry) waitForVersion(path, version string) {
	r.t.Helper()
	esc, err := module.EscapePath(path)
	if err != nil {
		r.t.Fatal(err)
	}
	r.waitFor("/go/"+esc+"/@v/list", version+"\n")
}

var gonosumdbLine = regexp.MustCompile(`go env -w GONOSUMDB=([^\s<]+)`)

// noSumDB returns the GONOSUMDB value the status page's snippet sets.
func (r *goRegistry) noSumDB() string {
	r.t.Helper()
	_, page := r.get("/")
	m := gonosumdbLine.FindStringSubmatch(page)
	if m == nil {
		r.t.Fatalf("status page has no GONOSUMDB line:\n%s", page)
	}
	return m[1]
}

// sidecar returns the stored version.json hashes of a tag version.
func (r *goRegistry) sidecar(path, version string) (zipH1, modH1 string) {
	r.t.Helper()
	d, err := storage.Open(r.t.Context(), r.cfg.Storage.State)
	if err != nil {
		r.t.Fatal(err)
	}
	rc, _, err := d.Get(r.t.Context(), "go-git/acme/"+storage.EscapeSegment(path)+"/"+storage.EscapeSegment(version)+"/version.json")
	if err != nil {
		r.t.Fatalf("version.json of %s@%s: %v", path, version, err)
	}
	defer rc.Close()
	var rec struct {
		ZipH1 string `json:"zip_h1"`
		ModH1 string `json:"mod_h1"`
	}
	if err := json.NewDecoder(rc).Decode(&rec); err != nil {
		r.t.Fatal(err)
	}
	return rec.ZipH1, rec.ModH1
}

// goClient is one machine's go command: its own HOME, module cache and
// GOPATH, so a new client downloads everything again.
type goClient struct {
	r   *goRegistry
	env []string
}

// client returns a go command pointed at tspackages only. withNoSumDB sets
// GONOSUMDB as the status page prints it.
func (r *goRegistry) client(withNoSumDB bool) *goClient {
	r.t.Helper()
	tmp := r.t.TempDir()
	// Telemetry off in the config file, not the environment: otherwise the
	// go command leaves a child process writing below HOME after it exits.
	confDir := ".config"
	if runtime.GOOS == "darwin" {
		confDir = filepath.Join("Library", "Application Support")
	}
	writeTree(r.t, tmp, map[string]string{filepath.Join(confDir, "go", "telemetry", "mode"): "off"})
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + tmp,
		"GOPROXY=" + r.URL + "/go",
		"GOSUMDB=" + r.key,
		"GOFLAGS=-modcacherw",
		"GOTOOLCHAIN=local",
		"GOMODCACHE=" + filepath.Join(tmp, "modcache"),
		"GOPATH=" + filepath.Join(tmp, "gopath"),
	}
	if withNoSumDB {
		env = append(env, "GONOSUMDB="+r.noSumDB())
	}
	return &goClient{r: r, env: env}
}

// run runs the go command in dir ("" is a fresh directory outside any
// module) and returns its combined output.
func (c *goClient) run(dir string, args ...string) (string, error) {
	t := c.r.t
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = c.env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (c *goClient) must(dir string, args ...string) string {
	c.r.t.Helper()
	out, err := c.run(dir, args...)
	if err != nil {
		c.r.t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

type downloaded struct{ Version, Sum, GoModSum, Error string }

// download runs `go mod download -json query` outside a module.
func (c *goClient) download(query string) (downloaded, error) {
	c.r.t.Helper()
	cmd := exec.CommandContext(c.r.t.Context(), "go", "mod", "download", "-json", query)
	cmd.Dir = c.r.t.TempDir()
	cmd.Env = c.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var d downloaded
	if jerr := json.Unmarshal(stdout.Bytes(), &d); jerr != nil {
		return d, fmt.Errorf("%w; output %s%s", errors.Join(err, jerr), stdout.Bytes(), stderr.Bytes())
	}
	if err != nil || d.Error != "" {
		return d, fmt.Errorf("go mod download %s: %w: %s%s", query, err, d.Error, stderr.Bytes())
	}
	return d, nil
}

// project returns a new module directory with main.go holding src.
func (c *goClient) project(src string) string {
	c.r.t.Helper()
	dir := c.r.t.TempDir()
	writeTree(c.r.t, dir, map[string]string{"go.mod": "module example.test/app\n\ngo 1.21\n", "main.go": src})
	return dir
}

// version returns the version of path that the module in dir requires.
func (c *goClient) version(dir, path string) string {
	c.r.t.Helper()
	return strings.TrimSpace(c.must(dir, "list", "-m", "-f", "{{.Version}}", path))
}

func TestGoModDownloadTagged(t *testing.T) {
	r := startGoRegistry(t, "")
	r.waitForVersion(modM, "v1.0.0")
	zipH1, modH1 := r.sidecar(modM, "v1.0.0")
	d, err := r.client(true).download(modM + "@v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if d.Sum != zipH1 || d.GoModSum != modH1 {
		t.Fatalf("go mod download: Sum %s GoModSum %s; sidecar %s %s", d.Sum, d.GoModSum, zipH1, modH1)
	}
	// The same hashes the go command computes over direct VCS.
	sum, goModSum := testutil.GoModDownload(t, r.repos, modM, "v1.0.0")
	if d.Sum != sum || d.GoModSum != goModSum {
		t.Fatalf("through tspackages %s %s; direct VCS %s %s", d.Sum, d.GoModSum, sum, goModSum)
	}
}

func TestGoGetLatestTaggedAndUntagged(t *testing.T) {
	r := startGoRegistry(t, "")
	r.waitForVersion(modM, "v1.1.0")
	c := r.client(true)
	dir := c.project("package main\n\nfunc main() {}\n")
	c.must(dir, "get", modM+"@latest")
	if v := c.version(dir, modM); v != "v1.1.0" {
		t.Errorf("%s@latest = %s, want v1.1.0", modM, v)
	}
	c.must(dir, "get", modU+"@latest")
	want, _ := testutil.GoListModule(t, r.repos, modU+"@main")
	if v := c.version(dir, modU); v != want {
		t.Errorf("%s@latest = %s, want the main pseudo-version %s", modU, v, want)
	}
}

func TestGoGetBranchAndSha(t *testing.T) {
	r := startGoRegistry(t, "")
	r.waitForVersion(modM, "v1.1.0")
	between := testutil.Git(t, filepath.Join(r.repos, "acme", "m.git"), "rev-parse", "v1.1.0~1")
	c := r.client(true)
	dir := c.project("package main\n\nfunc main() {}\n")
	for _, rev := range []string{"main", between, between[:12]} {
		want, _ := testutil.GoListModule(t, r.repos, modM+"@"+rev)
		c.must(dir, "get", modM+"@"+rev)
		if v := c.version(dir, modM); v != want {
			t.Errorf("%s@%s = %s, want %s", modM, rev, v, want)
		}
	}
}

func TestGoListVersions(t *testing.T) {
	r := startGoRegistry(t, "")
	for path, want := range map[string]string{
		modM:     "v1.0.0 v1.1.0",
		modTools: "v0.1.0",
		modBv2:   "v2.0.0",
		modMv2:   "v2.0.0",
	} {
		r.waitForVersion(path, strings.Fields(want)[0])
		out := r.client(true).must("", "list", "-m", "-versions", path)
		if got := strings.TrimSpace(out); got != path+" "+want {
			t.Errorf("go list -m -versions %s = %q, want %q", path, got, path+" "+want)
		}
	}
}

func TestPrivateWithoutGONOSUMDB(t *testing.T) {
	r := startGoRegistry(t, "")
	r.waitForVersion(modM, "v1.0.0")
	_, err := r.client(false).download(modM + "@v1.0.0")
	t.Logf("without GONOSUMDB: %v", err)
	if err == nil || !strings.Contains(err.Error(), modM+" is private: add it to GONOSUMDB") {
		t.Fatalf("go mod download without GONOSUMDB: %v", err)
	}
	if !r.saw("/go/sumdb/sum.golang.org/lookup/" + modM + "@v1.0.0") {
		t.Error("the go command did not look the private module up through tspackages")
	}
	if seen := r.sumdb.seen(); len(seen) != 0 {
		t.Errorf("the checksum database received requests: %v", seen)
	}
}

func TestPublicVerifiedThroughProxy(t *testing.T) {
	r := startGoRegistry(t, "")
	c := r.client(true)
	dir := c.project("package main\n\nimport \"example.com/pub\"\n\nfunc main() { println(pub.Name) }\n")
	c.must(dir, "get", modPub+"@v1.0.0")
	if out := c.must(dir, "mod", "verify"); !strings.Contains(out, "all modules verified") {
		t.Fatalf("go mod verify: %s", out)
	}
	lookup := "/lookup/" + modPub + "@v1.0.0"
	if !slices.Contains(r.sumdb.seen(), lookup) {
		t.Errorf("the checksum database never saw %s: %v", lookup, r.sumdb.seen())
	}
	if !r.saw("/go/sumdb/sum.golang.org/supported") || !r.saw("/go/sumdb/sum.golang.org"+lookup) {
		t.Error("the go command did not use tspackages' checksum database proxy")
	}
}

func TestTamperedUpstreamZipRejected(t *testing.T) {
	r := startGoRegistry(t, "")
	r.proxy.setTamper(true)
	d, err := r.client(true).download(modTamper + "@v1.0.0")
	if err == nil {
		t.Fatalf("tampered zip downloaded: %+v", d)
	}
	t.Logf("tampered: %v", err)
	r.proxy.setTamper(false)
	d, err = r.client(true).download(modTamper + "@v1.0.0")
	if err != nil {
		t.Fatalf("after the upstream was fixed: %v", err)
	}
	if want := strings.Fields(r.proxy.mods[modTamper].record)[2]; d.Sum != want {
		t.Fatalf("Sum = %s, want %s", d.Sum, want)
	}
}

func TestMovedTagStillServed(t *testing.T) {
	r := startGoRegistry(t, "")
	r.waitForVersion(modM, "v1.0.0")
	zipH1, _ := r.sidecar(modM, "v1.0.0")
	m := filepath.Join(r.repos, "acme", "m.git")
	moved := r.commit(m, map[string]string{"m.go": "package m\n\nconst Version = \"moved\"\n"})
	testutil.Git(t, m, "tag", "-f", "v1.0.0")
	r.waitFor("/", moved) // listed under moved tags
	d, err := r.client(true).download(modM + "@v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if d.Sum != zipH1 {
		t.Fatalf("moved tag served %s, want the stored %s", d.Sum, zipH1)
	}
}

func TestRestartWithRemoteUnreachable(t *testing.T) {
	r := startGoRegistry(t, "")
	r.waitForVersion(modM, "v1.0.0")
	zipH1, _ := r.sidecar(modM, "v1.0.0")
	r.stop()
	if err := os.RemoveAll(filepath.Join(r.repos, "acme", "m.git")); err != nil {
		t.Fatal(err)
	}
	r.start()
	c := r.client(true)
	d, err := c.download(modM + "@v1.0.0")
	if err != nil {
		t.Fatalf("stored version after the restart: %v", err)
	}
	if d.Sum != zipH1 {
		t.Fatalf("Sum = %s, want %s", d.Sum, zipH1)
	}
	_, err = c.download(modM + "@v1.5.0")
	t.Logf("unstored tag: %v", err)
	if err == nil || !strings.Contains(err.Error(), "502") || strings.Contains(err.Error(), "unknown revision") {
		t.Fatalf("unstored tag with the remote unreachable: %v", err)
	}
}

func TestGoAcceptanceBuild(t *testing.T) {
	r := startGoRegistry(t, "")
	r.waitForVersion(modM, "v1.1.0")
	c := r.client(true)
	dir := c.project("package main\n\nimport (\n\tm \"" + modM + "\"\n\t\"example.com/pub\"\n)\n\nfunc main() { println(m.Version, pub.Name) }\n")
	c.must(dir, "get", modM+"@v1.1.0", modPub+"@v1.0.0")
	c.must(dir, "build", "-o", "app", ".")
	if out, err := exec.CommandContext(t.Context(), filepath.Join(dir, "app")).CombinedOutput(); err != nil || string(out) != "v1.1.0 pub\n" {
		t.Fatalf("app: %q %v", out, err)
	}
	if out := c.must(dir, "mod", "verify"); !strings.Contains(out, "all modules verified") {
		t.Fatalf("go mod verify: %s", out)
	}
}

func TestGoForbidden(t *testing.T) {
	r := startGoRegistry(t, `{"read":["composer:*"]}`)
	_, err := r.client(false).download(modPub + "@v1.0.0")
	t.Logf("forbidden: %v", err)
	if err == nil || !strings.Contains(err.Error(), "403 Forbidden") || !strings.Contains(err.Error(), "forbidden: no go:"+modPub+" read rule") {
		t.Fatalf("go mod download without a go: rule: %v", err)
	}
	if seen := r.proxy.seen(); len(seen) != 0 {
		t.Errorf("a forbidden module was looked up upstream: %v", seen)
	}
}
