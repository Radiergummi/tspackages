//go:build integration

package integration

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/pypi"
	"github.com/radiergummi/tspackages/internal/server"
	"github.com/radiergummi/tspackages/internal/testutil"
)

// Build backends the fake upstream index serves, so sdists build offline
// through tspackages. uv_build has no dependencies; setuptools neither.
var backendPins = []string{"uv-build==0.12.21", "setuptools==80.9.0"}

var (
	backendsOnce sync.Once
	backendsDir  string
	backendsErr  error
)

// backends downloads the pinned backend wheels once per test binary.
func backends(t *testing.T) string {
	t.Helper()
	backendsOnce.Do(func() {
		backendsDir, backendsErr = os.MkdirTemp("", "tsp-backends")
		if backendsErr != nil {
			return
		}
		args := append([]string{"-m", "pip", "download", "--quiet", "--no-deps", "--only-binary=:all:", "--dest", backendsDir}, backendPins...)
		out, err := exec.Command("python3", args...).CombinedOutput()
		if err != nil {
			backendsErr = fmt.Errorf("pip download: %w\n%s", err, out)
		}
	})
	if backendsErr != nil {
		t.Skipf("cannot fetch build backends: %v", backendsErr)
	}
	return backendsDir
}

func needPython(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"python3", "uv", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not on PATH")
		}
	}
}

func sum256(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func fileSum256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fakeIndex is a PEP 691 index serving files by project.
type fakeIndex struct {
	*httptest.Server
	mu    sync.Mutex
	files map[string]map[string][]byte // project → filename → bytes
	bad   map[string]bool              // filenames whose declared sha256 is wrong
	slow  map[string]chan struct{}     // filename → released after the first MiB
	hits  map[string]int
}

func newFakeIndex(t *testing.T) *fakeIndex {
	t.Helper()
	f := &fakeIndex{files: map[string]map[string][]byte{}, bad: map[string]bool{}, slow: map[string]chan struct{}{}, hits: map[string]int{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		f.mu.Unlock()
		if rest, ok := strings.CutPrefix(r.URL.Path, "/simple/"); ok {
			f.page(w, strings.TrimSuffix(rest, "/"))
			return
		}
		if fn, ok := strings.CutPrefix(r.URL.Path, "/files/"); ok {
			f.file(w, fn)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeIndex) add(filename string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := projectOf(filename)
	if f.files[name] == nil {
		f.files[name] = map[string][]byte{}
	}
	f.files[name][filename] = b
}

func (f *fakeIndex) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func projectOf(filename string) string {
	if w, err := pypi.ParseWheelFilename(filename); err == nil {
		n, _ := pypi.Normalize(w.Name)
		return n
	}
	n, _, _ := pypi.ParseSdistFilename(filename)
	norm, _ := pypi.Normalize(n)
	return norm
}

func (f *fakeIndex) page(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	files, ok := f.files[name]
	if !ok {
		http.NotFound(w, nil)
		return
	}
	var entries []map[string]any
	for fn, b := range files {
		sha := sum256(b)
		if f.bad[fn] {
			sha = strings.Repeat("0", 64)
		}
		entries = append(entries, map[string]any{"filename": fn, "url": f.URL + "/files/" + fn, "hashes": map[string]string{"sha256": sha}, "size": len(b)})
	}
	w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
	json.NewEncoder(w).Encode(map[string]any{"meta": map[string]string{"api-version": "1.1"}, "name": name, "files": entries, "versions": []string{}})
}

func (f *fakeIndex) file(w http.ResponseWriter, fn string) {
	f.mu.Lock()
	b, release := f.files[projectOf(fn)][fn], f.slow[fn]
	f.mu.Unlock()
	if b == nil {
		http.NotFound(w, nil)
		return
	}
	if release == nil {
		w.Write(b)
		return
	}
	w.Write(b[:1<<20])
	w.(http.Flusher).Flush()
	select {
	case <-release:
	case <-time.After(30 * time.Second):
	}
	w.Write(b[1<<20:])
}

// pyRegistry is a wired tspackages with a pypi storage source claiming
// acme-*, a git source claiming gitpkg-* over one bare repository, and the
// fake index as the unclaimed pass-through.
type pyRegistry struct {
	t     *testing.T
	URL   string
	index *fakeIndex
	work  string // git working tree
	bare  string
	root  string
}

func startPyRegistry(t *testing.T, rules string) *pyRegistry {
	t.Helper()
	needPython(t)
	dir := backends(t)
	root := t.TempDir()
	r := &pyRegistry{t: t, index: newFakeIndex(t), work: filepath.Join(root, "work-tree"), bare: filepath.Join(root, "repo.git"), root: root}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		r.index.add(e.Name(), b)
	}
	os.MkdirAll(r.work, 0o755)
	testutil.Git(t, r.work, "init", "-q")
	r.commit(map[string]string{"README.md": "repo"})
	testutil.Git(t, root, "clone", "-q", "--bare", r.work, r.bare)

	iu, _ := url.Parse(r.index.URL)
	cfg := &config.Config{
		Tailscale: config.Tailscale{Hostname: "registry", Capability: capName, StateDir: filepath.Join(root, "ts")},
		Storage: config.Storage{
			WorkDir: filepath.Join(root, "work"),
			Cache:   config.StoreConfig{Driver: "fs", Path: filepath.Join(root, "cache"), MaxSize: 4 << 30},
			State:   config.StoreConfig{Driver: "fs", Path: filepath.Join(root, "state")},
			Stores:  map[string]config.StoreConfig{"main": {Driver: "fs", Path: filepath.Join(root, "hosted")}},
		},
		Ecosystems: map[string]config.Ecosystem{"pypi": {Sources: []config.Source{
			{Name: "hosted", Type: "storage", Store: "main", Claims: []string{"acme-*"}},
			{Name: "repo", Type: "git", Claims: []string{"gitpkg-*"}, Remotes: []string{r.bare}, PollInterval: 200 * time.Millisecond},
			{Name: "upstream", Type: "registry", URL: r.index.URL + "/simple/", FetchHosts: []string{iu.Host}, MetadataTTL: time.Nanosecond},
		}}},
	}
	if rules == "" {
		rules = `{"read":["*"],"write":["pypi:acme-*"]}`
	}
	ctx, cancel := context.WithCancel(t.Context())
	handler, start, err := server.Build(ctx, cfg, testutil.NewWho(capName, rules), slog.New(slog.DiscardHandler),
		server.Hooks{AllowPrivateUpstreams: true, AllowFileRemotes: true})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	loops := make(chan struct{})
	go func() { start(ctx); close(loops) }()
	srv := httptest.NewServer(handler)
	t.Cleanup(func() { srv.Close(); cancel(); <-loops })
	r.URL = srv.URL
	return r
}

func (r *pyRegistry) commit(files map[string]string) {
	r.t.Helper()
	for name, body := range files {
		p := filepath.Join(r.work, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	testutil.Git(r.t, r.work, "add", "-A")
	testutil.Git(r.t, r.work, "commit", "-q", "-m", "c")
}

func (r *pyRegistry) tagAndPush(tag string) {
	r.t.Helper()
	testutil.Git(r.t, r.work, "tag", tag)
	testutil.Git(r.t, r.work, "push", "-q", r.bare, "HEAD:refs/heads/main", "--tags")
}

func (r *pyRegistry) simple(name string) string { return r.URL + "/pypi/simple/" + name + "/" }

// waitFor polls a project page until its body contains want.
func (r *pyRegistry) waitFor(name, want string) string {
	r.t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; {
		resp, err := http.Get(r.simple(name))
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(b), want) {
				return string(b)
			}
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("%s never listed %s", name, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// run runs a command with a private uv cache and no user configuration.
func (r *pyRegistry) run(dir string, name string, args ...string) (string, error) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(r.t.Context(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"UV_CACHE_DIR="+r.t.TempDir(), "UV_NO_CONFIG=1", "UV_PYTHON_DOWNLOADS=never",
		"PIP_CONFIG_FILE=/dev/null", "PIP_NO_CACHE_DIR=1", "PIP_DISABLE_PIP_VERSION_CHECK=1",
		"UV_DEFAULT_INDEX="+r.URL+"/pypi/simple/", "UV_INDEX_URL=",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (r *pyRegistry) must(dir string, name string, args ...string) string {
	r.t.Helper()
	out, err := r.run(dir, name, args...)
	if err != nil {
		r.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

// venv creates a virtualenv with pip (from ensurepip, offline) and returns
// its python.
func (r *pyRegistry) venv() string {
	r.t.Helper()
	dir := filepath.Join(r.t.TempDir(), "venv")
	r.must("", "python3", "-m", "venv", dir)
	return filepath.Join(dir, "bin", "python")
}

// uvInstall installs requirements into a fresh venv through tspackages.
func (r *pyRegistry) uvInstall(reqs ...string) (string, string, error) {
	py := r.venv()
	out, err := r.run("", "uv", append([]string{"pip", "install", "--python", py, "--default-index", r.URL + "/pypi/simple/"}, reqs...)...)
	return py, out, err
}

// pipInstall installs requirements into a fresh venv with pip through
// tspackages.
func (r *pyRegistry) pipInstall(reqs ...string) (string, string, error) {
	py := r.venv()
	host, _ := url.Parse(r.URL)
	out, err := r.run("", py, append([]string{"-m", "pip", "install", "--index-url", r.URL + "/pypi/simple/", "--trusted-host", host.Hostname()}, reqs...)...)
	return py, out, err
}

// project writes a uv_build project for name at version into dir.
func uvProject(name, version, extra string) map[string]string {
	mod := strings.ReplaceAll(name, "-", "_")
	return map[string]string{
		"pyproject.toml": "[project]\nname = \"" + name + "\"\nversion = \"" + version + "\"\nrequires-python = \">=3.9\"\n" + extra +
			"\n[build-system]\nrequires = [\"uv_build>=0.9,<0.13\"]\nbuild-backend = \"uv_build\"\n",
		"src/" + mod + "/__init__.py": "VERSION = \"" + version + "\"\n",
	}
}

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// buildDist builds a project's wheel and sdist with uv, fetching the backend
// through tspackages.
func (r *pyRegistry) buildDist(name, version string) []string {
	r.t.Helper()
	dir := r.t.TempDir()
	writeTree(r.t, dir, uvProject(name, version, ""))
	r.must(dir, "uv", "build", "-q", "--default-index", r.URL+"/pypi/simple/", "--out-dir", "dist")
	wheels, _ := filepath.Glob(filepath.Join(dir, "dist", "*.whl"))
	sdists, _ := filepath.Glob(filepath.Join(dir, "dist", "*.tar.gz"))
	files := slices.Concat(wheels, sdists)
	if len(files) != 2 {
		r.t.Fatalf("built %v", files)
	}
	return files
}

func twine(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("twine")
	if err != nil {
		t.Skip("twine not on PATH")
	}
	return p
}

func TestPipInstallFromUpload(t *testing.T) {
	r := startPyRegistry(t, "")
	files := r.buildDist("acme-core", "1.2.0")
	r.must("", twine(t), append([]string{"upload", "--non-interactive", "--disable-progress-bar", "--repository-url", r.URL + "/pypi/legacy/", "-u", "x", "-p", "x"}, files...)...)
	py, out, err := r.pipInstall("acme-core==1.2.0")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if out := r.must("", py, "-c", "import acme_core; print(acme_core.VERSION)"); strings.TrimSpace(out) != "1.2.0" {
		t.Fatalf("installed %q", out)
	}
}

func TestUvPublishDuplicate(t *testing.T) {
	r := startPyRegistry(t, "")
	files := r.buildDist("acme-dup", "1.0.0")
	publish := append([]string{"publish", "--publish-url", r.URL + "/pypi/legacy/", "--username", "x", "--password", "x"}, files...)
	r.must("", "uv", publish...)
	out, err := r.run("", "uv", publish...)
	if err == nil || !strings.Contains(out, "File already exists") {
		t.Fatalf("second publish: err=%v\n%s", err, out)
	}
}

func TestGitSdistInstalls(t *testing.T) {
	r := startPyRegistry(t, "")
	r.commit(uvProject("gitpkg-core", "0.3.0", ""))
	r.tagAndPush("release-0.3")
	r.waitFor("gitpkg-core", "gitpkg_core-0.3.0.tar.gz")
	// pip, not uv: uv builds uv_build projects itself and would never fetch
	// the backend.
	py, out, err := r.pipInstall("gitpkg-core==0.3.0")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if got := r.must("", py, "-c", "import gitpkg_core; print(gitpkg_core.VERSION)"); strings.TrimSpace(got) != "0.3.0" {
		t.Fatalf("installed %q", got)
	}
	if r.index.count("/simple/uv-build/") == 0 {
		t.Error("the build backend was not fetched through tspackages")
	}
}

func TestWorkspaceMembers(t *testing.T) {
	r := startPyRegistry(t, "")
	files := map[string]string{"pyproject.toml": "[tool.uv.workspace]\nmembers = [\"packages/*\"]\n"}
	for _, m := range []struct{ name, version string }{{"gitpkg-a", "1.0.0"}, {"gitpkg-b", "2.0.0"}} {
		for k, v := range uvProject(m.name, m.version, "") {
			files["packages/"+m.name+"/"+k] = v
		}
	}
	r.commit(files)
	r.tagAndPush("v1")
	page := r.waitFor("gitpkg-a", "gitpkg_a-1.0.0.tar.gz")
	r.waitFor("gitpkg-b", "gitpkg_b-2.0.0.tar.gz")
	if _, out, err := r.uvInstall("gitpkg-a==1.0.0", "gitpkg-b==2.0.0"); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	// Change a without a version bump and tag again: a keeps its first bytes.
	r.commit(map[string]string{"packages/gitpkg-a/src/gitpkg_a/extra.py": "changed = True\n"})
	r.tagAndPush("v1-again")
	time.Sleep(time.Second) // a few poll intervals
	if again := r.waitFor("gitpkg-a", "gitpkg_a-1.0.0.tar.gz"); sha256Of(t, again) != sha256Of(t, page) {
		t.Fatalf("published sdist changed:\n%s\n%s", page, again)
	}
	resp, err := http.Get(r.URL + "/")
	if err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(b), "changed without a version bump") {
			t.Error("the status page does not report the change")
		}
	}
}

// sha256Of returns the sha256 fragment of the first file link on a page.
func sha256Of(t *testing.T, page string) string {
	t.Helper()
	_, rest, ok := strings.Cut(page, "#sha256=")
	if !ok {
		t.Fatalf("no sha256 in %s", page)
	}
	return rest[:64]
}

func TestSetuptoolsPackageData(t *testing.T) {
	r := startPyRegistry(t, "")
	r.commit(map[string]string{
		"pyproject.toml":          "[project]\nname = \"gitpkg-data\"\nversion = \"1.0.0\"\n\n[build-system]\nrequires = [\"setuptools>=70\"]\nbuild-backend = \"setuptools.build_meta\"\n\n[tool.setuptools.package-data]\ngitpkg_data = [\"*.json\"]\n",
		"gitpkg_data/__init__.py": "",
		"gitpkg_data/data.json":   "{\"ok\": true}\n",
	})
	r.tagAndPush("v1.0.0")
	r.waitFor("gitpkg-data", "gitpkg_data-1.0.0.tar.gz")
	py, out, err := r.uvInstall("gitpkg-data==1.0.0")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	got := r.must("", py, "-c", "import importlib.resources as r; print(r.files('gitpkg_data').joinpath('data.json').read_text())")
	if !strings.Contains(got, `"ok": true`) {
		t.Fatalf("package data missing: %q", got)
	}
}

func TestDependencyConfusion(t *testing.T) {
	r := startPyRegistry(t, "")
	decoy := wheelBytes(t, "acme_secret", "99.0.0", 0)
	r.index.add("acme_secret-99.0.0-py3-none-any.whl", decoy)
	if _, out, err := r.uvInstall("acme-secret"); err == nil {
		t.Fatalf("installed a claimed name from upstream:\n%s", out)
	}
	if n := r.index.count("/simple/acme-secret/"); n != 0 {
		t.Fatalf("upstream asked for a claimed name %d times", n)
	}
}

func TestPyPIForbidden(t *testing.T) {
	r := startPyRegistry(t, `{"read":["pypi:uv-build"]}`)
	if _, out, err := r.uvInstall("gitpkg-hidden"); err == nil || !strings.Contains(out, "403") {
		t.Fatalf("err=%v\n%s", err, out)
	}
}

// wheelBytes builds a pure-Python wheel with a payload of n random bytes.
func wheelBytes(t *testing.T, mod, version string, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	dist := mod + "-" + version + ".dist-info/"
	for name, body := range map[string]string{
		mod + "/__init__.py": "",
		dist + "METADATA":    "Metadata-Version: 2.1\nName: " + mod + "\nVersion: " + version + "\n",
		dist + "WHEEL":       "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
		dist + "RECORD":      "",
	} {
		w, _ := zw.Create(name)
		io.WriteString(w, body)
	}
	if n > 0 {
		w, _ := zw.CreateHeader(&zip.FileHeader{Name: mod + "/blob.bin", Method: zip.Store})
		io.CopyN(w, rand.Reader, int64(n))
	}
	zw.Close()
	return buf.Bytes()
}

// TestLargeStreamedWheel: the first client gets bytes before the upstream
// finishes, concurrent clients share one fetch, and every copy is intact.
func TestLargeStreamedWheel(t *testing.T) {
	r := startPyRegistry(t, "")
	const fn = "bigpkg-1.0.0-py3-none-any.whl"
	whl := wheelBytes(t, "bigpkg", "1.0.0", 300<<20)
	want := sum256(whl)
	release := make(chan struct{})
	r.index.add(fn, whl)
	r.index.mu.Lock()
	r.index.slow[fn] = release
	r.index.mu.Unlock()

	resp, err := http.Get(r.URL + "/pypi/files/upstream/bigpkg/" + fn)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadFull(resp.Body, make([]byte, 1<<20)); err != nil {
		t.Fatalf("first MiB before the upstream finished: %v", err)
	}
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range 4 {
		wg.Go(func() {
			py := r.venv()
			dest := t.TempDir()
			host, _ := url.Parse(r.URL)
			if out, err := r.run("", py, "-m", "pip", "download", "--no-deps", "--dest", dest, "--index-url", r.URL+"/pypi/simple/", "--trusted-host", host.Hostname(), "bigpkg==1.0.0"); err != nil {
				t.Logf("pip download: %v\n%s", err, out)
				failures.Add(1)
				return
			}
			if got, err := fileSum256(filepath.Join(dest, fn)); err != nil || got != want {
				failures.Add(1)
			}
		})
	}
	time.Sleep(2 * time.Second) // let the pip clients join the download
	close(release)
	rest, err := io.ReadAll(resp.Body)
	if err != nil || int64(len(rest))+1<<20 != int64(len(whl)) {
		t.Fatalf("first client: %d bytes, %v", len(rest)+1<<20, err)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d clients failed", failures.Load())
	}
	if n := r.index.count("/files/" + fn); n != 1 {
		t.Fatalf("upstream fetched %d times", n)
	}
}

func TestUpstreamMismatchAborts(t *testing.T) {
	r := startPyRegistry(t, "")
	const fn = "badpkg-1.0.0-py3-none-any.whl"
	r.index.add(fn, wheelBytes(t, "badpkg", "1.0.0", 0))
	r.index.mu.Lock()
	r.index.bad[fn] = true
	r.index.mu.Unlock()
	// uv retries a broken transfer, so count fetches per install: a cached
	// file would leave the second install without upstream fetches.
	fetches := 0
	for i := range 2 {
		if _, out, err := r.uvInstall("badpkg==1.0.0"); err == nil {
			t.Fatalf("installed a file that does not match its sha256:\n%s", out)
		}
		n := r.index.count("/files/" + fn)
		if n == fetches {
			t.Fatalf("install %d did not fetch upstream; the mismatching file was cached", i+1)
		}
		fetches = n
	}
}
