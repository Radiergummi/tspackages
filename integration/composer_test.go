//go:build integration

// Package integration runs real clients against a fully wired server.
package integration

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
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

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/server"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

const capName = "github.com/radiergummi/tspackages"

func sha1Hex(b []byte) string {
	s := sha1.Sum(b)
	return hex.EncodeToString(s[:])
}

func needTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"composer", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not on PATH")
		}
	}
}

// fakePackagist serves psr/log 3.0.0, psr/container 2.0.0, a decoy
// matchory/a 9.9.9 and psr/bad 1.0.0, whose archive does not match its
// shasum. It records every request path and answers 503 while down.
type fakePackagist struct {
	*httptest.Server
	down  atomic.Bool
	mu    sync.Mutex
	paths []string
}

func (f *fakePackagist) saw(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.paths, path)
}

func (f *fakePackagist) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func newFakePackagist(t *testing.T) *fakePackagist {
	t.Helper()
	zipFor := func(dir, name string) []byte {
		return testutil.ZipOf(t, map[string]string{
			dir + "/composer.json": `{"name":"` + name + `"}`,
			dir + "/src/Foo.php":   `<?php`,
		})
	}
	f := &fakePackagist{}
	mux := http.NewServeMux()
	add := func(name, version string, zipBytes []byte, shasum string) {
		distPath := "/dist/" + name + "/" + version + ".zip"
		doc := map[string]any{"packages": map[string]any{name: []any{map[string]any{
			"name": name, "version": version, "version_normalized": version + ".0",
			"dist": map[string]any{
				"type": "zip", "url": f.URL + distPath, "reference": "ref" + version, "shasum": shasum,
			},
		}}}}
		meta, _ := json.Marshal(doc)
		mux.HandleFunc("/p2/"+name+".json", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(meta)
		})
		mux.HandleFunc(distPath, func(w http.ResponseWriter, _ *http.Request) { w.Write(zipBytes) })
	}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.mu.Unlock()
		if f.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.Close)
	for _, p := range []struct{ name, version, dir string }{
		{"psr/log", "3.0.0", "log-3.0.0"},
		{"psr/container", "2.0.0", "container-2.0.0"},
		{"matchory/a", "9.9.9", "a-9.9.9"},
	} {
		z := zipFor(p.dir, p.name)
		add(p.name, p.version, z, sha1Hex(z))
	}
	add("psr/bad", "1.0.0", zipFor("bad-1.0.0", "psr/bad"), sha1Hex([]byte("something else")))
	return f
}

// gitRepo is a working repository for matchory/a and the bare remote the
// git source mirrors.
type gitRepo struct {
	t          *testing.T
	work, bare string
}

func newGitRepo(t *testing.T, root string) *gitRepo {
	t.Helper()
	g := &gitRepo{t: t, work: filepath.Join(root, "a-work"), bare: filepath.Join(root, "a.git")}
	if err := os.MkdirAll(g.work, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.Git(t, g.work, "init", "-q")
	g.commit("one")
	g.tag("v1.0.0")
	testutil.Git(t, root, "clone", "-q", "--bare", g.work, g.bare)
	return g
}

// commit changes composer.json's description, so every commit has its own
// tree and archive, and returns the commit SHA.
func (g *gitRepo) commit(msg string) string {
	g.t.Helper()
	if err := os.WriteFile(filepath.Join(g.work, "composer.json"), []byte(`{"name":"matchory/a","description":"`+msg+`"}`), 0o644); err != nil {
		g.t.Fatal(err)
	}
	testutil.Git(g.t, g.work, "add", ".")
	testutil.Git(g.t, g.work, "commit", "-q", "-m", msg)
	return testutil.Git(g.t, g.work, "rev-parse", "HEAD")
}

func (g *gitRepo) tag(name string, args ...string) {
	g.t.Helper()
	testutil.Git(g.t, g.work, append([]string{"tag"}, append(args, name)...)...)
}

func (g *gitRepo) push(args ...string) {
	g.t.Helper()
	testutil.Git(g.t, g.work, append([]string{"push", "-q"}, append(args, g.bare, "main", "--tags")...)...)
}

type options struct {
	rules       string // capability rules for every caller
	metadataTTL time.Duration
	stores      func(t *testing.T, root string) (state, hosted config.StoreConfig)
}

func fsStores(_ *testing.T, root string) (state, hosted config.StoreConfig) {
	return config.StoreConfig{Driver: "fs", Path: filepath.Join(root, "state")},
		config.StoreConfig{Driver: "fs", Path: filepath.Join(root, "hosted")}
}

// s3Store returns an s3 store config for a fresh bucket on the test
// service (see testutil.S3Env), and removes the bucket and its objects after
// the test.
func s3Store(t *testing.T) config.StoreConfig {
	t.Helper()
	endpoint, accessKey, secretKey, bucket := testutil.S3Env(t)
	c := config.StoreConfig{Driver: "s3", Endpoint: endpoint, Bucket: bucket, AccessKeyID: accessKey, SecretAccessKey: secretKey}
	ctx := context.Background()
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, "")))
	if err != nil {
		t.Fatal(err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &c.Bucket}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pager := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &c.Bucket})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				t.Logf("list %s: %v", c.Bucket, err)
				return
			}
			for _, o := range page.Contents {
				client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &c.Bucket, Key: o.Key})
			}
		}
		client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &c.Bucket})
	})
	return c
}

// s3Stores keeps the state store and the hosted store in one bucket under
// separate prefixes, as examples/config.yaml does.
func s3Stores(t *testing.T, _ string) (state, hosted config.StoreConfig) {
	b := s3Store(t)
	state, hosted = b, b
	state.Prefix, hosted.Prefix = "state/", "hosted/"
	return state, hosted
}

// registry is a fully wired tspackages with a git source claiming
// matchory/*, a storage source claiming matchory-internal/* and an unclaimed
// registry source in front of a fake Packagist.
type registry struct {
	t         *testing.T
	URL       string
	root      string
	cfg       *config.Config
	git       *gitRepo
	packagist *fakePackagist
}

func startRegistry(t *testing.T, o options) *registry {
	t.Helper()
	needTools(t)
	if o.rules == "" {
		o.rules = `{"read":["*"],"write":["composer:matchory-internal/*"]}`
	}
	if o.stores == nil {
		o.stores = fsStores
	}
	root := t.TempDir()
	r := &registry{t: t, root: root, git: newGitRepo(t, root), packagist: newFakePackagist(t)}
	pu, _ := url.Parse(r.packagist.URL)
	state, hosted := o.stores(t, root)
	r.cfg = &config.Config{
		Tailscale: config.Tailscale{Hostname: "registry", Capability: capName, StateDir: filepath.Join(root, "ts")},
		Storage: config.Storage{
			WorkDir: filepath.Join(root, "work"),
			Cache:   config.StoreConfig{Driver: "fs", Path: filepath.Join(root, "cache"), MaxSize: 1 << 30},
			State:   state,
			Stores:  map[string]config.StoreConfig{"main": hosted},
		},
		Ecosystems: map[string]config.Ecosystem{"composer": {Sources: []config.Source{
			{Name: "matchory-git", Type: "git", Claims: []string{"matchory/*"}, Remotes: []string{r.git.bare}, PollInterval: 200 * time.Millisecond},
			{Name: "hosted", Type: "storage", Store: "main", Claims: []string{"matchory-internal/*"}},
			{Name: "packagist", Type: "registry", URL: r.packagist.URL, FetchHosts: []string{pu.Host}, MetadataTTL: o.metadataTTL},
		}}},
	}
	ctx, cancel := context.WithCancel(t.Context())
	handler, start, err := server.Build(ctx, r.cfg, testutil.NewWho(capName, o.rules), slog.New(slog.DiscardHandler),
		server.Hooks{AllowPrivateUpstreams: true, AllowFileRemotes: true})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	loops := make(chan struct{})
	go func() { start(ctx); close(loops) }()
	srv := httptest.NewServer(handler)
	// The git loop writes below root: stop it before TempDir cleanup.
	t.Cleanup(func() { srv.Close(); cancel(); <-loops })
	r.URL = srv.URL
	return r
}

// storedArchive returns the git-built archive of commit from the state store.
func (r *registry) storedArchive(commit string) []byte {
	r.t.Helper()
	d, err := storage.Open(r.t.Context(), r.cfg.Storage.State)
	if err != nil {
		r.t.Fatal(err)
	}
	rc, _, err := d.Get(r.t.Context(), "composer-git/matchory-git/"+commit+".zip")
	if err != nil {
		r.t.Fatalf("stored archive: %v", err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		r.t.Fatal(err)
	}
	return b
}

// waitForGit waits until the git source has indexed matchory/a v1.0.0.
func (r *registry) waitForGit() { r.t.Helper(); r.waitFor("/composer/p2/matchory/a.json", `"v1.0.0"`) }

// get returns the status and body of a GET on the registry.
func (r *registry) get(path string) (int, string) {
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
func (r *registry) waitFor(path, want string) {
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

func (r *registry) upload(name, version string) {
	r.t.Helper()
	req, _ := http.NewRequest(http.MethodPut, r.URL+"/composer/upload/"+name+"/"+version,
		bytes.NewReader(testutil.ZipOf(r.t, map[string]string{"composer.json": `{"name":"` + name + `","description":"b"}`})))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		r.t.Fatalf("upload = %d %s", resp.StatusCode, body)
	}
}

// project writes a composer.json that requires require from this registry
// only, and returns its directory.
func (r *registry) project(require map[string]string) string {
	r.t.Helper()
	dir := r.t.TempDir()
	b, _ := json.Marshal(map[string]any{
		"repositories": []any{
			map[string]any{"type": "composer", "url": r.URL + "/composer"},
			map[string]any{"packagist.org": false},
		},
		"config":            map[string]any{"secure-http": false},
		"require":           require,
		"minimum-stability": "dev",
		"prefer-stable":     true,
	})
	if err := os.WriteFile(filepath.Join(dir, "composer.json"), b, 0o644); err != nil {
		r.t.Fatal(err)
	}
	return dir
}

// composer runs composer in dir with a fresh cache, so every run talks to the
// registry, and returns its output and error.
func (r *registry) composer(dir string, args ...string) (string, error) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(r.t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "composer", append(args, "--no-interaction", "--prefer-dist")...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "COMPOSER_HOME="+filepath.Join(r.root, "composer-home"), "COMPOSER_CACHE_DIR="+r.t.TempDir())
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (r *registry) mustComposer(dir string, args ...string) {
	r.t.Helper()
	if out, err := r.composer(dir, args...); err != nil {
		r.t.Fatalf("composer %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

type lockedPackage struct {
	Name    string
	Version string
	Dist    struct{ URL, Reference, Shasum string }
}

// lock returns the packages of dir's composer.lock by name.
func (r *registry) lock(dir string) map[string]lockedPackage {
	r.t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "composer.lock"))
	if err != nil {
		r.t.Fatal(err)
	}
	var lock struct{ Packages []lockedPackage }
	if err := json.Unmarshal(raw, &lock); err != nil {
		r.t.Fatal(err)
	}
	out := map[string]lockedPackage{}
	for _, p := range lock.Packages {
		if !strings.HasPrefix(p.Dist.URL, r.URL) {
			r.t.Errorf("%s dist.url = %q, want prefix %q", p.Name, p.Dist.URL, r.URL)
		}
		out[p.Name] = p
	}
	return out
}

func TestComposerEndToEnd(t *testing.T) {
	t.Run("fs", func(t *testing.T) { testEndToEnd(t, fsStores) })
	t.Run("s3", func(t *testing.T) { testEndToEnd(t, s3Stores) })
}

func testEndToEnd(t *testing.T, stores func(*testing.T, string) (config.StoreConfig, config.StoreConfig)) {
	r := startRegistry(t, options{stores: stores})
	r.waitForGit()
	r.upload("matchory-internal/b", "1.0.0")
	commit := testutil.Git(t, r.git.work, "rev-parse", "v1.0.0^{commit}")

	project := r.project(map[string]string{"matchory/a": "^1.0", "matchory-internal/b": "^1.0", "psr/log": "^3.0"})
	r.mustComposer(project, "install")
	for _, p := range []string{"matchory/a/composer.json", "matchory-internal/b/composer.json", "psr/log"} {
		if _, err := os.Stat(filepath.Join(project, "vendor", p)); err != nil {
			t.Errorf("vendor/%s: %v", p, err)
		}
	}

	checkLock := func() {
		t.Helper()
		lock := r.lock(project)
		for _, n := range []string{"matchory/a", "matchory-internal/b", "psr/log"} {
			if _, ok := lock[n]; !ok {
				t.Errorf("%s missing from composer.lock", n)
			}
		}
		a := lock["matchory/a"]
		if a.Version != "v1.0.0" {
			t.Errorf("matchory/a resolved to %q, want v1.0.0", a.Version)
		}
		if a.Dist.Reference != commit {
			t.Errorf("matchory/a reference = %q, want %q", a.Dist.Reference, commit)
		}
		if a.Dist.Shasum != sha1Hex(r.storedArchive(commit)) {
			t.Errorf("matchory/a shasum = %q, want the sha1 of the stored archive", a.Dist.Shasum)
		}
	}
	checkLock()

	// Dependency confusion: packagist offers matchory/a 9.9.9, but the claim keeps it away.
	if err := os.Remove(filepath.Join(project, "composer.lock")); err != nil {
		t.Fatal(err)
	}
	r.mustComposer(project, "update")
	checkLock()
	if r.packagist.saw("/p2/matchory/a.json") || r.packagist.saw("/p2/matchory/a~dev.json") {
		t.Errorf("fake Packagist received a request for matchory/a: %v", r.packagist.seen())
	}
}

// TestComposerGitVersions follows a git remote as it changes: a new tag is
// installable after the next poll, a moved tag keeps its first commit, and
// the default branch is a dev version.
func TestComposerGitVersions(t *testing.T) {
	r := startRegistry(t, options{})
	r.waitForGit()
	first := testutil.Git(t, r.git.work, "rev-parse", "v1.0.0^{commit}")

	project := r.project(map[string]string{"matchory/a": "^1.0"})
	r.mustComposer(project, "update")
	if a := r.lock(project)["matchory/a"]; a.Version != "v1.0.0" || a.Dist.Reference != first {
		t.Fatalf("before the new tag: %+v", a)
	}

	second := r.git.commit("two")
	r.git.tag("v1.1.0")
	r.git.push()
	r.waitFor("/composer/p2/matchory/a.json", `"v1.1.0"`)
	r.mustComposer(project, "update")
	if a := r.lock(project)["matchory/a"]; a.Version != "v1.1.0" || a.Dist.Reference != second {
		t.Fatalf("after the new tag: %+v", a)
	}

	// Move v1.0.0 to a new commit: the pin keeps serving the first one.
	moved := r.git.commit("three")
	r.git.tag("v1.0.0", "-f")
	r.git.push("--force")
	r.waitFor("/", moved) // listed under moved tags
	pinned := r.project(map[string]string{"matchory/a": "1.0.0"})
	r.mustComposer(pinned, "update")
	if a := r.lock(pinned)["matchory/a"]; a.Dist.Reference != first {
		t.Fatalf("moved tag served %s, want the pinned %s", a.Dist.Reference, first)
	}
	raw, err := os.ReadFile(filepath.Join(pinned, "vendor", "matchory", "a", "composer.json"))
	if err != nil || !strings.Contains(string(raw), `"one"`) {
		t.Fatalf("installed composer.json for the moved tag: %s (%v)", raw, err)
	}

	head := testutil.Git(t, r.git.work, "rev-parse", "HEAD")
	r.waitFor("/composer/p2/matchory/a~dev.json", head)
	dev := r.project(map[string]string{"matchory/a": "dev-main"})
	r.mustComposer(dev, "update")
	if a := r.lock(dev)["matchory/a"]; a.Version != "dev-main" || a.Dist.Reference != head {
		t.Fatalf("dev-main: %+v", a)
	}
}

// TestComposerUpstreamFailures checks what Composer sees when Packagist
// fails: cached packages keep installing, the rest fail with a 5xx, and an
// archive that does not match its shasum is never served.
func TestComposerUpstreamFailures(t *testing.T) {
	r := startRegistry(t, options{metadataTTL: time.Nanosecond})
	warm := r.project(map[string]string{"psr/log": "^3.0"})
	r.mustComposer(warm, "update")

	r.packagist.down.Store(true)
	cold := r.project(map[string]string{"psr/log": "^3.0"})
	r.mustComposer(cold, "update") // stale metadata and the cached archive
	if _, ok := r.lock(cold)["psr/log"]; !ok {
		t.Fatal("psr/log missing while upstream is down")
	}
	uncached := r.project(map[string]string{"psr/container": "^2.0"})
	if out, err := r.composer(uncached, "update"); err == nil || !strings.Contains(out, "502") {
		t.Fatalf("uncached package while upstream is down: err=%v\n%s", err, out)
	}

	r.packagist.down.Store(false)
	bad := r.project(map[string]string{"psr/bad": "^1.0"})
	if out, err := r.composer(bad, "update"); err == nil || !strings.Contains(out, "502") {
		t.Fatalf("archive with a wrong shasum: err=%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(bad, "vendor", "psr", "bad")); err == nil {
		t.Fatal("archive with a wrong shasum was installed")
	}
}

// TestComposerForbidden checks that a caller without read access gets a 403
// Composer reports, and that the name is never looked up upstream.
func TestComposerForbidden(t *testing.T) {
	r := startRegistry(t, options{rules: `{"read":["composer:psr/*"]}`})
	project := r.project(map[string]string{"psr/log": "^3.0", "acme/secret": "^1.0"})
	out, err := r.composer(project, "update")
	if err == nil || !strings.Contains(out, "403") {
		t.Fatalf("err=%v\n%s", err, out)
	}
	if r.packagist.saw("/p2/acme/secret.json") {
		t.Error("a forbidden name was looked up upstream")
	}
}
