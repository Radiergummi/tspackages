//go:build integration

package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/server"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

func needNode(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range append([]string{"node", "npm"}, tools...) {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not on PATH")
		}
	}
}

// npmTarball builds a package tarball as npm pack lays it out: every file
// under package/, package.json from name and version, plus blob random
// bytes in package/blob.bin.
func npmTarball(t *testing.T, name, version string, blob int) []byte {
	t.Helper()
	pj, _ := json.Marshal(map[string]string{"name": name, "version": version, "main": "index.js"})
	files := map[string][]byte{
		"package/package.json": pj,
		"package/index.js":     []byte("module.exports = " + `"` + name + "@" + version + `"` + ";\n"),
	}
	if blob > 0 {
		b := make([]byte, blob)
		rand.Read(b)
		files["package/blob.bin"] = b
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	tw := tar.NewWriter(zw)
	for _, n := range slices.Sorted(maps.Keys(files)) {
		b := files[n]
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(b)), ModTime: time.Unix(499162500, 0), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(b)
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func integrity(b []byte) string {
	s := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

// fakeNpmjs serves unscoped packages the way registry.npmjs.org does:
// packuments at /<name>, tarballs at /<name>/-/<name>-<version>.tgz.
type fakeNpmjs struct {
	*httptest.Server
	mu     sync.Mutex
	pkgs   map[string]map[string][]byte // name → version → tarball
	tamper map[string]bool              // tarball path → serve other bytes than declared
	hits   map[string]int
}

func newFakeNpmjs(t *testing.T) *fakeNpmjs {
	t.Helper()
	f := &fakeNpmjs{pkgs: map[string]map[string][]byte{}, tamper: map[string]bool{}, hits: map[string]int{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits[r.URL.Path]++
		name, file, isTarball := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/-/")
		versions, ok := f.pkgs[name]
		if !ok {
			http.Error(w, `{"error":"Not found"}`, http.StatusNotFound)
			return
		}
		if !isTarball {
			f.packument(w, name, versions)
			return
		}
		v, ok := strings.CutSuffix(strings.TrimPrefix(file, name+"-"), ".tgz")
		b := versions[v]
		if !ok || b == nil {
			http.NotFound(w, r)
			return
		}
		if f.tamper[r.URL.Path] {
			b = bytes.Clone(b)
			b[len(b)-1] ^= 0xff
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(b)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeNpmjs) add(t *testing.T, name, version string, blob int) []byte {
	t.Helper()
	b := npmTarball(t, name, version, blob)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pkgs[name] == nil {
		f.pkgs[name] = map[string][]byte{}
	}
	f.pkgs[name][version] = b
	return b
}

func (f *fakeNpmjs) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *fakeNpmjs) packument(w http.ResponseWriter, name string, versions map[string][]byte) {
	vs := map[string]any{}
	times := map[string]string{"created": "2020-01-01T00:00:00.000Z", "modified": "2020-01-02T00:00:00.000Z"}
	latest := ""
	for _, v := range slices.Sorted(maps.Keys(versions)) {
		b := versions[v]
		vs[v] = map[string]any{
			"name": name, "version": v, "main": "index.js",
			"dist": map[string]any{
				"tarball": f.URL + "/" + name + "/-/" + name + "-" + v + ".tgz", "integrity": integrity(b), "shasum": sha1Hex(b),
			},
		}
		times[v] = "2020-01-01T00:00:00.000Z"
		latest = v
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"_id": name, "name": name, "dist-tags": map[string]string{"latest": latest}, "versions": vs, "time": times,
	})
}

// npmRegistry is a wired tspackages with an npm storage source claiming
// @acme/* and acme-*, and the fake npmjs as the unclaimed registry source.
type npmRegistry struct {
	t    *testing.T
	URL  string // the registry, ending in /npm/
	host string
	cfg  *config.Config
	up   *fakeNpmjs
	home string // HOME for every client run
}

func startNPMRegistry(t *testing.T, stores func(*testing.T, string) (config.StoreConfig, config.StoreConfig)) *npmRegistry {
	t.Helper()
	needNode(t)
	if stores == nil {
		stores = fsStores
	}
	root := t.TempDir()
	r := &npmRegistry{t: t, up: newFakeNpmjs(t), home: filepath.Join(root, "home")}
	if err := os.MkdirAll(r.home, 0o755); err != nil {
		t.Fatal(err)
	}
	uu, _ := url.Parse(r.up.URL)
	state, hosted := stores(t, root)
	r.cfg = &config.Config{
		Tailscale: config.Tailscale{Hostname: "registry", Capability: capName, StateDir: filepath.Join(root, "ts")},
		Storage: config.Storage{
			WorkDir: filepath.Join(root, "work"),
			Cache:   config.StoreConfig{Driver: "fs", Path: filepath.Join(root, "cache"), MaxSize: 4 << 30},
			State:   state,
			Stores:  map[string]config.StoreConfig{"main": hosted},
		},
		Ecosystems: map[string]config.Ecosystem{"npm": {Sources: []config.Source{
			{Name: "hosted", Type: "storage", Store: "main", Claims: []string{"@acme/*", "acme-*"}},
			{Name: "npmjs", Type: "registry", URL: r.up.URL + "/", FetchHosts: []string{uu.Host}, MetadataTTL: time.Nanosecond},
		}}},
	}
	rules := `{"read":["*"],"write":["npm:@acme/*","npm:acme-*"]}`
	ctx, cancel := context.WithCancel(t.Context())
	handler, start, err := server.Build(ctx, r.cfg, testutil.NewWho(capName, rules), slog.New(slog.DiscardHandler),
		server.Hooks{AllowPrivateUpstreams: true})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	loops := make(chan struct{})
	go func() { start(ctx); close(loops) }()
	srv := httptest.NewServer(handler)
	t.Cleanup(func() { srv.Close(); cancel(); <-loops })
	su, _ := url.Parse(srv.URL)
	r.URL, r.host = srv.URL+"/npm/", su.Host
	return r
}

// npmrc is all a project needs: the registry and the dummy token npm wants
// before it publishes.
func (r *npmRegistry) npmrc() string {
	return "registry=" + r.URL + "\n//" + r.host + "/npm/:_authToken=tailscale\n"
}

// project writes package.json from pkg and the .npmrc into a fresh
// directory.
func (r *npmRegistry) project(pkg map[string]any, extra map[string]string) string {
	r.t.Helper()
	dir := r.t.TempDir()
	pj, _ := json.MarshalIndent(pkg, "", "  ")
	files := map[string]string{"package.json": string(pj), ".npmrc": r.npmrc()}
	maps.Copy(files, extra)
	writeTree(r.t, dir, files)
	return dir
}

// lib writes a publishable package.
func (r *npmRegistry) lib(name, version, body string) string {
	return r.project(map[string]any{"name": name, "version": version, "main": "index.js"},
		map[string]string{"index.js": "module.exports = " + body + ";\n"})
}

// run runs a client with a private HOME (no user .npmrc, cache or pnpm
// store), no global npmrc and stdin closed.
func (r *npmRegistry) run(dir, name string, args ...string) (string, error) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(r.t.Context(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	globalrc := filepath.Join(r.home, "global-npmrc")
	if err := os.WriteFile(globalrc, nil, 0o644); err != nil {
		r.t.Fatal(err)
	}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "npm_") || strings.HasPrefix(lk, "pnpm_") || strings.HasPrefix(lk, "xdg_") || k == "HOME" || k == "CI" {
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	cmd.Env = append(cmd.Env, "HOME="+r.home, "npm_config_globalconfig="+globalrc, "npm_config_update_notifier=false")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (r *npmRegistry) must(dir, name string, args ...string) string {
	r.t.Helper()
	out, err := r.run(dir, name, args...)
	if err != nil {
		r.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func (r *npmRegistry) publish(name, version string) {
	r.t.Helper()
	r.must(r.lib(name, version, `"`+name+"@"+version+`"`), "npm", "publish")
}

// get returns the status and body of a GET below the registry.
func (r *npmRegistry) get(path string) (int, string) {
	r.t.Helper()
	resp, err := http.Get(r.URL + path)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (r *npmRegistry) hosted(key string) ([]byte, error) {
	r.t.Helper()
	d, err := storage.Open(r.t.Context(), r.cfg.Storage.Stores["main"])
	if err != nil {
		r.t.Fatal(err)
	}
	rc, _, err := d.Get(r.t.Context(), key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// installed reads package.json and index.js of each package in
// dir/node_modules, following pnpm's symlinks.
func installed(t *testing.T, dir string, names ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range names {
		for _, f := range []string{"package.json", "index.js"} {
			b, err := os.ReadFile(filepath.Join(dir, "node_modules", n, f))
			if err != nil {
				t.Fatalf("node_modules/%s/%s: %v", n, f, err)
			}
			out[n+"/"+f] = string(b)
		}
	}
	return out
}

func TestNPMPublish(t *testing.T) {
	t.Run("fs", func(t *testing.T) { testNPMPublish(t, fsStores) })
	t.Run("s3", func(t *testing.T) { testNPMPublish(t, s3Stores) })
}

func testNPMPublish(t *testing.T, stores func(*testing.T, string) (config.StoreConfig, config.StoreConfig)) {
	r := startNPMRegistry(t, stores)
	r.publish("@acme/lib", "1.0.0")
	r.publish("acme-util", "2.1.0")
	for name, v := range map[string]string{"@acme%2flib": "1.0.0", "acme-util": "2.1.0"} {
		code, body := r.get(name)
		var doc struct {
			DistTags map[string]string `json:"dist-tags"`
			Versions map[string]struct {
				Dist struct{ Tarball, Integrity string }
			}
		}
		if code != http.StatusOK || json.Unmarshal([]byte(body), &doc) != nil || doc.DistTags["latest"] != v {
			t.Fatalf("%s: %d %s", name, code, body)
		}
		if tb := doc.Versions[v].Dist.Tarball; !strings.HasPrefix(tb, r.URL) {
			t.Errorf("%s tarball %q is not served by tspackages", name, tb)
		}
	}

	// npm publish --provenance needs a CI OIDC token, so send its body shape
	// with a .sigstore attachment directly.
	tgz := npmTarball(t, "@acme/prov", "1.0.0", 0)
	bundle := `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{},"dsseEnvelope":{}}`
	body, _ := json.Marshal(map[string]any{
		"_id": "@acme/prov", "name": "@acme/prov", "access": nil,
		"dist-tags": map[string]string{"latest": "1.0.0"},
		"versions": map[string]any{"1.0.0": map[string]any{
			"name": "@acme/prov", "version": "1.0.0", "_id": "@acme/prov@1.0.0",
			"dist": map[string]string{"integrity": integrity(tgz), "shasum": sha1Hex(tgz), "tarball": "http://x/@acme/prov/-/@acme/prov-1.0.0.tgz"},
		}},
		"_attachments": map[string]any{
			"@acme/prov-1.0.0.tgz":      map[string]any{"content_type": "application/octet-stream", "data": base64.StdEncoding.EncodeToString(tgz), "length": len(tgz)},
			"@acme/prov-1.0.0.sigstore": map[string]any{"content_type": "application/vnd.dev.sigstore.bundle.v0.3+json", "data": bundle, "length": len(bundle)},
		},
	})
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPut, r.URL+"@acme%2fprov", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("provenance publish: %d", resp.StatusCode)
	}
	got, err := r.hosted("npm/" + storage.EscapeSegment("@acme/prov") + "/" + storage.EscapeSegment("1.0.0") + "/package.sigstore")
	if err != nil || string(got) != bundle {
		t.Fatalf("stored bundle %q, %v", got, err)
	}
}

func TestNPMRepublishConflict(t *testing.T) {
	r := startNPMRegistry(t, nil)
	r.publish("acme-util", "1.0.0")
	// --force skips npm's own check for an existing version.
	out, err := r.run(r.lib("acme-util", "1.0.0", `"changed"`), "npm", "publish", "--force")
	if err == nil || !strings.Contains(out, "E409") || !strings.Contains(out, "version already exists") {
		t.Fatalf("republish: err=%v\n%s", err, out)
	}
}

func TestNPMDistTag(t *testing.T) {
	r := startNPMRegistry(t, nil)
	r.publish("@acme/lib", "1.0.0")
	r.publish("@acme/lib", "1.1.0")
	dir := r.project(map[string]any{"name": "app", "private": true}, nil)
	r.must(dir, "npm", "dist-tag", "add", "@acme/lib@1.0.0", "beta")
	if out := r.must(dir, "npm", "dist-tag", "ls", "@acme/lib"); !strings.Contains(out, "beta: 1.0.0") || !strings.Contains(out, "latest: 1.1.0") {
		t.Fatalf("ls after add:\n%s", out)
	}
	r.must(dir, "npm", "dist-tag", "rm", "@acme/lib", "beta")
	if out := r.must(dir, "npm", "dist-tag", "ls", "@acme/lib"); strings.Contains(out, "beta") {
		t.Fatalf("ls after rm:\n%s", out)
	}
}

var appDeps = []string{"@acme/lib", "left-pad"}

// appProject depends on a storage package and an upstream one.
func (r *npmRegistry) appProject() string {
	r.t.Helper()
	r.publish("@acme/lib", "1.0.0")
	r.up.add(r.t, "left-pad", "1.3.0", 0)
	return r.project(map[string]any{"name": "app", "version": "1.0.0", "private": true,
		"dependencies": map[string]string{"@acme/lib": "^1.0.0", "left-pad": "^1.3.0"}}, nil)
}

func TestNPMInstallAndCI(t *testing.T) {
	t.Run("fs", func(t *testing.T) { testNPMInstallAndCI(t, fsStores) })
	t.Run("s3", func(t *testing.T) { testNPMInstallAndCI(t, s3Stores) })
}

func testNPMInstallAndCI(t *testing.T, stores func(*testing.T, string) (config.StoreConfig, config.StoreConfig)) {
	r := startNPMRegistry(t, stores)
	dir := r.appProject()
	r.must(dir, "npm", "install")
	first := installed(t, dir, appDeps...)
	lock, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{r.URL + "@acme/lib/-/lib-1.0.0.tgz", r.URL + "left-pad/-/left-pad-1.3.0.tgz"} {
		if !strings.Contains(string(lock), want) {
			t.Errorf("package-lock.json does not resolve %s:\n%s", want, lock)
		}
	}
	if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
		t.Fatal(err)
	}
	r.must(dir, "npm", "ci")
	if again := installed(t, dir, appDeps...); !maps.Equal(again, first) {
		t.Fatalf("npm ci installed %v, npm install %v", again, first)
	}
}

func TestNPMCIFromNpmjsLockfile(t *testing.T) {
	r := startNPMRegistry(t, nil)
	pad := r.up.add(t, "left-pad", "1.3.0", 0)
	self := r.up.add(t, "npm", "11.0.0", 0)
	deps := map[string]string{"left-pad": "^1.3.0", "npm": "^11.0.0"}
	lock, _ := json.MarshalIndent(map[string]any{
		"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"": map[string]any{"name": "app", "version": "1.0.0", "dependencies": deps},
			"node_modules/left-pad": map[string]any{
				"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "integrity": integrity(pad),
			},
			"node_modules/npm": map[string]any{
				"version": "11.0.0", "resolved": "https://registry.npmjs.org/npm/-/npm-11.0.0.tgz", "integrity": integrity(self),
			},
		},
	}, "", "  ")
	dir := r.project(map[string]any{"name": "app", "version": "1.0.0", "private": true, "dependencies": deps},
		map[string]string{"package-lock.json": string(lock)})
	r.must(dir, "npm", "ci")
	for _, f := range []string{"left-pad/index.js", "npm/index.js"} {
		if _, err := os.Stat(filepath.Join(dir, "node_modules", f)); err != nil {
			t.Error(err)
		}
	}
	for _, p := range []string{"/left-pad/-/left-pad-1.3.0.tgz", "/npm/-/npm-11.0.0.tgz"} {
		if r.up.count(p) != 1 {
			t.Errorf("%s fetched %d times through tspackages", p, r.up.count(p))
		}
	}
}

func TestPNPMInstall(t *testing.T) {
	needNode(t, "pnpm")
	r := startNPMRegistry(t, nil)
	dir := r.appProject()
	// Explicit: pnpm defaults to --frozen-lockfile when it detects CI.
	r.must(dir, "pnpm", "install", "--no-frozen-lockfile")
	first := installed(t, dir, appDeps...)
	if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
		t.Fatal(err)
	}
	r.must(dir, "pnpm", "install", "--frozen-lockfile")
	if again := installed(t, dir, appDeps...); !maps.Equal(again, first) {
		t.Fatalf("frozen install %v, install %v", again, first)
	}
}

func TestPNPMPublish(t *testing.T) {
	needNode(t, "pnpm")
	r := startNPMRegistry(t, nil)
	r.must(r.lib("@acme/other", "0.1.0", `"other"`), "pnpm", "publish", "--no-git-checks")
	code, body := r.get("@acme%2fother")
	if code != http.StatusOK || !strings.Contains(body, `"0.1.0"`) {
		t.Fatalf("packument after pnpm publish: %d %s", code, body)
	}
	dir := r.project(map[string]any{"name": "app", "private": true, "dependencies": map[string]string{"@acme/other": "0.1.0"}}, nil)
	r.must(dir, "npm", "install")
	if b, err := os.ReadFile(filepath.Join(dir, "node_modules/@acme/other/index.js")); err != nil || !strings.Contains(string(b), `"other"`) {
		t.Fatalf("installed %q, %v", b, err)
	}
}

func TestNPMTamperedTarball(t *testing.T) {
	r := startNPMRegistry(t, nil)
	b := r.up.add(t, "badpkg", "1.0.0", 0)
	r.up.mu.Lock()
	r.up.tamper["/badpkg/-/badpkg-1.0.0.tgz"] = true
	r.up.mu.Unlock()
	dir := r.project(map[string]any{"name": "app", "private": true, "dependencies": map[string]string{"badpkg": "1.0.0"}}, nil)
	// The relay streams while it hashes and breaks the transfer on a
	// mismatch, which npm reports as ECONNRESET. npm retries; each retry must
	// reach the upstream again, since nothing was cached.
	out, err := r.run(dir, "npm", "install", "--fetch-retries=2", "--fetch-retry-mintimeout=100", "--fetch-retry-maxtimeout=200")
	if err == nil || !strings.Contains(out, "ECONNRESET") && !strings.Contains(out, "EINTEGRITY") && !strings.Contains(out, "502") {
		t.Fatalf("installed a tampered tarball: err=%v\n%s", err, out)
	}
	if n := r.up.count("/badpkg/-/badpkg-1.0.0.tgz"); n < 2 {
		t.Errorf("upstream fetched %d times for npm's retries; the tampered tarball was served from cache", n)
	}
	sum := sha512.Sum512(b)
	cache, err := storage.Open(t.Context(), r.cfg.Storage.Cache)
	if err != nil {
		t.Fatal(err)
	}
	if rc, _, err := cache.Get(t.Context(), "npm/npmjs/tarballs/sha512-"+hex.EncodeToString(sum[:])); !errors.Is(err, storage.ErrNotFound) {
		if rc != nil {
			rc.Close()
		}
		t.Fatalf("the tampered tarball is cached: %v", err)
	}
}

func TestNPMLargeTarball(t *testing.T) {
	r := startNPMRegistry(t, nil)
	r.up.add(t, "bigpkg", "1.0.0", 65<<20)
	dir := r.project(map[string]any{"name": "app", "private": true, "dependencies": map[string]string{"bigpkg": "1.0.0"}}, nil)
	r.must(dir, "npm", "install")
	if fi, err := os.Stat(filepath.Join(dir, "node_modules/bigpkg/blob.bin")); err != nil || fi.Size() != 65<<20 {
		t.Fatalf("blob.bin: %v %v", fi, err)
	}
}

func TestNPMDeprecateUnpublish405(t *testing.T) {
	r := startNPMRegistry(t, nil)
	r.publish("@acme/lib", "1.0.0")
	dir := r.project(map[string]any{"name": "app", "private": true}, nil)
	for _, args := range [][]string{
		{"deprecate", "@acme/lib@1.0.0", "use 2.x"},
		{"unpublish", "@acme/lib@1.0.0", "--force"},
	} {
		out, err := r.run(dir, "npm", args...)
		if err == nil || !strings.Contains(out, "E405") {
			t.Errorf("npm %s: err=%v\n%s", args[0], err, out)
		}
		if strings.Contains(strings.ToLower(out), "one-time") || strings.Contains(out, "EOTP") {
			t.Errorf("npm %s asked for an OTP:\n%s", args[0], out)
		}
	}
	if code, body := r.get("@acme%2flib"); code != http.StatusOK || !strings.Contains(body, `"1.0.0"`) || strings.Contains(body, "deprecated") {
		t.Fatalf("after deprecate/unpublish: %d %s", code, body)
	}
}
