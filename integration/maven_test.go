//go:build integration

package integration

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/maven"
	"github.com/radiergummi/tspackages/internal/server"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

// The public dependency the seed holds and the test projects use.
const (
	slf4jJar = "org/slf4j/slf4j-api/2.0.17/slf4j-api-2.0.17.jar"
	slf4jUse = "org.slf4j.LoggerFactory.class.getName()"
	libUse   = "com.example.lib.Lib.value()"
)

func needJava(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range append([]string{"java", "keytool"}, tools...) {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not on PATH")
		}
	}
}

// mavenSeed returns the local repository make maven-seed populated. mvn
// needs its build plugins from the upstream, and the fake upstream serves
// them from there. Under CI a missing seed is a failure, not a skip.
func mavenSeed(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("TSP_TEST_MAVEN_SEED")
	if dir != "" {
		if _, err := os.Stat(filepath.Join(dir, path.Dir(slf4jJar))); err == nil {
			return dir
		}
	}
	msg := fmt.Sprintf("no Maven seed at TSP_TEST_MAVEN_SEED=%q; run make maven-seed", dir)
	if os.Getenv("CI") == "true" {
		t.Fatal(msg)
	}
	t.Skip(msg)
	return ""
}

// fakeCentral serves a Maven repository the way Maven Central does: the
// seed read-only, plus files added in memory. It answers <file>.sha1 from
// the seed's copy, or computed from the file when there is none, and
// records every request path.
type fakeCentral struct {
	*httptest.Server
	seed   *os.Root // nil: in-memory files only
	mu     sync.Mutex
	extra  map[string][]byte // path → bytes
	tamper map[string]bool   // path → serve other bytes than its .sha1 declares
	paths  []string
}

func newFakeCentral(t *testing.T, seed string) *fakeCentral {
	t.Helper()
	f := &fakeCentral{extra: map[string][]byte{}, tamper: map[string]bool{}}
	if seed != "" {
		root, err := os.OpenRoot(seed)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.Close() })
		f.seed = root
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeCentral) serve(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	f.mu.Lock()
	f.paths = append(f.paths, p)
	f.mu.Unlock()
	if base, ok := strings.CutSuffix(p, ".sha1"); ok {
		if b, err := f.read(p); err == nil {
			w.Write(b)
			return
		}
		if b, err := f.read(base); err == nil {
			io.WriteString(w, sha1Hex(b))
			return
		}
		http.NotFound(w, r)
		return
	}
	b, err := f.read(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	if f.tamper[p] {
		b = bytes.Clone(b)
		b[len(b)-1] ^= 0xff
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Write(b)
}

func (f *fakeCentral) read(p string) ([]byte, error) {
	f.mu.Lock()
	b, ok := f.extra[p]
	f.mu.Unlock()
	if ok {
		return b, nil
	}
	if f.seed == nil || !fs.ValidPath(p) || path.Base(p) == "_remote.repositories" {
		return nil, fs.ErrNotExist
	}
	return f.seed.ReadFile(p)
}

// add serves a release artifact: its POM, and its jar when jar is not nil.
func (f *fakeCentral) add(group, artifact, version string, jar []byte) {
	dir := strings.ReplaceAll(group, ".", "/") + "/" + artifact + "/" + version + "/" + artifact + "-" + version
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extra[dir+".pom"] = fmt.Appendf(nil, `<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>`+
		`<groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version></project>`, group, artifact, version)
	if jar != nil {
		f.extra[dir+".jar"] = jar
	}
}

func (f *fakeCentral) saw(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.ContainsFunc(f.paths, func(p string) bool { return strings.HasPrefix(p, prefix) })
}

func (f *fakeCentral) count(p string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.paths {
		if s == p {
			n++
		}
	}
	return n
}

// mvnRegistry is a wired tspackages behind TLS with a Maven storage source
// claiming com.example and com.example.*, and the fake Central as the
// unclaimed registry source. Clients are configured with the status page's
// snippets.
type mvnRegistry struct {
	t     *testing.T
	URL   string // the repository, ending in /maven/
	host  string
	cfg   *config.Config
	up    *fakeCentral
	trust string // a PKCS12 trust store holding the server's certificate
	mu    sync.Mutex
	reqs  []string // "METHOD /path" of every request tspackages served
	http  *http.Client
}

type mvnOptions struct {
	seed   bool   // the fake Central serves the seed; mvn needs it
	rules  string // capability rules for every caller
	stores func(*testing.T, string) (config.StoreConfig, config.StoreConfig)
}

func startMavenRegistry(t *testing.T, o mvnOptions) *mvnRegistry {
	t.Helper()
	needJava(t)
	seed := ""
	if o.seed {
		needJava(t, "mvn")
		seed = mavenSeed(t)
	}
	if o.stores == nil {
		o.stores = fsStores
	}
	if o.rules == "" {
		o.rules = `{"read":["*"],"write":["maven:com.example","maven:com.example.*"]}`
	}
	root := t.TempDir()
	r := &mvnRegistry{t: t, up: newFakeCentral(t, seed)}
	uu, _ := url.Parse(r.up.URL)
	state, hosted := o.stores(t, root)
	r.cfg = &config.Config{
		Tailscale: config.Tailscale{Hostname: "registry", Capability: capName, StateDir: filepath.Join(root, "ts")},
		Storage: config.Storage{
			WorkDir: filepath.Join(root, "work"),
			Cache:   config.StoreConfig{Driver: "fs", Path: filepath.Join(root, "cache"), MaxSize: 4 << 30},
			State:   state,
			Stores:  map[string]config.StoreConfig{"main": hosted},
		},
		// A cold build fetches a few hundred files, each after its .sha1: the
		// default of 10 upstream fetches a second would make every test take
		// a minute.
		Limits: config.Limits{UpstreamFetchesPerSecond: 1000},
		Ecosystems: map[string]config.Ecosystem{"maven": {Sources: []config.Source{
			{Name: "hosted", Type: "storage", Store: "main", Claims: []string{"com.example", "com.example.*"}},
			{Name: "central", Type: "registry", URL: r.up.URL + "/", FetchHosts: []string{uu.Host}, MetadataTTL: time.Nanosecond},
		}}},
	}
	ctx, cancel := context.WithCancel(t.Context())
	handler, start, err := server.Build(ctx, r.cfg, testutil.NewWho(capName, o.rules), slog.New(slog.DiscardHandler),
		server.Hooks{AllowPrivateUpstreams: true})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	loops := make(chan struct{})
	go func() { start(ctx); close(loops) }()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.reqs = append(r.reqs, req.Method+" "+req.URL.Path)
		r.mu.Unlock()
		handler.ServeHTTP(w, req)
	}))
	t.Cleanup(func() { srv.Close(); cancel(); <-loops })
	su, _ := url.Parse(srv.URL)
	r.URL, r.host, r.http = srv.URL+"/maven/", su.Host, srv.Client()

	// The JVM trusts the test server through a trust store of its own.
	pemFile := filepath.Join(root, "server.pem")
	if err := os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	r.trust = filepath.Join(root, "trust.p12")
	if out, err := exec.CommandContext(t.Context(), "keytool", "-importcert", "-noprompt", "-alias", "tspackages", "-file", pemFile,
		"-keystore", r.trust, "-storetype", "PKCS12", "-storepass", "changeit").CombinedOutput(); err != nil {
		t.Fatalf("keytool: %v\n%s", err, out)
	}
	return r
}

// snippet is the status page's snippet i for this registry.
func (r *mvnRegistry) snippet(i int) string {
	return strings.ReplaceAll(maven.StatusSection(nil).Snippets[i].Code, "{{host}}", r.host)
}

// Indexes into the status page's snippets.
const (
	snippetSettings = iota
	snippetDistribution
	snippetGradleRepositories
	snippetGradlePublishing
)

// project copies testdata/maven/<name> into a fresh directory, expanding
// every file as a template of data.
func (r *mvnRegistry) project(name string, data any) string {
	r.t.Helper()
	src := filepath.Join("testdata", "maven", name)
	dir := r.t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		tmpl, err := template.ParseFiles(p)
		if err != nil {
			return err
		}
		var b bytes.Buffer
		if err := tmpl.Execute(&b, data); err != nil {
			return err
		}
		writeTree(r.t, dir, map[string]string{rel: b.String()})
		return nil
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return dir
}

type mvnCoords struct {
	Group, Artifact, Version string
	Body                     string // what the library's value() returns
	DistributionManagement   string
}

// lib writes the library project for g:a:v with the documented
// distributionManagement.
func (r *mvnRegistry) lib(group, artifact, version, body string) string {
	return r.project("lib", mvnCoords{group, artifact, version, body, r.snippet(snippetDistribution)})
}

type mvnDep struct {
	Group, Artifact, Version string
	Use                      string // a Java expression the app prints, or ""
}

// app writes a project that compiles against deps.
func (r *mvnRegistry) app(deps ...mvnDep) string {
	return r.project("app", struct{ Deps []mvnDep }{deps})
}

// mvnClient is one mvn user: a private HOME, local repository and
// settings.xml (the status page's, verbatim).
type mvnClient struct {
	r        *mvnRegistry
	home     string
	repo     string
	settings string
}

func (r *mvnRegistry) mvn() *mvnClient {
	r.t.Helper()
	tmp := r.t.TempDir()
	c := &mvnClient{r: r, home: filepath.Join(tmp, "home"), repo: filepath.Join(tmp, "repository"), settings: filepath.Join(tmp, "settings.xml")}
	if err := os.MkdirAll(c.home, 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(c.settings, []byte(r.snippet(snippetSettings)), 0o644); err != nil {
		r.t.Fatal(err)
	}
	return c
}

// javaEnv is the environment for a JVM client: no inherited Maven, Gradle
// or Java options, and HOME set to home.
func javaEnv(home string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(k, "MAVEN_"), strings.HasPrefix(k, "GRADLE_"), strings.HasPrefix(k, "ORG_GRADLE_"),
			k == "JAVA_OPTS", k == "JAVA_TOOL_OPTIONS", k == "JDK_JAVA_OPTIONS", k == "_JAVA_OPTIONS", k == "HOME", k == "M2_HOME":
			continue
		}
		env = append(env, kv)
	}
	return append(env, "HOME="+home)
}

func (c *mvnClient) run(dir string, args ...string) (string, error) {
	c.r.t.Helper()
	ctx, cancel := context.WithTimeout(c.r.t.Context(), 5*time.Minute)
	defer cancel()
	args = append([]string{"-B", "-ntp", "-s", c.settings, "-Dmaven.repo.local=" + c.repo}, args...)
	cmd := exec.CommandContext(ctx, "mvn", args...)
	cmd.Dir = dir
	cmd.Env = append(javaEnv(c.home),
		"MAVEN_OPTS=-Djavax.net.ssl.trustStore="+c.r.trust+" -Djavax.net.ssl.trustStorePassword=changeit")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (c *mvnClient) must(dir string, args ...string) string {
	c.r.t.Helper()
	out, err := c.run(dir, args...)
	if err != nil {
		c.r.t.Fatalf("mvn %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// get returns the status and body of a GET below the repository.
func (r *mvnRegistry) get(p string) (int, string) {
	r.t.Helper()
	req, _ := http.NewRequestWithContext(r.t.Context(), http.MethodGet, r.URL+p, nil)
	resp, err := r.http.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// served reports whether tspackages answered a request "METHOD /path".
func (r *mvnRegistry) served(req string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.reqs, req)
}

// mustGet fails unless p answers 200, and returns its body.
func (r *mvnRegistry) mustGet(p string) string {
	r.t.Helper()
	code, body := r.get(p)
	if code != http.StatusOK {
		r.t.Fatalf("GET %s: %d %s", p, code, body)
	}
	return body
}

func TestMavenDeployRelease(t *testing.T) {
	t.Run("fs", func(t *testing.T) { testMavenDeployRelease(t, fsStores) })
	t.Run("s3", func(t *testing.T) { testMavenDeployRelease(t, s3Stores) })
}

func testMavenDeployRelease(t *testing.T, stores func(*testing.T, string) (config.StoreConfig, config.StoreConfig)) {
	r := startMavenRegistry(t, mvnOptions{seed: true, stores: stores})
	r.mvn().must(r.lib("com.example", "lib", "1.0", "one"), "deploy")
	if md := r.mustGet("com/example/lib/maven-metadata.xml"); !strings.Contains(md, "<version>1.0</version>") || !strings.Contains(md, "<release>1.0</release>") {
		t.Fatalf("artifact metadata:\n%s", md)
	}
	for _, f := range []string{"lib-1.0.pom", "lib-1.0.jar", "lib-1.0-sources.jar", "lib-1.0-javadoc.jar"} {
		body := r.mustGet("com/example/lib/1.0/" + f)
		if sum := r.mustGet("com/example/lib/1.0/" + f + ".sha1"); sum != sha1Hex([]byte(body)) {
			t.Errorf("%s.sha1 = %s, want %s", f, sum, sha1Hex([]byte(body)))
		}
	}
}

func TestMavenRedeployConflict(t *testing.T) {
	r := startMavenRegistry(t, mvnOptions{seed: true})
	c := r.mvn()
	c.must(r.lib("com.example", "lib", "1.0", "one"), "deploy")
	jar := r.mustGet("com/example/lib/1.0/lib-1.0.jar")
	out, err := c.run(r.lib("com.example", "lib", "1.0", "two"), "deploy")
	if err == nil || !strings.Contains(out, "409") {
		t.Fatalf("redeploy with other bytes: err=%v\n%s", err, out)
	}
	if again := r.mustGet("com/example/lib/1.0/lib-1.0.jar"); again != jar {
		t.Fatal("the released jar changed")
	}
}

func TestMavenResolve(t *testing.T) {
	t.Run("fs", func(t *testing.T) { testMavenResolve(t, fsStores) })
	t.Run("s3", func(t *testing.T) { testMavenResolve(t, s3Stores) })
}

func testMavenResolve(t *testing.T, stores func(*testing.T, string) (config.StoreConfig, config.StoreConfig)) {
	r := startMavenRegistry(t, mvnOptions{seed: true, stores: stores})
	r.mvn().must(r.lib("com.example", "lib", "1.0", "one"), "deploy")
	c := r.mvn()
	c.must(r.app(mvnDep{"com.example", "lib", "1.0", libUse}, mvnDep{"org.slf4j", "slf4j-api", "2.0.17", slf4jUse}), "compile")
	for _, f := range []string{"com/example/lib/1.0/lib-1.0.jar", slf4jJar} {
		if _, err := os.Stat(filepath.Join(c.repo, f)); err != nil {
			t.Error(err)
		}
	}
	if r.up.saw("com/example/") {
		t.Error("a com.example path reached the upstream")
	}
}

func TestMavenSnapshotDeploy(t *testing.T) {
	r := startMavenRegistry(t, mvnOptions{seed: true})
	c := r.mvn()
	c.must(r.lib("com.example", "lib", "1.0-SNAPSHOT", "one"), "deploy")
	c.must(r.lib("com.example", "lib", "1.0-SNAPSHOT", "two"), "deploy")
	md := r.mustGet("com/example/lib/1.0-SNAPSHOT/maven-metadata.xml")
	for _, want := range []string{"<buildNumber>2</buildNumber>", "<extension>jar</extension>", "<classifier>sources</classifier>", "<classifier>javadoc</classifier>"} {
		if !strings.Contains(md, want) {
			t.Fatalf("version metadata lacks %s:\n%s", want, md)
		}
	}
	if md := r.mustGet("com/example/lib/maven-metadata.xml"); !strings.Contains(md, "<version>1.0-SNAPSHOT</version>") {
		t.Fatalf("artifact metadata:\n%s", md)
	}
}

// TestMavenSnapshotConsumer resolves a SNAPSHOT through the repository the
// status page's settings.xml declares for it.
func TestMavenSnapshotConsumer(t *testing.T) {
	r := startMavenRegistry(t, mvnOptions{seed: true})
	r.mvn().must(r.lib("com.example", "lib", "1.0-SNAPSHOT", "snapshot-one"), "deploy")
	c := r.mvn()
	app := r.app(mvnDep{"com.example", "lib", "1.0-SNAPSHOT", libUse})
	c.must(app, "compile")
	r.mvn().must(r.lib("com.example", "lib", "1.0-SNAPSHOT", "snapshot-two"), "deploy")
	// -U: the daily update policy would otherwise keep the first build.
	c.must(app, "-U", "compile")
	md := r.mustGet("com/example/lib/1.0-SNAPSHOT/maven-metadata.xml")
	_, rest, _ := strings.Cut(md, "<timestamp>")
	stamp, _, ok := strings.Cut(rest, "</timestamp>")
	if !ok {
		t.Fatalf("version metadata without a timestamp:\n%s", md)
	}
	jar := filepath.Join(c.repo, "com/example/lib/1.0-SNAPSHOT/lib-1.0-"+stamp+"-2.jar")
	if _, err := os.Stat(jar); err != nil {
		t.Fatalf("the second build was not resolved: %v", err)
	}
}

func TestMavenPluginDeploy(t *testing.T) {
	r := startMavenRegistry(t, mvnOptions{seed: true})
	r.mvn().must(r.project("plugin", mvnCoords{"com.example", "hello-maven-plugin", "1.0", "", r.snippet(snippetDistribution)}), "deploy")
	if !r.served("PUT /maven/com/example/maven-metadata.xml") {
		t.Error("mvn sent no group-level metadata")
	}
	if md := r.mustGet("com/example/hello-maven-plugin/maven-metadata.xml"); !strings.Contains(md, "<version>1.0</version>") {
		t.Fatalf("artifact metadata:\n%s", md)
	}
	// By full coordinates: storage serves no group-level metadata, so the
	// prefix does not resolve.
	out := r.mvn().must(r.t.TempDir(), "com.example:hello-maven-plugin:1.0:hello")
	if !strings.Contains(out, "[INFO] hello") {
		t.Fatalf("plugin did not run:\n%s", out)
	}
}

func TestMavenTamperedUpstream(t *testing.T) {
	r := startMavenRegistry(t, mvnOptions{seed: true})
	good, err := r.up.read(slf4jJar)
	if err != nil {
		t.Fatal(err)
	}
	r.up.mu.Lock()
	r.up.tamper[slf4jJar] = true
	r.up.mu.Unlock()
	c := r.mvn()
	out, err := c.run(r.app(mvnDep{"org.slf4j", "slf4j-api", "2.0.17", slf4jUse}), "compile")
	if err == nil {
		t.Fatalf("built with a tampered upstream jar:\n%s", out)
	}
	if !strings.Contains(out, "slf4j-api") {
		t.Errorf("the build failed for another reason:\n%s", out)
	}
	if r.up.count(slf4jJar) == 0 {
		t.Fatal("the jar was never fetched")
	}
	cache, err := storage.Open(t.Context(), r.cfg.Storage.Cache)
	if err != nil {
		t.Fatal(err)
	}
	if rc, _, err := cache.Get(t.Context(), "maven/central/files/sha1-"+sha1Hex(good)); !errors.Is(err, storage.ErrNotFound) {
		if rc != nil {
			rc.Close()
		}
		t.Fatalf("the tampered jar is cached: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(c.repo, slf4jJar)); err == nil && !bytes.Equal(b, good) {
		t.Fatal("mvn stored the tampered jar")
	}
}

// bigJar is a valid jar of more than 64 MiB: one stored entry of random
// bytes.
func bigJar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "blob.bin", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 65<<20)
	rand.Read(blob)
	w.Write(blob)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestMavenLargeArtifact(t *testing.T) {
	r := startMavenRegistry(t, mvnOptions{seed: true})
	jar := bigJar(t)
	r.up.add("org.example.big", "big", "1.0", jar)
	c := r.mvn()
	c.must(r.app(mvnDep{"org.example.big", "big", "1.0", ""}), "compile")
	got, err := os.ReadFile(filepath.Join(c.repo, "org/example/big/big/1.0/big-1.0.jar"))
	if err != nil || !bytes.Equal(got, jar) {
		t.Fatalf("big-1.0.jar: %d bytes, %v", len(got), err)
	}
}

// seedReadRules grants read on every group of the seed and on com.example,
// but not on the rest of com.example.*.
func seedReadRules(t *testing.T, seed string) string {
	t.Helper()
	rules := []string{`"maven:com.example"`}
	add := func(dir, group string) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || group+e.Name() == "com.example" {
				continue
			}
			rules = append(rules, `"maven:`+group+e.Name()+`"`, `"maven:`+group+e.Name()+`.*"`)
		}
	}
	ents, err := os.ReadDir(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		switch {
		case !e.IsDir() || strings.HasPrefix(e.Name(), "."):
		case e.Name() == "com":
			add(filepath.Join(seed, "com"), "com.")
		default:
			rules = append(rules, `"maven:`+e.Name()+`"`, `"maven:`+e.Name()+`.*"`)
		}
	}
	return `{"read":[` + strings.Join(rules, ",") + `]}`
}

// TestMavenDeniedFallsNowhere: a claimed artifact the caller may not read
// fails the build, although the upstream has the same coordinates.
func TestMavenDeniedFallsNowhere(t *testing.T) {
	needJava(t, "mvn")
	r := startMavenRegistry(t, mvnOptions{seed: true, rules: seedReadRules(t, mavenSeed(t))})
	r.up.add("com.example.internal", "secret", "1.0", smallJar(t))
	out, err := r.mvn().run(r.app(mvnDep{"com.example.internal", "secret", "1.0", ""}), "compile")
	if err == nil {
		t.Fatalf("resolved a denied artifact:\n%s", out)
	}
	if !strings.Contains(out, "com.example.internal:secret") || !strings.Contains(out, "403") {
		t.Errorf("mvn did not report the 403 for the denied artifact:\n%s", out)
	}
	if r.up.saw("com/example/") {
		t.Error("the denied artifact was asked for upstream")
	}
}

// smallJar is a valid jar with one small entry.
func smallJar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("upstream.txt")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "public decoy")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// gradleClient is one Gradle user: a private GRADLE_USER_HOME whose
// gradle.properties makes the JVM trust the test server.
type gradleClient struct {
	r    *mvnRegistry
	home string
	env  []string
}

func (r *mvnRegistry) gradle() *gradleClient {
	r.t.Helper()
	needJava(r.t, "gradle")
	tmp := r.t.TempDir()
	c := &gradleClient{r: r, home: filepath.Join(tmp, "home")}
	writeTree(r.t, filepath.Join(tmp, "gradle-home"), map[string]string{"gradle.properties": "systemProp.javax.net.ssl.trustStore=" + r.trust +
		"\nsystemProp.javax.net.ssl.trustStorePassword=changeit\norg.gradle.daemon=false\n"})
	if err := os.MkdirAll(c.home, 0o755); err != nil {
		r.t.Fatal(err)
	}
	c.env = append(javaEnv(c.home), "GRADLE_USER_HOME="+filepath.Join(tmp, "gradle-home"))
	return c
}

func (c *gradleClient) run(dir string, env []string, args ...string) (string, error) {
	c.r.t.Helper()
	ctx, cancel := context.WithTimeout(c.r.t.Context(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gradle", append([]string{"--no-daemon", "--console=plain", "--stacktrace"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(slices.Clone(c.env), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (c *gradleClient) must(dir string, env []string, args ...string) string {
	c.r.t.Helper()
	out, err := c.run(dir, env, args...)
	if err != nil {
		c.r.t.Fatalf("gradle %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

type gradleLib struct {
	Group, Artifact, Version, Body string
	Repositories, Publishing       string
}

// gradleLib writes the Gradle library project with the documented
// repositories and publishing blocks.
func (r *mvnRegistry) gradleLib(group, artifact, version, body string) string {
	return r.project("gradle/lib", gradleLib{group, artifact, version, body, r.snippet(snippetGradleRepositories), r.snippet(snippetGradlePublishing)})
}

func (r *mvnRegistry) gradleApp(dependency string) string {
	return r.project("gradle/app", struct{ Repositories, Dependency string }{r.snippet(snippetGradleRepositories), dependency})
}

// signingKey generates an unprotected OpenPGP key and returns it armored,
// as Gradle's useInMemoryPgpKeys takes it.
func signingKey(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not on PATH")
	}
	// gpg-agent's socket path must stay short: not below t.TempDir().
	home, err := os.MkdirTemp("", "gpg")
	if err != nil {
		t.Fatal(err)
	}
	gpg := func(args ...string) []byte {
		cmd := exec.CommandContext(t.Context(), "gpg", append([]string{"--batch", "--homedir", home, "--pinentry-mode", "loopback", "--passphrase", ""}, args...)...)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("gpg %s: %v", strings.Join(args, " "), err)
		}
		return out
	}
	t.Cleanup(func() {
		exec.Command("gpgconf", "--homedir", home, "--kill", "gpg-agent").Run() //nolint:noctx // cleanup runs after t.Context is done
		os.RemoveAll(home)
	})
	gpg("--quick-gen-key", "tspackages test <test@example.com>", "rsa3072", "sign", "never")
	return string(gpg("--armor", "--export-secret-keys"))
}

func TestGradlePublishAndResolve(t *testing.T) {
	r := startMavenRegistry(t, mvnOptions{})
	key := signingKey(t)
	r.gradle().must(r.gradleLib("com.example", "glib", "1.0", "gradle-one"), []string{"SIGNING_KEY=" + key}, "publish")
	for _, f := range []string{"glib-1.0.jar", "glib-1.0.pom", "glib-1.0.module", "glib-1.0-sources.jar",
		"glib-1.0.jar.asc", "glib-1.0.pom.asc", "glib-1.0.module.asc"} {
		r.mustGet("com/example/glib/1.0/" + f)
	}
	if md := r.mustGet("com/example/glib/maven-metadata.xml"); !strings.Contains(md, "<version>1.0</version>") {
		t.Fatalf("artifact metadata:\n%s", md)
	}

	c := r.gradle()
	app := r.gradleApp("com.example:glib:1.+")
	out := c.must(app, nil, "compileJava", "resolved")
	if !strings.Contains(out, "resolved com.example:glib:1.0 glib-1.0.jar") {
		t.Fatalf("1.+ did not resolve to 1.0:\n%s", out)
	}
	if !r.served("GET /maven/com/example/glib/1.0/glib-1.0.module") {
		t.Error("Gradle did not read the module metadata")
	}
}

func TestGradleSnapshot(t *testing.T) {
	r := startMavenRegistry(t, mvnOptions{})
	g := r.gradle()
	g.must(r.gradleLib("com.example", "glib", "1.0-SNAPSHOT", "gradle-snapshot"), nil, "publish")
	md := r.mustGet("com/example/glib/1.0-SNAPSHOT/maven-metadata.xml")
	if !strings.Contains(md, "<buildNumber>1</buildNumber>") {
		t.Fatalf("version metadata:\n%s", md)
	}
	out := r.gradle().must(r.gradleApp("com.example:glib:1.0-SNAPSHOT"), nil, "compileJava", "resolved")
	if !strings.Contains(out, "resolved com.example:glib:1.0-SNAPSHOT") {
		t.Fatalf("the SNAPSHOT did not resolve:\n%s", out)
	}
}
