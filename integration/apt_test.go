//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
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
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/apt"
	"github.com/radiergummi/tspackages/internal/server"
	"github.com/radiergummi/tspackages/internal/testutil"
)

// needApt skips without apt-get and apt-cache, and fails under CI, whose
// Ubuntu runner has them.
func needApt(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"apt-get", "apt-cache"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("CI") == "true" {
				t.Fatal(tool + " not on PATH")
			}
			t.Skip(tool + " not on PATH")
		}
	}
}

// aptDeb builds a .deb of name, version and arch; desc varies its bytes.
func aptDeb(t *testing.T, name, version, arch, desc string) []byte {
	t.Helper()
	return testutil.Deb(t, "Package: "+name+"\nVersion: "+version+"\nArchitecture: "+arch+
		"\nMaintainer: Test <test@example.com>\nDescription: "+desc+"\n", testutil.DebOptions{})
}

// fakeAptRepo serves a signed apt repository the way a Debian mirror does:
// one suite "stable", component "main", architecture "amd64", indexes also
// by hash. It records every request path.
type fakeAptRepo struct {
	*httptest.Server
	t      *testing.T
	signer *apt.Signer
	public string // armored public key
	mu     sync.Mutex
	debs   []fakeDeb
	files  map[string][]byte // path → bytes
	tamper map[string]bool   // path → serve other bytes than the index declares
	paths  []string
}

type fakeDeb struct {
	name, version string
	path          string // pool path
	b             []byte
}

func newFakeAptRepo(t *testing.T) *fakeAptRepo {
	t.Helper()
	private, public := testutil.PGPKey(t, "upstream")
	signer, err := apt.LoadSigner(private, "")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAptRepo{t: t, signer: signer, public: public, files: map[string][]byte{}, tamper: map[string]bool{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	f.publish()
	return f
}

func (f *fakeAptRepo) serve(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, p)
	b, ok := f.files[p]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if f.tamper[p] {
		b = bytes.Clone(b)
		b[len(b)-1] ^= 0xff
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Write(b)
}

// add offers an amd64 package and publishes a new Release; it returns the
// pool path.
func (f *fakeAptRepo) add(name, version string, b []byte) string {
	p := "pool/main/" + name[:1] + "/" + name + "/" + name + "_" + version + "_amd64.deb"
	f.mu.Lock()
	f.debs = append(f.debs, fakeDeb{name, version, p, b})
	f.files[p] = b
	f.mu.Unlock()
	f.publish()
	return p
}

// publish writes the indexes, by-hash copies and the signed Release.
func (f *fakeAptRepo) publish() {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var pkgs bytes.Buffer
	for i, d := range f.debs {
		if i > 0 {
			pkgs.WriteByte('\n')
		}
		sum := sha256.Sum256(d.b)
		fmt.Fprintf(&pkgs, "Package: %s\nVersion: %s\nArchitecture: amd64\nMaintainer: Test <test@example.com>\n"+
			"Description: upstream\nFilename: %s\nSize: %d\nSHA256: %s\n", d.name, d.version, d.path, len(d.b), hex.EncodeToString(sum[:]))
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(pkgs.Bytes())
	zw.Close()
	var hashes []apt.FileHash
	for rel, b := range map[string][]byte{"main/binary-amd64/Packages": pkgs.Bytes(), "main/binary-amd64/Packages.gz": gz.Bytes()} {
		sum := sha256.Sum256(b)
		h := hex.EncodeToString(sum[:])
		f.files["dists/stable/"+rel] = b
		f.files["dists/stable/main/binary-amd64/by-hash/SHA256/"+h] = b
		hashes = append(hashes, apt.FileHash{Path: rel, Size: int64(len(b)), SHA256: h})
	}
	doc := apt.ReleaseDoc{
		Fields: apt.Stanza{
			{Name: "Origin", Value: "Upstream"}, {Name: "Label", Value: "Upstream"}, {Name: "Suite", Value: "stable"},
			{Name: "Codename", Value: "stable"}, {Name: "Date"}, {Name: "Architectures", Value: "amd64"},
			{Name: "Components", Value: "main"}, {Name: "Acquire-By-Hash"},
		},
		Date: time.Now().UTC().Truncate(time.Second), ByHash: true, SHA256: hashes,
	}
	release := doc.Render()
	in, err := f.signer.ClearSign(release)
	if err != nil {
		f.t.Fatal(err)
	}
	sig, err := f.signer.DetachSign(release)
	if err != nil {
		f.t.Fatal(err)
	}
	f.files["dists/stable/Release"], f.files["dists/stable/InRelease"], f.files["dists/stable/Release.gpg"] = release, in, sig
}

func (f *fakeAptRepo) count(p string) int {
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

// aptRegistry is a wired tspackages behind TLS with an apt storage source
// "hosted" claiming acme-* and a registry source "upstream" in front of the
// fake repository.
type aptRegistry struct {
	t    *testing.T
	URL  string // ending in /apt/
	host string
	ca   string // PEM file of the server's certificate
	up   *fakeAptRepo
	http *http.Client
	mu   sync.Mutex
	reqs []string // "<status> METHOD /path" of every request tspackages answered
}

type aptOptions struct {
	rules  string // capability rules for every caller
	stores func(*testing.T, string) (config.StoreConfig, config.StoreConfig)
	// failByHash answers 404 to the first by-hash request for hosted.
	failByHash bool
}

func startAptRegistry(t *testing.T, o aptOptions) *aptRegistry {
	t.Helper()
	needApt(t)
	if o.stores == nil {
		o.stores = fsStores
	}
	if o.rules == "" {
		o.rules = `{"read":["*"],"write":["apt:acme-*"]}`
	}
	root := aptRoot(t)
	r := &aptRegistry{t: t, up: newFakeAptRepo(t)}
	uu, _ := url.Parse(r.up.URL)
	keyring := filepath.Join(root, "upstream.asc")
	if err := os.WriteFile(keyring, []byte(r.up.public), 0o644); err != nil {
		t.Fatal(err)
	}
	signingKey, _ := testutil.PGPKey(t, "tspackages")
	state, hosted := o.stores(t, root)
	cfg := &config.Config{
		Tailscale: config.Tailscale{Hostname: "registry", Capability: capName, StateDir: filepath.Join(root, "ts")},
		Storage: config.Storage{
			WorkDir: filepath.Join(root, "work"),
			Cache:   config.StoreConfig{Driver: "fs", Path: filepath.Join(root, "cache"), MaxSize: 1 << 30},
			State:   state,
			Stores:  map[string]config.StoreConfig{"main": hosted},
		},
		Ecosystems: map[string]config.Ecosystem{"apt": {
			SigningKey: signingKey,
			Sources: []config.Source{
				{Name: "hosted", Type: "storage", Store: "main", Claims: []string{"acme-*"}},
				{
					Name: "upstream", Type: "registry", URL: r.up.URL + "/", FetchHosts: []string{uu.Host}, Keyring: keyring,
					Suites: []string{"stable"}, Components: []string{"main"}, Architectures: []string{"amd64"},
					MetadataTTL: time.Nanosecond,
				},
			},
		}},
	}
	ctx, cancel := context.WithCancel(t.Context())
	handler, start, err := server.Build(ctx, cfg, testutil.NewWho(capName, o.rules), slog.New(slog.DiscardHandler),
		server.Hooks{AllowPrivateUpstreams: true})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	loops := make(chan struct{})
	go func() { start(ctx); close(loops) }()
	failed := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		r.mu.Lock()
		fail := o.failByHash && !failed && strings.HasPrefix(req.URL.Path, "/apt/hosted/dists/") &&
			strings.Contains(req.URL.Path, "/by-hash/")
		failed = failed || fail
		r.mu.Unlock()
		if fail {
			http.NotFound(rec, req)
		} else {
			handler.ServeHTTP(rec, req)
		}
		r.mu.Lock()
		r.reqs = append(r.reqs, strconv.Itoa(rec.status)+" "+req.Method+" "+req.URL.Path)
		r.mu.Unlock()
	}))
	t.Cleanup(func() { srv.Close(); cancel(); <-loops })
	su, _ := url.Parse(srv.URL)
	r.URL, r.host, r.http = srv.URL+"/apt/", su.Host, srv.Client()
	r.ca = filepath.Join(root, "server.pem")
	if err := os.WriteFile(r.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	return r
}

// aptRoot returns a temporary directory removed after the test, once
// nothing writes to it any more: the relay commits a download to the cache
// after the client has read it, so a write may still run when the test
// ends.
func aptRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "tsp-apt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for range 50 {
			if err = os.RemoveAll(root); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Errorf("remove %s: %v", root, err)
	})
	return root
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// requests returns the "<status> METHOD /path" of every request so far.
func (r *aptRegistry) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.reqs)
}

// put uploads b as file into suite/component of hosted and returns the status.
func (r *aptRegistry) put(suite, component, file string, b []byte) int {
	r.t.Helper()
	req, _ := http.NewRequestWithContext(r.t.Context(), http.MethodPut, r.URL+"hosted/"+suite+"/"+component+"/"+file, bytes.NewReader(b))
	resp, err := r.http.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// mustPut fails unless the upload answers 201.
func (r *aptRegistry) mustPut(suite, file string, b []byte) {
	r.t.Helper()
	if code := r.put(suite, "main", file, b); code != http.StatusCreated {
		r.t.Fatalf("PUT %s into %s: %d", file, suite, code)
	}
}

// get returns the status and body of a GET below /apt/.
func (r *aptRegistry) get(p string) (int, []byte) {
	r.t.Helper()
	req, _ := http.NewRequestWithContext(r.t.Context(), http.MethodGet, r.URL+p, nil)
	resp, err := r.http.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (r *aptRegistry) mustGet(p string) []byte {
	r.t.Helper()
	code, b := r.get(p)
	if code != http.StatusOK {
		r.t.Fatalf("GET %s: %d %s", p, code, b)
	}
	return b
}

// aptClient is one apt user with a private root: its own sources,
// preferences, lists, cache and an empty dpkg status, so apt runs
// unprivileged and sees nothing of the host's configuration of repositories.
type aptClient struct {
	r    *aptRegistry
	root string
	arch string
}

func (r *aptRegistry) client(arch string) *aptClient {
	r.t.Helper()
	c := &aptClient{r: r, root: r.t.TempDir(), arch: arch}
	for _, d := range []string{"apt.conf.d", "preferences.d", "var/lib/apt/lists/partial", "var/cache/apt/archives/partial", "download"} {
		if err := os.MkdirAll(filepath.Join(c.root, d), 0o755); err != nil {
			r.t.Fatal(err)
		}
	}
	// APT_CONFIG is read before the host's apt.conf.d, and points it at an
	// empty directory.
	var conf strings.Builder
	for _, kv := range [][2]string{
		{"Dir", c.root},
		{"Dir::Etc::Parts", filepath.Join(c.root, "apt.conf.d")},
		{"Dir::State::status", filepath.Join(c.root, "status")},
		{"Dir::Etc::SourceList", filepath.Join(c.root, "sources.list")},
		{"Dir::Etc::SourceParts", "-"},
		{"Dir::Etc::PreferencesParts", filepath.Join(c.root, "preferences.d")},
		{"Dir::Etc::TrustedParts", "-"},
		{"Acquire::https::CaInfo", r.ca},
		{"Debug::NoLocking", "1"},
		{"APT::Architecture", arch},
	} {
		fmt.Fprintf(&conf, "%s %q;\n", kv[0], kv[1])
	}
	c.write("apt.conf", []byte(conf.String()))
	c.write("status", nil)
	c.write("tspackages.asc", r.mustGet("key.asc"))
	c.write("upstream.asc", []byte(r.up.public))
	return c
}

func (c *aptClient) write(name string, b []byte) {
	c.r.t.Helper()
	if err := os.WriteFile(filepath.Join(c.root, name), b, 0o644); err != nil {
		c.r.t.Fatal(err)
	}
}

// hosted is the sources.list line of a hosted suite, trusting keyring (a
// file in the client's root).
func (c *aptClient) hosted(suite, keyring string) string {
	return "deb [signed-by=" + filepath.Join(c.root, keyring) + "] " + c.r.URL + "hosted/ " + suite + " main"
}

// upstream is the sources.list line of the registry source, trusting the
// upstream's key.
func (c *aptClient) upstream() string {
	return "deb [signed-by=" + filepath.Join(c.root, "upstream.asc") + "] " + c.r.URL + "upstream/ stable main"
}

func (c *aptClient) sources(lines ...string) {
	c.write("sources.list", []byte(strings.Join(lines, "\n")+"\n"))
}

// run runs tool (apt-get or apt-cache) in the client's download directory.
func (c *aptClient) run(tool string, args ...string) (stdout, stderr string, err error) {
	c.r.t.Helper()
	ctx, cancel := context.WithTimeout(c.r.t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Dir = filepath.Join(c.root, "download")
	cmd.Env = append(os.Environ(), "LC_ALL=C", "APT_CONFIG="+filepath.Join(c.root, "apt.conf"))
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}

func (c *aptClient) must(tool string, args ...string) string {
	c.r.t.Helper()
	out, errOut, err := c.run(tool, args...)
	if err != nil {
		c.r.t.Fatalf("%s %s: %v\n%s%s", tool, strings.Join(args, " "), err, out, errOut)
	}
	return out
}

// update runs apt-get update and fails on an error or a warning.
func (c *aptClient) update() {
	c.r.t.Helper()
	out, errOut, err := c.run("apt-get", "update")
	if err != nil || strings.Contains(errOut, "W:") || strings.Contains(errOut, "E:") {
		c.r.t.Fatalf("apt-get update: %v\n%s%s", err, out, errOut)
	}
	if errOut != "" {
		c.r.t.Logf("apt-get update:\n%s", errOut)
	}
}

// candidate returns apt-cache policy's candidate for pkg: "" when apt knows
// no version it would install.
func (c *aptClient) candidate(pkg string) string {
	c.r.t.Helper()
	out := c.must("apt-cache", "policy", pkg)
	for line := range strings.Lines(out) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Candidate: "); ok && v != "(none)" {
			return v
		}
	}
	return ""
}

// download runs apt-get download pkg and returns the file it saved.
func (c *aptClient) download(pkg, file string) []byte {
	c.r.t.Helper()
	c.must("apt-get", "download", pkg)
	b, err := os.ReadFile(filepath.Join(c.root, "download", file))
	if err != nil {
		c.r.t.Fatal(err)
	}
	return b
}

// plans fails unless apt-get install -s pkg would install version.
func (c *aptClient) plans(pkg, version string) {
	c.r.t.Helper()
	out := c.must("apt-get", "install", "-s", pkg)
	if !strings.Contains(out, "Inst "+pkg+" ("+version+" ") {
		c.r.t.Fatalf("apt-get install -s %s does not install %s:\n%s", pkg, version, out)
	}
}

// dearmor writes an armored key as a binary keyring, the format of
// /usr/share/keyrings/debian-archive-keyring.gpg.
func dearmor(t *testing.T, armored []byte) []byte {
	t.Helper()
	blk, err := armor.Decode(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(blk.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAptUploadInstall(t *testing.T) {
	t.Run("fs", func(t *testing.T) { testAptUploadInstall(t, fsStores) })
	t.Run("s3", func(t *testing.T) { testAptUploadInstall(t, s3Stores) })
}

func testAptUploadInstall(t *testing.T, stores func(*testing.T, string) (config.StoreConfig, config.StoreConfig)) {
	r := startAptRegistry(t, aptOptions{stores: stores})
	deb := aptDeb(t, "acme-tool", "1.0", "amd64", "tool")
	r.mustPut("bookworm", "acme-tool_1.0_amd64.deb", deb)

	c := r.client("amd64")
	c.sources(c.hosted("bookworm", "tspackages.asc"))
	c.update()
	if got := c.download("acme-tool", "acme-tool_1.0_amd64.deb"); !bytes.Equal(got, deb) {
		t.Fatal("apt-get download acme-tool: other bytes than uploaded")
	}
	c.plans("acme-tool", "1.0")

	// The key as a binary keyring, the format of Debian's own keyrings.
	bin := r.client("amd64")
	bin.write("tspackages.gpg", dearmor(t, r.mustGet("key.asc")))
	bin.sources(bin.hosted("bookworm", "tspackages.gpg"))
	bin.update()
	bin.plans("acme-tool", "1.0")
}

func TestAptSecondSuiteAndConflict(t *testing.T) {
	r := startAptRegistry(t, aptOptions{})
	deb := aptDeb(t, "acme-tool", "1.0", "amd64", "tool")
	r.mustPut("bookworm", "acme-tool_1.0_amd64.deb", deb)
	r.mustPut("trixie", "acme-tool_1.0_amd64.deb", deb)

	c := r.client("amd64")
	c.sources(c.hosted("trixie", "tspackages.asc"))
	c.update()
	if got := c.candidate("acme-tool"); got != "1.0" {
		t.Fatalf("trixie candidate for acme-tool = %q, want 1.0", got)
	}

	other := aptDeb(t, "acme-tool", "1.0", "amd64", "other")
	for _, suite := range []string{"bookworm", "trixie", "sid"} {
		if code := r.put(suite, "main", "acme-tool_1.0_amd64.deb", other); code != http.StatusConflict {
			t.Fatalf("other bytes into %s: %d, want 409", suite, code)
		}
	}
}

func TestAptPerCallerIndex(t *testing.T) {
	r := startAptRegistry(t, aptOptions{rules: `{"read":["apt:acme-a*"],"write":["apt:acme-*"]}`})
	r.mustPut("bookworm", "acme-a_1.0_amd64.deb", aptDeb(t, "acme-a", "1.0", "amd64", "a"))
	r.mustPut("bookworm", "acme-b_1.0_amd64.deb", aptDeb(t, "acme-b", "1.0", "amd64", "b"))

	c := r.client("amd64")
	c.sources(c.hosted("bookworm", "tspackages.asc"))
	c.update()
	if got := c.candidate("acme-b"); got != "" {
		t.Fatalf("candidate for acme-b = %q, want none", got)
	}
	c.plans("acme-a", "1.0")
}

func TestAptArchAllOnly(t *testing.T) {
	r := startAptRegistry(t, aptOptions{})
	r.mustPut("noarch", "acme-all_1.0_all.deb", aptDeb(t, "acme-all", "1.0", "all", "all"))
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			c := r.client(arch)
			c.sources(c.hosted("noarch", "tspackages.asc"))
			c.update()
			c.plans("acme-all", "1.0")
		})
	}
}

func TestAptRegistry(t *testing.T) {
	r := startAptRegistry(t, aptOptions{})
	hello := aptDeb(t, "hello", "2.10-3", "amd64", "hello")
	r.up.add("hello", "2.10-3", hello)
	bad := aptDeb(t, "bad", "1.0", "amd64", "bad")
	badPath := r.up.add("bad", "1.0", bad)
	r.up.mu.Lock()
	r.up.tamper[badPath] = true
	r.up.mu.Unlock()

	c := r.client("amd64")
	c.sources(c.upstream())
	c.update()
	c.plans("hello", "2.10-3")
	if got := c.download("hello", "hello_2.10-3_amd64.deb"); !bytes.Equal(got, hello) {
		t.Fatal("apt-get download hello: other bytes than upstream's")
	}

	if out, errOut, err := c.run("apt-get", "-o", "Acquire::Retries=0", "download", "bad"); err == nil {
		t.Fatalf("apt-get download of a tampered .deb succeeded:\n%s%s", out, errOut)
	}
	n := r.up.count(badPath)
	if n == 0 {
		t.Fatal("upstream saw no request for the tampered .deb")
	}
	// Not cached: the next download fetches again and gets the real bytes.
	r.up.mu.Lock()
	r.up.tamper[badPath] = false
	r.up.mu.Unlock()
	if got := c.download("bad", "bad_1.0_amd64.deb"); !bytes.Equal(got, bad) {
		t.Fatal("apt-get download bad: other bytes than upstream's")
	}
	if got := r.up.count(badPath); got != n+1 {
		t.Fatalf("upstream saw %d requests for the .deb after %d, want one more", got, n)
	}
}

func TestAptPinningProtects(t *testing.T) {
	r := startAptRegistry(t, aptOptions{})
	r.mustPut("bookworm", "acme-tool_1.0_amd64.deb", aptDeb(t, "acme-tool", "1.0", "amd64", "tool"))
	shadow := r.up.add("acme-tool", "9.0", aptDeb(t, "acme-tool", "9.0", "amd64", "shadow"))

	c := r.client("amd64")
	c.write("preferences.d/tspackages.pref", r.mustGet("preferences"))
	c.sources(c.hosted("bookworm", "tspackages.asc"), c.upstream())
	c.update()
	if got := c.candidate("acme-tool"); got != "1.0" {
		t.Fatalf("candidate for acme-tool = %q, want 1.0 from hosted", got)
	}

	c.sources(c.upstream())
	c.update()
	if got := c.candidate("acme-tool"); got != "" {
		t.Fatalf("candidate for acme-tool from upstream only = %q, want none", got)
	}

	if code, _ := r.get("upstream/" + shadow); code != http.StatusNotFound {
		t.Fatalf("GET upstream/%s: %d, want 404", shadow, code)
	}
	if n := r.up.count(shadow); n != 0 {
		t.Fatalf("upstream saw %d requests for a claimed name", n)
	}
}

func TestAptByHashFallback(t *testing.T) {
	r := startAptRegistry(t, aptOptions{failByHash: true})
	r.mustPut("bookworm", "acme-tool_1.0_amd64.deb", aptDeb(t, "acme-tool", "1.0", "amd64", "tool"))

	c := r.client("amd64")
	c.sources(c.hosted("bookworm", "tspackages.asc"))
	out, errOut, err := c.run("apt-get", "update")
	reqs := r.requests()
	t.Logf("apt-get update: %v\n%s%s\nrequests:\n%s", err, out, errOut, strings.Join(reqs, "\n"))
	if err != nil {
		t.Fatal("apt-get update failed after a by-hash 404")
	}
	// After the 404, apt asked for an index by its canonical path.
	i := slices.IndexFunc(reqs, func(s string) bool { return strings.HasPrefix(s, "404 ") })
	if i < 0 || !slices.ContainsFunc(reqs[i+1:], func(s string) bool {
		p := s[strings.LastIndexByte(s, ' ')+1:]
		return strings.HasPrefix(s, "200 GET ") && strings.HasPrefix(path.Base(p), "Packages")
	}) {
		t.Fatal("apt did not fetch a canonical index path after the by-hash 404")
	}
	c.plans("acme-tool", "1.0")
}

func TestAptTildePlusVersion(t *testing.T) {
	r := startAptRegistry(t, aptOptions{})
	file := "acme-x_1.0+git20261125~rc1_all.deb"
	deb := aptDeb(t, "acme-x", "1.0+git20261125~rc1", "all", "x")
	r.mustPut("bookworm", file, deb)

	c := r.client("amd64")
	c.sources(c.hosted("bookworm", "tspackages.asc"))
	c.update()
	if got := c.download("acme-x", file); !bytes.Equal(got, deb) {
		t.Fatal("apt-get download acme-x: other bytes than uploaded")
	}
}
