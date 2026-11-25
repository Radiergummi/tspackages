package apt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/relay"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
	"github.com/radiergummi/tspackages/internal/upstream"
)

const (
	regSuite  = "stable"
	curlPool  = "pool/main/c/curl/curl_8.0-1_amd64.deb"
	acmePool  = "pool/main/a/acme-tool/acme-tool_1.0_amd64.deb"
	pkgsPath  = "main/binary-amd64/Packages"
	pkgsGz    = "main/binary-amd64/Packages.gz"
	regSource = "debian"
)

// aptUpstream is an apt repository over HTTP, serving bodies by path and
// recording every request path.
type aptUpstream struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	paths []string
}

func newAptUpstream(t *testing.T) *aptUpstream {
	t.Helper()
	u := &aptUpstream{files: map[string][]byte{}}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.paths = append(u.paths, r.URL.Path)
		b, ok := u.files[r.URL.Path]
		u.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *aptUpstream) set(p string, b []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.files["/"+p] = b
}

func (u *aptUpstream) del(p string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.files, "/"+p)
}

func (u *aptUpstream) requests() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.paths)
}

func (u *aptUpstream) count(p string) int {
	n := 0
	for _, r := range u.requests() {
		if r == "/"+p {
			n++
		}
	}
	return n
}

type regEnv struct {
	up      *aptUpstream
	src     *RegistrySource
	cfg     RegistryConfig
	cache   *storage.Cache
	cd      storage.Driver
	relay   *relay.Relay
	rec     *records.Store
	key     *openpgp.Entity
	clock   time.Time
	debs    map[string][]byte // pool path → bytes
	claimed map[string]bool
}

func newRegEnv(t *testing.T) *regEnv {
	t.Helper()
	e := &regEnv{up: newAptUpstream(t), key: newEntity(t, "upstream", nil), clock: time.Now().Add(time.Minute).UTC(),
		debs:    map[string][]byte{curlPool: []byte("curl deb bytes"), acmePool: []byte("acme deb bytes")},
		claimed: map[string]bool{}}
	var err error
	e.cd, err = storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e.cache, err = storage.NewCache(context.Background(), e.cd, 1<<30, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.relay, err = relay.New(e.cache, filepath.Join(t.TempDir(), "relay"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.relay.Wait)
	sd, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e.rec = records.New(sd)
	e.cfg = RegistryConfig{
		Name: regSource, URL: e.up.srv.URL + "/", Keyring: keyring(t, e.key),
		Suites: []string{regSuite}, Components: []string{"main"}, Architectures: []string{"amd64"},
		TTL: time.Hour, MaxArtifact: 1 << 20,
		Claimed: func(name string) bool { return e.claimed[name] },
	}
	e.src = e.newSource()
	return e
}

// newSource returns a source over e's cache, upstream and config, as after
// a restart.
func (e *regEnv) newSource() *RegistrySource {
	c := upstream.New(upstream.Options{FetchHosts: []string{"127.0.0.1"}, AllowPrivateForTesting: true})
	s := NewRegistrySource(e.cfg, c, e.cache, e.relay, e.rec, nil, slog.New(slog.DiscardHandler))
	s.now = func() time.Time { return e.clock }
	return s
}

// packages renders a Packages index of e.debs.
func (e *regEnv) packages() []byte {
	var b strings.Builder
	for _, p := range slices.Sorted(func(yield func(string) bool) {
		for k := range e.debs {
			if !yield(k) {
				return
			}
		}
	}) {
		d, err := ParseFileName(path.Base(p))
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(&b, "Package: %s\nVersion: %s\nArchitecture: %s\nFilename: %s\nSize: %d\nSHA256: %s\nDescription: test\n\n",
			d.Name, d.Version, d.Arch, p, len(e.debs[p]), hexSHA256(e.debs[p]))
	}
	return []byte(b.String())
}

type pubOpts struct {
	date, validUntil time.Time
	signer           *openpgp.Entity // nil: e.key
	noInRelease      bool
}

// publish puts the repository on the upstream: pool files, the Packages
// indexes (by path and by hash) and a Release signed both ways. It returns
// the InRelease bytes.
func (e *regEnv) publish(t *testing.T, o pubOpts) []byte {
	t.Helper()
	if o.date.IsZero() {
		o.date = e.clock.Add(-time.Hour)
	}
	if o.signer == nil {
		o.signer = e.key
	}
	for p, b := range e.debs {
		e.up.set(p, b)
	}
	plain := e.packages()
	gz := testutil.Gzip(t, plain)
	var rel strings.Builder
	fmt.Fprintf(&rel, "Origin: Test\nSuite: %s\nCodename: %s\nDate: %s\n", regSuite, regSuite, o.date.Format(releaseDate))
	if !o.validUntil.IsZero() {
		fmt.Fprintf(&rel, "Valid-Until: %s\n", o.validUntil.Format(releaseDate))
	}
	rel.WriteString("Architectures: amd64\nComponents: main\nAcquire-By-Hash: yes\nSHA256:\n")
	for _, f := range []struct {
		p string
		b []byte
	}{{pkgsPath, plain}, {pkgsGz, gz}} {
		sum := hexSHA256(f.b)
		fmt.Fprintf(&rel, " %s %d %s\n", sum, len(f.b), f.p)
		e.up.set("dists/"+regSuite+"/"+f.p, f.b)
		e.up.set("dists/"+regSuite+"/"+path.Dir(f.p)+"/by-hash/SHA256/"+sum, f.b)
	}
	s := signer(t, o.signer)
	text := []byte(rel.String())
	in, err := s.ClearSign(text)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.DetachSign(text)
	if err != nil {
		t.Fatal(err)
	}
	e.up.set("dists/"+regSuite+"/Release", text)
	e.up.set("dists/"+regSuite+"/Release.gpg", sig)
	if o.noInRelease {
		e.up.del("dists/" + regSuite + "/InRelease")
	} else {
		e.up.set("dists/"+regSuite+"/InRelease", in)
	}
	return in
}

func (e *regEnv) has(t *testing.T, key string) bool {
	t.Helper()
	_, err := e.cd.Stat(context.Background(), key)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

func poolPath(t *testing.T, rel string) Path {
	t.Helper()
	p, err := ParsePath(regSource+"/"+rel, false)
	if err != nil || p.Kind != KindPool {
		t.Fatalf("ParsePath(%s) = %+v, %v", rel, p, err)
	}
	return p
}

var anyAcc = ReadAccess{Any: true, Name: func(string) bool { return false }}

// body reads a source result to its end, failing t on an error.
func body(t *testing.T) func(Blob, error) []byte {
	return func(b Blob, err error) []byte {
		t.Helper()
		return blobBytes(t, b, err)
	}
}

// readBlob reads a source result to its end.
func readBlob(b Blob, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	defer b.Body.Close()
	return io.ReadAll(b.Body)
}

func TestRegistryPassThrough(t *testing.T) {
	e := newRegEnv(t)
	in := e.publish(t, pubOpts{})
	ctx := context.Background()

	got := body(t)(e.src.Release(ctx, anyAcc, regSuite, "InRelease"))
	if string(got) != string(in) {
		t.Fatalf("InRelease not passed through byte for byte:\n%s", got)
	}
	text, err := e.cfg.Keyring.VerifyInRelease(in, e.clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := body(t)(e.src.Release(ctx, anyAcc, regSuite, "Release")); string(got) != string(text) {
		t.Errorf("Release = %q, want the signed text of InRelease", got)
	}
	if _, err := e.src.Release(ctx, anyAcc, regSuite, "Release.gpg"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("Release.gpg with only InRelease fetched: err = %v, want ErrNotFound", err)
	}
	if n := e.up.count("dists/" + regSuite + "/InRelease"); n != 1 {
		t.Errorf("InRelease fetched %d times within the TTL", n)
	}

	gz := testutil.Gzip(t, e.packages())
	sum := hexSHA256(gz)
	byHashPath := "dists/" + regSuite + "/main/binary-amd64/by-hash/SHA256/" + sum
	for range 2 {
		b, err := e.src.ByHash(ctx, anyAcc, regSuite, "main/binary-amd64/by-hash/SHA256/"+sum, sum)
		if got := blobBytes(t, b, err); string(got) != string(gz) || !b.Immutable {
			t.Fatalf("ByHash = %d bytes, immutable %v", len(got), b.Immutable)
		}
		e.relay.Wait()
	}
	if n := e.up.count(byHashPath); n != 1 {
		t.Errorf("by-hash index fetched %d times, want 1", n)
	}
	if !e.has(t, "apt/"+regSource+"/sha256-"+sum) {
		t.Error("index not cached by its sha256")
	}
	b, err := e.src.Dist(ctx, anyAcc, regSuite, pkgsGz)
	if got := blobBytes(t, b, err); string(got) != string(gz) || b.Immutable || b.ETag != `"`+sum+`"` {
		t.Errorf("Dist = %d bytes, immutable %v, ETag %s", len(got), b.Immutable, b.ETag)
	}
	if n := e.up.count("dists/" + regSuite + "/" + pkgsGz); n != 0 {
		t.Errorf("canonical index path fetched %d times; Acquire-By-Hash and the cache should serve it", n)
	}

	deb := e.debs[curlPool]
	for range 2 {
		b, err := e.src.Pool(ctx, anyAcc, poolPath(t, curlPool))
		if got := blobBytes(t, b, err); string(got) != string(deb) || !b.Immutable {
			t.Fatalf("Pool = %q, immutable %v", got, b.Immutable)
		}
		e.relay.Wait()
	}
	if n := e.up.count(curlPool); n != 1 {
		t.Errorf("pool file fetched %d times, want 1", n)
	}
	recs, err := e.rec.FileProvenance(ctx, ecoName, "curl", "8.0-1", curlPool)
	if err != nil || len(recs) != 1 {
		t.Fatalf("provenance = %+v, %v", recs, err)
	}
	if r := recs[0]; r.SourceType != "registry" || r.Source != regSource || r.DeclaredDigest != "sha256:"+hexSHA256(deb) ||
		r.UpstreamURL != e.up.srv.URL+"/"+curlPool {
		t.Errorf("provenance = %+v", r)
	}
	if h := e.src.Health(ctx); len(h) != 1 || !h[0].OK {
		t.Errorf("Health = %+v", h)
	}
}

func TestReleaseFallback(t *testing.T) {
	e := newRegEnv(t)
	e.publish(t, pubOpts{noInRelease: true})
	ctx := context.Background()
	if _, err := e.src.Release(ctx, anyAcc, regSuite, "InRelease"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("InRelease without an upstream one: err = %v, want ErrNotFound", err)
	}
	rel := body(t)(e.src.Release(ctx, anyAcc, regSuite, "Release"))
	sig := body(t)(e.src.Release(ctx, anyAcc, regSuite, "Release.gpg"))
	if err := e.cfg.Keyring.VerifyDetached(rel, sig, e.clock); err != nil {
		t.Fatalf("served Release and Release.gpg don't verify: %v", err)
	}
	b, err := e.src.Pool(ctx, anyAcc, poolPath(t, curlPool))
	if got, err := readBlob(b, err); err != nil || string(got) != string(e.debs[curlPool]) {
		t.Errorf("Pool = %q, %v", got, err)
	}
}

func TestRegistryRejects(t *testing.T) {
	ctx := context.Background()
	bad := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("err = %v, want a non-404 failure", err)
		}
	}

	t.Run("bad signature", func(t *testing.T) {
		e := newRegEnv(t)
		in := e.publish(t, pubOpts{})
		body(t)(e.src.Release(ctx, anyAcc, regSuite, "InRelease"))
		e.publish(t, pubOpts{signer: newEntity(t, "mallory", nil), date: e.clock})
		e.clock = e.clock.Add(2 * time.Hour)
		if got := body(t)(e.src.Release(ctx, anyAcc, regSuite, "InRelease")); string(got) != string(in) {
			t.Error("the previous verified copy is not served")
		}
		if h := e.src.Health(ctx); h[0].OK || h[0].Detail != "serving stale" {
			t.Errorf("Health = %+v", h)
		}
		fresh := newRegEnv(t)
		fresh.publish(t, pubOpts{signer: newEntity(t, "mallory", nil)})
		_, err := fresh.src.Release(ctx, anyAcc, regSuite, "InRelease")
		bad(t, err)
	})

	t.Run("valid-until passed", func(t *testing.T) {
		e := newRegEnv(t)
		e.publish(t, pubOpts{validUntil: e.clock.Add(-time.Minute)})
		_, err := e.src.Release(ctx, anyAcc, regSuite, "InRelease")
		bad(t, err)
	})

	t.Run("rollback", func(t *testing.T) {
		e := newRegEnv(t)
		in := e.publish(t, pubOpts{})
		body(t)(e.src.Release(ctx, anyAcc, regSuite, "InRelease"))
		e.debs["pool/main/o/old/old_0.1_amd64.deb"] = []byte("old")
		e.publish(t, pubOpts{date: e.clock.Add(-2 * time.Hour)})
		e.clock = e.clock.Add(2 * time.Hour)
		if got := body(t)(e.src.Release(ctx, anyAcc, regSuite, "InRelease")); string(got) != string(in) {
			t.Error("an older Release replaced the cached one")
		}
		// Nor does a new source over the same cache take it.
		if got := body(t)(e.newSource().Release(ctx, anyAcc, regSuite, "InRelease")); string(got) != string(in) {
			t.Error("an older Release replaced the cached one after a restart")
		}
	})

	t.Run("index mismatch", func(t *testing.T) {
		e := newRegEnv(t)
		e.publish(t, pubOpts{})
		gz := testutil.Gzip(t, e.packages())
		sum := hexSHA256(gz)
		e.up.set("dists/"+regSuite+"/main/binary-amd64/by-hash/SHA256/"+sum, []byte("tampered"))
		_, err := readBlob(e.src.Dist(ctx, anyAcc, regSuite, pkgsGz))
		if err == nil {
			t.Fatal("tampered index served without error")
		}
		e.relay.Wait()
		if e.has(t, "apt/"+regSource+"/sha256-"+sum) {
			t.Error("tampered index cached")
		}
	})

	t.Run("tampered deb", func(t *testing.T) {
		e := newRegEnv(t)
		e.publish(t, pubOpts{})
		e.up.set(curlPool, []byte("evil deb bytes"))
		_, err := readBlob(e.src.Pool(ctx, anyAcc, poolPath(t, curlPool)))
		if !errors.Is(err, relay.ErrDigestMismatch) {
			t.Fatalf("err = %v, want relay.ErrDigestMismatch", err)
		}
		e.relay.Wait()
		if e.has(t, "apt/"+regSource+"/sha256-"+hexSHA256(e.debs[curlPool])) {
			t.Error("tampered deb cached")
		}
	})
}

func TestRegistryByHashPrevious(t *testing.T) {
	e := newRegEnv(t)
	e.publish(t, pubOpts{})
	ctx := context.Background()
	body(t)(e.src.Release(ctx, anyAcc, regSuite, "InRelease"))
	oldGz := testutil.Gzip(t, e.packages())
	old := hexSHA256(oldGz)

	e.debs["pool/main/n/new/new_1.0_amd64.deb"] = []byte("new")
	e.publish(t, pubOpts{date: e.clock})
	e.clock = e.clock.Add(2 * time.Hour)
	body(t)(e.src.Release(ctx, anyAcc, regSuite, "InRelease"))
	if got := body(t)(e.src.ByHash(ctx, anyAcc, regSuite, "main/binary-amd64/by-hash/SHA256/"+old, old)); string(got) != string(oldGz) {
		t.Error("by-hash file of the previous Release not served")
	}

	e.debs["pool/main/n/newer/newer_1.0_amd64.deb"] = []byte("newer")
	e.publish(t, pubOpts{date: e.clock})
	e.clock = e.clock.Add(2 * time.Hour)
	body(t)(e.src.Release(ctx, anyAcc, regSuite, "InRelease"))
	if _, err := e.src.ByHash(ctx, anyAcc, regSuite, "main/binary-amd64/by-hash/SHA256/"+old, old); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("by-hash file two Releases back: err = %v, want ErrNotFound", err)
	}
}

func TestRegistryClaimedName(t *testing.T) {
	e := newRegEnv(t)
	e.publish(t, pubOpts{})
	e.claimed["acme-tool"] = true
	_, err := e.src.Pool(context.Background(), anyAcc, poolPath(t, acmePool))
	if !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("claimed name: err = %v, want ErrNotFound", err)
	}
	if n := e.up.count(acmePool); n != 0 {
		t.Errorf("claimed name fetched upstream %d times", n)
	}

	// The Package field decides too, whatever the file is called.
	e2 := newRegEnv(t)
	e2.claimed["acme-tool"] = true
	idx := "Package: acme-tool\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/x/renamed.deb\nSize: 7\nSHA256: " + hexSHA256([]byte("renamed")) + "\n\n"
	e2.publishIndex(t, []byte(idx))
	e2.up.set("pool/x/renamed.deb", []byte("renamed"))
	_, err = e2.src.Pool(context.Background(), anyAcc, poolPath(t, "pool/x/renamed.deb"))
	if !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("claimed Package field: err = %v, want ErrNotFound", err)
	}
	if n := e2.up.count("pool/x/renamed.deb"); n != 0 {
		t.Errorf("claimed Package fetched upstream %d times", n)
	}
}

// publishIndex publishes a Release listing only idx as the plain Packages
// index.
func (e *regEnv) publishIndex(t *testing.T, idx []byte) {
	t.Helper()
	sum := hexSHA256(idx)
	text := fmt.Sprintf("Suite: %s\nDate: %s\nAcquire-By-Hash: yes\nSHA256:\n %s %d %s\n", regSuite,
		e.clock.Add(-time.Hour).Format(releaseDate), sum, len(idx), pkgsPath)
	e.up.set("dists/"+regSuite+"/main/binary-amd64/by-hash/SHA256/"+sum, idx)
	in, err := signer(t, e.key).ClearSign([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	e.up.set("dists/"+regSuite+"/InRelease", in)
}

func TestRegistryUnlisted(t *testing.T) {
	e := newRegEnv(t)
	e.publish(t, pubOpts{})
	ctx := context.Background()
	for _, rel := range []string{"main/binary-amd64/Packages.bz2", "contrib/binary-amd64/Packages", "main/binary-arm64/Packages"} {
		if _, err := e.src.Dist(ctx, anyAcc, regSuite, rel); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("Dist(%s): err = %v, want ErrNotFound", rel, err)
		}
	}
	sum := strings.Repeat("ab", 32)
	if _, err := e.src.ByHash(ctx, anyAcc, regSuite, "main/binary-amd64/by-hash/SHA256/"+sum, sum); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("ByHash of an unlisted hash: err = %v, want ErrNotFound", err)
	}
	for _, which := range []string{"InRelease", "Release", "Release.gpg"} {
		if _, err := e.src.Release(ctx, anyAcc, "testing", which); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("Release(testing, %s): err = %v, want ErrNotFound", which, err)
		}
	}
	if _, err := e.src.Dist(ctx, anyAcc, "testing", pkgsGz); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("Dist in an unconfigured suite: err = %v, want ErrNotFound", err)
	}
	for _, r := range e.up.requests() {
		if strings.Contains(r, "/testing/") {
			t.Errorf("unconfigured suite requested upstream: %s", r)
		}
	}
	_, err := e.src.Pool(ctx, anyAcc, poolPath(t, "pool/main/x/xyz/xyz_1.0_amd64.deb"))
	if !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("Pool of an unlisted path: err = %v, want ErrNotFound", err)
	}
	if n := e.up.count("pool/main/x/xyz/xyz_1.0_amd64.deb"); n != 0 {
		t.Errorf("unlisted pool path fetched upstream %d times", n)
	}
}

func TestRegistryChanged(t *testing.T) {
	e := newRegEnv(t)
	e.publish(t, pubOpts{})
	ctx := context.Background()
	body(t)(e.src.Pool(ctx, anyAcc, poolPath(t, curlPool)))
	e.relay.Wait()
	first := hexSHA256(e.debs[curlPool])

	e.debs[curlPool] = []byte("rebuilt curl deb bytes")
	e.publish(t, pubOpts{date: e.clock})
	e.clock = e.clock.Add(2 * time.Hour)
	if got := body(t)(e.src.Pool(ctx, anyAcc, poolPath(t, curlPool))); string(got) != string(e.debs[curlPool]) {
		t.Fatalf("changed file not served: %q", got)
	}
	e.relay.Wait()
	want := []ChangedFile{{Source: regSource, Path: curlPool, First: first, Now: hexSHA256(e.debs[curlPool])}}
	if got := e.src.Changed(); !slices.Equal(got, want) {
		t.Errorf("Changed = %+v, want %+v", got, want)
	}
}
