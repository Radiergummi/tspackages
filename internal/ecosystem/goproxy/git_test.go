package goproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/pins"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

const modP = "git.test/acme/m"

// gitEnv is an upstream repository, a state store and the pieces a
// GitSource is built from.
type gitEnv struct {
	t          *testing.T
	repo       string
	remote     string
	state      storage.Driver
	mirrorBase string
}

func newGitEnv(t *testing.T) *gitEnv {
	t.Helper()
	repo := t.TempDir()
	testutil.Git(t, repo, "init", "-q")
	state, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &gitEnv{t: t, repo: repo, remote: "file://" + repo, state: state, mirrorBase: t.TempDir()}
}

func (e *gitEnv) git(args ...string) string {
	e.t.Helper()
	return testutil.Git(e.t, e.repo, args...)
}

// commit writes files (an empty value removes the file) and commits them.
func (e *gitEnv) commit(files map[string]string) string {
	e.t.Helper()
	for name, content := range files {
		p := filepath.Join(e.repo, filepath.FromSlash(name))
		if content == "" {
			if err := os.Remove(p); err != nil {
				e.t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			e.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			e.t.Fatal(err)
		}
	}
	e.git("add", "-A")
	e.git("commit", "-q", "--allow-empty", "-m", "c")
	return e.git("rev-parse", "HEAD")
}

func (e *gitEnv) tag(names ...string) {
	e.t.Helper()
	for _, n := range names {
		e.git("tag", "-f", n)
	}
}

type srcOpt func(*GitOptions, *GitSource)

// source returns a GitSource over the env's state with its own mirror in
// base (the env's shared base when ""), without starting its queue.
func (e *gitEnv) sourceIn(base string, mods []Module, opts ...srcOpt) *GitSource {
	e.t.Helper()
	if base == "" {
		base = e.mirrorBase
	}
	m, err := gitmirror.New(gitmirror.Options{Remote: e.remote, BaseDir: base, AllowFileRemotesForTesting: true})
	if err != nil {
		e.t.Fatal(err)
	}
	for i := range mods {
		mods[i].Remote = e.remote
	}
	o := GitOptions{
		Name: "acme", Claims: []string{"git.test/acme/*"}, Modules: mods,
		Mirrors: map[string]*gitmirror.Mirror{e.remote: m},
		Pins:    pins.New(e.state), State: e.state, Records: records.New(e.state),
		Poll: time.Hour, TmpDir: e.t.TempDir(), Log: slog.New(slog.DiscardHandler),
	}
	g, err := newGitSource(o, func(g *GitSource) {
		g.q.backoffMin, g.q.backoffMax = time.Millisecond, 10*time.Millisecond
		g.syncEvery = 0 // every pass syncs; the throttle tests set it back
		e.t.Cleanup(g.stopLife)
		for _, f := range opts {
			f(&o, g)
		}
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return g
}

func (e *gitEnv) source(mods []Module, opts ...srcOpt) *GitSource {
	e.t.Helper()
	g := e.sourceIn("", mods, opts...)
	startQueue(e.t, g.q)
	return g
}

func rootMod() []Module { return []Module{{Path: modP}} }

// pass runs one pass and waits for every job it enqueued.
func pass(t *testing.T, g *GitSource) {
	t.Helper()
	if err := g.Index(t.Context()); err != nil {
		t.Fatalf("Index: %v", err)
	}
	settle(t, g)
}

// settle waits until g's queue is empty.
func settle(t *testing.T, g *GitSource) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		g.q.mu.Lock()
		n := len(g.q.jobs)
		g.q.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d jobs still queued", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func list(t *testing.T, g *GitSource, path string) []string {
	t.Helper()
	vs, err := g.List(t.Context(), path)
	if err != nil {
		t.Fatalf("List(%s): %v", path, err)
	}
	return vs
}

func wantList(t *testing.T, g *GitSource, path string, want ...string) {
	t.Helper()
	got := list(t, g, path)
	if !slices.Equal(got, want) {
		t.Fatalf("List(%s) = %q, want %q", path, got, want)
	}
}

// fetch reads a whole artifact of p@v from f (a source's Mod or Zip).
func fetch(t *testing.T, f func(context.Context, string, string) (Artifact, error), p, v string) []byte {
	t.Helper()
	a, err := f(t.Context(), p, v)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Body.Close()
	b, err := io.ReadAll(a.Body)
	if err != nil {
		t.Fatal(err)
	}
	if a.Size != int64(len(b)) {
		t.Fatalf("Size %d, read %d bytes", a.Size, len(b))
	}
	return b
}

func zipHashOf(t *testing.T, z []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "m.zip")
	if err := os.WriteFile(p, z, 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := dirhash.HashZip(p, dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func refusalFor(g *GitSource, path, version string) (Refusal, bool) {
	for _, r := range g.Refusals() {
		if r.Module == path && r.Version == version {
			return r, true
		}
	}
	return Refusal{}, false
}

func wantRefused(t *testing.T, g *GitSource, path, version, kind, reasonPrefix string) Refusal {
	t.Helper()
	r, ok := refusalFor(g, path, version)
	if !ok {
		t.Fatalf("no refusal for %s@%s in %+v", path, version, g.Refusals())
	}
	if r.Kind != kind || !strings.HasPrefix(r.Reason, reasonPrefix) {
		t.Fatalf("refusal %+v, want kind %q reason %q…", r, kind, reasonPrefix)
	}
	return r
}

func versionKey(path, version, file string) string {
	ps, _ := pathSeg(path)
	vs, _ := versionSeg(version)
	return "go-git/acme/" + ps + "/" + vs + "/" + file
}

func (e *gitEnv) record(path, version string) (versionRecord, bool) {
	e.t.Helper()
	rc, _, err := e.state.Get(e.t.Context(), versionKey(path, version, "version.json"))
	if errors.Is(err, storage.ErrNotFound) {
		return versionRecord{}, false
	}
	if err != nil {
		e.t.Fatal(err)
	}
	defer rc.Close()
	var r versionRecord
	if err := json.NewDecoder(rc).Decode(&r); err != nil {
		e.t.Fatal(err)
	}
	return r, true
}

func (e *gitEnv) pinned(tag string) (string, bool) {
	e.t.Helper()
	ps, _, err := pins.New(e.state).List(e.t.Context(), "go", "acme", e.remote)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, p := range ps {
		if p.Tag == tag {
			return p.SHA, true
		}
	}
	return "", false
}

func gomodOf(path string) string { return "module " + path + "\n\ngo 1.21\n" }

func TestRootModuleTags(t *testing.T) {
	e := newGitEnv(t)
	commit := e.commit(map[string]string{"go.mod": gomodOf(modP), "a.go": "package m\n", "LICENSE": "MIT\n"})
	e.tag("v1.0.0", "v1.1.0-rc.1", "v1.2", "release")
	g := e.source(rootMod())
	pass(t, g)
	wantList(t, g, modP, "v1.0.0", "v1.1.0-rc.1")

	m := g.mirrors[e.remote]
	want := goldenBuild(t, m, Module{Path: modP}, modP, "v1.0.0", commit)
	z := fetch(t, g.Zip, modP, "v1.0.0")
	if h := zipHashOf(t, z); h != want.ZipHash {
		t.Fatalf("zip h1 %s, want %s", h, want.ZipHash)
	}
	rec, ok := e.record(modP, "v1.0.0")
	if !ok || rec.ZipHash != want.ZipHash || rec.ModHash != want.ModHash || rec.Commit != commit ||
		rec.Format != GoZipFormat || rec.Tag != "v1.0.0" || rec.Dir != "" || rec.Size != int64(len(z)) {
		t.Fatalf("record %+v", rec)
	}
	mod := fetch(t, g.Mod, modP, "v1.0.0")
	if string(mod) != gomodOf(modP) {
		t.Fatalf("go.mod %q", mod)
	}
	info, err := g.Info(t.Context(), modP, "v1.0.0")
	when, _ := m.CommitTime(t.Context(), commit)
	if err != nil || info.Version != "v1.0.0" || !info.Time.Equal(when) {
		t.Fatalf("Info = %+v, %v; want time %v", info, err, when)
	}
	if sha, ok := e.pinned("v1.0.0"); !ok || sha != commit {
		t.Fatalf("pin %q %v", sha, ok)
	}
	prov, err := records.New(e.state).GetProvenance(t.Context(), "go", modP, "v1.0.0", rec.SHA256)
	if err != nil || prov.Commit != commit || prov.DeclaredDigest != want.ZipHash || prov.SourceType != "git" {
		t.Fatalf("provenance %+v, %v", prov, err)
	}
	for _, v := range []string{"v1.2", "release", "v1.2.0"} {
		if _, err := g.Info(t.Context(), modP, v); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("Info(%s) = %v, want not found", v, err)
		}
	}
	if _, err := g.List(t.Context(), "git.test/acme/other"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("List of an unconfigured path = %v", err)
	}
	if _, err := g.List(t.Context(), modP+"/v1"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("List of /v1 = %v", err)
	}
}

func TestSubdirectoryModule(t *testing.T) {
	e := newGitEnv(t)
	tools := "git.test/acme/mono/tools"
	e.commit(map[string]string{"go.mod": gomodOf("git.test/acme/mono"), "tools/go.mod": gomodOf(tools), "tools/t.go": "package tools\n"})
	e.tag("tools/v0.1.0", "v1.0.0")
	g := e.source([]Module{{Path: tools, Dir: "tools"}})
	pass(t, g)
	wantList(t, g, tools, "v0.1.0")
	if rec, _ := e.record(tools, "v0.1.0"); rec.Dir != "tools" || rec.Tag != "tools/v0.1.0" {
		t.Fatalf("record %+v", rec)
	}
	if _, ok := e.record(tools, "v1.0.0"); ok {
		t.Fatal("root tag stored for the subdirectory module")
	}
}

func TestMajorBranchAndSubdirStyles(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP + "/v2")})
	e.tag("v2.0.0")
	e.commit(map[string]string{"go.mod": gomodOf(modP), "v3/go.mod": gomodOf(modP + "/v3")})
	e.tag("v3.0.0")
	e.commit(map[string]string{"go.mod": gomodOf(modP + "/v4"), "v4/go.mod": gomodOf(modP + "/v4")})
	e.tag("v4.0.0")
	g := e.source(rootMod())
	pass(t, g)
	wantList(t, g, modP+"/v2", "v2.0.0")
	wantList(t, g, modP+"/v3", "v3.0.0")
	wantList(t, g, modP+"/v4")
	wantList(t, g, modP)
	if rec, _ := e.record(modP+"/v3", "v3.0.0"); rec.Dir != "v3" {
		t.Fatalf("v3 record dir %q", rec.Dir)
	}
	if rec, _ := e.record(modP+"/v2", "v2.0.0"); rec.Dir != "" {
		t.Fatalf("v2 record dir %q", rec.Dir)
	}
	wantRefused(t, g, modP+"/v4", "v4.0.0", RefusalSkipped, "go.mod found in both")
}

func TestV2TagOnUnsuffixedModuleSkipped(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v2.0.0")
	g := e.source(rootMod())
	pass(t, g)
	wantList(t, g, modP)
	wantList(t, g, modP+"/v2")
	wantRefused(t, g, modP+"/v2", "v2.0.0", RefusalSkipped, "major version not in the module path")
}

func TestDeclaredPathMismatchSkipped(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf("git.test/acme/other")})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	pass(t, g)
	wantList(t, g, modP)
	r := wantRefused(t, g, modP, "v1.0.0", RefusalSkipped, "module declares its path as git.test/acme/other")
	if r.Tag != "v1.0.0" || r.Remote != e.remote || r.Commit == "" {
		t.Fatalf("refusal %+v", r)
	}
}

// countingTree counts ListTree calls and answers with fn.
func countingTree(n *atomic.Int32, fn func(ctx context.Context, m *gitmirror.Mirror, commit, dir string) ([]gitmirror.TreeEntry, error)) srcOpt {
	return func(_ *GitOptions, g *GitSource) {
		g.listTree = func(ctx context.Context, m *gitmirror.Mirror, commit, dir string) ([]gitmirror.TreeEntry, error) {
			n.Add(1)
			if fn != nil {
				return fn(ctx, m, commit, dir)
			}
			return m.ListTree(ctx, commit, dir)
		}
	}
}

func TestTooNewGoDirectiveRefused(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": "module " + modP + "\n\ngo 1.99\n"})
	e.tag("v1.0.0")
	var n atomic.Int32
	g := e.source(rootMod(), countingTree(&n, nil))
	pass(t, g)
	wantList(t, g, modP)
	wantRefused(t, g, modP, "v1.0.0", RefusalRefused, "go 1.99 is newer than")
	pass(t, g)
	if n.Load() != 1 {
		t.Fatalf("ListTree ran %d times; the refusal was retried", n.Load())
	}
	wantRefused(t, g, modP, "v1.0.0", RefusalRefused, "go 1.99 is newer than")
}

func TestTreeCapRefused(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0", "v1.0.1")
	var n atomic.Int32
	g := e.source(rootMod(), countingTree(&n, func(context.Context, *gitmirror.Mirror, string, string) ([]gitmirror.TreeEntry, error) {
		return nil, fmt.Errorf("listing: %w", gitmirror.ErrTreeTooLarge)
	}))
	pass(t, g)
	wantList(t, g, modP)
	wantRefused(t, g, modP, "v1.0.0", RefusalRefused, "tree over the listing caps")
	wantRefused(t, g, modP, "v1.0.1", RefusalRefused, "tree over the listing caps")
	if n.Load() != 1 {
		t.Fatalf("ListTree ran %d times for one commit", n.Load())
	}
}

func TestStoredSurvivesTagAndMirrorLoss(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP), "a.go": "package m\n"})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	pass(t, g)
	zip1 := fetch(t, g.Zip, modP, "v1.0.0")
	mod1 := fetch(t, g.Mod, modP, "v1.0.0")

	e.git("tag", "-d", "v1.0.0")
	if err := os.RemoveAll(g.mirrors[e.remote].Dir()); err != nil {
		t.Fatal(err)
	}
	pass(t, g)
	wantList(t, g, modP, "v1.0.0")
	if z := fetch(t, g.Zip, modP, "v1.0.0"); !bytes.Equal(z, zip1) {
		t.Fatal("zip changed after the tag was deleted")
	}

	// A restart with neither tag nor mirror.
	if err := os.RemoveAll(g.mirrors[e.remote].Dir()); err != nil {
		t.Fatal(err)
	}
	g2 := e.sourceIn(t.TempDir(), rootMod())
	wantList(t, g2, modP, "v1.0.0")
	if z := fetch(t, g2.Zip, modP, "v1.0.0"); !bytes.Equal(z, zip1) {
		t.Fatal("zip changed after a restart")
	}
	if m := fetch(t, g2.Mod, modP, "v1.0.0"); !bytes.Equal(m, mod1) {
		t.Fatal("go.mod changed after a restart")
	}
	if info, err := g2.Info(t.Context(), modP, "v1.0.0"); err != nil || info.Version != "v1.0.0" {
		t.Fatalf("Info after a restart: %+v, %v", info, err)
	}
}

func TestTagMovedDuringBuildIsDropped(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP), "a.go": "package m\n"})
	e.tag("v1.0.0")
	var moved string
	var once sync.Once
	g := e.source(rootMod(), func(_ *GitOptions, g *GitSource) {
		g.beforeRecheck = func(k jobKey) {
			once.Do(func() {
				moved = e.commit(map[string]string{"a.go": "package m // moved\n"})
				e.tag("v1.0.0")
				if err := g.mirrors[k.Remote].Sync(context.Background()); err != nil {
					t.Error(err)
				}
			})
		}
	})
	pass(t, g)
	if _, ok := e.record(modP, "v1.0.0"); ok {
		t.Fatal("a record was written for the old commit")
	}
	if _, ok := e.pinned("v1.0.0"); ok {
		t.Fatal("a pin was written for the old commit")
	}
	wantList(t, g, modP)
	if _, ok := refusalFor(g, modP, "v1.0.0"); ok {
		t.Fatal("a dropped job was reported")
	}

	pass(t, g)
	rec, ok := e.record(modP, "v1.0.0")
	if !ok || rec.Commit != moved {
		t.Fatalf("record %+v, want commit %s", rec, moved)
	}
	if sha, _ := e.pinned("v1.0.0"); sha != moved {
		t.Fatalf("pin %s, want %s", sha, moved)
	}
	wantList(t, g, modP, "v1.0.0")
}

func TestMovedTagKeepsServing(t *testing.T) {
	e := newGitEnv(t)
	first := e.commit(map[string]string{"go.mod": gomodOf(modP), "a.go": "package m\n"})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	pass(t, g)
	zip1 := fetch(t, g.Zip, modP, "v1.0.0")

	second := e.commit(map[string]string{"a.go": "package m // moved\n"})
	e.tag("v1.0.0")
	pass(t, g)
	if z := fetch(t, g.Zip, modP, "v1.0.0"); !bytes.Equal(z, zip1) {
		t.Fatal("served zip changed after the tag moved")
	}
	movedTags := g.pins.Moved()
	if len(movedTags) != 1 || movedTags[0].Tag != "v1.0.0" || movedTags[0].Pinned != first || movedTags[0].Seen != second {
		t.Fatalf("Moved() = %+v", movedTags)
	}
	if got := g.MovedPackage(movedTags[0]); got != modP {
		t.Fatalf("MovedPackage = %q", got)
	}
	if _, ok := refusalFor(g, modP, "v1.0.0"); ok {
		t.Fatalf("a pinned move was reported as a refusal: %+v", g.Refusals())
	}
}

func TestRepinnedElsewhereReported(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP), "a.go": "package m\n"})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	pass(t, g)
	zip1 := fetch(t, g.Zip, modP, "v1.0.0")

	// The operator deletes the pin, then the tag moves.
	var pinKey string
	for info, err := range e.state.List(t.Context(), "pins/go/acme/") {
		if err != nil {
			t.Fatal(err)
		}
		pinKey = info.Key
	}
	if err := e.state.Delete(t.Context(), pinKey); err != nil {
		t.Fatal(err)
	}
	second := e.commit(map[string]string{"a.go": "package m // moved\n"})
	e.tag("v1.0.0")
	pass(t, g)
	r := wantRefused(t, g, modP, "v1.0.0", RefusalMovedAfterStore, "")
	if r.Commit != second || r.Tag != "v1.0.0" {
		t.Fatalf("refusal %+v", r)
	}
	if z := fetch(t, g.Zip, modP, "v1.0.0"); !bytes.Equal(z, zip1) {
		t.Fatal("served zip changed")
	}
	// It stays reported on the next pass.
	pass(t, g)
	wantRefused(t, g, modP, "v1.0.0", RefusalMovedAfterStore, "")
}

func TestTwoIndexersOneRecord(t *testing.T) {
	e := newGitEnv(t)
	first := e.commit(map[string]string{"go.mod": gomodOf(modP), "a.go": "package m\n"})
	e.tag("v1.0.0")
	g1 := e.source(rootMod())
	g2 := e.sourceIn(t.TempDir(), rootMod())
	startQueue(t, g2.q)
	pass(t, g1)
	zip1 := fetch(t, g1.Zip, modP, "v1.0.0")

	// g2 builds another commit for the tag and loses the record to g1.
	var pinKey string
	for info, err := range e.state.List(t.Context(), "pins/go/acme/") {
		if err != nil {
			t.Fatal(err)
		}
		pinKey = info.Key
	}
	if err := e.state.Delete(t.Context(), pinKey); err != nil {
		t.Fatal(err)
	}
	e.commit(map[string]string{"a.go": "package m // moved\n"})
	e.tag("v1.0.0")
	pass(t, g2)

	n := 0
	for info, err := range e.state.List(t.Context(), "go-git/acme/") {
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(info.Key, "/version.json") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d version records", n)
	}
	if rec, _ := e.record(modP, "v1.0.0"); rec.Commit != first {
		t.Fatalf("record commit %s, want %s", rec.Commit, first)
	}
	if sha, _ := e.pinned("v1.0.0"); sha != first {
		t.Fatalf("the loser pinned %s, not the winner's %s", sha, first)
	}
	wantList(t, g2, modP, "v1.0.0")
	if z := fetch(t, g2.Zip, modP, "v1.0.0"); !bytes.Equal(z, zip1) {
		t.Fatal("the loser serves other bytes")
	}
}

func TestRepairMissingZip(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP), "a.go": "package m\n"})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	pass(t, g)
	rec, _ := e.record(modP, "v1.0.0")
	zipKey := versionKey(modP, "v1.0.0", "module.zip")
	if err := e.state.Delete(t.Context(), zipKey); err != nil {
		t.Fatal(err)
	}

	g2 := e.sourceIn("", rootMod())
	if _, err := g2.List(t.Context(), modP); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("List before the first sync with nothing listed = %v, want ErrUnavailable", err)
	}
	if _, err := g2.Info(t.Context(), modP, "v1.0.0"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("Info of a record without its zip = %v, want ErrUnavailable", err)
	}
	startQueue(t, g2.q)
	settle(t, g2)
	wantList(t, g2, modP, "v1.0.0")
	if h := zipHashOf(t, fetch(t, g2.Zip, modP, "v1.0.0")); h != rec.ZipHash {
		t.Fatalf("repaired zip h1 %s, want %s", h, rec.ZipHash)
	}

	// A record whose h1 differs from the rebuild is refused, not completed.
	if err := e.state.Delete(t.Context(), zipKey); err != nil {
		t.Fatal(err)
	}
	rec.ZipHash = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	body, _ := json.Marshal(rec)
	if _, err := e.state.Put(t.Context(), versionKey(modP, "v1.0.0", "version.json"), bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	g3 := e.source(rootMod())
	settle(t, g3)
	if _, err := g3.List(t.Context(), modP); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("List before the first sync with nothing listed = %v, want ErrUnavailable", err)
	}
	wantRefused(t, g3, modP, "v1.0.0", RefusalRefused, "h1 differs from the record")
	if _, err := e.state.Stat(t.Context(), zipKey); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a zip was written: %v", err)
	}
	if _, err := g3.Zip(t.Context(), modP, "v1.0.0"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Zip = %v, want ErrUnavailable", err)
	}
	// Record-derived refusals survive passes.
	pass(t, g3)
	wantRefused(t, g3, modP, "v1.0.0", RefusalRefused, "h1 differs from the record")
}

func TestRepairCommitGone(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	pass(t, g)
	rec, _ := e.record(modP, "v1.0.0")
	rec.Commit = strings.Repeat("ab", 20)
	body, _ := json.Marshal(rec)
	if _, err := e.state.Put(t.Context(), versionKey(modP, "v1.0.0", "version.json"), bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if err := e.state.Delete(t.Context(), versionKey(modP, "v1.0.0", "module.zip")); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	g2 := e.source(rootMod(), func(_ *GitOptions, g *GitSource) {
		g.repairHook = func() { attempts.Add(1) }
	})
	// The on-disk mirror may predate the record until the remote synced in
	// this process: the repair retries.
	deadline := time.Now().Add(20 * time.Second)
	for attempts.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("the repair did not retry")
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := refusalFor(g2, modP, "v1.0.0"); ok {
		t.Fatal("refused before the remote's first sync")
	}
	pass(t, g2)
	wantRefused(t, g2, modP, "v1.0.0", RefusalRefused, "zip missing and commit gone")
	if _, err := g2.Info(t.Context(), modP, "v1.0.0"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("Info = %v, want ErrUnavailable", err)
	}
}

func TestArchiveFailsTwiceRefused(t *testing.T) {
	failing := func(times int32) (srcOpt, *atomic.Int32) {
		var n atomic.Int32
		return func(_ *GitOptions, g *GitSource) {
			g.archive = func(ctx context.Context, m *gitmirror.Mirror, commit, dir string, w io.Writer) error {
				if n.Add(1) <= times {
					return fmt.Errorf("%w: exit status 128", gitmirror.ErrArchiveFailed)
				}
				return m.ArchiveModuleZip(ctx, commit, dir, w)
			}
		}, &n
	}
	t.Run("twice", func(t *testing.T) {
		e := newGitEnv(t)
		e.commit(map[string]string{"go.mod": gomodOf(modP)})
		e.tag("v1.0.0")
		opt, n := failing(100)
		g := e.source(rootMod(), opt)
		pass(t, g)
		wantList(t, g, modP)
		wantRefused(t, g, modP, "v1.0.0", RefusalRefused, "git archive failed twice: ")
		if n.Load() != 2 {
			t.Fatalf("archive ran %d times", n.Load())
		}
	})
	t.Run("once", func(t *testing.T) {
		e := newGitEnv(t)
		e.commit(map[string]string{"go.mod": gomodOf(modP)})
		e.tag("v1.0.0")
		opt, n := failing(1)
		g := e.source(rootMod(), opt)
		pass(t, g)
		wantList(t, g, modP, "v1.0.0")
		if n.Load() != 2 {
			t.Fatalf("archive ran %d times", n.Load())
		}
	})
}

func TestPassNeverWaitsForBuilds(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0", "v1.0.1")
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	g := e.source(rootMod(), func(_ *GitOptions, g *GitSource) {
		g.archive = func(ctx context.Context, m *gitmirror.Mirror, commit, dir string, w io.Writer) error {
			started <- struct{}{}
			<-release
			return m.ArchiveModuleZip(ctx, commit, dir, w)
		}
	})
	done := make(chan error, 1)
	go func() { done <- g.Index(t.Context()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Index waited for the builds")
	}
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		t.Fatal("no build started")
	}
	wantList(t, g, modP)
	close(release)
	settle(t, g)
	wantList(t, g, modP, "v1.0.0", "v1.0.1")
}

func TestRefusalsPrunedToCandidates(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf("git.test/acme/other")})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	pass(t, g)
	wantRefused(t, g, modP, "v1.0.0", RefusalSkipped, "module declares its path as")
	e.git("tag", "-d", "v1.0.0")
	pass(t, g)
	if rs := g.Refusals(); len(rs) != 0 {
		t.Fatalf("Refusals() = %+v after the tag was deleted", rs)
	}
}

func TestMovedPackage(t *testing.T) {
	e := newGitEnv(t)
	tools := "git.test/acme/mono/tools"
	g := e.sourceIn("", []Module{{Path: "git.test/acme/mono"}, {Path: tools, Dir: "tools"}})
	for tag, want := range map[string]string{"tools/v0.1.0": tools, "v1.0.0": "git.test/acme/mono", "toolsx/v1.0.0": "git.test/acme/mono"} {
		if got := g.MovedPackage(pins.MovedTag{Ecosystem: "go", Source: "acme", Remote: e.remote, Tag: tag}); got != want {
			t.Errorf("MovedPackage(%s) = %q, want %q", tag, got, want)
		}
	}
	if got := g.MovedPackage(pins.MovedTag{Ecosystem: "go", Source: "other", Remote: e.remote, Tag: "v1.0.0"}); got != "" {
		t.Errorf("another source's tag: %q", got)
	}
	if got := g.MovedPackage(pins.MovedTag{Ecosystem: "go", Source: "acme", Remote: "file:///elsewhere", Tag: "v1.0.0"}); got != "" {
		t.Errorf("another remote's tag: %q", got)
	}
}

// faultDriver fails List or Get of version records on demand and counts
// pin writes.
type faultDriver struct {
	storage.Driver
	failList, failGet atomic.Bool
	pinPuts           atomic.Int32
}

var errFault = errors.New("injected store fault")

func (d *faultDriver) List(ctx context.Context, prefix string) iter.Seq2[storage.Info, error] {
	if d.failList.Load() {
		return func(yield func(storage.Info, error) bool) { yield(storage.Info{}, errFault) }
	}
	return d.Driver.List(ctx, prefix)
}

func (d *faultDriver) Get(ctx context.Context, key string) (io.ReadCloser, storage.Info, error) {
	if d.failGet.Load() && strings.HasSuffix(key, "/version.json") {
		return nil, storage.Info{}, errFault
	}
	return d.Driver.Get(ctx, key)
}

func (d *faultDriver) PutIfAbsent(ctx context.Context, key string, r io.Reader) (storage.Info, error) {
	if strings.HasPrefix(key, "pins/") {
		d.pinPuts.Add(1)
	}
	return d.Driver.PutIfAbsent(ctx, key, r)
}

func (e *gitEnv) faults() *faultDriver {
	d := &faultDriver{Driver: e.state}
	e.state = d
	return d
}

func wantUnavailable(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("%s = %v, want ErrUnavailable", what, err)
	}
}

func TestFailedLoadAnswersUnavailable(t *testing.T) {
	for _, mode := range []string{"list", "get"} {
		t.Run(mode, func(t *testing.T) {
			e := newGitEnv(t)
			fd := e.faults()
			e.commit(map[string]string{"go.mod": gomodOf(modP)})
			e.tag("v1.0.0")
			pass(t, e.source(rootMod()))

			fail := &fd.failList
			if mode == "get" {
				fail = &fd.failGet
			}
			fail.Store(true)
			g := e.source(rootMod())
			_, err := g.List(t.Context(), modP)
			wantUnavailable(t, "List", err)
			_, err = g.Info(t.Context(), modP, "v1.0.0")
			wantUnavailable(t, "Info", err)
			_, err = g.Latest(t.Context(), modP)
			wantUnavailable(t, "Latest", err)
			_, err = g.Zip(t.Context(), modP, "v1.0.0")
			wantUnavailable(t, "Zip", err)
			_, err = g.Mod(t.Context(), modP, "v1.0.0")
			wantUnavailable(t, "Mod", err)
			if _, err := g.List(t.Context(), "git.test/acme/other"); !errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("an unconfigured path = %v", err)
			}
			if err := g.Index(t.Context()); err == nil {
				t.Fatal("Index succeeded although the load failed")
			}
			fail.Store(false)
			pass(t, g)
			wantList(t, g, modP, "v1.0.0")
		})
	}
}

func TestBadRecordsReported(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0", "v1.1.0", "v1.2.0")
	pass(t, e.source(rootMod()))
	put := func(v string, body []byte) {
		if _, err := e.state.Put(t.Context(), versionKey(modP, v, "version.json"), bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	put("v1.0.0", []byte("{"))
	rec, _ := e.record(modP, "v1.1.0")
	rec.Format = 99
	body, _ := json.Marshal(rec)
	put("v1.1.0", body)

	g := e.sourceIn("", rootMod())
	wantList(t, g, modP, "v1.2.0")
	wantRefused(t, g, modP, "v1.0.0", RefusalRefused, "unreadable version record")
	wantRefused(t, g, modP, "v1.1.0", RefusalRefused, "version record format 99")
	_, err := g.Info(t.Context(), modP, "v1.0.0")
	wantUnavailable(t, "Info of an unreadable record", err)
}

func TestCorruptPinReported(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	pass(t, e.source(rootMod()))
	key := "pins/go/acme/" + storage.EscapeSegment(e.remote) + "/" + storage.EscapeSegment("v1.0.0") + ".json"
	if _, err := e.state.Put(t.Context(), key, strings.NewReader("garbage")); err != nil {
		t.Fatal(err)
	}
	e.tag("v1.2.0")
	g := e.source(rootMod())
	pass(t, g)
	wantList(t, g, modP, "v1.0.0", "v1.2.0")
	wantRefused(t, g, modP, "v1.0.0", RefusalCorruptPin, "")
}

func TestPinMemoised(t *testing.T) {
	e := newGitEnv(t)
	fd := e.faults()
	e.commit(map[string]string{"go.mod": gomodOf(modP), "a.go": "package m\n"})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	pass(t, g)
	pass(t, g)
	n := fd.pinPuts.Load()
	pass(t, g)
	if got := fd.pinPuts.Load(); got != n {
		t.Fatalf("an unmoved stored tag was pinned again (%d pin writes, then %d)", n, got)
	}
	e.commit(map[string]string{"a.go": "package m // moved\n"})
	e.tag("v1.0.0")
	pass(t, g)
	if fd.pinPuts.Load() == n {
		t.Fatal("a moved tag did not reach Pin")
	}
	if mv := g.pins.Moved(); len(mv) != 1 || mv[0].Tag != "v1.0.0" {
		t.Fatalf("Moved() = %+v", mv)
	}
}

func TestServeMissingZipRepairs(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP), "a.go": "package m\n"})
	e.tag("v1.0.0")
	g := e.sourceIn("", rootMod())
	startQueue(t, g.q)
	pass(t, g)
	rec, _ := e.record(modP, "v1.0.0")
	for _, f := range []string{"module.zip", "go.mod"} {
		if err := e.state.Delete(t.Context(), versionKey(modP, "v1.0.0", f)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := g.Zip(t.Context(), modP, "v1.0.0")
	wantUnavailable(t, "Zip of a lost zip", err)
	wantList(t, g, modP, "v1.0.0")
	settle(t, g)
	if h := zipHashOf(t, fetch(t, g.Zip, modP, "v1.0.0")); h != rec.ZipHash {
		t.Fatalf("repaired zip h1 %s, want %s", h, rec.ZipHash)
	}
	if m := fetch(t, g.Mod, modP, "v1.0.0"); string(m) != gomodOf(modP) {
		t.Fatalf("repaired go.mod %q", m)
	}
}

func TestFollowerTimeoutNotCounted(t *testing.T) {
	e := newGitEnv(t)
	commit := e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	started, release := make(chan struct{}), make(chan struct{})
	g := e.source(rootMod(), func(_ *GitOptions, g *GitSource) {
		g.archive = func(context.Context, *gitmirror.Mirror, string, string, io.Writer) error {
			close(started)
			<-release
			return fmt.Errorf("%w: exit status 128", gitmirror.ErrArchiveFailed)
		}
	})
	m := g.mirrors[e.remote]
	dk := dirKey{e.remote, commit, ""}
	mv := module.Version{Path: modP, Version: "v1.0.0"}
	leader := make(chan error, 1)
	go func() {
		_, _, err := g.build(context.Background(), m, dk, mv, []byte(gomodOf(modP)))
		leader <- err
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := g.build(ctx, m, dk, mv, []byte(gomodOf(modP))); err == nil {
		t.Fatal("the follower's build succeeded")
	}
	close(release)
	if err := <-leader; !errors.Is(err, gitmirror.ErrArchiveFailed) {
		t.Fatalf("leader: %v", err)
	}
	if reason := g.dirRefusal(dk); reason != "" {
		t.Fatalf("one archive failure and a follower's timeout were refused: %s", reason)
	}
}

func TestAdoptedRecordInvalid(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	body, _ := json.Marshal(versionRecord{Format: GoZipFormat, Version: "v9.9.9", Commit: "nothex"})
	if _, err := e.state.Put(t.Context(), versionKey(modP, "v1.0.0", "version.json"), bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	pass(t, g)
	wantRefused(t, g, modP, "v1.0.0", RefusalRefused, "invalid version record")
	_, err := g.Info(t.Context(), modP, "v1.0.0")
	wantUnavailable(t, "Info", err)
}

func TestPublishClearsRecordRefusal(t *testing.T) {
	e := newGitEnv(t)
	g := e.sourceIn("", rootMod())
	vk := verKey{modP, "v1.0.0"}
	rec := versionRecord{Format: GoZipFormat, Version: "v1.0.0", Commit: strings.Repeat("ab", 20)}
	_ = g.refuseRecord(vk, rec, "h1 differs from the record")
	g.publish(vk, rec)
	if rs := g.Refusals(); len(rs) != 0 {
		t.Fatalf("Refusals() = %+v after another indexer completed the version", rs)
	}
}

func TestGoSourceRecreatesStoredRefs(t *testing.T) {
	e := newGitEnv(t)
	c1 := e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	c2 := e.commit(map[string]string{"a.go": "package m\n"})
	e.tag("v1.1.0")
	g := e.source(rootMod())
	pass(t, g) // stores both versions
	m := g.mirrors[e.remote]
	hasRefs := func(when string) {
		t.Helper()
		refs := testutil.Git(t, m.Dir(), "show-ref")
		for _, c := range []string{c1, c2} {
			if !strings.Contains(refs, gitmirror.StoredRefPrefix+c) {
				t.Fatalf("%s: no stored ref for %s in\n%s", when, c, refs)
			}
		}
	}
	hasRefs("once stored")

	if err := os.RemoveAll(m.Dir()); err != nil {
		t.Fatal(err)
	}
	pass(t, g)
	hasRefs("after the mirror was recreated")
}
