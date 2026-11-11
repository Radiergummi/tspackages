package pypi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

// repo is a working repository the tests commit and tag in.
type repo struct {
	t   *testing.T
	dir string
}

func newRepo(t *testing.T) *repo {
	t.Helper()
	r := &repo{t: t, dir: t.TempDir()}
	testutil.Git(t, r.dir, "init", "-q")
	return r
}

func (r *repo) write(files map[string]string) string {
	r.t.Helper()
	for name, body := range files {
		p := filepath.Join(r.dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			r.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	testutil.Git(r.t, r.dir, "add", "-A")
	testutil.Git(r.t, r.dir, "commit", "-q", "-m", "c", "--allow-empty")
	return testutil.Git(r.t, r.dir, "rev-parse", "HEAD")
}

func (r *repo) tag(name string) { r.t.Helper(); testutil.Git(r.t, r.dir, "tag", "-f", name) }

func pyproject(name, version string) string {
	return "[project]\nname = \"" + name + "\"\nversion = \"" + version + "\"\nrequires-python = \">=3.10\"\ndependencies = [\"requests\"]\n" + buildSystem
}

func workspaceRoot() string {
	return "[tool.uv.workspace]\nmembers = [\"packages/*\"]\n"
}

type gitEnv struct {
	state    storage.Driver
	rec      *records.Store
	maxBytes int64 // 0 = MaxGitSdistBytes
}

func newGitEnv(t *testing.T) *gitEnv {
	t.Helper()
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &gitEnv{state: d, rec: records.New(d)}
}

func (e *gitEnv) source(t *testing.T, tags map[string]map[string][]string, remotes ...string) *GitSource {
	t.Helper()
	var mirrors []*gitmirror.Mirror
	for _, r := range remotes {
		m, err := gitmirror.New(gitmirror.Options{Remote: r, BaseDir: t.TempDir(), AllowFileRemotesForTesting: true})
		if err != nil {
			t.Fatal(err)
		}
		mirrors = append(mirrors, m)
	}
	maxBytes := e.maxBytes
	if maxBytes == 0 {
		maxBytes = MaxGitSdistBytes
	}
	g, err := NewGitSource("git", []string{"*"}, mirrors, tags, e.state, e.rec, 0, nil, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func index(t *testing.T, g *GitSource) {
	t.Helper()
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func versionsOf(t *testing.T, g *GitSource, name string) []string {
	t.Helper()
	p, err := g.Project(context.Background(), name)
	if err != nil {
		t.Fatalf("Project(%s): %v", name, err)
	}
	var out []string
	for _, f := range p.Files {
		out = append(out, f.Filename)
	}
	slices.Sort(out)
	return out
}

func sdistBytes(t *testing.T, g *GitSource, name, filename string) []byte {
	t.Helper()
	b, err := readAllArtifact(g.File(context.Background(), name, filename))
	if err != nil {
		t.Fatalf("File(%s): %v", filename, err)
	}
	return b
}

func TestSingleRepoStaticVersion(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("Acme_Core", "1.2.0"), "acme_core/__init__.py": ""})
	r.tag("v1.2.0")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	if got := versionsOf(t, g, "acme-core"); !slices.Equal(got, []string{"acme_core-1.2.0.tar.gz"}) {
		t.Fatalf("files = %v", got)
	}
	p, _ := g.Project(context.Background(), "acme-core")
	if f := p.Files[0]; f.RequiresPython != ">=3.10" || f.CoreMetadata == "" || f.UploadTime.IsZero() || f.SHA256 == "" {
		t.Fatalf("file = %+v", f)
	}
	sd := sdistBytes(t, g, "acme-core", "acme_core-1.2.0.tar.gz")
	if sum256(sd) != p.Files[0].SHA256 {
		t.Fatal("served sha256 does not match the bytes")
	}
	meta, err := readAllArtifact(g.Metadata(context.Background(), "acme-core", "acme_core-1.2.0.tar.gz"))
	if err != nil || !bytes.Contains(meta, []byte("Version: 1.2.0")) {
		t.Fatalf("metadata = %q %v", meta, err)
	}
}

func TestTagNameIrrelevant(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "3.1.4")})
	r.tag("release-2026-11")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	if got := versionsOf(t, g, "acme-core"); !slices.Equal(got, []string{"acme_core-3.1.4.tar.gz"}) {
		t.Fatalf("files = %v", got)
	}
}

func TestWorkspaceMembersReleased(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{
		"pyproject.toml":               workspaceRoot(),
		"packages/core/pyproject.toml": pyproject("acme-core", "1.0.0"),
		"packages/api/pyproject.toml":  pyproject("acme-api", "2.0.0"),
	})
	r.tag("v1")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	if got := versionsOf(t, g, "acme-core"); len(got) != 1 {
		t.Fatalf("core = %v", got)
	}
	if got := versionsOf(t, g, "acme-api"); len(got) != 1 {
		t.Fatalf("api = %v", got)
	}
}

func TestChangedWithoutBump(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": workspaceRoot(), "packages/core/pyproject.toml": pyproject("acme-core", "1.0.0"), "packages/core/a.py": "one"})
	r.tag("core@1.0.0")
	env := newGitEnv(t)
	g := env.source(t, nil, r.dir)
	index(t, g)
	first := sdistBytes(t, g, "acme-core", "acme_core-1.0.0.tar.gz")
	r.write(map[string]string{"packages/core/a.py": "two", "packages/api/pyproject.toml": pyproject("acme-api", "1.0.0")})
	r.tag("api@1.0.0")
	index(t, g)
	if got := sdistBytes(t, g, "acme-core", "acme_core-1.0.0.tar.gz"); !bytes.Equal(got, first) {
		t.Fatal("published bytes changed")
	}
	c := g.Conflicts()
	if len(c) != 1 || c[0].Package != "acme-core" || c[0].Kind != ConflictNoBump || !slices.Contains(c[0].Tags, "api@1.0.0") {
		t.Fatalf("conflicts = %+v", c)
	}
	index(t, g) // a second pass reports it once, not twice
	if len(g.Conflicts()) != 1 {
		t.Fatalf("conflicts after another pass = %+v", g.Conflicts())
	}
}

func TestTagMapping(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": workspaceRoot(), "packages/core/pyproject.toml": pyproject("acme-core", "1.0.0"), "packages/api/pyproject.toml": pyproject("acme-api", "1.0.0")})
	r.tag("core@1.0.0")
	g := newGitEnv(t).source(t, map[string]map[string][]string{r.dir: {"core@*": {"packages/core"}, "api@*": {"packages/api"}}}, r.dir)
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-api"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("api released from a core tag: %v", err)
	}
	r.write(map[string]string{"packages/core/a.py": "changed without a bump"})
	r.tag("api@1.0.0")
	index(t, g)
	if got := versionsOf(t, g, "acme-api"); len(got) != 1 {
		t.Fatalf("api = %v", got)
	}
	if len(g.Conflicts()) != 0 {
		t.Fatalf("an api tag must not offer core: %+v", g.Conflicts())
	}
}

func TestAncestorWinsOnFreshIndex(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0"), "a.py": "first"})
	r.tag("zzz-first")
	r.write(map[string]string{"a.py": "second"})
	r.tag("aaa-second")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	sd := sdistBytes(t, g, "acme-core", "acme_core-1.0.0.tar.gz")
	if !bytes.Contains(gunzip(t, sd), []byte("first")) {
		t.Fatal("the descendant won over its ancestor")
	}
	if c := g.Conflicts(); len(c) != 1 || c[0].Kind != ConflictNoBump {
		t.Fatalf("conflicts = %+v", c)
	}
}

func TestDivergentWithheld(t *testing.T) {
	r := newRepo(t)
	base := r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0"), "a.py": "base"})
	_ = base
	testutil.Git(t, r.dir, "checkout", "-q", "-b", "left")
	r.write(map[string]string{"a.py": "left"})
	r.tag("left")
	testutil.Git(t, r.dir, "checkout", "-q", "-b", "right", base)
	r.write(map[string]string{"a.py": "right"})
	r.tag("right")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-core"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("divergent release served or missing: %v", err)
	}
	if c := g.Conflicts(); len(c) != 1 || c[0].Kind != ConflictDivergent {
		t.Fatalf("conflicts = %+v", c)
	}
}

func TestSameNameTwoRepos(t *testing.T) {
	a, b := newRepo(t), newRepo(t)
	a.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	a.tag("v1")
	b.write(map[string]string{"pyproject.toml": pyproject("Acme.Core", "2.0.0")})
	b.tag("v2")
	g := newGitEnv(t).source(t, nil, a.dir, b.dir)
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if c := g.Conflicts(); len(c) != 1 || c[0].Kind != ConflictRepositories || len(c[0].Remotes) != 2 {
		t.Fatalf("conflicts = %+v", c)
	}
}

func TestRefusedAndSkipped(t *testing.T) {
	r := newRepo(t)
	head := r.write(map[string]string{"pyproject.toml": workspaceRoot(),
		"packages/sub/pyproject.toml": pyproject("acme-sub", "1.0.0"),
		"packages/lfs/pyproject.toml": pyproject("acme-lfs", "1.0.0"), "packages/lfs/model.bin": "version https://git-lfs.github.com/spec/v1\noid sha256:x\nsize 1\n",
		"packages/dyn/pyproject.toml": "[project]\nname = \"acme-dyn\"\ndynamic = [\"version\"]\n" + buildSystem,
	})
	testutil.Git(t, r.dir, "update-index", "--add", "--cacheinfo", "160000,"+head+",packages/sub/vendored")
	testutil.Git(t, r.dir, "commit", "-q", "-m", "sub")
	r.tag("v1")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	for _, n := range []string{"acme-sub", "acme-lfs", "acme-dyn"} {
		if _, err := g.Project(context.Background(), n); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("%s served: %v", n, err)
		}
	}
	reasons := map[string]string{}
	for _, s := range g.Skipped() {
		reasons[s.Package] = s.Reason
	}
	if !strings.Contains(reasons["acme-sub"], "submodule") || !strings.Contains(reasons["acme-lfs"], "LFS") || !strings.Contains(reasons["acme-dyn"], "dynamic") {
		t.Fatalf("skipped = %+v", g.Skipped())
	}
}

func TestServedSurvivesTagAndMirrorLoss(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	r.tag("v1")
	env := newGitEnv(t)
	g := env.source(t, nil, r.dir)
	index(t, g)
	first := sdistBytes(t, g, "acme-core", "acme_core-1.0.0.tar.gz")
	testutil.Git(t, r.dir, "tag", "-d", "v1")
	// A new source on the same state store with a fresh mirror.
	g2 := env.source(t, nil, r.dir)
	if got := sdistBytes(t, g2, "acme-core", "acme_core-1.0.0.tar.gz"); !bytes.Equal(got, first) {
		t.Fatal("served release lost before indexing")
	}
	index(t, g2)
	if got := sdistBytes(t, g2, "acme-core", "acme_core-1.0.0.tar.gz"); !bytes.Equal(got, first) {
		t.Fatal("served release lost after the tag was deleted")
	}
}

func TestTwoIndexersOneRelease(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	r.tag("v1")
	env := newGitEnv(t)
	a, b := env.source(t, nil, r.dir), env.source(t, nil, r.dir)
	var wg sync.WaitGroup
	for _, g := range []*GitSource{a, b} {
		wg.Go(func() { g.Index(context.Background()) })
	}
	wg.Wait()
	n := 0
	for info, err := range env.state.List(context.Background(), "pypi-git/") {
		if err == nil && strings.HasSuffix(info.Key, "/release.json") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d release records", n)
	}
	if !bytes.Equal(sdistBytes(t, a, "acme-core", "acme_core-1.0.0.tar.gz"), sdistBytes(t, b, "acme-core", "acme_core-1.0.0.tar.gz")) {
		t.Fatal("indexers serve different bytes")
	}
}

// Review Focus 4: a member removed later keeps its earlier releases.
func TestMemberRemovedLater(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": workspaceRoot(), "packages/old/pyproject.toml": pyproject("acme-old", "1.0.0")})
	r.tag("v1")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	testutil.Git(t, r.dir, "rm", "-rq", "packages/old")
	r.write(map[string]string{"packages/new/pyproject.toml": pyproject("acme-new", "1.0.0")})
	r.tag("v2")
	index(t, g)
	if got := versionsOf(t, g, "acme-old"); len(got) != 1 {
		t.Fatalf("old member's release lost: %v", got)
	}
}

func TestEqualVersionsDifferentSpelling(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0")})
	r.tag("a")
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	r.tag("b")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	if got := versionsOf(t, g, "acme-core"); len(got) != 1 {
		t.Fatalf("one release expected for 1.0 and 1.0.0: %v", got)
	}
}

func TestUnavailableBeforeFirstPass(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	r.tag("v1")
	g := newGitEnv(t).source(t, nil, r.dir)
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("before the first pass: %v", err)
	}
	index(t, g)
	if _, err := g.Project(context.Background(), "unknown"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("after: %v", err)
	}
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(gz)
	return out
}

func TestLFSAttributesRefused(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{".gitattributes": "*.bin filter=lfs diff=lfs merge=lfs -text\n", "pyproject.toml": pyproject("acme-core", "1.0.0")})
	r.tag("v1")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("served: %v", err)
	}
	if s := g.Skipped(); len(s) != 1 || !strings.Contains(s[0].Reason, "filter=lfs") {
		t.Fatalf("skipped = %+v", s)
	}
}

// failReleaseWrites fails every release record write, as an unreachable
// state store would.
type failReleaseWrites struct{ storage.Driver }

func (f failReleaseWrites) PutIfAbsent(ctx context.Context, key string, r io.Reader) (storage.Info, error) {
	if strings.HasSuffix(key, "release.json") {
		return storage.Info{}, errors.New("state store unavailable")
	}
	return f.Driver.PutIfAbsent(ctx, key, r)
}

// TestBuildFailureIsNotNotFound: a name whose only release failed to build
// is unavailable, not missing, so a later claiming source isn't asked.
func TestBuildFailureIsNotNotFound(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0"), "a.py": ""})
	r.tag("v1")
	env := newGitEnv(t)
	env.state = failReleaseWrites{env.state}
	g := env.source(t, nil, r.dir)
	g.Index(context.Background())
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("Project after a failed build: %v", err)
	}
}

// TestOversizedPackageRefused: a package directory larger than the cap is
// refused and reported instead of being read into memory whole.
func TestOversizedPackageRefused(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-big", "1.0.0"), "blob.bin": strings.Repeat("x", 64<<10)})
	r.tag("v1")
	env := newGitEnv(t)
	env.maxBytes = 16 << 10
	g := env.source(t, nil, r.dir)
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-big"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("oversized package served: %v", err)
	}
	if s := g.Skipped(); len(s) != 1 || !strings.Contains(s[0].Reason, "larger than") {
		t.Fatalf("skipped = %+v", s)
	}
}

// TestRemoteNeverIndexedIsUnavailable: while a remote has never been indexed,
// a name it might declare is unavailable, not missing, so a later claiming
// source isn't asked for it.
func TestRemoteNeverIndexedIsUnavailable(t *testing.T) {
	a := newRepo(t)
	a.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	a.tag("v1")
	missing := filepath.Join(t.TempDir(), "later")
	g := newGitEnv(t).source(t, nil, a.dir, missing)
	index(t, g)
	// Nothing new is built yet: the unindexed remote may declare it too.
	for _, n := range []string{"acme-core", "acme-api"} {
		if _, err := g.Project(context.Background(), n); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("%s while a remote never indexed: %v", n, err)
		}
	}
	if err := os.MkdirAll(missing, 0o755); err != nil {
		t.Fatal(err)
	}
	b := &repo{t: t, dir: missing}
	testutil.Git(t, b.dir, "init", "-q")
	b.write(map[string]string{"pyproject.toml": pyproject("acme-api", "1.0.0")})
	b.tag("v1")
	index(t, g)
	for _, n := range []string{"acme-core", "acme-api"} {
		if got := versionsOf(t, g, n); len(got) != 1 {
			t.Fatalf("%s = %v", n, got)
		}
	}
	if _, err := g.Project(context.Background(), "unknown"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("once every remote is indexed: %v", err)
	}
}

// TestUnreadableTagIsUnavailable: a tag that cannot be read makes unknown
// names unavailable for that pass instead of missing.
func TestUnreadableTagIsUnavailable(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	r.tag("v1")
	m := mirrorWithout(t, r, testutil.Git(t, r.dir, "rev-parse", "v1^{tree}"))
	env := newGitEnv(t)
	g, err := NewGitSource("git", []string{"*"}, []*gitmirror.Mirror{m}, nil, env.state, env.rec, 0, nil, MaxGitSdistBytes)
	if err != nil {
		t.Fatal(err)
	}
	g.Index(context.Background())
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("a name at an unreadable tag: %v", err)
	}
}

// mirrorWithout returns a synced mirror of r that lost object (say, a tag's
// root tree: the tag lists, its tree does not read), with r's remote gone, so
// a pass indexes the local mirror.
func mirrorWithout(t *testing.T, r *repo, object string) *gitmirror.Mirror {
	t.Helper()
	m, err := gitmirror.New(gitmirror.Options{Remote: r.dir, BaseDir: t.TempDir(), AllowFileRemotesForTesting: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	dropObject(t, m, object)
	if err := os.Rename(r.dir, r.dir+"-gone"); err != nil {
		t.Fatal(err)
	}
	return m
}

// dropObject removes object from m: its packs are unpacked into loose
// objects first.
func dropObject(t *testing.T, m *gitmirror.Mirror, object string) {
	t.Helper()
	packs, _ := filepath.Glob(filepath.Join(m.Dir(), "objects", "pack", "*.pack"))
	for _, p := range packs {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{p, strings.TrimSuffix(p, ".pack") + ".idx", strings.TrimSuffix(p, ".pack") + ".rev"} {
			os.Remove(f)
		}
		cmd := exec.Command("git", "unpack-objects", "-q")
		cmd.Dir, cmd.Stdin = m.Dir(), bytes.NewReader(b)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("unpack-objects: %v %s", err, out)
		}
	}
	if err := os.Remove(filepath.Join(m.Dir(), "objects", object[:2], object[2:])); err != nil {
		t.Fatal(err)
	}
}

// releaseRecords counts the stored release records.
func releaseRecords(t *testing.T, d storage.Driver) int {
	t.Helper()
	n := 0
	for info, err := range d.List(context.Background(), "pypi-git/") {
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(info.Key, "/release.json") {
			n++
		}
	}
	return n
}

// TestIncompletePassBuildsNothing: after a restart, a remote that has not
// synced yet may declare a name the other remotes do, so no release is
// built until every remote has been scanned.
func TestIncompletePassBuildsNothing(t *testing.T) {
	a, b := newRepo(t), newRepo(t)
	a.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0"), "a.py": "a"})
	a.tag("v1")
	b.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0"), "b.py": "b"})
	b.tag("v1")
	env := newGitEnv(t)
	index(t, env.source(t, nil, a.dir, b.dir))
	if err := os.Rename(b.dir, b.dir+"-away"); err != nil {
		t.Fatal(err)
	}
	g := env.source(t, nil, a.dir, b.dir) // a restart: b's fresh mirror never synced
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("while b is unreachable: %v", err)
	}
	if n := releaseRecords(t, env.state); n != 0 {
		t.Fatalf("%d releases built from an incomplete pass", n)
	}
	if err := os.Rename(b.dir+"-away", b.dir); err != nil {
		t.Fatal(err)
	}
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("once b is back: %v", err)
	}
	if n := releaseRecords(t, env.state); n != 0 {
		t.Fatalf("%d releases of a name two repositories declare", n)
	}
}

// TestUnreadEarliestTagBuildsNothing: when the earliest tag of a version
// cannot be read, a later tag must not be stored in its place.
func TestUnreadEarliestTagBuildsNothing(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0"), "a.py": "first"})
	r.tag("v1")
	// Unrelated history, so building the later tag never reads v1's tree.
	testutil.Git(t, r.dir, "checkout", "-q", "--orphan", "other")
	r.write(map[string]string{"a.py": "second"})
	r.tag("v1-again")
	m := mirrorWithout(t, r, testutil.Git(t, r.dir, "rev-parse", "v1^{tree}"))
	env := newGitEnv(t)
	g, err := NewGitSource("git", []string{"*"}, []*gitmirror.Mirror{m}, nil, env.state, env.rec, 0, nil, MaxGitSdistBytes)
	if err != nil {
		t.Fatal(err)
	}
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if n := releaseRecords(t, env.state); n != 0 {
		t.Fatalf("%d releases built while the earliest tag was unread", n)
	}
}

// TestSymlinkedReadmeRefused: a readme that is a symlink would be read as its
// target path and left out of the sdist, so the release is refused.
func TestSymlinkedReadmeRefused(t *testing.T) {
	r := newRepo(t)
	if err := os.Symlink("docs/README.md", filepath.Join(r.dir, "README.md")); err != nil {
		t.Fatal(err)
	}
	r.write(map[string]string{
		"pyproject.toml": strings.Replace(pyproject("acme-core", "1.0.0"), "[project]\n", "[project]\nreadme = \"README.md\"\n", 1),
		"docs/README.md": "# Acme\n",
	})
	r.tag("v1")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("served: %v", err)
	}
	if s := g.Skipped(); len(s) != 1 || !strings.Contains(s[0].Reason, "regular file") {
		t.Fatalf("skipped = %+v", s)
	}
}

// TestFailedRemoteKeepsItsLastScan: a remote that fails a pass after being
// indexed still counts, so a name it shares with another remote stays
// withheld.
func TestFailedRemoteKeepsItsLastScan(t *testing.T) {
	a, b := newRepo(t), newRepo(t)
	a.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	a.tag("v1")
	b.write(map[string]string{"pyproject.toml": pyproject("acme-core", "2.0.0")})
	b.tag("v2")
	g := newGitEnv(t).source(t, nil, a.dir, b.dir)
	index(t, g)
	// b's remote and its mirror's objects are gone: its refs no longer read.
	if err := os.Rename(b.dir, b.dir+"-gone"); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(g.mirrors[1].Dir(), "objects")); err != nil {
		t.Fatal(err)
	}
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

// TestRebuildMustMatchRecord: a release record's sdist is only written when
// the rebuilt bytes have the recorded digest; otherwise it is reported.
func TestRebuildMustMatchRecord(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	r.tag("v1")
	env := newGitEnv(t)
	g := env.source(t, nil, r.dir)
	index(t, g)
	ctx := context.Background()
	v, _ := ParseVersion("1.0.0")
	dir := g.releaseDir("acme-core", v.Canonical())
	rel, err := g.readRelease(ctx, dir+"release.json")
	if err != nil {
		t.Fatal(err)
	}
	// As if the first build had produced other bytes and stopped before
	// writing them.
	rel.SHA256 = sum256([]byte("other bytes"))
	body, _ := json.Marshal(rel)
	if _, err := env.state.Put(ctx, dir+"release.json", bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	sdKey := dir + storage.EscapeSegment(rel.Filename)
	if err := env.state.Delete(ctx, sdKey); err != nil {
		t.Fatal(err)
	}
	g2 := env.source(t, nil, r.dir)
	index(t, g2)
	if _, err := env.state.Stat(ctx, sdKey); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("an sdist that does not match its record was written: %v", err)
	}
	if c := g2.Conflicts(); len(c) != 1 || c[0].Kind != ConflictRebuild || c[0].Package != "acme-core" {
		t.Fatalf("conflicts = %+v", c)
	}
}

// hideRecords lists no release records, as a store does before another
// indexer's claim shows up in its listing.
type hideRecords struct{ storage.Driver }

func (h hideRecords) List(ctx context.Context, prefix string) iter.Seq2[storage.Info, error] {
	return func(yield func(storage.Info, error) bool) {
		for info, err := range h.Driver.List(ctx, prefix) {
			if err == nil && strings.HasSuffix(info.Key, "/release.json") {
				continue
			}
			if !yield(info, err) {
				return
			}
		}
	}
}

// TestClaimedElsewhereIsPending: a build that finds another indexer's record
// it cannot complete leaves the name unavailable for the pass, not missing.
func TestClaimedElsewhereIsPending(t *testing.T) {
	for _, c := range []struct {
		name     string
		change   func(*release)
		conflict string
	}{
		{"other identity", func(r *release) { r.Identity = "other" }, ""},
		{"other bytes", func(r *release) { r.SHA256 = sum256([]byte("other bytes")) }, ConflictRebuild},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRepo(t)
			r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
			r.tag("v1")
			env := newGitEnv(t)
			g := env.source(t, nil, r.dir)
			index(t, g)
			ctx := context.Background()
			v, _ := ParseVersion("1.0.0")
			dir := g.releaseDir("acme-core", v.Canonical())
			rel, err := g.readRelease(ctx, dir+"release.json")
			if err != nil {
				t.Fatal(err)
			}
			c.change(&rel)
			body, _ := json.Marshal(rel)
			if _, err := env.state.Put(ctx, dir+"release.json", bytes.NewReader(body)); err != nil {
				t.Fatal(err)
			}
			if err := env.state.Delete(ctx, dir+storage.EscapeSegment(rel.Filename)); err != nil {
				t.Fatal(err)
			}
			env.state = hideRecords{env.state}
			g2 := env.source(t, nil, r.dir)
			index(t, g2)
			if _, err := g2.Project(ctx, "acme-core"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err = %v", err)
			}
			if c.conflict != "" && !slices.ContainsFunc(g2.Conflicts(), func(x Conflict) bool { return x.Kind == c.conflict }) {
				t.Fatalf("conflicts = %+v", g2.Conflicts())
			}
		})
	}
}

// TestTagMappingRootDir: "." in a tag mapping is the root package.
func TestTagMappingRootDir(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	r.tag("v1")
	g := newGitEnv(t).source(t, map[string]map[string][]string{r.dir: {"v*": {"."}}}, r.dir)
	index(t, g)
	if got := versionsOf(t, g, "acme-core"); len(got) != 1 {
		t.Fatalf("root = %v", got)
	}
}

// lastSyncGauge returns the git last-sync gauge of a pypi source, and
// whether it is set.
func lastSyncGauge(t *testing.T, source string) (float64, bool) {
	t.Helper()
	fams, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != "tspackages_git_last_sync_timestamp_seconds" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if len(labels) == 2 && labels["ecosystem"] == "pypi" && labels["source"] == source {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

// TestLastSyncMetric: the gauge is the oldest last successful sync among
// the remotes, 0 while one never synced.
func TestLastSyncMetric(t *testing.T) {
	a := newRepo(t)
	a.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	a.tag("v1")
	missing := filepath.Join(t.TempDir(), "later")
	var mirrors []*gitmirror.Mirror
	for _, r := range []string{a.dir, missing} {
		m, err := gitmirror.New(gitmirror.Options{Remote: r, BaseDir: t.TempDir(), AllowFileRemotesForTesting: true})
		if err != nil {
			t.Fatal(err)
		}
		mirrors = append(mirrors, m)
	}
	env := newGitEnv(t)
	g, err := NewGitSource("metric-git", []string{"*"}, mirrors, nil, env.state, env.rec, 0, nil, MaxGitSdistBytes)
	if err != nil {
		t.Fatal(err)
	}
	index(t, g)
	if v, ok := lastSyncGauge(t, "metric-git"); !ok || v != 0 {
		t.Fatalf("with a remote that never synced: %v %v", v, ok)
	}
	b := &repo{t: t, dir: missing}
	if err := os.MkdirAll(missing, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.Git(t, b.dir, "init", "-q")
	b.write(map[string]string{"pyproject.toml": pyproject("acme-api", "1.0.0")})
	index(t, g)
	want := float64(min(mirrors[0].LastSync().Unix(), mirrors[1].LastSync().Unix()))
	if v, _ := lastSyncGauge(t, "metric-git"); v != want {
		t.Fatalf("gauge = %v, want the oldest sync %v", v, want)
	}
}

// TestContentProblemsAreRefusals: a release that can never be built from
// its repository's content is a reported skip, not a name that stays
// unavailable, and leaves the index complete.
func TestContentProblemsAreRefusals(t *testing.T) {
	long := "acme-" + strings.Repeat("x", 150)
	cases := []struct {
		name, pkg, reason string
		files             map[string]string
	}{
		{"name too long for the store", long, "too long",
			map[string]string{"pyproject.toml": pyproject(long, "1.0.0")}},
		{"invalid extra", "acme-core", "extra",
			map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0") + "[project.optional-dependencies]\n\"bad extra\" = [\"x\"]\n"}},
		{"root pyproject.toml over 1MiB", "", "does not parse",
			map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0") + "#" + strings.Repeat("x", 1<<20) + "\n"}},
		{"member directory with a newline", "", "path",
			map[string]string{"pyproject.toml": workspaceRoot(), "packages/a\nb/pyproject.toml": pyproject("acme-nl", "1.0.0")}},
		{"member directory starting with a dash", "acme-dash", "path",
			map[string]string{"pyproject.toml": "[tool.uv.workspace]\nmembers = [\"*\"]\n", "-x/pyproject.toml": pyproject("acme-dash", "1.0.0")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRepo(t)
			r.write(c.files)
			r.tag("v1")
			g := newGitEnv(t).source(t, nil, r.dir)
			index(t, g)
			if c.pkg != "" {
				if _, err := g.Project(context.Background(), c.pkg); !errors.Is(err, resolve.ErrNotFound) {
					t.Fatalf("Project: %v", err)
				}
			}
			if _, err := g.Project(context.Background(), "unknown"); !errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("an unknown name: %v", err)
			}
			if s := g.Skipped(); len(s) != 1 || !strings.Contains(s[0].Reason, c.reason) {
				t.Fatalf("skipped = %+v", s)
			}
		})
	}
}

// gitStdin runs git in dir with in on stdin and returns its trimmed output.
func gitStdin(t *testing.T, dir, in string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_GLOBAL=/dev/null")
	cmd.Stdin = strings.NewReader(in)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// tagTree tags a commit of tree in r as tag.
func tagTree(t *testing.T, r *repo, tree, tag string) {
	t.Helper()
	c := gitStdin(t, r.dir, "", "commit-tree", "-m", "x", tree)
	testutil.Git(t, r.dir, "update-ref", "refs/tags/"+tag, c)
}

func unhex(s string) string {
	b, _ := hex.DecodeString(s)
	return string(b)
}

// TestMalformedTreePaths: trees that fsck would reject (an entry named
// "/x" or "..") end in a refusal or are ignored; they neither hang a pass,
// leave a tag unread forever nor reach an sdist.
func TestMalformedTreePaths(t *testing.T) {
	t.Run("leading slash", func(t *testing.T) {
		r := newRepo(t)
		r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
		blob := gitStdin(t, r.dir, "hi\n", "hash-object", "-w", "--stdin")
		root := testutil.Git(t, r.dir, "rev-parse", "HEAD:pyproject.toml")
		raw := "100644 /x\x00" + unhex(blob) + "100644 pyproject.toml\x00" + unhex(root)
		tagTree(t, r, gitStdin(t, r.dir, raw, "hash-object", "-t", "tree", "-w", "--stdin", "--literally"), "v1")
		g := newGitEnv(t).source(t, nil, r.dir)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- g.Index(ctx) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Index: %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("Index still running 10s after its context expired")
		}
		assertRefused(t, g, "acme-core", "invalid path")
	})
	t.Run("dot-dot member", func(t *testing.T) {
		r := newRepo(t)
		r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
		sub := gitStdin(t, r.dir, "100644 blob "+testutil.Git(t, r.dir, "rev-parse", "HEAD:pyproject.toml")+"\tpyproject.toml\n", "mktree")
		rootBlob := gitStdin(t, r.dir, "[tool.uv.workspace]\nmembers = [\"*\"]\n", "hash-object", "-w", "--stdin")
		tagTree(t, r, gitStdin(t, r.dir, fmt.Sprintf("040000 tree %s\t..\n100644 blob %s\tpyproject.toml\n", sub, rootBlob), "mktree"), "bad")
		g := newGitEnv(t).source(t, nil, r.dir)
		index(t, g)
		if _, err := g.Project(context.Background(), "unknown"); !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("the source never completes: %v", err)
		}
	})
	t.Run("dot-dot in a root package", func(t *testing.T) {
		r := newRepo(t)
		r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
		evil := gitStdin(t, r.dir, "pwned\n", "hash-object", "-w", "--stdin")
		sub := gitStdin(t, r.dir, "100644 blob "+evil+"\t.bashrc\n", "mktree")
		root := testutil.Git(t, r.dir, "rev-parse", "HEAD:pyproject.toml")
		tagTree(t, r, gitStdin(t, r.dir, fmt.Sprintf("040000 tree %s\t..\n100644 blob %s\tpyproject.toml\n", sub, root), "mktree"), "v1")
		g := newGitEnv(t).source(t, nil, r.dir)
		index(t, g)
		assertRefused(t, g, "acme-core", "invalid path")
	})
}

// assertRefused checks that pkg is not served, a skip names reason, no
// release is stored and the index is complete.
func assertRefused(t *testing.T, g *GitSource, pkg, reason string) {
	t.Helper()
	if _, err := g.Project(context.Background(), pkg); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("%s: %v", pkg, err)
	}
	if !slices.ContainsFunc(g.Skipped(), func(s Skipped) bool { return strings.Contains(s.Reason, reason) }) {
		t.Fatalf("skipped = %+v", g.Skipped())
	}
	if n := releaseRecords(t, g.state); n != 0 {
		t.Fatalf("%d releases stored", n)
	}
	if _, err := g.Project(context.Background(), "unknown"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("index incomplete: %v", err)
	}
}

// TestRefusedEarliestTagRefusesTheVersion: the earliest tag of a version
// decides; when its content is refused, a later tag does not stand in.
func TestRefusedEarliestTagRefusesTheVersion(t *testing.T) {
	r := newRepo(t)
	if err := os.Symlink("docs/README.md", filepath.Join(r.dir, "README.md")); err != nil {
		t.Fatal(err)
	}
	withReadme := strings.Replace(pyproject("acme-core", "1.0.0"), "[project]\n", "[project]\nreadme = \"README.md\"\n", 1)
	r.write(map[string]string{"pyproject.toml": withReadme, "docs/README.md": "# Acme\n"})
	r.tag("v1")
	if err := os.Remove(filepath.Join(r.dir, "README.md")); err != nil {
		t.Fatal(err)
	}
	r.write(map[string]string{"README.md": "# Acme\n"})
	r.tag("v1-fixed")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	assertRefused(t, g, "acme-core", "regular file")
}

// TestAncestryErrorIsPending: when ancestry cannot be decided, the version
// is unavailable for the pass rather than reported as divergent or built.
func TestAncestryErrorIsPending(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0"), "a.py": "first"})
	r.tag("v1")
	between := r.write(map[string]string{"a.py": "between"})
	r.write(map[string]string{"a.py": "second"})
	r.tag("v2")
	m := mirrorWithout(t, r, between)
	env := newGitEnv(t)
	g, err := NewGitSource("git", []string{"*"}, []*gitmirror.Mirror{m}, nil, env.state, env.rec, 0, nil, MaxGitSdistBytes)
	if err != nil {
		t.Fatal(err)
	}
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if c := g.Conflicts(); len(c) != 0 {
		t.Fatalf("conflicts = %+v", c)
	}
	if n := releaseRecords(t, env.state); n != 0 {
		t.Fatalf("%d releases stored", n)
	}
}

// TestUnreadableAttributes: a .gitattributes that cannot be read leaves the
// tag unread (nothing is built); one over 1MiB is refused.
func TestUnreadableAttributes(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{".gitattributes": "*.bin filter=lfs\n", "pyproject.toml": pyproject("acme-core", "1.0.0")})
	r.tag("v1")
	m := mirrorWithout(t, r, testutil.Git(t, r.dir, "rev-parse", "v1:.gitattributes"))
	env := newGitEnv(t)
	g, err := NewGitSource("git", []string{"*"}, []*gitmirror.Mirror{m}, nil, env.state, env.rec, 0, nil, MaxGitSdistBytes)
	if err != nil {
		t.Fatal(err)
	}
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unreadable attributes: %v", err)
	}
	if n := releaseRecords(t, env.state); n != 0 {
		t.Fatalf("%d releases stored", n)
	}

	big := newRepo(t)
	big.write(map[string]string{".gitattributes": "#" + strings.Repeat("x", 1<<20) + "\n", "pyproject.toml": pyproject("acme-core", "1.0.0")})
	big.tag("v1")
	g2 := newGitEnv(t).source(t, nil, big.dir)
	index(t, g2)
	assertRefused(t, g2, "acme-core", ".gitattributes")
}

// TestMissingObjectIsUnread: a file the tree lists but the mirror lacks is a
// broken mirror, not missing content: the tag is unread, nothing is refused.
func TestMissingObjectIsUnread(t *testing.T) {
	for _, c := range []struct{ name, file string }{
		{"pyproject.toml", "pyproject.toml"},
		{"readme", "README.md"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRepo(t)
			r.write(map[string]string{
				"pyproject.toml": strings.Replace(pyproject("acme-core", "1.0.0"), "[project]\n", "[project]\nreadme = \"README.md\"\n", 1),
				"README.md":      "# Acme\n",
			})
			r.tag("v1")
			m := mirrorWithout(t, r, testutil.Git(t, r.dir, "rev-parse", "v1:"+c.file))
			env := newGitEnv(t)
			g, err := NewGitSource("git", []string{"*"}, []*gitmirror.Mirror{m}, nil, env.state, env.rec, 0, nil, MaxGitSdistBytes)
			if err != nil {
				t.Fatal(err)
			}
			index(t, g)
			if _, err := g.Project(context.Background(), "acme-core"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("err = %v", err)
			}
			if s := g.Skipped(); len(s) != 0 {
				t.Fatalf("refused: %+v", s)
			}
		})
	}
}

// TestRefusedElsewhereDoesNotWithhold: a refused copy of a name in another
// repository does not take down the name the first one serves.
func TestRefusedElsewhereDoesNotWithhold(t *testing.T) {
	a, b := newRepo(t), newRepo(t)
	a.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	a.tag("v1")
	b.write(map[string]string{"pyproject.toml": strings.Replace(pyproject("acme-core", "9.0.0"), "[project]\n", "[project]\nreadme = \"MISSING.md\"\n", 1)})
	b.tag("v9")
	g := newGitEnv(t).source(t, nil, a.dir, b.dir)
	index(t, g)
	if got := versionsOf(t, g, "acme-core"); len(got) != 1 {
		t.Fatalf("files = %v", got)
	}
	if c := g.Conflicts(); len(c) != 0 {
		t.Fatalf("conflicts = %+v", c)
	}
	if s := g.Skipped(); len(s) != 1 || !strings.Contains(s[0].Reason, "does not exist") {
		t.Fatalf("skipped = %+v", s)
	}
}

// TestBuildRefusalCached: a release refused at build time is not built again
// on later passes.
func TestBuildRefusalCached(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-big", "1.0.0"), "blob.bin": strings.Repeat("x", 64<<10)})
	r.tag("v1")
	m, err := gitmirror.New(gitmirror.Options{Remote: r.dir, BaseDir: t.TempDir(), AllowFileRemotesForTesting: true})
	if err != nil {
		t.Fatal(err)
	}
	env := newGitEnv(t)
	g, err := NewGitSource("git", []string{"*"}, []*gitmirror.Mirror{m}, nil, env.state, env.rec, 0, nil, 16<<10)
	if err != nil {
		t.Fatal(err)
	}
	index(t, g)
	// A build now fails on the missing blob instead of being refused.
	dropObject(t, m, testutil.Git(t, r.dir, "rev-parse", "v1:blob.bin"))
	if err := os.Rename(r.dir, r.dir+"-gone"); err != nil {
		t.Fatal(err)
	}
	index(t, g)
	if _, err := g.Project(context.Background(), "acme-big"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("built again: %v", err)
	}
	if s := g.Skipped(); len(s) != 1 || !strings.Contains(s[0].Reason, "larger than") {
		t.Fatalf("skipped = %+v", s)
	}
}

// bombTree returns a tree of fan^depth leaf directories, each holding leaf
// (name → blob), from depth+1 tree objects.
func bombTree(t *testing.T, r *repo, fan, depth int, leaf map[string]string) string {
	t.Helper()
	var sb strings.Builder
	for name, blob := range leaf {
		fmt.Fprintf(&sb, "100644 blob %s\t%s\n", blob, name)
	}
	cur := gitStdin(t, r.dir, sb.String(), "mktree")
	for range depth {
		sb.Reset()
		for i := range fan {
			fmt.Fprintf(&sb, "040000 tree %s\td%02d\n", cur, i)
		}
		cur = gitStdin(t, r.dir, sb.String(), "mktree")
	}
	return cur
}

// TestTreeBombsRefused: a tree with more entries than the cap, or more
// pyproject.toml files than packages are looked at, is refused once and
// cached, without being read whole.
func TestTreeBombsRefused(t *testing.T) {
	for _, c := range []struct {
		name, reason string
		root         string
		fan, depth   int
		leaf         func(r *repo) map[string]string
	}{
		{"entries", "entries", pyproject("acme-core", "1.0.0"), 16, 5,
			func(r *repo) map[string]string {
				return map[string]string{"f": gitStdin(t, r.dir, "x\n", "hash-object", "-w", "--stdin")}
			}},
		{"packages", "pyproject.toml", "[tool.uv.workspace]\nmembers = [\"bomb/*/*/*\"]\n", 16, 3,
			func(r *repo) map[string]string {
				return map[string]string{"pyproject.toml": gitStdin(t, r.dir, pyproject("acme-m", "1.0.0"), "hash-object", "-w", "--stdin")}
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRepo(t)
			r.write(map[string]string{"pyproject.toml": c.root})
			bomb := bombTree(t, r, c.fan, c.depth, c.leaf(r))
			root := testutil.Git(t, r.dir, "rev-parse", "HEAD:pyproject.toml")
			tagTree(t, r, gitStdin(t, r.dir, fmt.Sprintf("040000 tree %s\tbomb\n100644 blob %s\tpyproject.toml\n", bomb, root), "mktree"), "v1")
			g := newGitEnv(t).source(t, nil, r.dir)
			start := time.Now()
			index(t, g)
			index(t, g)
			if d := time.Since(start); d > 20*time.Second {
				t.Errorf("two passes took %v", d)
			}
			if s := g.Skipped(); len(s) != 1 || !strings.Contains(s[0].Reason, c.reason) {
				t.Fatalf("skipped = %+v", s)
			}
			if _, err := g.Project(context.Background(), "unknown"); !errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("index incomplete: %v", err)
			}
		})
	}
}

// TestCarriageReturnPathRefused: git's batch input drops a trailing "\r",
// so such a path is refused instead of being looked up as another one; the
// source completes and other remotes' packages stay served.
func TestCarriageReturnPathRefused(t *testing.T) {
	a := newRepo(t)
	a.write(map[string]string{"pyproject.toml": pyproject("acme-good", "1.0.0")})
	a.tag("v1")
	b := newRepo(t)
	b.write(map[string]string{
		"pyproject.toml": strings.Replace(pyproject("acme-cr", "1.0.0"), "[project]\n", "[project]\nreadme = \"README\\r\"\n", 1),
		"README\r":       "x",
	})
	b.tag("v1")
	g := newGitEnv(t).source(t, nil, a.dir, b.dir)
	index(t, g)
	if got := versionsOf(t, g, "acme-good"); len(got) != 1 {
		t.Fatalf("acme-good = %v", got)
	}
	if _, err := g.Project(context.Background(), "acme-cr"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("acme-cr: %v", err)
	}
	if !slices.ContainsFunc(g.Skipped(), func(s Skipped) bool { return strings.Contains(s.Reason, "carriage return") }) {
		t.Fatalf("skipped = %+v", g.Skipped())
	}
	if _, err := g.Project(context.Background(), "unknown"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("index incomplete: %v", err)
	}
}

// TestLongTreePathRefused: a path over 1MiB refuses its commit instead of
// leaving the tag unread on every pass.
func TestLongTreePathRefused(t *testing.T) {
	a := newRepo(t)
	a.write(map[string]string{"pyproject.toml": pyproject("acme-good", "1.0.0")})
	a.tag("v1")
	b := newRepo(t)
	b.write(map[string]string{"pyproject.toml": pyproject("acme-other", "1.0.0")})
	blob := gitStdin(t, b.dir, "x\n", "hash-object", "-w", "--stdin")
	root := testutil.Git(t, b.dir, "rev-parse", "HEAD:pyproject.toml")
	tagTree(t, b, gitStdin(t, b.dir, "100644 blob "+root+"\tpyproject.toml\n100644 blob "+blob+"\t"+strings.Repeat("n", 1100000)+"\n", "mktree"), "v2")
	g := newGitEnv(t).source(t, nil, a.dir, b.dir)
	index(t, g)
	if got := versionsOf(t, g, "acme-good"); len(got) != 1 {
		t.Fatalf("acme-good = %v", got)
	}
	if !slices.ContainsFunc(g.Skipped(), func(s Skipped) bool { return strings.Contains(s.Reason, "too large") }) {
		t.Fatalf("skipped = %+v", g.Skipped())
	}
	if _, err := g.Project(context.Background(), "unknown"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("index incomplete: %v", err)
	}
}

// TestUnreadPyprojectsNotCounted: pyproject.toml files discovery never reads
// (no workspace member matches them) do not count towards the cap.
func TestUnreadPyprojectsNotCounted(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
	leaf := map[string]string{"pyproject.toml": gitStdin(t, r.dir, pyproject("acme-m", "1.0.0"), "hash-object", "-w", "--stdin")}
	bomb := bombTree(t, r, 16, 3, leaf)
	root := testutil.Git(t, r.dir, "rev-parse", "HEAD:pyproject.toml")
	tagTree(t, r, gitStdin(t, r.dir, fmt.Sprintf("040000 tree %s\tvendor\n100644 blob %s\tpyproject.toml\n", bomb, root), "mktree"), "v1")
	g := newGitEnv(t).source(t, nil, r.dir)
	index(t, g)
	if got := versionsOf(t, g, "acme-core"); len(got) != 1 {
		t.Fatalf("acme-core = %v (skipped %+v)", got, g.Skipped())
	}
}

// TestBadCommitTimeRefused: a committer time no int64 holds, or one past
// the year 9999 (no RFC 3339 time for the release record), is the commit's
// content, so the release is refused, not retried.
func TestBadCommitTimeRefused(t *testing.T) {
	for _, when := range []string{"99999999999999999999999", "999999999999"} {
		t.Run(when, func(t *testing.T) {
			r := newRepo(t)
			r.write(map[string]string{"pyproject.toml": pyproject("acme-core", "1.0.0")})
			tree := testutil.Git(t, r.dir, "rev-parse", "HEAD^{tree}")
			raw := "tree " + tree + "\nauthor T <t@e> 1 +0000\ncommitter T <t@e> " + when + " +0000\n\nx\n"
			c := gitStdin(t, r.dir, raw, "hash-object", "-t", "commit", "-w", "--stdin", "--literally")
			testutil.Git(t, r.dir, "update-ref", "refs/tags/v1", c)
			g := newGitEnv(t).source(t, nil, r.dir)
			index(t, g)
			assertRefused(t, g, "acme-core", "commit time")
		})
	}
}
