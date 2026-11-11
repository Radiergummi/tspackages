package pypi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/radiergummi/tspackages/internal/gitmirror"
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
	if got := versionsOf(t, g, "acme-core"); len(got) != 1 {
		t.Fatalf("core = %v", got)
	}
	if _, err := g.Project(context.Background(), "acme-api"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("a name of the unindexed remote: %v", err)
	}
	if err := os.MkdirAll(missing, 0o755); err != nil {
		t.Fatal(err)
	}
	b := &repo{t: t, dir: missing}
	testutil.Git(t, b.dir, "init", "-q")
	b.write(map[string]string{"pyproject.toml": pyproject("acme-api", "1.0.0")})
	b.tag("v1")
	index(t, g)
	if got := versionsOf(t, g, "acme-api"); len(got) != 1 {
		t.Fatalf("api = %v", got)
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
	m, err := gitmirror.New(gitmirror.Options{Remote: r.dir, BaseDir: t.TempDir(), AllowFileRemotesForTesting: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Lose the tagged commit's tree from the mirror: the tag lists, its
	// tree does not read.
	tree := testutil.Git(t, r.dir, "rev-parse", "v1^{tree}")
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
	if err := os.Remove(filepath.Join(m.Dir(), "objects", tree[:2], tree[2:])); err != nil {
		t.Fatal(err)
	}
	// The remote is gone too, so the pass indexes the local mirror.
	if err := os.Rename(r.dir, r.dir+"-gone"); err != nil {
		t.Fatal(err)
	}
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
