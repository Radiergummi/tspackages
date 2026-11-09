package composer

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/pins"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// gitRepo builds a work tree whose main branch holds composer.json for name.
func gitRepo(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	commitFile(t, dir, "composer.json", `{"name":"`+name+`","description":"d","scripts":{"x":"y"},"dist":{"url":"evil"}}`, "one")
	return dir
}

func commitFile(t *testing.T, dir, file, content, msg string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", msg)
	return runGit(t, dir, "rev-parse", "HEAD")
}

func newGit(t *testing.T, d storage.Driver, branches []string, remotes ...string) (*GitSource, *pins.Store) {
	t.Helper()
	var ms []*gitmirror.Mirror
	base := t.TempDir()
	for _, r := range remotes {
		m, err := gitmirror.New(gitmirror.Options{Remote: r, BaseDir: base, AllowFileRemotesForTesting: true})
		if err != nil {
			t.Fatal(err)
		}
		ms = append(ms, m)
	}
	ps := pins.New(d)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return NewGitSource("git", []string{"matchory/*"}, branches, ms, ps, records.New(d), d, time.Minute, log, 64<<20), ps
}

func fsState(t *testing.T) storage.Driver {
	t.Helper()
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func versionNames(vs []Version) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.Version)
	}
	slices.Sort(out)
	return out
}

func TestIndexTagsAndDefaultBranch(t *testing.T) {
	src := gitRepo(t, "Matchory/A")
	runGit(t, src, "tag", "v1.0.0")
	runGit(t, src, "tag", "latest")
	runGit(t, src, "branch", "feature/x")
	g, _ := newGit(t, fsState(t), nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	vs, err := g.Versions(context.Background(), "matchory/a")
	if err != nil {
		t.Fatal(err)
	}
	if got := versionNames(vs); !slices.Equal(got, []string{"dev-main", "v1.0.0"}) {
		t.Fatalf("versions = %v", got)
	}
	for _, v := range vs {
		if v.Dev != (v.Version == "dev-main") {
			t.Errorf("%s: Dev = %v", v.Version, v.Dev)
		}
		p := v.Package
		if p["name"] != "matchory/a" || p["description"] != "d" || p["scripts"] != nil {
			t.Errorf("package fields: %v", p)
		}
		dist := p["dist"].(map[string]any)
		if dist["type"] != "zip" || dist["reference"] != v.Reference || dist["shasum"] == "" || dist["url"] != nil || p["source"] != nil {
			t.Errorf("dist: %v", dist)
		}
	}
	names, enum, err := g.Packages(context.Background())
	if err != nil || !enum || !slices.Equal(names, []string{"matchory/a"}) {
		t.Fatalf("Packages = %v %v %v", names, enum, err)
	}
}

func TestBranchAllowlist(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "branch", "release/1")
	runGit(t, src, "branch", "other")
	g, _ := newGit(t, fsState(t), []string{"release/*"}, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	vs, _ := g.Versions(context.Background(), "matchory/a")
	if got := versionNames(vs); !slices.Equal(got, []string{"dev-release/1"}) {
		t.Fatalf("versions = %v", got)
	}
}

func TestTagPinnedAfterForcePush(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	old := runGit(t, src, "rev-parse", "HEAD")
	runGit(t, src, "tag", "v1.0.0")
	g, ps := newGit(t, fsState(t), nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	commitFile(t, src, "a.txt", "x", "two")
	runGit(t, src, "tag", "-f", "v1.0.0")
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	vs, _ := g.Versions(ctx, "matchory/a")
	for _, v := range vs {
		if v.Version == "v1.0.0" && v.Reference != old {
			t.Fatalf("reference = %s, want %s", v.Reference, old)
		}
	}
	if len(ps.Moved()) != 1 {
		t.Fatalf("moved = %v", ps.Moved())
	}
	if _, err := g.Dist(ctx, "matchory/a", "v1.0.0", old); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveStableAcrossRebuilds(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	d := fsState(t)
	shasum := func() string {
		g, _ := newGit(t, d, nil, src)
		if err := g.Index(context.Background()); err != nil {
			t.Fatal(err)
		}
		vs, _ := g.Versions(context.Background(), "matchory/a")
		for _, v := range vs {
			if v.Version == "v1.0.0" {
				return v.Package["dist"].(map[string]any)["shasum"].(string)
			}
		}
		t.Fatal("no v1.0.0")
		return ""
	}
	a := shasum()
	b := shasum()
	if a == "" || a != b {
		t.Fatalf("shasum changed: %q vs %q", a, b)
	}
	commit := runGit(t, src, "rev-parse", "HEAD")
	if _, err := d.Stat(context.Background(), "composer-git/git/"+commit+".zip"); err != nil {
		t.Fatalf("archive not in state store: %v", err)
	}
}

func TestProvenanceRecorded(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	d := fsState(t)
	g, _ := newGit(t, d, nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	vs, _ := g.Versions(context.Background(), "matchory/a")
	var v Version
	for _, x := range vs {
		if x.Version == "v1.0.0" {
			v = x
		}
	}
	art, err := g.Dist(context.Background(), "matchory/a", "v1.0.0", v.Reference)
	if err != nil {
		t.Fatal(err)
	}
	art.Body.Close()
	if art.SHA1 != v.Package["dist"].(map[string]any)["shasum"] || art.Size == 0 {
		t.Fatalf("artifact = %+v", art)
	}
	var found bool
	for info, err := range d.List(context.Background(), "provenance/composer/") {
		if err != nil {
			t.Fatal(err)
		}
		found = found || strings.HasSuffix(info.Key, ".json")
	}
	if !found {
		t.Fatal("no provenance record")
	}
}

func TestDuplicatePackageName(t *testing.T) {
	a := gitRepo(t, "matchory/a")
	b := gitRepo(t, "matchory/a")
	c := gitRepo(t, "matchory/c")
	g, _ := newGit(t, fsState(t), nil, a, b, c)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Versions(context.Background(), "matchory/a"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := g.Versions(context.Background(), "matchory/c"); err != nil {
		t.Fatal(err)
	}
	cs := g.Conflicts()
	if len(cs) != 1 || cs[0].Package != "matchory/a" || len(cs[0].Remotes) != 2 {
		t.Fatalf("conflicts = %+v", cs)
	}
}

func TestTagWithMismatchedName(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	commitFile(t, src, "composer.json", `{"name":"matchory/other"}`, "rename")
	runGit(t, src, "tag", "v2.0.0")
	commitFile(t, src, "composer.json", `{"name":"matchory/a"}`, "back")
	g, _ := newGit(t, fsState(t), nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	vs, _ := g.Versions(context.Background(), "matchory/a")
	if got := versionNames(vs); !slices.Equal(got, []string{"dev-main", "v1.0.0"}) {
		t.Fatalf("versions = %v", got)
	}
}

func TestDistUnknownReference(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	g, _ := newGit(t, fsState(t), nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	vs, _ := g.Versions(ctx, "matchory/a")
	good := vs[0].Reference
	for _, tc := range []struct{ name, version, ref string }{
		{"matchory/a", "v1.0.0", strings.Repeat("a", 40)},
		{"matchory/a", "v9.9.9", good},
		{"matchory/zzz", "v1.0.0", good},
		{"matchory/a", "v1.0.0", "../../x"},
	} {
		if _, err := g.Dist(ctx, tc.name, tc.version, tc.ref); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("%+v: err = %v", tc, err)
		}
	}
}

func TestOversizeArchiveSkipped(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	g, _ := newGit(t, fsState(t), nil, src)
	g.maxArchive = 10
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Versions(context.Background(), "matchory/a"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	g, _ := newGit(t, fsState(t), nil, src)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := g.Versions(ctx, "matchory/a"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first pass never ran")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
