package composer

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
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
	return newGitIn(t, t.TempDir(), d, branches, remotes...)
}

func newGitIn(t *testing.T, base string, d storage.Driver, branches []string, remotes ...string) (*GitSource, *pins.Store) {
	t.Helper()
	var ms []*gitmirror.Mirror
	for _, r := range remotes {
		m, err := gitmirror.New(gitmirror.Options{Remote: r, BaseDir: base, AllowFileRemotesForTesting: true})
		if err != nil {
			t.Fatal(err)
		}
		ms = append(ms, m)
	}
	ps := pins.New(d)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	g, err := NewGitSource("git", []string{"matchory/*"}, branches, ms, ps, records.New(d), d, time.Minute, log, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	return g, ps
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
	var seen bool
	for _, v := range vs {
		if v.Version == "v1.0.0" {
			seen = true
			if v.Reference != old {
				t.Fatalf("reference = %s, want %s", v.Reference, old)
			}
		}
	}
	if !seen {
		t.Fatal("v1.0.0 not served")
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
	if _, err := g.Versions(context.Background(), "matchory/a"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := g.Dist(context.Background(), "matchory/a", "v1.0.0", strings.Repeat("a", 40)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Dist err = %v", err)
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

func versionsOf(t *testing.T, g *GitSource, name string) map[string]Version {
	t.Helper()
	vs, err := g.Versions(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Version{}
	for _, v := range vs {
		out[v.Version] = v
	}
	return out
}

func shasumOf(v Version) string { return v.Package["dist"].(map[string]any)["shasum"].(string) }

func TestDevLookingTagsSkipped(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	for _, tag := range []string{"dev-main", "master", "1.x-dev", "1.0.0-dev"} {
		runGit(t, src, "tag", tag)
	}
	g, _ := newGit(t, fsState(t), nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	vs, _ := g.Versions(context.Background(), "matchory/a")
	if len(vs) != 1 || vs[0].Version != "dev-main" || !vs[0].Dev {
		t.Fatalf("versions = %+v", versionNames(vs))
	}
}

func TestTransientFailureKeepsPreviousIndex(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	g, _ := newGit(t, fsState(t), nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	commitFile(t, src, "composer.json", `{broken`, "break")
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if got := versionNames(mapVals(versionsOf(t, g, "matchory/a"))); !slices.Equal(got, []string{"dev-main", "v1.0.0"}) {
		t.Fatalf("versions = %v", got)
	}
}

func mapVals(m map[string]Version) []Version {
	var out []Version
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestConflictStaysWithheldWhenOneSideFails(t *testing.T) {
	a := gitRepo(t, "matchory/a")
	b := gitRepo(t, "matchory/a")
	g, _ := newGit(t, fsState(t), nil, a, b)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	commitFile(t, b, "composer.json", `{broken`, "break")
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Versions(ctx, "matchory/a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if len(g.Conflicts()) != 1 {
		t.Fatalf("conflicts = %+v", g.Conflicts())
	}
}

func TestUnavailableBeforeFirstPassAndForNeverIndexedRemote(t *testing.T) {
	good := gitRepo(t, "matchory/a")
	bad := gitRepo(t, "matchory/b")
	commitFile(t, bad, "composer.json", `{broken`, "break")
	g, _ := newGit(t, fsState(t), nil, good, bad)
	ctx := context.Background()
	if _, err := g.Versions(ctx, "matchory/a"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("before first pass: %v", err)
	}
	if _, err := g.Dist(ctx, "matchory/a", "v1.0.0", strings.Repeat("a", 40)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Dist before first pass: %v", err)
	}
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Versions(ctx, "matchory/a"); err != nil {
		t.Fatalf("healthy remote: %v", err)
	}
	if _, err := g.Versions(ctx, "matchory/b"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("never-indexed remote: %v", err)
	}
	if _, err := g.Versions(ctx, "other/x"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("unclaimed name: %v", err)
	}
}

func TestServedVersionSurvivesMirrorAndTagLoss(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	d := fsState(t)
	g, _ := newGit(t, d, nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	before := versionsOf(t, g, "matchory/a")["v1.0.0"]

	runGit(t, src, "tag", "-d", "v1.0.0")
	g2, _ := newGit(t, d, nil, src) // fresh mirror directory, tag gone upstream
	if err := g2.Index(ctx); err != nil {
		t.Fatal(err)
	}
	after, ok := versionsOf(t, g2, "matchory/a")["v1.0.0"]
	if !ok || shasumOf(after) != shasumOf(before) || after.Reference != before.Reference {
		t.Fatalf("after = %+v", after)
	}
	art, err := g2.Dist(ctx, "matchory/a", "v1.0.0", after.Reference)
	if err != nil {
		t.Fatal(err)
	}
	art.Body.Close()
}

func TestServedVersionSurvivesMissingCommit(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	d := fsState(t)
	g, _ := newGit(t, d, nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := versionsOf(t, g, "matchory/a")["v1.0.0"]
	// Rewrite history so the pinned commit is gone from the remote entirely.
	runGit(t, src, "tag", "-d", "v1.0.0")
	runGit(t, src, "commit", "-q", "--amend", "-m", "rewritten")
	g2, _ := newGit(t, d, nil, src)
	if err := g2.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after := versionsOf(t, g2, "matchory/a")["v1.0.0"]; shasumOf(after) != shasumOf(before) {
		t.Fatalf("after = %+v", after)
	}
}

func TestStoredArchiveIsReadBackNotRebuilt(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	root := t.TempDir()
	d, err := storage.NewFS(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	g, _ := newGit(t, d, nil, src)
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	v := versionsOf(t, g, "matchory/a")["v1.0.0"]
	zipK := "composer-git/git/" + v.Reference + ".zip"
	junk := []byte("not a zip, stored bytes are canonical")
	if _, err := d.Put(ctx, zipK, strings.NewReader(string(junk))); err != nil {
		t.Fatal(err)
	}

	// With the sidecar present, a new source trusts it and does not re-read the zip.
	g2, _ := newGit(t, d, nil, src)
	if err := g2.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if got := shasumOf(versionsOf(t, g2, "matchory/a")["v1.0.0"]); got != shasumOf(v) {
		t.Fatalf("sidecar shasum changed: %s vs %s", got, shasumOf(v))
	}

	// Without it, the digest comes from the stored bytes, not from a rebuild.
	if err := d.Delete(ctx, "composer-git/git/"+v.Reference+".meta.json"); err != nil {
		t.Fatal(err)
	}
	g3, _ := newGit(t, d, nil, src)
	if err := g3.Index(ctx); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha1.Sum(junk))
	v3 := versionsOf(t, g3, "matchory/a")["v1.0.0"]
	if shasumOf(v3) != want {
		t.Fatalf("shasum = %s, want sha1 of stored bytes %s", shasumOf(v3), want)
	}
	art, err := g3.Dist(ctx, "matchory/a", "v1.0.0", v3.Reference)
	if err != nil {
		t.Fatal(err)
	}
	defer art.Body.Close()
	body, _ := io.ReadAll(art.Body)
	if !bytes.Equal(body, junk) || art.SHA1 != want {
		t.Fatalf("Dist served %d bytes, sha1 %s", len(body), art.SHA1)
	}
}

func TestTagPinnedOnlyOnceValid(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	commitFile(t, src, "composer.json", `{broken`, "broken")
	runGit(t, src, "tag", "v1.0.0")
	fixed := commitFile(t, src, "composer.json", `{"name":"matchory/a"}`, "fixed")
	g, ps := newGit(t, fsState(t), nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := versionsOf(t, g, "matchory/a")["v1.0.0"]; ok {
		t.Fatal("broken tag served")
	}
	runGit(t, src, "tag", "-f", "v1.0.0")
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if v := versionsOf(t, g, "matchory/a")["v1.0.0"]; v.Reference != fixed {
		t.Fatalf("reference = %s, want %s", v.Reference, fixed)
	}
	if len(ps.Moved()) != 0 {
		t.Fatalf("moved = %v", ps.Moved())
	}
}

func TestClaimsFilterIndexedPackages(t *testing.T) {
	inside := gitRepo(t, "matchory/a")
	outside := gitRepo(t, "other/b")
	g, _ := newGit(t, fsState(t), nil, inside, outside)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	names, _, _ := g.Packages(context.Background())
	if !slices.Equal(names, []string{"matchory/a"}) {
		t.Fatalf("packages = %v", names)
	}
	if _, err := g.Versions(context.Background(), "other/b"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

// cancelOnPin cancels a context once the first pin is written.
type cancelOnPin struct {
	storage.Driver
	cancel context.CancelFunc
}

func (c *cancelOnPin) PutIfAbsent(ctx context.Context, key string, r io.Reader) (storage.Info, error) {
	info, err := c.Driver.PutIfAbsent(ctx, key, r)
	if c.cancel != nil && strings.HasPrefix(key, "pins/") {
		c.cancel()
	}
	return info, err
}

func TestCancelledPassDoesNotChangeIndex(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	d := &cancelOnPin{Driver: fsState(t)}
	g, _ := newGit(t, d, nil, src)
	var logs bytes.Buffer
	g.log = slog.New(slog.NewTextHandler(&logs, nil))
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	runGit(t, src, "tag", "v2.0.0") // first sight: pinned mid-pass, then the pass is cancelled
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	logs.Reset()
	if err := g.Index(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Index = %v", err)
	}
	if got := versionNames(mapVals(versionsOf(t, g, "matchory/a"))); !slices.Equal(got, []string{"dev-main", "v1.0.0"}) {
		t.Fatalf("versions = %v", got)
	}
	if strings.Contains(logs.String(), "skipped") || strings.Contains(logs.String(), "failed") {
		t.Fatalf("noise on cancel:\n%s", logs.String())
	}
}

func TestBeforeFirstPassIsUnavailable(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	g, _ := newGit(t, fsState(t), nil, src)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.Index(ctx); err == nil {
		t.Fatal("want ctx error")
	}
	if _, err := g.Versions(context.Background(), "matchory/a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnclaimedSourceNotFoundWhilePending(t *testing.T) {
	good := gitRepo(t, "matchory/a")
	bad := gitRepo(t, "matchory/b")
	commitFile(t, bad, "composer.json", `{broken`, "break")
	g, _ := newGit(t, fsState(t), nil, good, bad)
	g.claims = nil
	ctx := context.Background()
	if _, err := g.Versions(ctx, "any/thing"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("before first pass: %v", err)
	}
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Versions(ctx, "any/thing"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("pending remote: %v", err)
	}
	if _, err := g.Versions(ctx, "matchory/a"); err != nil {
		t.Fatal(err)
	}
}

func TestDistFaultsAreNotNotFound(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	d := fsState(t)
	g, _ := newGit(t, d, nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	ref := versionsOf(t, g, "matchory/a")["v1.0.0"].Reference
	zipK := "composer-git/git/" + ref + ".zip"

	if _, err := d.Put(ctx, zipK, strings.NewReader("short")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Dist(ctx, "matchory/a", "v1.0.0", ref); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("size mismatch: %v", err)
	}
	if err := d.Delete(ctx, zipK); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Dist(ctx, "matchory/a", "v1.0.0", ref); err == nil || errors.Is(err, resolve.ErrNotFound) || errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing zip: %v", err)
	}
}

func TestCorruptPinDoesNotFreezeRemote(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	runGit(t, src, "tag", "v1.0.0")
	runGit(t, src, "tag", "v1.1.0")
	d := fsState(t)
	g, _ := newGit(t, d, nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	key := "pins/composer/git/" + storage.EscapeSegment(src) + "/" + storage.EscapeSegment("v1.1.0") + ".json"
	if _, err := d.Put(context.Background(), key, strings.NewReader("{garbage")); err != nil {
		t.Fatal(err)
	}
	g2, _ := newGit(t, d, nil, src)
	var logs bytes.Buffer
	g2.log = slog.New(slog.NewTextHandler(&logs, nil))
	if err := g2.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := versionsOf(t, g2, "matchory/a")["v1.0.0"]; !ok {
		t.Fatal("v1.0.0 lost")
	}
	if !strings.Contains(logs.String(), "unreadable pin") {
		t.Fatalf("corrupt pin not logged:\n%s", logs.String())
	}
}

func TestNewGitSourceValidation(t *testing.T) {
	d := fsState(t)
	if _, err := NewGitSource("git", nil, []string{"[bad"}, nil, pins.New(d), records.New(d), d, time.Minute, slog.Default(), 1); err == nil {
		t.Fatal("bad branch pattern accepted")
	}
	g, err := NewGitSource("git", nil, nil, nil, pins.New(d), records.New(d), d, 0, slog.Default(), 1)
	if err != nil || g.poll != time.Minute {
		t.Fatalf("poll = %v, err = %v", g.poll, err)
	}
}
