package composer

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http/httptest"
	"os"
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
	"github.com/radiergummi/tspackages/internal/testutil"
)

// gitRepo builds a work tree whose main branch holds composer.json for name.
func gitRepo(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	testutil.Git(t, dir, "init", "-q")
	commitFile(t, dir, "composer.json", `{"name":"`+name+`","description":"d","scripts":{"x":"y"},"dist":{"url":"evil"}}`, "one")
	return dir
}

func commitFile(t *testing.T, dir, file, content, msg string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	testutil.Git(t, dir, "add", ".")
	testutil.Git(t, dir, "commit", "-q", "-m", msg)
	return testutil.Git(t, dir, "rev-parse", "HEAD")
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
	testutil.Git(t, src, "tag", "v1.0.0")
	testutil.Git(t, src, "tag", "latest")
	testutil.Git(t, src, "branch", "feature/x")
	g, _ := newGit(t, fsState(t), nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	vs, err := allVersions(context.Background(), g, "matchory/a")
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
}

func TestBranchAllowlist(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "branch", "release/1")
	testutil.Git(t, src, "branch", "other")
	g, _ := newGit(t, fsState(t), []string{"release/*"}, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	vs, _ := allVersions(context.Background(), g, "matchory/a")
	if got := versionNames(vs); !slices.Equal(got, []string{"dev-release/1"}) {
		t.Fatalf("versions = %v", got)
	}
}

func TestTagPinnedAfterForcePush(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	old := testutil.Git(t, src, "rev-parse", "HEAD")
	testutil.Git(t, src, "tag", "v1.0.0")
	g, ps := newGit(t, fsState(t), nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	commitFile(t, src, "a.txt", "x", "two")
	testutil.Git(t, src, "tag", "-f", "v1.0.0")
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	vs, _ := allVersions(ctx, g, "matchory/a")
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
	testutil.Git(t, src, "tag", "v1.0.0")
	d := fsState(t)
	shasum := func() string {
		g, _ := newGit(t, d, nil, src)
		if err := g.Index(context.Background()); err != nil {
			t.Fatal(err)
		}
		vs, _ := allVersions(context.Background(), g, "matchory/a")
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
	commit := testutil.Git(t, src, "rev-parse", "HEAD")
	if _, err := d.Stat(context.Background(), "composer-git/git/"+commit+".zip"); err != nil {
		t.Fatalf("archive not in state store: %v", err)
	}
}

func TestProvenanceRecorded(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	d := fsState(t)
	g, _ := newGit(t, d, nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	vs, _ := allVersions(context.Background(), g, "matchory/a")
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
	body, _ := io.ReadAll(art.Body)
	art.Body.Close()
	if fmt.Sprintf("%x", sha1.Sum(body)) != v.Package["dist"].(map[string]any)["shasum"] || art.Size != int64(len(body)) {
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
	if _, err := allVersions(context.Background(), g, "matchory/a"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := g.Dist(context.Background(), "matchory/a", "v1.0.0", strings.Repeat("a", 40)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Dist err = %v", err)
	}
	if _, err := allVersions(context.Background(), g, "matchory/c"); err != nil {
		t.Fatal(err)
	}
	cs := g.Conflicts()
	if len(cs) != 1 || cs[0].Package != "matchory/a" || len(cs[0].Remotes) != 2 {
		t.Fatalf("conflicts = %+v", cs)
	}
}

func TestTagWithMismatchedName(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	commitFile(t, src, "composer.json", `{"name":"matchory/other"}`, "rename")
	testutil.Git(t, src, "tag", "v2.0.0")
	commitFile(t, src, "composer.json", `{"name":"matchory/a"}`, "back")
	g, _ := newGit(t, fsState(t), nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	vs, _ := allVersions(context.Background(), g, "matchory/a")
	if got := versionNames(vs); !slices.Equal(got, []string{"dev-main", "v1.0.0"}) {
		t.Fatalf("versions = %v", got)
	}
}

func TestDistUnknownReference(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	g, _ := newGit(t, fsState(t), nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	vs, _ := allVersions(ctx, g, "matchory/a")
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
	testutil.Git(t, src, "tag", "v1.0.0")
	g, _ := newGit(t, fsState(t), nil, src)
	g.maxArchive = 10
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := allVersions(context.Background(), g, "matchory/a"); !errors.Is(err, resolve.ErrNotFound) {
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
		if _, err := allVersions(ctx, g, "matchory/a"); err == nil {
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

// allVersions returns the stable and then the dev versions of name.
func allVersions(ctx context.Context, g *GitSource, name string) ([]Version, error) {
	vs, err := g.Versions(ctx, name, false)
	if err != nil {
		return nil, err
	}
	dev, err := g.Versions(ctx, name, true)
	return append(vs, dev...), err
}

func mustVersions(t *testing.T, g *GitSource, name string) []Version {
	t.Helper()
	vs, err := allVersions(context.Background(), g, name)
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

// versionsOf is mustVersions by version string.
func versionsOf(t *testing.T, g *GitSource, name string) map[string]Version {
	t.Helper()
	out := map[string]Version{}
	for _, v := range mustVersions(t, g, name) {
		out[v.Version] = v
	}
	return out
}

func shasumOf(v Version) string { return v.Package["dist"].(map[string]any)["shasum"].(string) }

func TestDevLookingTagsSkipped(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	for _, tag := range []string{"dev-main", "master", "1.x-dev", "1.0.0-dev"} {
		testutil.Git(t, src, "tag", tag)
	}
	g, _ := newGit(t, fsState(t), nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	vs, _ := allVersions(context.Background(), g, "matchory/a")
	if len(vs) != 1 || vs[0].Version != "dev-main" || !vs[0].Dev {
		t.Fatalf("versions = %+v", versionNames(vs))
	}
}

func TestTransientFailureKeepsPreviousIndex(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	g, _ := newGit(t, fsState(t), nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	commitFile(t, src, "composer.json", `{broken`, "break")
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if got := versionNames(mustVersions(t, g, "matchory/a")); !slices.Equal(got, []string{"dev-main", "v1.0.0"}) {
		t.Fatalf("versions = %v", got)
	}
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
	if _, err := allVersions(ctx, g, "matchory/a"); !errors.Is(err, ErrUnavailable) {
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
	if _, err := allVersions(ctx, g, "matchory/a"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("before first pass: %v", err)
	}
	if _, err := g.Dist(ctx, "matchory/a", "v1.0.0", strings.Repeat("a", 40)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Dist before first pass: %v", err)
	}
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := allVersions(ctx, g, "matchory/a"); err != nil {
		t.Fatalf("healthy remote: %v", err)
	}
	if _, err := allVersions(ctx, g, "matchory/b"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("never-indexed remote: %v", err)
	}
	if _, err := allVersions(ctx, g, "other/x"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("unclaimed name: %v", err)
	}
}

func TestServedVersionSurvivesMirrorAndTagLoss(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	d := fsState(t)
	g, _ := newGit(t, d, nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	before := versionsOf(t, g, "matchory/a")["v1.0.0"]

	testutil.Git(t, src, "tag", "-d", "v1.0.0")
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
	testutil.Git(t, src, "tag", "v1.0.0")
	d := fsState(t)
	g, _ := newGit(t, d, nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := versionsOf(t, g, "matchory/a")["v1.0.0"]
	// Rewrite history so the pinned commit is gone from the remote entirely.
	testutil.Git(t, src, "tag", "-d", "v1.0.0")
	testutil.Git(t, src, "commit", "-q", "--amend", "-m", "rewritten")
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
	testutil.Git(t, src, "tag", "v1.0.0")
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
	if !bytes.Equal(body, junk) {
		t.Fatalf("Dist served %d bytes", len(body))
	}
}

func TestTagPinnedOnlyOnceValid(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	commitFile(t, src, "composer.json", `{broken`, "broken")
	testutil.Git(t, src, "tag", "v1.0.0")
	fixed := commitFile(t, src, "composer.json", `{"name":"matchory/a"}`, "fixed")
	g, ps := newGit(t, fsState(t), nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := versionsOf(t, g, "matchory/a")["v1.0.0"]; ok {
		t.Fatal("broken tag served")
	}
	testutil.Git(t, src, "tag", "-f", "v1.0.0")
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
	if _, err := g.Versions(context.Background(), "matchory/a", false); err != nil {
		t.Fatal(err)
	}
	if _, err := allVersions(context.Background(), g, "other/b"); !errors.Is(err, resolve.ErrNotFound) {
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
	testutil.Git(t, src, "tag", "v1.0.0")
	d := &cancelOnPin{Driver: fsState(t)}
	g, _ := newGit(t, d, nil, src)
	var logs bytes.Buffer
	g.log = slog.New(slog.NewTextHandler(&logs, nil))
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	testutil.Git(t, src, "tag", "v2.0.0") // first sight: pinned mid-pass, then the pass is cancelled
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	logs.Reset()
	if err := g.Index(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Index = %v", err)
	}
	if got := versionNames(mustVersions(t, g, "matchory/a")); !slices.Equal(got, []string{"dev-main", "v1.0.0"}) {
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
	if _, err := allVersions(context.Background(), g, "matchory/a"); !errors.Is(err, ErrUnavailable) {
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
	if _, err := allVersions(ctx, g, "any/thing"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("before first pass: %v", err)
	}
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := allVersions(ctx, g, "any/thing"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("pending remote: %v", err)
	}
	if _, err := allVersions(ctx, g, "matchory/a"); err != nil {
		t.Fatal(err)
	}
}

func TestDistFaultsAreNotNotFound(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
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
	testutil.Git(t, src, "tag", "v1.0.0")
	testutil.Git(t, src, "tag", "v1.1.0")
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

// Dist checks the size recorded at indexing, not the sidecar; a missing zip
// of an indexed version is a source fault, never a not-found.
func TestDistMissingArchiveIsNotNotFound(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	d := fsState(t)
	g, _ := newGit(t, d, nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	ref := versionsOf(t, g, "matchory/a")["v1.0.0"].Reference
	if err := d.Delete(ctx, "composer-git/git/"+ref+".meta.json"); err != nil {
		t.Fatal(err)
	}
	a, err := g.Dist(ctx, "matchory/a", "v1.0.0", ref)
	if err != nil {
		t.Fatalf("without sidecar: %v", err)
	}
	a.Body.Close()
	if err := d.Delete(ctx, "composer-git/git/"+ref+".zip"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Dist(ctx, "matchory/a", "v1.0.0", ref); err == nil || errors.Is(err, resolve.ErrNotFound) || errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

// racePin makes another "instance" pin the first tag before this one can.
type racePin struct {
	storage.Driver
	done bool
}

func (r *racePin) PutIfAbsent(ctx context.Context, key string, body io.Reader) (storage.Info, error) {
	if !r.done && strings.HasPrefix(key, "pins/") {
		r.done = true
		other := `{"tag":"v1.0.0","sha":"` + strings.Repeat("b", 40) + `","first_seen":"2026-01-01T00:00:00Z"}`
		if _, err := r.Put(ctx, key, strings.NewReader(other)); err != nil {
			return storage.Info{}, err
		}
	}
	return r.Driver.PutIfAbsent(ctx, key, body)
}

func TestFirstSightPinLostRaceLogsMove(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	g, ps := newGit(t, &racePin{Driver: fsState(t)}, nil, src)
	var logs bytes.Buffer
	g.log = slog.New(slog.NewTextHandler(&logs, nil))
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "tag moved upstream") || len(ps.Moved()) != 1 {
		t.Fatalf("moved = %v, logs:\n%s", ps.Moved(), logs.String())
	}
}

// allVersions is the stable versions of name followed by its dev versions.
func TestVersionsSplitByDevAndDefaultBranchFlag(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	testutil.Git(t, src, "branch", "feature")
	g, _ := newGit(t, fsState(t), []string{"main", "feature"}, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	stable, err := g.Versions(ctx, "matchory/a", false)
	if err != nil || !slices.Equal(versionNames(stable), []string{"v1.0.0"}) {
		t.Fatalf("stable = %v, %v", versionNames(stable), err)
	}
	if _, ok := stable[0].Package["default-branch"]; ok {
		t.Error("tag carries default-branch")
	}
	dev, err := g.Versions(ctx, "matchory/a", true)
	if err != nil || !slices.Equal(versionNames(dev), []string{"dev-feature", "dev-main"}) {
		t.Fatalf("dev = %v, %v", versionNames(dev), err)
	}
	for _, v := range dev {
		db, ok := v.Package["default-branch"]
		if (v.Version == "dev-main") != ok || (ok && db != true) {
			t.Errorf("%s: default-branch = %v (%v)", v.Version, db, ok)
		}
	}
}

// moveAway makes a local remote unreachable without changing its URL.
func moveAway(t *testing.T, dir string) {
	t.Helper()
	if err := os.Rename(dir, dir+".gone"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir + ".gone") })
}

func TestServedVersionsSurviveUnreachableRemoteAtStartup(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	base, d := t.TempDir(), fsState(t)
	g1, _ := newGitIn(t, base, d, nil, src)
	ctx := context.Background()
	if err := g1.Index(ctx); err != nil {
		t.Fatal(err)
	}
	moveAway(t, src)

	// The local mirror survives: index from it, dev branch included.
	g2, _ := newGitIn(t, base, d, nil, src)
	if err := g2.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if got := versionNames(mustVersions(t, g2, "matchory/a")); !slices.Equal(got, []string{"dev-main", "v1.0.0"}) {
		t.Fatalf("from mirror: %v", got)
	}
	if h := g2.Health(ctx); h[0].OK {
		t.Errorf("unreachable remote reported OK: %+v", h[0])
	}

	// No mirror at all: the pinned tags are served from their sidecars.
	g3, _ := newGit(t, d, nil, src)
	if err := g3.Index(ctx); err != nil {
		t.Fatal(err)
	}
	vs := mustVersions(t, g3, "matchory/a")
	if got := versionNames(vs); !slices.Equal(got, []string{"v1.0.0"}) {
		t.Fatalf("from pins: %v", got)
	}
	if vs[0].Reference != versionsOf(t, g1, "matchory/a")["v1.0.0"].Reference || shasumOf(vs[0]) != shasumOf(versionsOf(t, g1, "matchory/a")["v1.0.0"]) {
		t.Errorf("pinned version differs: %+v", vs[0])
	}
	art, err := g3.Dist(ctx, "matchory/a", "v1.0.0", vs[0].Reference)
	if err != nil {
		t.Fatal(err)
	}
	art.Body.Close()
	if h := g3.Health(ctx); h[0].OK || h[0].Package != "matchory/a" {
		t.Errorf("health: %+v", h[0])
	}
}

func TestBrokenDefaultBranchFallsBackToPins(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	d := fsState(t)
	ctx := context.Background()
	g1, _ := newGit(t, d, nil, src)
	if err := g1.Index(ctx); err != nil {
		t.Fatal(err)
	}
	commitFile(t, src, "composer.json", `{broken`, "break")
	g2, _ := newGit(t, d, nil, src)
	if err := g2.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if got := versionNames(mustVersions(t, g2, "matchory/a")); !slices.Equal(got, []string{"v1.0.0"}) {
		t.Fatalf("versions = %v", got)
	}
}

func TestPinFallbackSkipsDisagreeingNames(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	d := fsState(t)
	ctx := context.Background()
	g1, _ := newGit(t, d, nil, src)
	if err := g1.Index(ctx); err != nil {
		t.Fatal(err)
	}
	// The repository renames its package; v2.0.0 is pinned under the new name.
	commitFile(t, src, "composer.json", `{"name":"matchory/b"}`, "rename")
	testutil.Git(t, src, "tag", "v2.0.0")
	if err := g1.Index(ctx); err != nil {
		t.Fatal(err)
	}
	moveAway(t, src)
	g2, _ := newGit(t, d, nil, src)
	if err := g2.Index(ctx); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"matchory/a", "matchory/b"} {
		if _, err := g2.Versions(ctx, n, false); err == nil {
			t.Errorf("%s served despite disagreeing pins", n)
		}
	}
}

func TestLoadedAndProvenanceCachesPruned(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	old := testutil.Git(t, src, "rev-parse", "HEAD")
	g, _ := newGit(t, fsState(t), nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.loaded[old]; !ok {
		t.Fatal("first pass did not load the head")
	}
	head := commitFile(t, src, "README", "x", "two")
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.loaded[old]; ok || len(g.loaded) != 1 {
		t.Errorf("loaded not pruned: %v", slices.Collect(maps.Keys(g.loaded)))
	}
	if len(g.prov) != 1 || !g.prov[head+"\x00dev-main"] {
		t.Errorf("prov not pruned: %v", g.prov)
	}
}

// GitSource returns its indexed metadata without copying: the handler's copy
// must keep consecutive responses apart.
func TestP2ResponsesDoNotShareMetadata(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	g, _ := newGit(t, fsState(t), nil, src)
	if err := g.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := server(t, []Source{g}, readAll)
	get := func(host string) string {
		t.Helper()
		req := httptest.NewRequest("GET", "/composer/p2/matchory/a.json", nil)
		req.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", host, w.Code, w.Body)
		}
		return w.Body.String()
	}
	first, second := get("a.example"), get("b.example")
	if !strings.Contains(first, "http://a.example/composer/dist/") || strings.ReplaceAll(first, "a.example", "b.example") != second {
		t.Fatalf("responses differ beyond the host:\n%s\n%s", first, second)
	}
	for _, v := range mustVersions(t, g, "matchory/a") {
		if _, ok := v.Package["dist"].(map[string]any)["url"]; ok {
			t.Fatalf("%s: source metadata was modified", v.Version)
		}
	}
}

// failPinWrites fails every pin write while fail is set.
type failPinWrites struct {
	storage.Driver
	fail bool
}

func (f *failPinWrites) PutIfAbsent(ctx context.Context, key string, r io.Reader) (storage.Info, error) {
	if f.fail && strings.HasPrefix(key, "pins/") {
		return storage.Info{}, errors.New("store down")
	}
	return f.Driver.PutIfAbsent(ctx, key, r)
}

func TestMovedTagStaysServedWhenRecordingTheMoveFails(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	testutil.Git(t, src, "tag", "v1.0.0")
	pinned := testutil.Git(t, src, "rev-parse", "HEAD")
	d := &failPinWrites{Driver: fsState(t)}
	g, _ := newGit(t, d, nil, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	commitFile(t, src, "README", "x", "two")
	testutil.Git(t, src, "tag", "-f", "v1.0.0")
	d.fail = true
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	vs, err := g.Versions(ctx, "matchory/a", false)
	if err != nil || len(vs) != 1 || vs[0].Version != "v1.0.0" || vs[0].Reference != pinned {
		t.Fatalf("versions = %+v, %v", vs, err)
	}
}

// Numeric branches are named as Composer's VCS repository names them.
func TestNumericBranchVersionNames(t *testing.T) {
	src := gitRepo(t, "matchory/a")
	for _, b := range []string{"1.x", "1.2", "v2.3", "1.2.3"} {
		testutil.Git(t, src, "branch", b)
	}
	g, _ := newGit(t, fsState(t), []string{"*"}, src)
	ctx := context.Background()
	if err := g.Index(ctx); err != nil {
		t.Fatal(err)
	}
	dev, err := g.Versions(ctx, "matchory/a", true)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range dev {
		got[v.Version] = normalizedOf(v)
	}
	want := map[string]string{
		"dev-main":    "dev-main",
		"1.x-dev":     "1.9999999.9999999.9999999-dev",
		"1.2.x-dev":   "1.2.9999999.9999999-dev",
		"v2.3.x-dev":  "2.3.9999999.9999999-dev",
		"1.2.3.x-dev": "1.2.3.9999999-dev",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}
