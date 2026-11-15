package goproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"

	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

// commitTime returns the committer time of an upstream commit.
func (e *gitEnv) commitTime(commit string) time.Time {
	e.t.Helper()
	sec, err := strconv.ParseInt(e.git("show", "-s", "--format=%ct", commit), 10, 64)
	if err != nil {
		e.t.Fatal(err)
	}
	return time.Unix(sec, 0).UTC()
}

// pseudoFor is the pseudo-version cmd/go mints for commit with base.
func (e *gitEnv) pseudoFor(major, base, commit string) string {
	e.t.Helper()
	return module.PseudoVersion(major, base, e.commitTime(commit), commit[:12])
}

func branches(b ...string) srcOpt {
	return func(_ *GitOptions, g *GitSource) { g.branches = b }
}

// wantInfo asserts that p@rev resolves to version v at the commit's time.
func wantInfo(t *testing.T, e *gitEnv, g *GitSource, p, rev, v, commit string) {
	t.Helper()
	info, err := g.Info(t.Context(), p, rev)
	if err != nil {
		t.Fatalf("Info(%s@%s): %v", p, rev, err)
	}
	if info.Version != v || !info.Time.Equal(e.commitTime(commit)) {
		t.Fatalf("Info(%s@%s) = %+v, want %s at %s", p, rev, info, v, e.commitTime(commit))
	}
}

func pseudoKeyOf(p, v, ext string) string {
	ps, _ := pathSeg(p)
	vs, _ := versionSeg(v)
	return "go-pseudo/acme/" + ps + "/" + vs + ext
}

func TestBranchPseudoVersion(t *testing.T) {
	e := newGitEnv(t)
	c := e.commit(map[string]string{"go.mod": gomodOf(modP)})
	g := e.source(rootMod())
	want := e.pseudoFor("", "", c)
	if !strings.HasPrefix(want, "v0.0.0-") {
		t.Fatalf("fixture pseudo-version %s", want)
	}
	wantInfo(t, e, g, modP, "main", want, c)
}

func TestBaseFromMergedTag(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.2.0")
	c2 := e.commit(map[string]string{"a.go": "package m\n"})
	g := e.source(rootMod())
	want := e.pseudoFor("", "v1.2.0", c2)
	if !strings.HasPrefix(want, "v1.2.1-0.") {
		t.Fatalf("fixture pseudo-version %s", want)
	}
	wantInfo(t, e, g, modP, c2, want, c2)

	e.tag("v1.3.0-rc.1")
	c4 := e.commit(map[string]string{"b.go": "package m\n"})
	want = e.pseudoFor("", "v1.3.0-rc.1", c4)
	if !strings.HasPrefix(want, "v1.3.0-rc.1.0.") {
		t.Fatalf("fixture pseudo-version %s", want)
	}
	wantInfo(t, e, g, modP, "main", want, c4)
}

func TestRetractedBaseSkipped(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.1.0")
	e.commit(map[string]string{"a.go": "package m\n"})
	e.tag("v1.2.0")
	// The highest release, on another branch, retracts v1.2.0.
	e.git("checkout", "-q", "-b", "other")
	e.commit(map[string]string{"go.mod": gomodOf(modP) + "\nretract v1.2.0\n"})
	e.tag("v1.3.0")
	e.git("checkout", "-q", "main")
	c := e.commit(map[string]string{"b.go": "package m\n"})
	g := e.source(rootMod())
	wantInfo(t, e, g, modP, "main", e.pseudoFor("", "v1.1.0", c), c)
}

func TestCommitOnTagAnswersTag(t *testing.T) {
	e := newGitEnv(t)
	c1 := e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	pass(t, g)
	info, err := g.Info(t.Context(), modP, c1)
	if err != nil || info.Version != "v1.0.0" || !info.Time.Equal(e.commitTime(c1)) {
		t.Fatalf("Info(sha of v1.0.0) = %+v, %v", info, err)
	}

	c2 := e.commit(map[string]string{"a.go": "package m\n"})
	e.tag("v1.1.0")
	_, err = g.Info(t.Context(), modP, c2)
	wantUnavailable(t, "Info of a commit carrying a pending tag", err)

	c3 := e.commit(map[string]string{"b.go": "package m\n"})
	e.tag("v1.0.0") // moved
	_, err = g.Info(t.Context(), modP, c3)
	wantNotFound(t, "Info of a commit carrying a moved tag", err)
	if !strings.Contains(err.Error(), "tag v1.0.0 moved; pinned to "+c1) {
		t.Fatalf("error %q lacks the move", err)
	}
}

func TestBranchNotAllowlisted404(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.git("checkout", "-q", "-b", "feature")
	e.commit(map[string]string{"a.go": "package m\n"})
	e.git("checkout", "-q", "main")
	g := e.source(rootMod(), branches("main"))
	_, err := g.Info(t.Context(), modP, "feature")
	wantNotFound(t, "Info of a branch not allowlisted", err)
	if _, err := g.Info(t.Context(), modP, "main"); err != nil {
		t.Fatalf("Info(main): %v", err)
	}
}

func TestUnreachableCommit404(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.git("checkout", "-q", "-b", "feature")
	f1 := e.commit(map[string]string{"a.go": "package m\n"})
	e.commit(map[string]string{"b.go": "package m\n"})
	e.tag("v1.0.0")
	f3 := e.commit(map[string]string{"c.go": "package m\n"})
	e.git("checkout", "-q", "main")

	block, release := blockedArchive(t)
	g := e.source(rootMod(), block)
	_, err := g.Info(t.Context(), modP, f1)
	wantNotFound(t, "Info of a commit only on a branch not allowlisted", err)

	// Reachable only from the pending v1.0.0: not yet.
	if err := g.Index(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, err = g.Info(t.Context(), modP, f1)
	wantUnavailable(t, "Info of a commit reachable only from a pending tag", err)
	_, err = g.Info(t.Context(), modP, f3)
	wantNotFound(t, "Info of a commit after the pending tag", err)

	release()
	settle(t, g)
	wantList(t, g, modP, "v1.0.0")
	wantInfo(t, e, g, modP, f1, e.pseudoFor("", "", f1), f1)
	_, err = g.Info(t.Context(), modP, f3)
	wantNotFound(t, "Info of a commit after the stored tag", err)
}

func TestHeadAndNonSemverTag404(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("release-1")
	g := e.source(rootMod())
	for _, rev := range []string{"HEAD", "release-1", "refs/heads/main", "main~1"} {
		_, err := g.Info(t.Context(), modP, rev)
		wantNotFound(t, "Info("+rev+")", err)
	}
}

func TestShortHashSameAsFull(t *testing.T) {
	e := newGitEnv(t)
	c := e.commit(map[string]string{"go.mod": gomodOf(modP)})
	g := e.source(rootMod())
	want := e.pseudoFor("", "", c)
	for _, rev := range []string{c[:7], c[:12], c} {
		wantInfo(t, e, g, modP, rev, want, c)
	}
}

func TestDirectPseudoValidated(t *testing.T) {
	e := newGitEnv(t)
	c1 := e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.2.0")
	c2 := e.commit(map[string]string{"a.go": "package m\n"})
	g := e.source(rootMod())

	good := e.pseudoFor("", "v1.2.0", c2)
	wantInfo(t, e, g, modP, good, good, c2)
	// An older base that is still an ancestor is accepted too.
	if _, err := g.Info(t.Context(), modP, e.pseudoFor("", "", c2)); err != nil {
		t.Fatalf("Info of a v0.0.0 pseudo-version: %v", err)
	}

	t2 := e.commitTime(c2)
	for name, v := range map[string]string{
		"wrong time":                 module.PseudoVersion("", "v1.2.0", t2.Add(time.Second), c2[:12]),
		"wrong base":                 module.PseudoVersion("", "v1.1.0", t2, c2[:12]),
		"base tag on the commit":     e.pseudoFor("", "v1.2.0", c1),
		"major mismatch":             module.PseudoVersion("v2", "", t2, c2[:12]),
		"v1 without a base":          module.PseudoVersion("v1", "", t2, c2[:12]),
		"unknown commit":             module.PseudoVersion("", "v1.2.0", t2, "0123456789ab"),
		"revision not 12 hex digits": strings.TrimSuffix(good, c2[:12]) + c2[:10],
	} {
		_, err := g.Info(t.Context(), modP, v)
		wantNotFound(t, name+" ("+v+")", err)
	}
}

// pseudoRecord reads a pseudo-version's record from the env's state.
func (e *gitEnv) pseudoRecord(p, v string) (pseudoRecord, bool) {
	e.t.Helper()
	rc, _, err := e.state.Get(e.t.Context(), pseudoKeyOf(p, v, ".json"))
	if errors.Is(err, storage.ErrNotFound) {
		return pseudoRecord{}, false
	}
	if err != nil {
		e.t.Fatal(err)
	}
	defer rc.Close()
	var r pseudoRecord
	if err := json.NewDecoder(rc).Decode(&r); err != nil {
		e.t.Fatal(err)
	}
	return r, true
}

func TestPseudoZipRecordedAndRebuilt(t *testing.T) {
	e := newGitEnv(t)
	c := e.commit(map[string]string{"go.mod": gomodOf(modP), "a.go": "package m\n"})
	g := e.source(rootMod())
	v := e.pseudoFor("", "", c)
	if _, err := g.Info(t.Context(), modP, "main"); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.pseudoRecord(modP, v); ok {
		t.Fatal(".info wrote a record")
	}

	z1 := fetch(t, g.Zip, modP, v)
	if mod := fetch(t, g.Mod, modP, v); string(mod) != gomodOf(modP) {
		t.Fatalf(".mod = %q", mod)
	}
	rec, ok := e.pseudoRecord(modP, v)
	if !ok {
		t.Fatal("no record after the first .zip")
	}
	if rec.Commit != c || rec.Dir != "" || rec.ZipHash != zipHashOf(t, z1) || !strings.HasPrefix(rec.ModHash, "h1:") {
		t.Fatalf("record %+v", rec)
	}
	digests, err := g.rec.ProvenanceDigests(t.Context(), "go", modP, v)
	if err != nil || len(digests) != 1 {
		t.Fatalf("provenance digests %q, %v", digests, err)
	}

	evict := func() {
		for _, ext := range []string{".zip", ".mod"} {
			if err := g.cache.Delete(t.Context(), pseudoKeyOf(modP, v, ext)); err != nil {
				t.Fatal(err)
			}
		}
	}
	evict()
	if z2 := fetch(t, g.Zip, modP, v); zipHashOf(t, z2) != rec.ZipHash {
		t.Fatal("the rebuilt zip's h1 differs")
	}

	rec.ZipHash = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.state.Put(t.Context(), pseudoKeyOf(modP, v, ".json"), bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	evict()
	_, err = g.Zip(t.Context(), modP, v)
	wantUnavailable(t, "Zip whose rebuild differs from the record", err)
	wantRefused(t, g, modP, v, RefusalRefused, "h1 differs from the record")
}

func TestPseudoCommitGone(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.git("checkout", "-q", "-b", "tmp")
	c := e.commit(map[string]string{"a.go": "package m\n"})
	e.git("checkout", "-q", "main")
	g := e.source(rootMod(), branches("main", "tmp"))
	v := e.pseudoFor("", "", c)
	fetch(t, g.Zip, modP, v)

	e.git("branch", "-q", "-D", "tmp")
	m := g.mirrors[e.remote]
	if err := m.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	testutil.Git(t, m.Dir(), "reflog", "expire", "--expire=now", "--all")
	testutil.Git(t, m.Dir(), "gc", "-q", "--prune=now")
	if ok, err := m.HasCommit(t.Context(), c); err != nil || ok {
		t.Fatalf("HasCommit after the prune = %v, %v", ok, err)
	}
	if _, _, err := g.cache.Open(t.Context(), pseudoKeyOf(modP, v, ".zip")); err != nil {
		t.Fatalf("the zip is no longer cached: %v", err)
	}
	_, err := g.Zip(t.Context(), modP, v)
	wantUnavailable(t, "Zip of a recorded pseudo-version whose commit is gone", err)
	_, err = g.Info(t.Context(), modP, v)
	wantUnavailable(t, "Info of a recorded pseudo-version whose commit is gone", err)
}

func TestPseudoRestartGate(t *testing.T) {
	e := newGitEnv(t)
	c1 := e.commit(map[string]string{"go.mod": gomodOf(modP)})
	g := e.source(rootMod())
	v1 := e.pseudoFor("", "", c1)
	z1 := fetch(t, g.Zip, modP, v1)
	c2 := e.commit(map[string]string{"a.go": "package m\n"})
	v2 := e.pseudoFor("", "", c2)
	if err := g.mirrors[e.remote].Sync(t.Context()); err != nil {
		t.Fatal(err)
	}

	e.takeRemote()
	g2 := e.source(rootMod())
	// Recorded: served (rebuilt into g2's empty cache) without a sync.
	if z := fetch(t, g2.Zip, modP, v1); zipHashOf(t, z) != zipHashOf(t, z1) {
		t.Fatal("the rebuilt zip's h1 differs")
	}
	if _, err := g2.Info(t.Context(), modP, v1); err != nil {
		t.Fatalf("Info of a recorded pseudo-version: %v", err)
	}
	// Anything new waits for the first sync.
	_, err := g2.Info(t.Context(), modP, "main")
	wantUnavailable(t, "Info(main) before the first sync", err)
	_, err = g2.Zip(t.Context(), modP, v2)
	wantUnavailable(t, "Zip of an unrecorded pseudo-version before the first sync", err)
}

func TestLatestUntaggedUsesDefaultBranch(t *testing.T) {
	e := newGitEnv(t)
	c := e.commit(map[string]string{"go.mod": gomodOf(modP)})
	g := e.source(rootMod(), branches("main"))
	pass(t, g)
	wantList(t, g, modP)
	info, err := g.Latest(t.Context(), modP)
	if err != nil || info.Version != e.pseudoFor("", "", c) || !info.Time.Equal(e.commitTime(c)) {
		t.Fatalf("Latest = %+v, %v", info, err)
	}

	g2 := e.source(rootMod(), branches("release"))
	pass(t, g2)
	_, err = g2.Latest(t.Context(), modP)
	wantNotFound(t, "Latest with the default branch not allowlisted", err)
}
