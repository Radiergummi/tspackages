package goproxy

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// fakeClock is a GitSource's now seam, moved by hand.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// throttled gives a source the production throttle on clock and counts its
// sync attempts.
func throttled(clock *fakeClock, syncs *atomic.Int32) srcOpt {
	return func(_ *GitOptions, g *GitSource) {
		g.now = clock.Now
		g.syncEvery = syncEvery
		g.sync = func(ctx context.Context, m *gitmirror.Mirror) error {
			syncs.Add(1)
			return m.Sync(ctx)
		}
	}
}

// blockedArchive makes every git archive wait until release runs (or its
// job's context ends); release also runs on cleanup.
func blockedArchive(t *testing.T) (opt srcOpt, release func()) {
	ch := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(ch) }) }
	t.Cleanup(release)
	return func(_ *GitOptions, g *GitSource) {
		g.archive = func(ctx context.Context, m *gitmirror.Mirror, commit, dir string, w io.Writer) error {
			select {
			case <-ch:
			case <-ctx.Done():
				return ctx.Err()
			}
			return m.ArchiveModuleZip(ctx, commit, dir, w)
		}
	}, release
}

func shortWait(_ *GitOptions, g *GitSource) { g.requestWait = 100 * time.Millisecond }

// takeRemote makes the env's remote unreachable until the returned func runs.
func (e *gitEnv) takeRemote() (restore func()) {
	e.t.Helper()
	gone := e.repo + ".gone"
	if err := os.Rename(e.repo, gone); err != nil {
		e.t.Fatal(err)
	}
	var once sync.Once
	restore = func() {
		once.Do(func() {
			if err := os.Rename(gone, e.repo); err != nil {
				e.t.Fatal(err)
			}
		})
	}
	e.t.Cleanup(restore)
	return restore
}

func wantNotFound(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, resolve.ErrNotFound) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("%s = %v, want ErrNotFound", what, err)
	}
}

func TestOnDemandUnknownTag(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	pass(t, g)

	e.commit(map[string]string{"a.go": "package m\n"})
	e.tag("v1.1.0")
	info, err := g.Info(t.Context(), modP, "v1.1.0")
	if err != nil || info.Version != "v1.1.0" {
		t.Fatalf("Info(v1.1.0) = %+v, %v", info, err)
	}
	wantList(t, g, modP, "v1.0.0", "v1.1.0")
	if _, ok := e.record(modP, "v1.1.0"); !ok {
		t.Fatal("no record for the on-demand build")
	}
	_, err = g.Info(t.Context(), modP, "v9.9.9")
	wantNotFound(t, "Info of a version without a tag", err)
}

func TestOnDemandThrottle(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	clock := newFakeClock()
	var syncs atomic.Int32
	g := e.source(rootMod(), throttled(clock, &syncs))
	pass(t, g)
	if n := syncs.Load(); n != 1 {
		t.Fatalf("%d syncs after a pass", n)
	}

	// A pass sync counts: inside its window the request answers from the
	// current state.
	e.commit(map[string]string{"a.go": "package m\n"})
	e.tag("v1.1.0")
	clock.Add(time.Second)
	_, err := g.Info(t.Context(), modP, "v1.1.0")
	wantNotFound(t, "Info inside the window after the pass", err)
	if n := syncs.Load(); n != 1 {
		t.Fatalf("%d syncs inside the window", n)
	}

	clock.Add(syncEvery)
	if _, err := g.Info(t.Context(), modP, "v1.1.0"); err != nil {
		t.Fatalf("Info after the window: %v", err)
	}
	e.commit(map[string]string{"b.go": "package m\n"})
	e.tag("v1.2.0")
	clock.Add(time.Second)
	_, err = g.Info(t.Context(), modP, "v1.2.0")
	wantNotFound(t, "Info one second after an on-demand sync", err)
	if n := syncs.Load(); n != 2 {
		t.Fatalf("%d syncs for two requests 1 s apart, want 2 in all", n)
	}
	// The pass shares the throttle too.
	pass(t, g)
	if n := syncs.Load(); n != 2 {
		t.Fatalf("%d syncs after a pass inside the window", n)
	}

	clock.Add(syncEvery)
	if _, err := g.Info(t.Context(), modP, "v1.2.0"); err != nil {
		t.Fatalf("Info after the window: %v", err)
	}
	if n := syncs.Load(); n != 3 {
		t.Fatalf("%d syncs, want 3", n)
	}
}

func TestFailedSyncAnswersUnavailable(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	clock := newFakeClock()
	var syncs atomic.Int32
	g := e.source(rootMod(), throttled(clock, &syncs))
	pass(t, g)

	restore := e.takeRemote()
	clock.Add(syncEvery)
	_, err := g.Info(t.Context(), modP, "v1.1.0")
	wantUnavailable(t, "Info with the remote gone", err)
	_, err = g.Info(t.Context(), modP, "master")
	wantUnavailable(t, "a branch query with the remote gone", err)
	clock.Add(syncEvery - time.Second)
	_, err = g.Info(t.Context(), modP, "v1.1.0")
	wantUnavailable(t, "Info at the end of the window", err)
	_, err = g.Zip(t.Context(), modP, "v1.1.0")
	wantUnavailable(t, "Zip at the end of the window", err)
	if n := syncs.Load(); n != 2 {
		t.Fatalf("%d syncs, want 2", n)
	}
	// Stored versions are served throughout.
	if _, err := g.Info(t.Context(), modP, "v1.0.0"); err != nil {
		t.Fatalf("Info of a stored version: %v", err)
	}

	restore()
	clock.Add(time.Second)
	_, err = g.Info(t.Context(), modP, "v1.1.0")
	wantNotFound(t, "Info after a successful sync", err)
}

func TestRequestWaitCapped(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	block, release := blockedArchive(t)
	g := e.source(rootMod(), block, shortWait)
	pass(t, g)

	e.tag("v1.0.0")
	start := time.Now()
	_, err := g.Info(t.Context(), modP, "v1.0.0")
	wantUnavailable(t, "Info with its build blocked", err)
	if d := time.Since(start); d < 100*time.Millisecond || d > 10*time.Second {
		t.Fatalf("Info returned after %s, want about 100ms", d)
	}
	// The request's time ran out during the sync or the build; either way
	// the version builds once nothing blocks it.
	release()
	g.requestWait = requestWait
	if _, err := g.Info(t.Context(), modP, "v1.0.0"); err != nil {
		t.Fatalf("Info once the build may run: %v", err)
	}
}

// A pending version is promoted to an on-demand job and waited for up to
// requestWait; it then answers ErrUnavailable, never ErrNotFound.
func TestPendingVersionPromotedThenUnavailable(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	block, release := blockedArchive(t)
	g := e.source(rootMod(), block, shortWait)
	if err := g.Index(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !g.pending(modP, "v1.0.0") {
		t.Fatal("a queued candidate is not pending")
	}
	start := time.Now()
	_, err := g.Info(t.Context(), modP, "v1.0.0")
	wantUnavailable(t, "Info of a pending version", err)
	if d := time.Since(start); d < g.requestWait {
		t.Fatalf("Info answered after %s, before requestWait", d)
	}
	g.q.mu.Lock()
	promoted := 0
	for _, j := range g.q.jobs {
		if j.key.Version == "v1.0.0" && j.demand && j.pass {
			promoted++
		}
	}
	g.q.mu.Unlock()
	if promoted != 1 {
		t.Fatal("the pending pass job was not promoted to on-demand")
	}
	_, err = g.Mod(t.Context(), modP, "v1.0.0")
	wantUnavailable(t, "Mod of a pending version", err)
	release()
	settle(t, g)
	if g.pending(modP, "v1.0.0") {
		t.Fatal("a stored version is pending")
	}
	if _, err := g.Info(t.Context(), modP, "v1.0.0"); err != nil {
		t.Fatal(err)
	}
}

func TestLatestPendingUnavailable(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	block, release := blockedArchive(t)
	g := e.source(rootMod(), block, shortWait)
	if err := g.Index(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, err := g.Latest(t.Context(), modP)
	wantUnavailable(t, "Latest with a pending candidate", err)
	release()
	settle(t, g)
	if info, err := g.Latest(t.Context(), modP); err != nil || info.Version != "v1.0.0" {
		t.Fatalf("Latest = %+v, %v", info, err)
	}
	// Synced, nothing stored and nothing pending: not found.
	_, err = g.Latest(t.Context(), modP+"/v2")
	wantNotFound(t, "Latest of a path without versions", err)
	wantList(t, g, modP+"/v2")
}

func TestRestartGateUntilSync(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	g := e.source(rootMod())
	pass(t, g)
	zip1 := fetch(t, g.Zip, modP, "v1.0.0")
	// The mirror learns v1.1.0, but the process ends before it is built.
	e.commit(map[string]string{"a.go": "package m\n"})
	e.tag("v1.1.0")
	if err := g.mirrors[e.remote].Sync(t.Context()); err != nil {
		t.Fatal(err)
	}

	restore := e.takeRemote()
	clock := newFakeClock()
	var syncs atomic.Int32
	g2 := e.source(rootMod(), throttled(clock, &syncs))
	if err := g2.Index(t.Context()); err != nil {
		t.Fatal(err)
	}
	settle(t, g2)
	if _, ok := e.record(modP, "v1.1.0"); ok {
		t.Fatal("a tag of the stale mirror was built")
	}
	if g2.pending(modP, "v1.1.0") {
		t.Fatal("a tag of the stale mirror is pending")
	}
	wantList(t, g2, modP, "v1.0.0")
	if z := fetch(t, g2.Zip, modP, "v1.0.0"); string(z) != string(zip1) {
		t.Fatal("the stored zip changed")
	}
	if info, err := g2.Latest(t.Context(), modP); err != nil || info.Version != "v1.0.0" {
		t.Fatalf("Latest = %+v, %v", info, err)
	}
	_, err := g2.Info(t.Context(), modP, "v1.1.0")
	wantUnavailable(t, "Info of an unstored tag before the first sync", err)
	_, err = g2.List(t.Context(), modP+"/v2")
	wantUnavailable(t, "List of a path without stored versions before the first sync", err)
	_, err = g2.Latest(t.Context(), modP+"/v2")
	wantUnavailable(t, "Latest of a path without stored versions before the first sync", err)

	restore()
	clock.Add(syncEvery)
	if info, err := g2.Info(t.Context(), modP, "v1.1.0"); err != nil || info.Version != "v1.1.0" {
		t.Fatalf("Info after the on-demand sync = %+v, %v", info, err)
	}
	wantList(t, g2, modP+"/v2")
}

func TestStalePassKeepsFresherCandidates(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	block, _ := blockedArchive(t)
	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	g := e.source(rootMod(), block, func(_ *GitOptions, g *GitSource) {
		g.afterRefs = func(string) {
			once.Do(func() {
				close(entered)
				<-proceed
			})
		}
	})
	// A slow pass read the refs before the tags existed.
	passDone := make(chan error, 1)
	go func() { passDone <- g.Index(context.Background()) }()
	<-entered

	// Meanwhile a request rescans: v2.0.0 of P/v2 is skipped (its go.mod
	// declares P), and v1.0.0, now a known candidate, is built (blocked).
	e.tag("v1.0.0", "v2.0.0")
	_, err := g.Info(t.Context(), modP+"/v2", "v2.0.0")
	wantNotFound(t, "Info of a skipped tag", err)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err = g.Info(ctx, modP, "v1.0.0")
	wantUnavailable(t, "Info of a blocked build", err)

	close(proceed)
	if err := <-passDone; err != nil {
		t.Fatal(err)
	}
	_, err = g.Latest(t.Context(), modP)
	wantUnavailable(t, "Latest after a stale pass ended", err)
	if _, ok := refusalFor(g, modP+"/v2", "v2.0.0"); !ok {
		t.Fatal("the stale pass pruned a fresher refusal")
	}
}

func TestOnDemandSyncKicksPass(t *testing.T) {
	e := newGitEnv(t)
	e.commit(map[string]string{"go.mod": gomodOf(modP)})
	e.tag("v1.0.0")
	g := e.sourceIn("", rootMod())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitListed(t, g, "v1.0.0")

	// Poll is an hour: only the kicked pass queues v1.2.0.
	e.commit(map[string]string{"a.go": "package m\n"})
	e.tag("v1.1.0", "v1.2.0")
	if _, err := g.Info(t.Context(), modP, "v1.1.0"); err != nil {
		t.Fatal(err)
	}
	waitListed(t, g, "v1.2.0")
}

func waitListed(t *testing.T, g *GitSource, v string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, ok := g.idx.Load().listed[verKey{modP, v}]; ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not listed", v)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
