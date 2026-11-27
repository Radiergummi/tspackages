package pypi

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/githubapp"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

// waitFor polls cond until it holds or a deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (e *ghEnv) health(t *testing.T) metrics.Health {
	t.Helper()
	h := e.src.Health(ctxBg)
	if len(h) != 1 {
		t.Fatalf("health rows: %+v", h)
	}
	return h[0]
}

// TestGitHubIndexServedWhileHashing: the index is published before the
// assets without a digest are downloaded, with the backlog in Health, and
// again with their digests once hashed.
func TestGitHubIndexServedWhileHashing(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.api.publish(repoA, 2, "v2.0.0", 11, wheel2, []byte("two"), false, t0.Add(time.Hour))
	e.api.gate = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- e.src.pass(ctxBg) }()

	waitFor(t, "the first index", func() bool { return e.src.Backlog() == 1 })
	p, err := e.src.Project(ctxBg, "acme-lib")
	if err != nil || len(p.Files) != 1 || p.Files[0].Filename != wheel1 {
		t.Fatalf("project while hashing: %+v, %v", p, err)
	}
	if h := e.health(t); !h.OK || !strings.Contains(h.Detail, "1 assets waiting to be hashed") {
		t.Fatalf("health while hashing: %+v", h)
	}

	close(e.api.gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	p, err = e.src.Project(ctxBg, "acme-lib")
	if err != nil || len(p.Files) != 2 {
		t.Fatalf("project after hashing: %+v, %v", p, err)
	}
	if h := e.health(t); !h.OK || strings.Contains(h.Detail, "waiting to be hashed") || e.src.Backlog() != 0 {
		t.Fatalf("health after hashing: %+v", h)
	}
}

// TestGitHubOlderUnhashedAssetDecidesOwner: a 2023 asset without a digest
// keeps a 2026 asset with one from deciding the owner; the name is
// unavailable until the older asset is hashed, which then owns it.
func TestGitHubOlderUnhashedAssetDecidesOwner(t *testing.T) {
	e := newGHEnv(t)
	old := time.Date(2023, 5, 1, 0, 0, 0, 0, time.UTC)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, false, old)
	e.api.publish(repoB, 2, "v2.0.0", 20, wheel2, []byte("evil"), true, t0)
	e.api.gate = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- e.src.pass(ctxBg) }()

	waitFor(t, "the first index", func() bool { return e.src.Backlog() == 1 })
	if _, err := e.src.Project(ctxBg, "acme-lib"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("project before the older asset is hashed: %v", err)
	}
	if got := e.src.Owners(); len(got) != 0 {
		t.Fatalf("owner decided before hashing: %v", got)
	}

	close(e.api.gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := e.src.Owners(); got["acme-lib"] != "acme/lib" {
		t.Fatalf("owners after hashing: %v", got)
	}
	p, err := e.src.Project(ctxBg, "acme-lib")
	if err != nil || len(p.Files) != 1 || p.Files[0].Filename != wheel1 {
		t.Fatalf("project after hashing: %+v, %v", p, err)
	}
}

// TestGitHubRateLimitWhileHashing: the index stays served, Health says rate
// limited and keeps the backlog.
func TestGitHubRateLimitWhileHashing(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.api.publish(repoA, 2, "v2.0.0", 11, wheel2, []byte("two"), false, t0.Add(time.Hour))
	reset := time.Date(2026, 11, 27, 12, 30, 0, 0, time.UTC)
	e.api.openErr = &githubapp.RateLimitError{Reset: reset}
	if err := e.pass(t); !errors.Is(err, githubapp.ErrRateLimited) {
		t.Fatalf("pass: %v", err)
	}
	p, err := e.src.Project(ctxBg, "acme-lib")
	if err != nil || len(p.Files) != 1 || p.Files[0].Filename != wheel1 {
		t.Fatalf("project: %+v, %v", p, err)
	}
	h := e.health(t)
	if h.OK || !strings.Contains(h.Detail, "rate limited until "+reset.Format(time.RFC3339)) ||
		!strings.Contains(h.Detail, "1 assets waiting to be hashed") || e.src.Backlog() != 1 {
		t.Fatalf("health: %+v", h)
	}
}

// TestGitHubStalledHashDownload: a hash download that stops sending is
// abandoned; the pass completes and the asset stays in the backlog.
func TestGitHubStalledHashDownload(t *testing.T) {
	e := newGHEnv(t)
	e.src.hashIdle = 50 * time.Millisecond
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.api.publish(repoA, 2, "v2.0.0", 11, wheel2, []byte("two"), false, t0.Add(time.Hour))
	e.api.stall = map[int64]bool{11: true}
	e.mustPass(t)
	if n := e.src.Backlog(); n != 1 {
		t.Fatalf("backlog: %d", n)
	}
	if logs := e.logs.String(); !strings.Contains(logs, "pypi github: hashing an asset failed") ||
		!strings.Contains(logs, "download stalled") {
		t.Fatalf("logs:\n%s", logs)
	}
	if p, err := e.src.Project(ctxBg, "acme-lib"); err != nil || len(p.Files) != 1 {
		t.Fatalf("project: %+v, %v", p, err)
	}
}

// TestGitHubCorruptOwnerPin: a corrupt owner pin withholds only its name;
// the pass goes on and reports it once.
func TestGitHubCorruptOwnerPin(t *testing.T) {
	e := newGHEnv(t)
	if _, err := e.state.Put(ctxBg, "pypi-github/gh/owners/"+storage.EscapeSegment("acme-lib")+".json", strings.NewReader("{")); err != nil {
		t.Fatal(err)
	}
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.api.publish(repoA, 2, "v1.0.0", 11, "acme_other-1.0.0-py3-none-any.whl", []byte("other"), true, t0)
	e.api.publish(repoA, 3, "v1.0.1", 12, "acme_lib-1.0.1.tar.gz", []byte("sdist"), false, t0)
	e.mustPass(t)
	if _, err := e.src.Project(ctxBg, "acme-lib"); !errors.Is(err, ErrUnavailable) || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("name with a corrupt owner pin: %v", err)
	}
	if p, err := e.src.Project(ctxBg, "acme-other"); err != nil || len(p.Files) != 1 {
		t.Fatalf("other name: %+v, %v", p, err)
	}
	if _, ok := e.src.Owners()["acme-lib"]; ok {
		t.Fatalf("owners: %v", e.src.Owners())
	}
	const msg = "pypi github: name unavailable: its owner pin is corrupt"
	if n := strings.Count(e.logs.String(), msg); n != 1 {
		t.Fatalf("%d reports in:\n%s", n, e.logs.String())
	}
}

// TestGitHubAuthFailureInHealth: a failed token exchange is named as such.
func TestGitHubAuthFailureInHealth(t *testing.T) {
	e := newGHEnv(t)
	e.api.listErr = fmt.Errorf("%w: status 401", githubapp.ErrAuthFailed)
	if err := e.pass(t); err == nil {
		t.Fatal("pass succeeded")
	}
	if h := e.health(t); h.OK || !strings.HasPrefix(h.Detail, "GitHub App authentication failed; nothing indexed yet") {
		t.Fatalf("health: %+v", h)
	}
}

// TestGitHubHealthDetail: Health names the installation and counts the
// repositories granted and the unclaimed assets, which are not listed as
// skipped.
func TestGitHubHealthDetail(t *testing.T) {
	e := newGHEnv(t)
	e.api.publish(repoA, 1, "v1.0.0", 10, wheel1, bodyOne, true, t0)
	e.api.publish(repoB, 2, "v1.0.0", 20, "private_tool-1.0-py3-none-any.whl", []byte("p"), true, t0)
	e.mustPass(t)
	h := e.health(t)
	if !h.OK || !strings.Contains(h.Detail, "; installation 42, 2 repositories granted") ||
		!strings.Contains(h.Detail, "; 1 unclaimed assets skipped") || strings.Contains(h.Detail, "evil/lib") {
		t.Fatalf("health: %+v", h)
	}
	if sk := e.src.Skipped(); len(sk) != 0 {
		t.Fatalf("skipped: %+v", sk)
	}
}
