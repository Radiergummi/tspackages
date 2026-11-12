package goproxy

import (
	"context"
	"fmt"
	"time"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// Defaults of GitSource.syncEvery and GitSource.requestWait.
const (
	syncEvery   = 10 * time.Second // at most one sync attempt per remote
	requestWait = 30 * time.Second // a request waits at most this long in all
)

// remoteState is one remote's sync throttle and restart gate. It is guarded
// by GitSource.mu.
type remoteState struct {
	lastAttempt time.Time // when the last attempt ended
	lastErr     error
	// syncedSinceStart is the restart gate: false until a successful sync
	// in this process. Until then the remote enqueues and mints nothing new.
	syncedSinceStart bool
	running          *syncAttempt // the attempt in flight, or nil
}

// syncAttempt is one sync of a mirror, shared by everyone who asks while it
// runs.
type syncAttempt struct {
	done chan struct{}
	err  error // set before done is closed
}

// syncRemote syncs m unless an attempt is younger than syncEvery
// (single-flight); it returns the outcome remembered for the window. The
// sync runs on the source's lifetime, so a caller whose ctx ends stops
// waiting without cutting it short.
func (g *GitSource) syncRemote(ctx context.Context, m *gitmirror.Mirror) error {
	g.mu.Lock()
	st := g.syncs[m]
	a := st.running
	if a == nil {
		if !st.lastAttempt.IsZero() && g.now().Sub(st.lastAttempt) < g.syncEvery {
			err := st.lastErr
			g.mu.Unlock()
			return err
		}
		a = &syncAttempt{done: make(chan struct{})}
		st.running = a
		go func() {
			err := g.sync(g.life, m)
			g.mu.Lock()
			st.running = nil
			st.lastAttempt, st.lastErr = g.now(), err
			if err == nil {
				st.syncedSinceStart = true
			}
			g.mu.Unlock()
			a.err = err
			close(a.done)
		}()
	}
	g.mu.Unlock()
	select {
	case <-a.done:
		return a.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// synced reports whether remote's restart gate is lifted.
func (g *GitSource) synced(remote string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.syncs[g.mirrors[remote]]
	return st != nil && st.syncedSinceStart
}

// pending reports whether path@version is a candidate from the current
// refs after the latest successful sync that is neither stored, refused
// nor skipped, or a repairable record.
func (g *GitSource) pending(path, version string) bool {
	return g.pendingWhere(path, func(v string) bool { return v == version })
}

// pendingWhere reports whether a version of path that match accepts is
// pending.
func (g *GitSource) pendingWhere(path string, match func(string) bool) bool {
	mod, ok := g.moduleFor(path)
	if !ok {
		return false
	}
	listed := g.idx.Load().listed
	g.mu.Lock()
	defer g.mu.Unlock()
	for k := range g.cands[mod.Remote] {
		vk := verKey{k.Path, k.Version}
		if k.Path != path || !match(k.Version) {
			continue
		}
		_, stored := listed[vk]
		_, refused := g.refusals[k]
		_, recRefused := g.recRefusals[vk]
		if !stored && !refused && !recRefused {
			return true
		}
	}
	for vk := range g.unlisted {
		if _, refused := g.recRefusals[vk]; vk.Path == path && match(vk.Version) && !refused {
			return true
		}
	}
	return false
}

// served answers p@v from the stored versions: the record of a listed one,
// ErrUnavailable for a record that cannot be served (awaiting repair or
// refused). ok is false when no record is known.
func (g *GitSource) served(p, v string) (rec versionRecord, ok bool, err error) {
	vk := verKey{p, v}
	if rec, ok := g.idx.Load().listed[vk]; ok {
		return rec, true, nil
	}
	g.mu.Lock()
	_, unlisted := g.unlisted[vk]
	refusal, refused := g.recRefusals[vk]
	g.mu.Unlock()
	switch {
	case refused:
		return versionRecord{}, true, fmt.Errorf("%w: %s@%s: %s", ErrUnavailable, p, v, refusal.Reason)
	case unlisted:
		return versionRecord{}, true, fmt.Errorf("%w: %s@%s: its zip is being repaired", ErrUnavailable, p, v)
	}
	return versionRecord{}, false, nil
}

// known returns the candidate for p@v among remote's current candidates.
func (g *GitSource) known(remote, p, v string) (candidate, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return findCandidate(g.cands[remote], p, v)
}

func findCandidate(cands map[jobKey]candidate, p, v string) (candidate, bool) {
	for k, c := range cands {
		if k.Path == p && k.Version == v {
			return c, true
		}
	}
	return candidate{}, false
}

// refused returns the refusal of a tag candidate as ErrNotFound with its
// reason, or nil.
func (g *GitSource) refused(c candidate) error {
	g.mu.Lock()
	r, ok := g.refusals[c.key]
	g.mu.Unlock()
	if !ok {
		return nil
	}
	return fmt.Errorf("%w: %s@%s: %s", resolve.ErrNotFound, c.key.Path, c.key.Version, r.Reason)
}

// demand answers a canonical version of mod that is not stored: a pending
// candidate is built on demand; any other version first syncs the remote
// and rescans its refs. It waits at most requestWait in all.
func (g *GitSource) demand(ctx context.Context, mod Module, p, v string) (versionRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, g.requestWait)
	defer cancel()
	c, ok := g.known(mod.Remote, p, v)
	if !ok {
		if err := g.syncForRequest(ctx, mod, p, v); err != nil {
			return versionRecord{}, err
		}
		m := g.mirrors[mod.Remote]
		refs, err := m.Refs(ctx)
		if err != nil {
			return versionRecord{}, fmt.Errorf("%w: %s@%s: reading the refs failed: %v", ErrUnavailable, p, v, err) //nolint:errorlint // a git failure is not a miss
		}
		cands := g.candidates(mod.Remote, refs)
		g.mu.Lock()
		g.cands[mod.Remote] = cands
		g.mu.Unlock()
		if c, ok = findCandidate(cands, p, v); !ok {
			return versionRecord{}, fmt.Errorf("%w: %s@%s: no such tag", resolve.ErrNotFound, p, v)
		}
		if rec, ok, err := g.served(p, v); ok {
			return rec, err // stored meanwhile
		}
	}
	if err := g.refused(c); err != nil {
		return versionRecord{}, err
	}
	t := g.q.enqueue(c.key, c.key.Path, jobOnDemand, g.tagJob(g.mirrors[mod.Remote], c))
	defer t.Leave()
	werr := t.Wait(ctx)
	if rec, ok, err := g.served(p, v); ok {
		return rec, err
	}
	if err := g.refused(c); err != nil {
		return versionRecord{}, err
	}
	if ctx.Err() != nil {
		return versionRecord{}, fmt.Errorf("%w: %s@%s: not built within %s", ErrUnavailable, p, v, g.requestWait)
	}
	// Dropped (its tag moved during the build), stopped, or stored from
	// another commit and awaiting repair.
	return versionRecord{}, fmt.Errorf("%w: %s@%s: not built (%v)", ErrUnavailable, p, v, werr) //nolint:errorlint // only ErrUnavailable is wrapped; werr may be a refusal
}

// query answers a non-canonical version of mod (a branch or a commit): the
// remote is synced first, and a failed sync is ErrUnavailable. Pseudo-
// versions are not minted yet, so a synced remote answers ErrNotFound.
func (g *GitSource) query(ctx context.Context, mod Module, p, v string) error {
	ctx, cancel := context.WithTimeout(ctx, g.requestWait)
	defer cancel()
	if err := g.syncForRequest(ctx, mod, p, v); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s@%s", resolve.ErrNotFound, p, v)
}

// syncForRequest syncs mod's remote for a request and maps a failure to
// ErrUnavailable: a 404 now could fall through to a later claimed source.
func (g *GitSource) syncForRequest(ctx context.Context, mod Module, p, v string) error {
	err := g.syncRemote(ctx, g.mirrors[mod.Remote])
	switch {
	case err == nil:
		return nil
	case ctx.Err() != nil:
		return fmt.Errorf("%w: %s@%s: its remote did not sync within %s", ErrUnavailable, p, v, g.requestWait)
	}
	return fmt.Errorf("%w: %s@%s: its remote's last sync failed: %v", ErrUnavailable, p, v, err) //nolint:errorlint // only ErrUnavailable is wrapped
}
