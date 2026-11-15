package goproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/radiergummi/tspackages/internal/digest"
	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

// pseudoRecord is go-pseudo/<source>/<path seg>/<version seg>.json: the
// durable record of a pseudo-version's first build.
type pseudoRecord struct {
	Commit  string `json:"commit"`
	Dir     string `json:"dir"` // the directory the zip was built from
	ZipHash string `json:"zip_h1"`
	ModHash string `json:"mod_h1"`
}

// revision is a resolved query: a commit and the branch it was named by.
type revision struct {
	Commit string
	Branch string // "" for a hash
}

// maxBranchLen bounds a branch name used as a query.
const maxBranchLen = 255

// isPseudo reports whether v is a canonical pseudo-version.
func isPseudo(v string) bool { return semver.Canonical(v) == v && module.IsPseudoVersion(v) }

// isRevisionHex reports whether rev is 7 to 64 lowercase hex digits
// (codehost/git.go's minHashDigits up to a SHA-256 id).
func isRevisionHex(rev string) bool {
	return len(rev) >= 7 && len(rev) <= 64 && digest.IsHex(rev, len(rev))
}

func tagPrefix(mod Module) string {
	if mod.Dir == "" {
		return ""
	}
	return mod.Dir + "/"
}

func notFound(p, v, format string, args ...any) error {
	return fmt.Errorf("%w: %s@%s: %s", resolve.ErrNotFound, p, v, fmt.Sprintf(format, args...))
}

// unavailable wraps a git or store failure; err is formatted, never wrapped,
// so that ErrUnavailable never wraps resolve.ErrNotFound.
func unavailable(p, v, what string, err error) error {
	return fmt.Errorf("%w: %s@%s: %s: %v", ErrUnavailable, p, v, what, err) //nolint:errorlint // only ErrUnavailable is wrapped
}

// pseudoKey is the key of p@v's record and cached files without the
// extension; ok is false when a segment does not fit.
func (g *GitSource) pseudoKey(p, v string) (string, bool) {
	ps, ok1 := pathSeg(p)
	vs, ok2 := versionSeg(v)
	return "go-pseudo/" + g.name + "/" + ps + "/" + vs, ok1 && ok2
}

// branchAllowed reports whether branch b matches the allowlist, or is the
// default branch when there is none.
func (g *GitSource) branchAllowed(ctx context.Context, m *gitmirror.Mirror, b string) (bool, error) {
	if len(g.branches) == 0 {
		def, err := m.DefaultBranch(ctx)
		return err == nil && b == def, err
	}
	for _, pat := range g.branches {
		if ok, _ := path.Match(pat, b); ok {
			return true, nil
		}
	}
	return false, nil
}

// resolveRevision maps a query to a reachable commit: rev is an allowlisted
// branch, "" for the default branch (@latest), or 7 to 64 hex digits naming
// exactly one commit reachable from an allowlisted branch or a stored
// version's commit. Anything else, HEAD and non-semver tags included, is
// not found; a commit reachable only from a pending tag is ErrUnavailable.
func (g *GitSource) resolveRevision(ctx context.Context, m *gitmirror.Mirror, mod Module, rev string) (revision, error) {
	p := mod.Path
	shown := rev
	if rev == "" {
		shown = "latest"
		def, err := m.DefaultBranch(ctx)
		if err != nil {
			return revision{}, unavailable(p, shown, "reading the default branch failed", err)
		}
		rev = def
	}
	if len(rev) > maxBranchLen {
		return revision{}, notFound(p, shown, "not a branch or commit")
	}
	refs, err := m.Refs(ctx)
	if err != nil {
		return revision{}, unavailable(p, shown, "reading the refs failed", err)
	}
	tagged := false
	for _, r := range refs {
		if r.Short != rev {
			continue
		}
		if r.IsTag {
			tagged = true
			continue
		}
		ok, err := g.branchAllowed(ctx, m, rev)
		switch {
		case err != nil:
			return revision{}, unavailable(p, shown, "reading the default branch failed", err)
		case !ok:
			return revision{}, notFound(p, shown, "branch %s is not served", rev)
		}
		return revision{Commit: r.Commit, Branch: rev}, nil
	}
	if tagged || !isRevisionHex(rev) || shown == "latest" {
		return revision{}, notFound(p, shown, "not a served branch or a commit")
	}
	commit, err := m.ResolveCommit(ctx, rev)
	switch {
	case errors.Is(err, resolve.ErrNotFound):
		return revision{}, notFound(p, shown, "no such commit, or an ambiguous one")
	case err != nil:
		return revision{}, unavailable(p, shown, "resolving the commit failed", err)
	}
	if err := g.reachable(ctx, m, mod, shown, commit); err != nil {
		return revision{}, err
	}
	return revision{Commit: commit}, nil
}

// reachable checks that commit is in an allowlisted branch or a stored
// version's commit (its hidden ref).
func (g *GitSource) reachable(ctx context.Context, m *gitmirror.Mirror, mod Module, shown, commit string) error {
	p := mod.Path
	refs, err := m.ContainingRefs(ctx, commit)
	if err != nil {
		return unavailable(p, shown, "listing the refs containing the commit failed", err)
	}
	for _, r := range refs {
		if strings.HasPrefix(r, gitmirror.StoredRefPrefix) {
			return nil
		}
		if b, ok := strings.CutPrefix(r, "refs/heads/"); ok {
			allowed, err := g.branchAllowed(ctx, m, b)
			if err != nil {
				return unavailable(p, shown, "reading the default branch failed", err)
			}
			if allowed {
				return nil
			}
		}
	}
	for _, c := range g.pendingCommits(mod.Remote) {
		ok, err := m.IsAncestor(ctx, commit, c)
		if err != nil {
			return unavailable(p, shown, "checking reachability failed", err)
		}
		if ok {
			return fmt.Errorf("%w: %s@%s: reachable only from a tag version not built yet", ErrUnavailable, p, shown)
		}
	}
	return notFound(p, shown, "commit not reachable from a served branch or version")
}

// moduleAt finds p's go.mod at commit as findModule does; a skip reason is
// not found.
func (g *GitSource) moduleAt(ctx context.Context, m *gitmirror.Mirror, mod Module, p, shown, commit string) (Found, error) {
	read := func(file string) ([]byte, error) { return m.ReadFileMax(ctx, commit, file, MaxGoMod) }
	found, reason, err := findModule(read, mod, p)
	var ref *RefusalError
	switch {
	case reason != "":
		return Found{}, notFound(p, shown, "%s", reason)
	case errors.As(err, &ref):
		return Found{}, notFound(p, shown, "%s", ref.Reason)
	case err != nil:
		return Found{}, unavailable(p, shown, "reading go.mod failed", err)
	}
	return found, nil
}

// commitTime returns the commit's committer time; an unusable one is not
// found.
func (g *GitSource) commitTime(ctx context.Context, m *gitmirror.Mirror, p, shown, commit string) (time.Time, error) {
	when, err := m.CommitTime(ctx, commit)
	switch {
	case errors.Is(err, gitmirror.ErrBadCommitTime) || err == nil && (when.Year() < 1 || when.Year() > 9999):
		return time.Time{}, notFound(p, shown, "the commit's commit time is unusable")
	case err != nil:
		return time.Time{}, unavailable(p, shown, "reading the commit time failed", err)
	}
	return when, nil
}

// tagsOnCommit applies step 3: the module's tag versions stored or pinned
// at commit, and the mirror's tags on it, each served, pending, refused or
// skipped, or moved. The highest decides: served answers its version,
// pending ErrUnavailable, refused, skipped or moved not found with the
// reason. With none it returns "".
func (g *GitSource) tagsOnCommit(ctx context.Context, m *gitmirror.Mirror, mod Module, p, commit string) (string, error) {
	pathMajor, err := requestedMajor(mod.Path, p)
	if err != nil {
		return "", err
	}
	prefix := tagPrefix(mod)
	tags := map[string]string{} // version → tag
	idx := g.idx.Load()
	for vk, rec := range idx.listed {
		if vk.Path == p && rec.Commit == commit {
			tags[vk.Version] = rec.Tag
		}
	}
	g.mu.Lock()
	for vk, rec := range g.unlisted {
		if vk.Path == p && rec.Commit == commit {
			tags[vk.Version] = rec.Tag
		}
	}
	g.mu.Unlock()
	pinList, _, err := g.pins.List(ctx, ecoName, g.name, mod.Remote)
	if err != nil {
		return "", unavailable(p, commit, "reading the pins failed", err)
	}
	pinned := map[string]string{}
	for _, pn := range pinList {
		pinned[pn.Tag] = pn.SHA
		if v, ok := TagVersion(pn.Tag, prefix, pathMajor); ok && pn.SHA == commit {
			tags[v] = pn.Tag
		}
	}
	refs, err := m.Refs(ctx)
	if err != nil {
		return "", unavailable(p, commit, "reading the refs failed", err)
	}
	for _, r := range refs {
		if v, ok := TagVersion(r.Short, prefix, pathMajor); ok && r.IsTag && r.Commit == commit {
			tags[v] = r.Short
		}
	}
	best := ""
	for v := range tags {
		if semver.Compare(v, best) > 0 {
			best = v
		}
	}
	if best == "" {
		return "", nil
	}
	tag := tags[best]
	vk := verKey{p, best}
	if rec, ok := idx.listed[vk]; ok {
		if rec.Commit == commit {
			return best, nil
		}
		return "", notFound(p, commit, "tag %s moved; pinned to %s", tag, rec.Commit)
	}
	g.mu.Lock()
	rec, unlisted := g.unlisted[vk]
	refusal, refused := g.refusals[jobKey{Remote: mod.Remote, Commit: commit, Dir: mod.Dir, Path: p, Version: best}]
	g.mu.Unlock()
	switch {
	case unlisted && rec.Commit == commit:
		return "", fmt.Errorf("%w: %s@%s: tag version %s is not servable yet", ErrUnavailable, p, commit, best)
	case unlisted:
		return "", notFound(p, commit, "tag %s moved; pinned to %s", tag, rec.Commit)
	case pinned[tag] != "" && pinned[tag] != commit:
		return "", notFound(p, commit, "tag %s moved; pinned to %s", tag, pinned[tag])
	case refused:
		return "", notFound(p, commit, "tag %s: %s", tag, refusal.Reason)
	}
	g.kickPass(mod.Remote)
	return "", fmt.Errorf("%w: %s@%s: tag version %s is pending", ErrUnavailable, p, commit, best)
}

// mint returns the pseudo-version of commit at time t (step 4): its base
// is the highest current mirror tag merged into the commit whose version
// fits the path's major and is not retracted.
func (g *GitSource) mint(ctx context.Context, m *gitmirror.Mirror, mod Module, p, commit string, t time.Time) (string, error) {
	pathMajor, err := requestedMajor(mod.Path, p)
	if err != nil {
		return "", err
	}
	prefix := tagPrefix(mod)
	merged, err := m.MergedTags(ctx, commit)
	if err != nil {
		return "", unavailable(p, commit, "listing the merged tags failed", err)
	}
	isRetracted := g.retractions(ctx, m, mod, p, pathMajor)
	base := ""
	for _, r := range merged {
		v, ok := TagVersion(r.Short, prefix, pathMajor)
		if ok && !isRetracted(v) && semver.Compare(v, base) > 0 {
			base = v
		}
	}
	return module.PseudoVersion(module.PathMajorPrefix(pathMajor), base, t, commit[:12]), nil
}

// retractions returns whether a version is retracted by the go.mod of p's
// highest candidate release tag, else prerelease tag, as
// coderepo.go:codeRepo.retractedVersions reads it: nothing is retracted
// when that read fails.
func (g *GitSource) retractions(ctx context.Context, m *gitmirror.Mirror, mod Module, p, pathMajor string) func(string) bool {
	none := func(string) bool { return false }
	refs, err := m.Refs(ctx)
	if err != nil {
		return none
	}
	var release, pre, releaseCommit, preCommit string
	for _, r := range refs {
		v, ok := TagVersion(r.Short, tagPrefix(mod), pathMajor)
		switch {
		case !ok || !r.IsTag:
		case semver.Prerelease(v) == "" && semver.Compare(v, release) > 0:
			release, releaseCommit = v, r.Commit
		case semver.Prerelease(v) != "" && semver.Compare(v, pre) > 0:
			pre, preCommit = v, r.Commit
		}
	}
	commit := releaseCommit
	if commit == "" {
		commit = preCommit
	}
	if commit == "" {
		return none
	}
	read := func(file string) ([]byte, error) { return m.ReadFileMax(ctx, commit, file, MaxGoMod) }
	found, reason, err := findModule(read, mod, p)
	if err != nil || reason != "" {
		return none
	}
	intervals := retracted(found.GoMod)
	return func(v string) bool {
		return isRetractedBy(intervals, v)
	}
}

func isRetractedBy(intervals []modfile.VersionInterval, v string) bool {
	for _, r := range intervals {
		if semver.Compare(r.Low, v) <= 0 && semver.Compare(v, r.High) <= 0 {
			return true
		}
	}
	return false
}

// checkDirectPseudo applies coderepo.go:validatePseudoVersion's rules to a
// canonical pseudo-version requested directly: its major fits the path, its
// 12-digit revision names a commit reachable per resolveRevision, findModule
// passes there, its time is the commit time, and its base is empty (major
// v0, or the path's vN) or the version of a mirror tag that is an ancestor
// of the commit and not on the commit itself.
func (g *GitSource) checkDirectPseudo(ctx context.Context, m *gitmirror.Mirror, mod Module, p, v string) (string, error) {
	pathMajor, err := requestedMajor(mod.Path, p)
	if err != nil {
		return "", err
	}
	if err := module.CheckPathMajor(v, pathMajor); err != nil {
		return "", notFound(p, v, "%v", err)
	}
	base, err := module.PseudoVersionBase(v)
	if err != nil {
		return "", notFound(p, v, "%v", err)
	}
	if base == "" && pathMajor == "" && semver.Major(v) != "v0" {
		return "", notFound(p, v, "major version without preceding tag must be v0")
	}
	rev, err := module.PseudoVersionRev(v)
	if err != nil || len(rev) != 12 {
		return "", notFound(p, v, "revision must be 12 hex digits")
	}
	r, err := g.resolveRevision(ctx, m, mod, rev)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(r.Commit, rev) {
		return "", notFound(p, v, "revision %s is a branch at another commit", rev)
	}
	if _, err := g.moduleAt(ctx, m, mod, p, v, r.Commit); err != nil {
		return "", err
	}
	when, err := g.commitTime(ctx, m, p, v, r.Commit)
	if err != nil {
		return "", err
	}
	if t, err := module.PseudoVersionTime(v); err != nil || !t.Equal(when) {
		return "", notFound(p, v, "does not match the commit time %s", when.Format("20060102150405"))
	}
	if base == "" {
		return r.Commit, nil
	}
	refs, err := m.Refs(ctx)
	if err != nil {
		return "", unavailable(p, v, "reading the refs failed", err)
	}
	var baseCommits []string
	for _, ref := range refs {
		if tv, ok := TagVersion(ref.Short, tagPrefix(mod), pathMajor); !ok || !ref.IsTag || tv != base {
			continue
		}
		if ref.Commit == r.Commit {
			return "", notFound(p, v, "tag %s is on the commit itself; use that version", ref.Short)
		}
		baseCommits = append(baseCommits, ref.Commit)
	}
	for _, c := range baseCommits {
		ok, err := m.IsAncestor(ctx, c, r.Commit)
		if err != nil {
			return "", unavailable(p, v, "checking the base tag failed", err)
		}
		if ok {
			return r.Commit, nil
		}
	}
	return "", notFound(p, v, "base %s is not a tag preceding the commit", base)
}

// queryInfo answers a branch, a commit hash or, with rev "", @latest's
// default branch: the remote is synced, the revision resolved, and the
// commit answers a tag version on it or a minted pseudo-version.
func (g *GitSource) queryInfo(ctx context.Context, mod Module, p, rev string) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, g.requestWait)
	defer cancel()
	shown := rev
	if rev == "" {
		shown = "latest"
	}
	if err := g.syncForRequest(ctx, mod, p, shown); err != nil {
		return Info{}, err
	}
	m := g.mirrors[mod.Remote]
	r, err := g.resolveRevision(ctx, m, mod, rev)
	if err != nil {
		return Info{}, err
	}
	if _, err := g.moduleAt(ctx, m, mod, p, shown, r.Commit); err != nil {
		return Info{}, err
	}
	v, err := g.tagsOnCommit(ctx, m, mod, p, r.Commit)
	switch {
	case err != nil:
		return Info{}, err
	case v != "":
		return Info{Version: v, Time: g.idx.Load().listed[verKey{p, v}].Time}, nil
	}
	when, err := g.commitTime(ctx, m, p, shown, r.Commit)
	if err != nil {
		return Info{}, err
	}
	pv, err := g.mint(ctx, m, mod, p, r.Commit, when)
	if err != nil {
		return Info{}, err
	}
	return Info{Version: pv, Time: when}, nil
}

// readPseudoRecord reads a pseudo-version record; one that does not decode
// or names no valid commit wraps errBadRecord.
func (g *GitSource) readPseudoRecord(ctx context.Context, key string) (pseudoRecord, error) {
	rc, _, err := g.state.Get(ctx, key)
	if err != nil {
		return pseudoRecord{}, err
	}
	defer rc.Close()
	var r pseudoRecord
	if err := json.NewDecoder(io.LimitReader(rc, 1<<20)).Decode(&r); err != nil {
		if ctx.Err() != nil {
			return r, err
		}
		return r, fmt.Errorf("%w: %w", errBadRecord, err)
	}
	if !digest.IsHex(r.Commit, 40, 64) {
		return r, fmt.Errorf("%w: commit %q", errBadRecord, r.Commit)
	}
	return r, nil
}

// checkPseudo vets a canonical pseudo-version. With a record it returns the
// record while its commit is in the mirror; without one it syncs the remote
// and applies checkDirectPseudo and step 3, and returns the commit.
func (g *GitSource) checkPseudo(ctx context.Context, mod Module, p, v string) (*pseudoRecord, string, error) {
	key, ok := g.pseudoKey(p, v)
	if !ok {
		return nil, "", notFound(p, v, "module path or version too long for a storage key")
	}
	m := g.mirrors[mod.Remote]
	rec, err := g.readPseudoRecord(ctx, key+".json")
	switch {
	case err == nil:
		present, err := m.HasCommit(ctx, rec.Commit)
		switch {
		case err != nil:
			return nil, "", unavailable(p, v, "looking up the recorded commit failed", err)
		case !present:
			return nil, "", fmt.Errorf("%w: %s@%s: recorded commit %s is gone from the mirror", ErrUnavailable, p, v, rec.Commit)
		}
		return &rec, rec.Commit, nil
	case !errors.Is(err, storage.ErrNotFound):
		return nil, "", unavailable(p, v, "reading the pseudo-version record failed", err)
	}
	if err := g.syncForRequest(ctx, mod, p, v); err != nil {
		return nil, "", err
	}
	commit, err := g.checkDirectPseudo(ctx, m, mod, p, v)
	if err != nil {
		return nil, "", err
	}
	// A served tag on the commit leaves the pseudo-version valid.
	if _, err := g.tagsOnCommit(ctx, m, mod, p, commit); err != nil {
		return nil, "", err
	}
	return nil, commit, nil
}

// pseudoInfo answers .info of a canonical pseudo-version; it builds nothing.
func (g *GitSource) pseudoInfo(ctx context.Context, mod Module, p, v string) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, g.requestWait)
	defer cancel()
	if _, _, err := g.checkPseudo(ctx, mod, p, v); err != nil {
		return Info{}, err
	}
	t, _ := module.PseudoVersionTime(v)
	return Info{Version: v, Time: t}, nil
}

// openPseudo serves a pseudo-version's go.mod or zip (ext ".mod" or ".zip")
// from the cache. A recorded one missing from the cache, and an unrecorded
// one, is built by an on-demand job, waited on for at most requestWait.
func (g *GitSource) openPseudo(ctx context.Context, mod Module, p, v, ext string) (Artifact, error) {
	ctx, cancel := context.WithTimeout(ctx, g.requestWait)
	defer cancel()
	rec, commit, err := g.checkPseudo(ctx, mod, p, v)
	if err != nil {
		return Artifact{}, err
	}
	key, _ := g.pseudoKey(p, v)
	vk := verKey{p, v}
	if rec != nil {
		if a, ok, err := g.openCached(ctx, key+ext); ok || err != nil {
			return a, err
		}
		if r, refused := g.recRefusal(vk); refused {
			return Artifact{}, fmt.Errorf("%w: %s@%s: %s", ErrUnavailable, p, v, r.Reason)
		}
	}
	k := jobKey{Remote: mod.Remote, Commit: commit, Dir: mod.Dir, Path: p, Version: v}
	t := g.q.enqueue(k, p, jobOnDemand, g.pseudoJob(mod, p, v, commit, rec))
	defer t.Leave()
	werr := t.Wait(ctx)
	var ref *RefusalError
	switch {
	case werr == nil:
	case errors.As(werr, &ref):
		if _, refused := g.recRefusal(vk); refused || rec != nil {
			return Artifact{}, fmt.Errorf("%w: %s@%s: %s", ErrUnavailable, p, v, ref.Reason)
		}
		return Artifact{}, notFound(p, v, "%s", ref.Reason)
	case ctx.Err() != nil:
		return Artifact{}, fmt.Errorf("%w: %s@%s: not built within %s", ErrUnavailable, p, v, g.requestWait)
	default:
		return Artifact{}, unavailable(p, v, "not built", werr)
	}
	a, ok, err := g.openCached(ctx, key+ext)
	if !ok && err == nil {
		return Artifact{}, fmt.Errorf("%w: %s@%s: evicted from the cache before it was served", ErrUnavailable, p, v)
	}
	return a, err
}

// openCached opens a cached file; ok is false when it is not cached.
func (g *GitSource) openCached(ctx context.Context, key string) (Artifact, bool, error) {
	rc, size, err := g.cache.Open(ctx, key)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return Artifact{}, false, nil
	case err != nil:
		return Artifact{}, false, err
	}
	return Artifact{Body: rc, Size: size}, true, nil
}

func (g *GitSource) recRefusal(vk verKey) (Refusal, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	r, ok := g.recRefusals[vk]
	return r, ok
}

// refusePseudo reports a recorded pseudo-version that cannot be rebuilt as
// recorded; it answers ErrUnavailable from then on.
func (g *GitSource) refusePseudo(vk verKey, remote string, rec pseudoRecord, reason string) error {
	g.mu.Lock()
	g.recRefusals[vk] = Refusal{
		Module: vk.Path, Version: vk.Version, Remote: metrics.RedactRemote(remote), Commit: rec.Commit,
		Kind: RefusalRefused, Reason: reason,
	}
	g.mu.Unlock()
	g.log.Warn("goproxy git: pseudo-version refused", "source", g.name, "module", vk.Path, "version", vk.Version,
		"commit", rec.Commit, "reason", reason)
	return &RefusalError{Reason: reason}
}

// pseudoJob builds p@v from commit. Without a record (rec nil) it finds the
// module, builds, and claims the record with PutIfAbsent; a job that finds
// the record claimed compares its h1 hashes with it. With a record it
// rebuilds from the recorded directory and compares. Then it writes a
// provenance record for the built sha256 and puts the zip and go.mod into
// the cache. A missing commit ends the job.
func (g *GitSource) pseudoJob(mod Module, p, v, commit string, rec *pseudoRecord) func(context.Context) error {
	m := g.mirrors[mod.Remote]
	vk := verKey{p, v}
	key, _ := g.pseudoKey(p, v)
	return func(ctx context.Context) error {
		var found Found
		if rec != nil {
			gomod, err := m.ReadFileMax(ctx, commit, path.Join(rec.Dir, "go.mod"), MaxGoMod)
			switch {
			case errors.Is(err, gitmirror.ErrNoCommit):
				return &RefusalError{Reason: "recorded commit gone from the mirror"}
			case errors.Is(err, resolve.ErrNotFound):
				return g.refusePseudo(vk, mod.Remote, *rec, "go.mod gone from the recorded commit")
			case errors.Is(err, gitmirror.ErrTooLarge):
				return g.refusePseudo(vk, mod.Remote, *rec, reasonGoModTooLarge)
			case err != nil:
				return err
			}
			found = Found{Dir: rec.Dir, GoMod: gomod}
		} else {
			read := func(file string) ([]byte, error) { return m.ReadFileMax(ctx, commit, file, MaxGoMod) }
			f, reason, err := findModule(read, mod, p)
			switch {
			case reason != "":
				return &RefusalError{Reason: reason}
			case errors.Is(err, gitmirror.ErrNoCommit):
				return &RefusalError{Reason: "commit gone from the mirror"}
			case err != nil:
				return err
			}
			found = f
		}
		res, zipPath, err := g.buildPseudo(ctx, m, mod, vk, commit, found)
		if err != nil {
			var ref *RefusalError
			if rec != nil && errors.As(err, &ref) {
				return g.refusePseudo(vk, mod.Remote, *rec, ref.Reason)
			}
			return err
		}
		defer os.Remove(zipPath)
		want := pseudoRecord{Commit: commit, Dir: found.Dir, ZipHash: res.ZipHash, ModHash: res.ModHash}
		if rec != nil {
			want = *rec
		} else if want, err = g.claimPseudo(ctx, key+".json", want); err != nil {
			if errors.Is(err, errBadRecord) {
				return g.refusePseudo(vk, mod.Remote, pseudoRecord{Commit: commit}, "unreadable pseudo-version record: "+err.Error())
			}
			return err
		}
		if res.ZipHash != want.ZipHash || res.ModHash != want.ModHash {
			return g.refusePseudo(vk, mod.Remote, want, "h1 differs from the record")
		}
		if err := g.rec.PutProvenance(ctx, records.Provenance{
			Ecosystem: ecoName, Package: p, Version: v, Source: g.name, SourceType: "git",
			Remote: metrics.RedactRemote(mod.Remote), Commit: commit, DeclaredDigest: want.ZipHash, SHA256: res.SHA256,
		}); err != nil {
			return err
		}
		if err := g.cache.Put(ctx, key+".mod", bytes.NewReader(found.GoMod)); err != nil {
			return err
		}
		f, err := os.Open(zipPath)
		if err != nil {
			return err
		}
		defer f.Close()
		return g.cache.Put(ctx, key+".zip", f)
	}
}

// buildPseudo applies the tree caps and the go directive check to the
// module's directory at commit and builds its zip.
func (g *GitSource) buildPseudo(ctx context.Context, m *gitmirror.Mirror, mod Module, vk verKey, commit string, found Found) (ZipResult, string, error) {
	dk := dirKey{mod.Remote, commit, found.Dir}
	if err := g.checkTree(ctx, m, dk); err != nil {
		return ZipResult{}, "", err
	}
	if reason := checkGoDirective(found.GoMod); reason != "" {
		return ZipResult{}, "", g.refuseDir(dk, reason)
	}
	zipPath, res, err := g.build(ctx, m, dk, module.Version{Path: vk.Path, Version: vk.Version}, found.GoMod)
	return res, zipPath, err
}

// claimPseudo writes rec with PutIfAbsent and returns the stored record:
// rec, or the one another job or indexer claimed first.
func (g *GitSource) claimPseudo(ctx context.Context, key string, rec pseudoRecord) (pseudoRecord, error) {
	body, err := json.Marshal(rec)
	if err != nil {
		return pseudoRecord{}, err
	}
	_, err = g.state.PutIfAbsent(ctx, key, bytes.NewReader(body))
	switch {
	case err == nil:
		return rec, nil
	case !errors.Is(err, storage.ErrExists):
		return pseudoRecord{}, err
	}
	return g.readPseudoRecord(ctx, key)
}
