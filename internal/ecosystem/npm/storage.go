package npm

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/flight"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/lru"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

const (
	// updateRetries bounds If-Match retries of an index or dist-tags write.
	updateRetries = 8
	// maxTags is the most dist-tags a package may have.
	maxTags = 100

	maxIndexBytes   = 32 << 20
	maxTagsBytes    = 1 << 20
	maxSidecarBytes = 4 << 20
	// maxStorageDocBytes caps each rendered packument, full and abbreviated.
	maxStorageDocBytes = 64 << 20
	// maxRenderedBytes caps the rendered packuments a storage source keeps
	// in memory; the least recently read are rendered again when needed.
	maxRenderedBytes = 256 << 20

	// sidecarBatch is how many sidecars a render reads concurrently.
	sidecarBatch = 16

	// timeFormat is the layout of npm's time fields.
	timeFormat = "2006-01-02T15:04:05.000Z"
)

// StorageSource holds published packages in a store. Versions are
// immutable; a package's index is rebuildable from the versions' sidecars;
// its dist-tags live in a document of their own, since they cannot be
// derived from the versions.
//
// Layout, with every name and version segment through storage.EscapeSegment:
//
//	npm/<name>/index.json                  {"versions": {"<version>": indexEntry}}
//	npm/<name>/dist-tags.json              {"<tag>": "<version>"}
//	npm/<name>/<version>/~claim            claim: the tarball's sha256
//	npm/<name>/<version>/~precedence       claim: the version holding this precedence
//	npm/<name>/<version>/~tagged           marker: the publish's tag step is done
//	npm/<name>/<version>/package.tgz       the tarball
//	npm/<name>/<version>/package.json      its sidecar
//	npm/<name>/<version>/package.sigstore  its provenance bundle, if published with one
//
// A ~precedence claim sits below the version without build metadata, so
// 1.0.0+a and 1.0.0+b compete for npm/<name>/1.0.0/~precedence.
type StorageSource struct {
	name      string
	claims    []string
	d         storage.Driver
	rec       *records.Store
	limits    archive.Limits
	maxUpload int64
	tmpDir    string
	log       *slog.Logger
	maxDoc    int64  // maxStorageDocBytes; lowered in tests
	onRender  func() // called at the start of every render; set in tests

	renders singleflight.Group // by Norm

	docs *lru.Cache[*rendered] // by Norm, at most maxRenderedBytes

	mu       sync.Mutex
	lostTags map[string]bool // Norms whose dist-tags document was missing or corrupt at the last read
	tooLarge map[string]bool // Norms whose packument exceeded maxDoc at the last render
}

var _ Publisher = (*StorageSource)(nil)

// NewStorageSource returns a storage source over d. Publishes are inspected
// with l and maxUpload, spooling the tarball to tmpDir. log nil means
// slog.Default().
func NewStorageSource(name string, claims []string, d storage.Driver, rec *records.Store, l archive.Limits, maxUpload int64, tmpDir string, log *slog.Logger) *StorageSource {
	if log == nil {
		log = slog.Default()
	}
	return &StorageSource{name: name, claims: claims, d: d, rec: rec, limits: l, maxUpload: maxUpload, tmpDir: tmpDir, log: log, maxDoc: maxStorageDocBytes,
		docs: lru.New(maxRenderedBytes, (*rendered).size), lostTags: map[string]bool{}, tooLarge: map[string]bool{}}
}

func (s *StorageSource) Name() string     { return s.name }
func (s *StorageSource) Claims() []string { return s.claims }

// sidecar is a version's record next to its tarball.
type sidecar struct {
	Version   string           `json:"version"`
	Doc       json.RawMessage  `json:"doc"` // the version object without dist
	Dist      storedDist       `json:"dist"`
	Published time.Time        `json:"published"`
	Uploader  records.Uploader `json:"uploader"`
	SHA256    string           `json:"sha256"`
	Tag       string           `json:"tag"` // the dist-tag the publish asked for
}

type storedDist struct {
	Integrity    string `json:"integrity"`
	Shasum       string `json:"shasum"`
	FileCount    int64  `json:"fileCount"`
	UnpackedSize int64  `json:"unpackedSize"`
}

// indexEntry is a version's summary in the index.
type indexEntry struct {
	Published time.Time `json:"published"`
	SHA256    string    `json:"sha256"`
}

type indexDoc struct {
	Versions map[string]indexEntry `json:"versions"`
}

func pkgPrefix(n Name) string { return "npm/" + storage.EscapeSegment(n.Norm) + "/" }
func indexKey(n Name) string  { return pkgPrefix(n) + "index.json" }
func tagsKey(n Name) string   { return pkgPrefix(n) + "dist-tags.json" }
func versionKey(n Name, v, file string) string {
	return pkgPrefix(n) + storage.EscapeSegment(v) + "/" + file
}
func precedenceKey(n Name, v Version) string {
	v.Build = ""
	return versionKey(n, v.String(), "~precedence")
}

// Publish inspects a publish body and stores its version. The same bytes
// published again are a success, and complete a publish interrupted after
// its claim; other bytes for a stored version are ErrVersionExists.
func (s *StorageSource) Publish(ctx context.Context, c identity.Caller, n Name, body *os.File, _ int64) (string, error) {
	pub, err := Inspect(body, n, s.maxUpload, s.limits, s.tmpDir)
	if err != nil {
		return "", err
	}
	defer func() { pub.Tarball.Close(); os.Remove(pub.Tarball.Name()) }() //nolint:gosec // Inspect's own temp file
	v := pub.Version.String()
	if err := s.precheck(ctx, n, pub.Version, pub.Tag); err != nil {
		return "", err
	}
	if err := s.claimPrecedence(ctx, n, pub.Version); err != nil {
		return "", err
	}
	if err := s.claim(ctx, n, v, pub.SHA256); err != nil {
		return "", err
	}
	if err := s.putIfAbsent(ctx, versionKey(n, v, "package.tgz"), pub.Tarball); err != nil {
		return "", err
	}
	if len(pub.Sigstore) > 0 {
		if err := s.putIfAbsent(ctx, versionKey(n, v, "package.sigstore"), bytes.NewReader(pub.Sigstore)); err != nil {
			return "", err
		}
	}
	up := records.UploaderFrom(c)
	// The sidecar goes last of the version's objects: an index rebuild
	// lists the versions that have one.
	sc, err := s.putSidecar(ctx, n, sidecar{
		Version: v, Doc: pub.Doc, Published: time.Now().UTC(), Uploader: up, SHA256: pub.SHA256, Tag: pub.Tag,
		Dist: storedDist{Integrity: pub.Dist.Integrity, Shasum: pub.Dist.Shasum, FileCount: pub.Dist.FileCount, UnpackedSize: pub.Dist.UnpackedSize},
	})
	if err != nil {
		return "", err
	}
	// Records go before the index: being indexed is what makes a publish
	// visible, so a retry after any failure up to here completes it.
	if err := s.rec.PutProvenance(ctx, records.Provenance{
		Ecosystem: ecoName, Package: n.Norm, Version: v, Source: s.name, SourceType: "storage",
		SHA1: pub.SHA1, SHA256: pub.SHA256, Uploader: &up,
	}); err != nil {
		return "", fmt.Errorf("record provenance: %w", err)
	}
	if err := s.rec.PutAudit(ctx, records.Audit{Time: time.Now().UTC(), Action: "publish", Ecosystem: ecoName,
		Package: n.Norm, Version: v, SHA256: pub.SHA256, Uploader: up}); err != nil {
		return "", fmt.Errorf("record audit: %w", err)
	}
	if err := s.addToIndex(ctx, n, pub.Version, sc); err != nil {
		return "", err
	}
	// A publish of these bytes that finished its tag step must not move the
	// tags again: they may have been moved on since.
	tagged := versionKey(n, v, "~tagged")
	if _, err := s.d.Stat(ctx, tagged); err == nil {
		return "", nil
	} else if !errors.Is(err, storage.ErrNotFound) {
		return "", err
	}
	notice, err := s.tagPublish(ctx, c, n, pub.Version, sc.Tag)
	if err != nil {
		return "", err
	}
	if err := s.putIfAbsent(ctx, tagged, strings.NewReader(sc.Tag)); err != nil {
		return "", err
	}
	return notice, nil
}

// precheck refuses, before anything is written, a version with the
// precedence of another one and a tag the package has no room for.
// addToIndex and the tag step check again against the state they write.
func (s *StorageSource) precheck(ctx context.Context, n Name, v Version, tag string) error {
	idx, _, _, err := s.readIndex(ctx, n)
	if err != nil {
		return err
	}
	if err := samePrecedence(idx, v); err != nil {
		return err
	}
	tags, _, _, err := s.readTags(ctx, n)
	if err != nil {
		return err
	}
	if _, ok := tags[tag]; !ok && tag != "latest" && len(tags) >= maxTags {
		return tooManyTags()
	}
	return nil
}

func tooManyTags() error { return badRequest("a package has at most %d dist-tags", maxTags) }

// samePrecedence refuses v when the index has another version of equal
// precedence: one differing only in build metadata.
func samePrecedence(idx map[string]indexEntry, v Version) error {
	for k := range idx {
		if kv, err := ParseVersion(k); err == nil && k != v.String() && Compare(kv, v) == 0 {
			return fmt.Errorf("%w: %s has the precedence of %s", ErrVersionExists, v, k)
		}
	}
	return nil
}

// claim reserves version v for a tarball. A claim already held by the same
// digest is a retry.
func (s *StorageSource) claim(ctx context.Context, n Name, v, sha string) error {
	held, err := s.reserve(ctx, versionKey(n, v, "~claim"), sha)
	if err != nil {
		return err
	}
	if held != sha {
		return fmt.Errorf("%w: %s", ErrVersionExists, v)
	}
	return nil
}

// claimPrecedence reserves the precedence of v for v, so that two versions
// differing only in build metadata are never both stored. A claim already
// held by v is a retry.
func (s *StorageSource) claimPrecedence(ctx context.Context, n Name, v Version) error {
	held, err := s.reserve(ctx, precedenceKey(n, v), v.String())
	if err != nil {
		return err
	}
	if held != v.String() {
		return fmt.Errorf("%w: %s has the precedence of %s", ErrVersionExists, v, held)
	}
	return nil
}

// reserve stores value at key unless the key exists, and returns the value
// held there.
func (s *StorageSource) reserve(ctx context.Context, key, value string) (string, error) {
	if _, err := s.d.PutIfAbsent(ctx, key, strings.NewReader(value)); !errors.Is(err, storage.ErrExists) {
		return value, err
	}
	held, _, err := s.get(ctx, key, 256)
	return string(held), err
}

func (s *StorageSource) putIfAbsent(ctx context.Context, key string, r io.Reader) error {
	if _, err := s.d.PutIfAbsent(ctx, key, r); err != nil && !errors.Is(err, storage.ErrExists) {
		return err
	}
	return nil
}

// putSidecar stores sc unless the version has a sidecar already, which it
// then returns: a resumed publish keeps the first attempt's time and tag.
func (s *StorageSource) putSidecar(ctx context.Context, n Name, sc sidecar) (sidecar, error) {
	b, err := json.Marshal(sc)
	if err != nil {
		return sidecar{}, err
	}
	_, err = s.d.PutIfAbsent(ctx, versionKey(n, sc.Version, "package.json"), bytes.NewReader(b))
	if errors.Is(err, storage.ErrExists) {
		return s.readSidecar(ctx, n, sc.Version)
	}
	return sc, err
}

func (s *StorageSource) readSidecar(ctx context.Context, n Name, v string) (sidecar, error) {
	b, _, err := s.get(ctx, versionKey(n, v, "package.json"), maxSidecarBytes)
	if err != nil {
		return sidecar{}, err
	}
	var sc sidecar
	if err := json.Unmarshal(b, &sc); err != nil {
		return sidecar{}, fmt.Errorf("npm: sidecar of %s@%s: %w", n.Norm, v, err)
	}
	return sc, nil
}

// get reads a whole object of at most limit bytes.
func (s *StorageSource) get(ctx context.Context, key string, limit int64) ([]byte, storage.Info, error) {
	rc, info, err := s.d.Get(ctx, key)
	if err != nil {
		return nil, info, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("npm: %s exceeds %d bytes", key, limit)
	}
	return b, info, err
}

// readIndex returns the versions of n (none for an unknown package) and
// the ETag of its index. A missing or corrupt index is rebuilt from the
// sidecars; rebuilt is then true and etag is the corrupt document's ETag,
// or "" when there is none.
func (s *StorageSource) readIndex(ctx context.Context, n Name) (idx map[string]indexEntry, etag string, rebuilt bool, err error) {
	b, info, err := s.get(ctx, indexKey(n), maxIndexBytes)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, "", false, err
	}
	var doc indexDoc
	if err == nil && json.Unmarshal(b, &doc) == nil && len(doc.Versions) > 0 {
		return doc.Versions, info.ETag, false, nil
	}
	idx, err = s.scan(ctx, n)
	return idx, info.ETag, true, err
}

// scan rebuilds a package's index from its sidecars, skipping a version
// that does not hold its precedence claim (the loser of a race between
// versions differing only in build metadata).
func (s *StorageSource) scan(ctx context.Context, n Name) (map[string]indexEntry, error) {
	idx := map[string]indexEntry{}
	for info, err := range s.d.List(ctx, pkgPrefix(n)) {
		if err != nil {
			return nil, err
		}
		seg, ok := strings.CutSuffix(strings.TrimPrefix(info.Key, pkgPrefix(n)), "/package.json")
		if !ok || strings.Contains(seg, "/") {
			continue
		}
		v, err := storage.UnescapeSegment(seg)
		if err != nil {
			continue
		}
		sc, err := s.readSidecar(ctx, n, v)
		if err != nil {
			s.log.Warn("npm: skipping unreadable sidecar", "source", s.name, "key", info.Key, "error", err)
			continue
		}
		pv, err := ParseVersion(sc.Version)
		if err != nil {
			s.log.Warn("npm: skipping sidecar with an invalid version", "source", s.name, "key", info.Key, "error", err)
			continue
		}
		owner, _, err := s.get(ctx, precedenceKey(n, pv), 256)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		if string(owner) != sc.Version {
			continue
		}
		idx[sc.Version] = indexEntry{Published: sc.Published, SHA256: sc.SHA256}
	}
	return idx, nil
}

// addToIndex lists version v (sidecar sc) in the index of n, writing a rebuilt index even when
// v was already in it.
func (s *StorageSource) addToIndex(ctx context.Context, n Name, v Version, sc sidecar) error {
	return s.update(ctx, indexKey(n), func() ([]byte, string, bool, error) {
		idx, etag, rebuilt, err := s.readIndex(ctx, n)
		if err != nil {
			return nil, "", false, err
		}
		if err := samePrecedence(idx, v); err != nil {
			return nil, "", false, err
		}
		if _, ok := idx[sc.Version]; ok && !rebuilt {
			return nil, "", false, nil
		}
		idx[sc.Version] = indexEntry{Published: sc.Published, SHA256: sc.SHA256}
		b, err := json.Marshal(indexDoc{Versions: idx})
		return b, etag, true, err
	})
}

// update writes key with If-Match until the write sticks: step reads the
// current state and returns the new body, the ETag it replaces ("" for
// none) and whether there is anything to write. A conflict reruns step
// after a jittered pause.
func (s *StorageSource) update(ctx context.Context, key string, step func() (body []byte, etag string, write bool, err error)) error {
	for attempt := range updateRetries {
		body, etag, write, err := step()
		if err != nil || !write {
			return err
		}
		_, err = s.d.PutIfMatch(ctx, key, bytes.NewReader(body), etag)
		if !errors.Is(err, storage.ErrPrecondition) {
			return err
		}
		// Jittered backoff: CI may publish several versions at once.
		select {
		case <-time.After(time.Duration(rand.Int64N(int64(attempt+1) * int64(20*time.Millisecond)))): //nolint:gosec // jitter, not a secret
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("npm: %s changed concurrently %d times", key, updateRetries)
}

// readTags returns the dist-tags document of n. lost reports a missing or
// corrupt one; info is then the corrupt document's, or zero.
func (s *StorageSource) readTags(ctx context.Context, n Name) (tags map[string]string, info storage.Info, lost bool, err error) {
	b, info, err := s.get(ctx, tagsKey(n), maxTagsBytes)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, storage.Info{}, true, nil
	}
	if err != nil {
		return nil, storage.Info{}, false, err
	}
	if json.Unmarshal(b, &tags) == nil && tags != nil {
		return tags, info, false, nil
	}
	return nil, info, true, nil
}

// sortedVersions returns the indexed versions by ascending precedence, ties
// in byte order.
func sortedVersions(idx map[string]indexEntry) []string {
	parsed := make(map[string]Version, len(idx))
	for k := range idx {
		parsed[k], _ = ParseVersion(k)
	}
	return slices.SortedFunc(maps.Keys(idx), func(a, b string) int {
		if c := Compare(parsed[a], parsed[b]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
}

// fallbackTags stands in for a lost dist-tags document: latest is the
// highest release, or the highest version when all are pre-releases.
func fallbackTags(idx map[string]indexEntry) map[string]string {
	var release, highest string
	for _, k := range sortedVersions(idx) {
		highest = k
		if v, _ := ParseVersion(k); !v.Prerelease() {
			release = k
		}
	}
	tags := map[string]string{}
	switch {
	case release != "":
		tags["latest"] = release
	case highest != "":
		tags["latest"] = highest
	}
	return tags
}

// tagMove is one dist-tag change; Version is "" for a removal and
// Previous "" for a new tag.
type tagMove struct{ Tag, Version, Previous string }

// moveTags applies change to the dist-tags of n, read afresh on every
// attempt; a lost document starts from fallbackTags, whose tags count as
// moves too. The moves of an attempt are audited, under the attempt's ID,
// before its write, so a failed audit leaves the tags as they were; a
// dist-tag-commit record for the ID follows the write that sticks.
func (s *StorageSource) moveTags(ctx context.Context, c identity.Caller, n Name, change func(tags map[string]string) ([]tagMove, error)) error {
	up := records.UploaderFrom(c)
	var attempt string // the ID of the attempt whose moves are audited
	err := s.update(ctx, tagsKey(n), func() ([]byte, string, bool, error) {
		attempt = ""
		tags, info, lost, err := s.readTags(ctx, n)
		if err != nil {
			return nil, "", false, err
		}
		if lost {
			idx, _, _, err := s.readIndex(ctx, n)
			if err != nil {
				return nil, "", false, err
			}
			tags = fallbackTags(idx)
		}
		// A lost document is written afresh, its fallback tags included.
		var moves []tagMove
		if lost {
			for t, v := range tags {
				moves = append(moves, tagMove{Tag: t, Version: v})
			}
		}
		changed, err := change(tags)
		if err != nil {
			return nil, "", false, err
		}
		moves = append(moves, changed...)
		if len(moves) == 0 {
			return nil, "", false, nil
		}
		if len(tags) > maxTags {
			return nil, "", false, tooManyTags()
		}
		id := crand.Text()
		for _, m := range moves {
			if err := s.rec.PutAudit(ctx, records.Audit{Time: time.Now().UTC(), Action: "dist-tag", Ecosystem: ecoName,
				Package: n.Norm, Version: m.Version, Tag: m.Tag, Previous: m.Previous, Uploader: up, Attempt: id}); err != nil {
				return nil, "", false, fmt.Errorf("record audit: %w", err)
			}
		}
		attempt = id
		return RenderDistTags(tags), info.ETag, true, nil
	})
	if err != nil {
		return err
	}
	s.noteTags(n, false)
	if attempt == "" {
		return nil
	}
	if err := s.rec.PutAudit(context.WithoutCancel(ctx), records.Audit{Time: time.Now().UTC(), Action: "dist-tag-commit", Ecosystem: ecoName,
		Package: n.Norm, Uploader: up, Attempt: attempt}); err != nil {
		s.log.Error("npm: dist-tags written but their commit record failed", "source", s.name, "package", n.Norm, "attempt", attempt, "error", err)
		return fmt.Errorf("record audit: %w", err)
	}
	return nil
}

// tagPublish applies the publish rules: a package's first version is
// latest; latest moves to v only when v is higher (otherwise the notice
// says where it stayed); any other tag moves to v.
func (s *StorageSource) tagPublish(ctx context.Context, c identity.Caller, n Name, v Version, tag string) (string, error) {
	vs := v.String()
	var notice string
	err := s.moveTags(ctx, c, n, func(tags map[string]string) ([]tagMove, error) {
		notice = ""
		var moves []tagMove
		set := func(t string) {
			moves = append(moves, tagMove{Tag: t, Version: vs, Previous: tags[t]})
			tags[t] = vs
		}
		cur, ok := tags["latest"]
		switch {
		case !ok:
			set("latest")
		case tag == "latest" && cur != vs:
			if cv, err := ParseVersion(cur); err == nil && Compare(v, cv) <= 0 {
				notice = "latest stayed at " + cur
			} else {
				set("latest")
			}
		}
		if tag != "latest" && tags[tag] != vs {
			set(tag)
		}
		return moves, nil
	})
	return notice, err
}

// SetTag points tag at an existing version. Like reads, it does not find a
// name in other than its normalised case.
func (s *StorageSource) SetTag(ctx context.Context, c identity.Caller, n Name, tag, version string) error {
	if n.Exact != n.Norm {
		return fmt.Errorf("%w: %s", resolve.ErrNotFound, n.Exact)
	}
	if !ValidTag(tag) {
		return badRequest("invalid dist-tag %q", tag)
	}
	idx, _, _, err := s.readIndex(ctx, n)
	if err != nil {
		return err
	}
	if len(idx) == 0 {
		return fmt.Errorf("%w: %s", resolve.ErrNotFound, n.Norm)
	}
	if _, ok := idx[version]; !ok {
		return badRequest("%s has no version %q", n.Norm, version)
	}
	return s.moveTags(ctx, c, n, func(tags map[string]string) ([]tagMove, error) {
		previous := tags[tag]
		if previous == version {
			return nil, nil
		}
		tags[tag] = version
		return []tagMove{{Tag: tag, Version: version, Previous: previous}}, nil
	})
}

// RemoveTag removes a dist-tag other than latest.
func (s *StorageSource) RemoveTag(ctx context.Context, c identity.Caller, n Name, tag string) error {
	if n.Exact != n.Norm {
		return fmt.Errorf("%w: %s", resolve.ErrNotFound, n.Exact)
	}
	if tag == "latest" {
		return badRequest("the latest dist-tag cannot be removed")
	}
	return s.moveTags(ctx, c, n, func(tags map[string]string) ([]tagMove, error) {
		previous, ok := tags[tag]
		if !ok {
			return nil, fmt.Errorf("%w: dist-tag %s of %s", resolve.ErrNotFound, tag, n.Norm)
		}
		delete(tags, tag)
		return []tagMove{{Tag: tag, Previous: previous}}, nil
	})
}

// noteTags records whether the dist-tags document of n was lost, for Health.
func (s *StorageSource) noteTags(n Name, lost bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if lost {
		s.lostTags[n.Norm] = true
	} else {
		delete(s.lostTags, n.Norm)
	}
}

// rendered holds the documents of one package, built from the index and
// dist-tags documents with these ETags.
type rendered struct {
	indexETag, tagsETag string
	tags                map[string]string
	versions            map[string][2]int // each full version object's offsets in full
	full, corgi         []byte
	sumFull, sumCorgi   string
	tokFull, tokCorgi   int
}

// load returns the rendered documents of n, from the cache while the index
// and dist-tags ETags still match it. Concurrent loads of a package share
// one render. A name read in other than its normalised case is not found.
func (s *StorageSource) load(ctx context.Context, n Name) (*rendered, error) {
	if n.Exact != n.Norm {
		return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, n.Exact)
	}
	iInfo, iErr := s.d.Stat(ctx, indexKey(n))
	tInfo, tErr := s.d.Stat(ctx, tagsKey(n))
	if iErr == nil && tErr == nil {
		if r, ok := s.docs.Get(n.Norm); ok && r.indexETag == iInfo.ETag && r.tagsETag == tInfo.ETag {
			return r, nil
		}
	}
	return flight.Do(ctx, &s.renders, n.Norm, func() (*rendered, error) {
		r, cacheable, err := s.render(ctx, n)
		s.mu.Lock()
		defer s.mu.Unlock()
		if errors.Is(err, errDocTooLarge) {
			s.tooLarge[n.Norm] = true
			s.docs.Delete(n.Norm)
		} else if err == nil {
			delete(s.tooLarge, n.Norm)
		}
		if err != nil {
			return nil, err
		}
		if cacheable {
			s.docs.Put(n.Norm, r)
		}
		return r, nil
	})
}

// size is what r holds in memory, near enough: its two documents.
func (r *rendered) size() int64 { return int64(len(r.full) + len(r.corgi)) }

// errDocTooLarge fails a render whose packument exceeds the source's cap.
var errDocTooLarge = errors.New("npm: packument too large")

// cappedBuffer is a bytes.Buffer that refuses to grow past max bytes.
type cappedBuffer struct {
	bytes.Buffer
	max int64
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if int64(b.Len()+len(p)) > b.max {
		return 0, fmt.Errorf("%w: exceeds %d bytes", errDocTooLarge, b.max)
	}
	return b.Buffer.Write(p)
}

// render builds the documents of n. They are cacheable when both the index
// and the dist-tags document exist, so their ETags cover every input.
func (s *StorageSource) render(ctx context.Context, n Name) (*rendered, bool, error) {
	if s.onRender != nil {
		s.onRender()
	}
	idx, indexETag, rebuilt, err := s.readIndex(ctx, n)
	if err != nil {
		return nil, false, err
	}
	if len(idx) == 0 {
		return nil, false, fmt.Errorf("%w: %s", resolve.ErrNotFound, n.Norm)
	}
	tags, tInfo, lost, err := s.readTags(ctx, n)
	if err != nil {
		return nil, false, err
	}
	s.noteTags(n, lost)
	if lost {
		tags = fallbackTags(idx)
	}
	r := &rendered{indexETag: indexETag, tagsETag: tInfo.ETag, tags: map[string]string{}, versions: map[string][2]int{}}
	for t, v := range tags {
		if _, ok := idx[v]; ok {
			r.tags[t] = v
		}
	}
	full, corgi := &cappedBuffer{max: s.maxDoc}, &cappedBuffer{max: s.maxDoc}
	dw := NewDocWriter(full, corgi)
	times := map[string]string{}
	var created, modified time.Time
	var latest map[string]json.RawMessage
	// Sidecars are read a batch at a time, concurrently within a batch, so
	// store round trips overlap while memory holds one batch.
	for batch := range slices.Chunk(sortedVersions(idx), sidecarBatch) {
		scs := make([]sidecar, len(batch))
		g, gctx := errgroup.WithContext(ctx)
		for i, v := range batch {
			g.Go(func() error {
				sc, err := s.readSidecar(gctx, n, v)
				if err != nil {
					// Indexed but unreadable: a store fault, not a miss.
					return fmt.Errorf("npm: indexed version %s@%s: %w", n.Norm, v, err)
				}
				scs[i] = sc
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return nil, false, err
		}
		for i, v := range batch {
			sc := scs[i]
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(sc.Doc, &obj); err != nil {
				return nil, false, fmt.Errorf("npm: version object of %s@%s: %w", n.Norm, v, err)
			}
			f, c, err := RenderVersion(obj, Dist{
				Tarball: BaseToken + n.Exact + "/-/" + n.TarballFile(v), Integrity: sc.Dist.Integrity, Shasum: sc.Dist.Shasum,
				FileCount: sc.Dist.FileCount, UnpackedSize: sc.Dist.UnpackedSize,
			})
			if err != nil {
				return nil, false, err
			}
			if err := dw.Version(v, f, c); err != nil {
				return nil, false, fmt.Errorf("npm: packument of %s: %w", n.Norm, err)
			}
			// DocWriter.Version ends the full document with f.
			r.versions[v] = [2]int{full.Len() - len(f), full.Len()}
			times[v] = sc.Published.UTC().Format(timeFormat)
			if created.IsZero() || sc.Published.Before(created) {
				created = sc.Published
			}
			if sc.Published.After(modified) {
				modified = sc.Published
			}
			if v == r.tags["latest"] {
				latest = obj
			}
		}
	}
	if !lost && tInfo.ModTime.After(modified) {
		modified = tInfo.ModTime
	}
	times["created"] = created.UTC().Format(timeFormat)
	times["modified"] = modified.UTC().Format(timeFormat)
	for k, raw := range latest {
		dw.Top(k, raw)
	}
	dw.Top("_id", encString(n.Exact))
	dw.Top("name", encString(n.Exact))
	if err := dw.Close(r.tags, times); err != nil {
		return nil, false, fmt.Errorf("npm: packument of %s: %w", n.Norm, err)
	}
	r.full, r.corgi = full.Bytes(), corgi.Bytes()
	r.sumFull, r.sumCorgi = sha256Hex(r.full), sha256Hex(r.corgi)
	r.tokFull, r.tokCorgi = dw.Tokens()
	return r, !rebuilt && tInfo.ETag != "", nil
}

func sha256Hex(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

// Packument returns the full or abbreviated document of n.
func (s *StorageSource) Packument(ctx context.Context, n Name, corgi bool) (Doc, error) {
	r, err := s.load(ctx, n)
	if err != nil {
		return Doc{}, err
	}
	b, sum, tok := r.full, r.sumFull, r.tokFull
	if corgi {
		b, sum, tok = r.corgi, r.sumCorgi, r.tokCorgi
	}
	return Doc{Body: io.NopCloser(bytes.NewReader(b)), Size: int64(len(b)), SHA256: sum, Tokens: tok}, nil
}

// Version returns one full version object; a tag is resolved first.
func (s *StorageSource) Version(ctx context.Context, n Name, versionOrTag string) ([]byte, error) {
	r, err := s.load(ctx, n)
	if err != nil {
		return nil, err
	}
	v := versionOrTag
	if t, ok := r.tags[versionOrTag]; ok {
		v = t
	}
	off, ok := r.versions[v]
	if !ok {
		return nil, fmt.Errorf("%w: %s@%s", resolve.ErrNotFound, n.Norm, versionOrTag)
	}
	return r.full[off[0]:off[1]:off[1]], nil
}

// DistTags returns the dist-tags of n.
func (s *StorageSource) DistTags(ctx context.Context, n Name) (map[string]string, error) {
	r, err := s.load(ctx, n)
	if err != nil {
		return nil, err
	}
	return maps.Clone(r.tags), nil
}

// Tarball streams the tarball of the indexed version whose file name is
// file.
func (s *StorageSource) Tarball(ctx context.Context, n Name, file string) (Artifact, error) {
	r, err := s.load(ctx, n)
	if err != nil {
		return Artifact{}, err
	}
	v, prefixed := strings.CutPrefix(file, n.Base+"-")
	v, suffixed := strings.CutSuffix(v, ".tgz")
	if _, ok := r.versions[v]; !prefixed || !suffixed || !ok {
		return Artifact{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, file)
	}
	key := versionKey(n, v, "package.tgz")
	rc, info, err := s.d.Get(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		// Indexed but missing: a store fault, not a miss.
		return Artifact{}, fmt.Errorf("npm: indexed object %s is missing", key)
	}
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Body: rc, Size: info.Size}, nil
}

// Health reports whether the store answers and, per package, a dist-tags
// document found missing or corrupt by the last read and a packument that
// exceeded the cap at its last render.
func (s *StorageSource) Health(ctx context.Context) []metrics.Health {
	h := []metrics.Health{{Name: s.name, Ecosystem: ecoName, OK: true, Detail: "store reachable"}}
	if err := storage.Reachable(ctx, s.d); err != nil {
		h[0].OK, h[0].Detail = false, "store unreachable"
	}
	s.mu.Lock()
	lost := slices.Sorted(maps.Keys(s.lostTags))
	large := slices.Sorted(maps.Keys(s.tooLarge))
	s.mu.Unlock()
	for _, name := range lost {
		h = append(h, metrics.Health{Name: s.name + " " + name, Ecosystem: ecoName, OK: false, Scoped: true, Packages: []string{name},
			Detail: "dist-tags document missing or corrupt; latest falls back to the highest version"})
	}
	for _, name := range large {
		h = append(h, metrics.Health{Name: s.name + " " + name, Ecosystem: ecoName, OK: false, Scoped: true, Packages: []string{name},
			Detail: fmt.Sprintf("packument exceeds %d bytes; reads of the package fail", s.maxDoc)})
	}
	return h
}
