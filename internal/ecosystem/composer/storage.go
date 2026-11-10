package composer

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/sync/singleflight"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

// ErrVersionExists is returned by Upload when the version is already stored.
var ErrVersionExists = errors.New("version already exists")

// UploadError is a rejected upload. Reason is safe to show to clients.
type UploadError struct{ Reason string }

func (e *UploadError) Error() string { return e.Reason }

func rejectUpload(format string, a ...any) error {
	return &UploadError{Reason: fmt.Sprintf(format, a...)}
}

const (
	indexRetries        = 5
	maxComposerJSONSize = 1 << 20
)

// StorageSource is a hosted source: CI uploads dist zips, which are stored
// immutably under
//
//	composer/<vendor>/<name>/<EscapeSegment(version_normalized)>.zip
//
// next to a rebuildable index composer/<vendor>/<name>/index.json holding
// {"versions":[Version...]}. The index is written with If-Match; the zips are
// the source of truth.
type StorageSource struct {
	name      string
	claims    []string
	d         storage.Driver
	rec       *records.Store
	limits    archive.Limits
	log       *slog.Logger
	rebuilds  singleflight.Group // per package: concurrent readers share one rebuild
	unhealthy atomic.Bool        // last Health probe failed; logs only on change
	locks     sync.Map           // "<pkg>@<normalized>" -> *sync.Mutex; serialises uploads of one version (entries are tiny and never freed)
}

// errCorruptIndex marks an index.json that cannot be decoded.
var errCorruptIndex = errors.New("composer: corrupt index")

var _ Uploader = (*StorageSource)(nil)

func NewStorageSource(name string, claims []string, d storage.Driver, rec *records.Store, l archive.Limits, log *slog.Logger) *StorageSource {
	if log == nil {
		log = slog.Default()
	}
	return &StorageSource{name: name, claims: claims, d: d, rec: rec, limits: l, log: log}
}

func (s *StorageSource) Name() string     { return s.name }
func (s *StorageSource) Claims() []string { return s.claims }

type index struct {
	Versions []Version `json:"versions"`
}

func zipKey(name, normalized string) string {
	return "composer/" + name + "/" + storage.EscapeSegment(normalized) + ".zip"
}

func indexKey(name string) string { return "composer/" + name + "/index.json" }

func metaKey(name, normalized string) string {
	return "composer/" + name + "/" + storage.EscapeSegment(normalized) + ".meta.json"
}

// sidecar records what the zip cannot: the version spelling as uploaded.
type sidecar struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func (s *StorageSource) putSidecar(ctx context.Context, pkg, normalized string, v Version) error {
	body, err := json.Marshal(sidecar{Version: v.Version, SHA256: v.Reference})
	if err != nil {
		return err
	}
	if _, err := s.d.PutIfAbsent(ctx, metaKey(pkg, normalized), bytes.NewReader(body)); err != nil && !errors.Is(err, storage.ErrExists) {
		return err
	}
	return nil
}

// Upload validates zipData as a dist for name at version and stores it. The
// name inside composer.json must match the URL name (content binding), any
// version inside it must match too, and dev versions are refused. It returns
// ErrVersionExists, *archive.Error or *UploadError for client mistakes.
//
// If the version's zip is already stored but missing from the index (a
// previous upload died between the two writes), the index is repaired first;
// the same bytes then succeed idempotently, other bytes get ErrVersionExists.
func (s *StorageSource) Upload(ctx context.Context, caller identity.Caller, name, version string, zipData []byte) (Version, error) {
	pkg, err := Normalize(name)
	if err != nil {
		return Version{}, rejectUpload("%v", err)
	}
	if version != strings.Trim(version, phpTrim) || strings.Contains(version, " as ") || strings.ContainsAny(version, "@+") {
		return Version{}, rejectUpload("version %q is not a plain version string", version)
	}
	d := sumsOf(zipData)
	v, normalized, err := s.inspect(pkg, version, zipData, &s.limits, d)
	if err != nil {
		return Version{}, err
	}

	mu, _ := s.locks.LoadOrStore(pkg+"@"+normalized, new(sync.Mutex))
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()

	if _, err := s.d.PutIfAbsent(ctx, zipKey(pkg, normalized), bytes.NewReader(zipData)); err != nil {
		if errors.Is(err, storage.ErrExists) {
			return s.repair(ctx, caller, pkg, normalized, v)
		}
		return Version{}, err
	}
	if err := s.putSidecar(ctx, pkg, normalized, v); err != nil {
		return Version{}, err
	}
	if err := s.record(ctx, caller, pkg, v, d.sha1); err != nil {
		return Version{}, err
	}
	if _, err := s.addToIndex(ctx, pkg, v); err != nil {
		return Version{}, err
	}
	return v, nil
}

// repair handles an upload whose zip already exists.
func (s *StorageSource) repair(ctx context.Context, caller identity.Caller, pkg, normalized string, v Version) (Version, error) {
	data, err := s.readZip(ctx, pkg, normalized)
	if err != nil {
		return Version{}, err
	}
	d := sumsOf(data)
	same := d.sha256 == v.Reference
	if same {
		if err := s.putSidecar(ctx, pkg, normalized, v); err != nil {
			return Version{}, err
		}
	}
	stored, err := s.entryFromZip(ctx, pkg, normalized, data, d)
	if err != nil {
		// The version exists, it is just unreadable: a conflict for the client,
		// with the reason for the server log.
		return Version{}, fmt.Errorf("%w: stored archive unreadable: %w", ErrVersionExists, err)
	}
	added, err := s.addToIndex(ctx, pkg, stored)
	if err != nil {
		return Version{}, err
	}
	exists := fmt.Errorf("%w: %s %s", ErrVersionExists, pkg, v.Version)
	if !same {
		return Version{}, exists
	}
	// Without provenance the interrupted original never recorded its publish
	// (a reader may have indexed it meanwhile): this retry completes it.
	_, err = s.rec.GetProvenance(ctx, "composer", pkg, stored.Version, stored.Reference)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		if err := s.record(ctx, caller, pkg, stored, d.sha1); err != nil {
			return Version{}, err
		}
	case err != nil:
		return Version{}, err
	case !added:
		return Version{}, exists
	}
	return stored, nil
}

func (s *StorageSource) record(ctx context.Context, caller identity.Caller, pkg string, v Version, sha1Hex string) error {
	u := records.UploaderFrom(caller)
	if err := s.rec.PutProvenance(ctx, records.Provenance{
		Ecosystem:  "composer",
		Package:    pkg,
		Version:    v.Version,
		Source:     s.name,
		SourceType: "storage",
		SHA1:       sha1Hex,
		SHA256:     v.Reference,
		Uploader:   &u,
	}); err != nil {
		return err
	}
	return s.rec.PutAudit(ctx, records.Audit{
		Action:    "publish",
		Ecosystem: "composer",
		Package:   pkg,
		Version:   v.Version,
		SHA256:    v.Reference,
		Uploader:  u,
	})
}

func (s *StorageSource) readZip(ctx context.Context, pkg, normalized string) ([]byte, error) {
	rc, _, err := s.d.Get(ctx, zipKey(pkg, normalized))
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// inspect validates a zip with digests d under limits l and builds its index
// entry; it is shared by Upload and the rebuild so both derive identical
// entries. A nil l is for archives this source already accepted once: they are
// not inspected again (and the current upload limits must not make old
// versions disappear from a rebuilt index), only composer.json is read.
func (s *StorageSource) inspect(pkg, version string, zipData []byte, l *archive.Limits, d sums) (Version, string, error) {
	normalized, err := NormalizeVersion(version)
	if err != nil {
		return Version{}, "", rejectUpload("%v", err)
	}
	if isDevVersion(normalized) {
		return Version{}, "", rejectUpload("dev versions cannot be uploaded: %q", version)
	}
	var zr *zip.Reader
	if l != nil {
		zr, err = archive.InspectZip(zipData, *l)
	} else {
		zr, err = zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	}
	if err != nil {
		return Version{}, "", err
	}
	f, err := archive.FindFile(zr, "composer.json")
	if err != nil {
		return Version{}, "", rejectUpload("archive contains no composer.json")
	}
	rc, err := f.Open()
	if err != nil {
		return Version{}, "", rejectUpload("composer.json is unreadable")
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, maxComposerJSONSize+1))
	if err != nil || len(raw) > maxComposerJSONSize {
		return Version{}, "", rejectUpload("composer.json is unreadable or larger than %d bytes", maxComposerJSONSize)
	}
	if !utf8.Valid(raw) {
		return Version{}, "", rejectUpload("composer.json is not valid UTF-8")
	}
	meta, err := parseComposerJSON(raw)
	if err != nil {
		return Version{}, "", rejectUpload("%v", err)
	}
	declared, _ := meta["name"].(string)
	if dn, err := Normalize(declared); err != nil || dn != pkg {
		return Version{}, "", rejectUpload("composer.json name %q does not match %q", declared, pkg)
	}
	if jv, ok := meta["version"]; ok {
		jvs, _ := jv.(string)
		if jn, err := NormalizeVersion(jvs); err != nil || jn != normalized {
			return Version{}, "", rejectUpload("composer.json version %v does not match %q", jv, version)
		}
	}

	pkgMap := packageEntry(meta, pkg, version, normalized, d.sha256, d.sha1)
	return Version{Package: pkgMap, Version: version, Reference: d.sha256}, normalized, nil
}

// addToIndex adds v to the package index, retrying when a concurrent upload
// changed it, and reports whether the index lacked it. A missing or corrupt
// index is first derived from the stored zips.
func (s *StorageSource) addToIndex(ctx context.Context, pkg string, v Version) (bool, error) {
	for range indexRetries {
		idx, etag, err := s.loadIndex(ctx, pkg)
		rebuilt := false // a missing or corrupt index lacked v
		switch {
		case errors.Is(err, storage.ErrNotFound), errors.Is(err, errCorruptIndex):
			// Derive from the stored zips (which include v) so versions
			// uploaded while the index was lost are not dropped.
			if idx, _, err = s.scan(ctx, pkg); err != nil {
				return false, err
			}
			rebuilt = true
		case err != nil:
			return false, err
		}
		idx, had := upsert(idx, v)
		if had && !rebuilt {
			return false, nil
		}
		err = s.writeIndex(ctx, pkg, idx, etag)
		if errors.Is(err, storage.ErrPrecondition) {
			continue
		}
		return err == nil, err
	}
	return false, fmt.Errorf("composer: index of %s changed concurrently %d times", pkg, indexRetries)
}

// upsert appends v unless an entry with its normalised version exists; had
// reports whether one did.
func upsert(vs []Version, v Version) (_ []Version, had bool) {
	n := normalizedOf(v)
	if slices.ContainsFunc(vs, func(x Version) bool { return normalizedOf(x) == n }) {
		return vs, true
	}
	return append(vs, v), false
}

func normalizedOf(v Version) string {
	s, _ := v.Package["version_normalized"].(string)
	return s
}

// loadIndex returns storage.ErrNotFound (wrapped) when there is no index and
// errCorruptIndex when it cannot be decoded or lists no version; the etag is set in the latter case.
func (s *StorageSource) loadIndex(ctx context.Context, pkg string) ([]Version, string, error) {
	rc, info, err := s.d.Get(ctx, indexKey(pkg))
	if err != nil {
		return nil, "", err
	}
	defer rc.Close()
	var idx index
	dec := json.NewDecoder(rc)
	dec.UseNumber()
	if err := dec.Decode(&idx); err != nil {
		return nil, info.ETag, fmt.Errorf("%w for %s: %w", errCorruptIndex, pkg, err)
	}
	if len(idx.Versions) == 0 { // never written: a package without versions has no index
		return nil, info.ETag, fmt.Errorf("%w for %s: no versions", errCorruptIndex, pkg)
	}
	return idx.Versions, info.ETag, nil
}

// writeIndex stores vs, sorted highest first in place, as the index of pkg.
func (s *StorageSource) writeIndex(ctx context.Context, pkg string, vs []Version, etag string) error {
	slices.SortStableFunc(vs, highestFirst)
	body, err := json.Marshal(index{Versions: vs})
	if err != nil {
		return err
	}
	_, err = s.d.PutIfMatch(ctx, indexKey(pkg), bytes.NewReader(body), etag)
	return err
}

// scan rebuilds the version entries from the stored zips, skipping (and
// returning) those that cannot be read so one bad archive does not hide the
// rest. Archives are not inspected again (see inspect). The version spelling comes
// from the sidecar; without one it is the normalised version with trailing ".0"
// parts trimmed ("1.2.0.0" becomes "1.2.0").
func (s *StorageSource) scan(ctx context.Context, pkg string) (vs []Version, skipped []error, err error) {
	var keys []string
	for info, err := range s.d.List(ctx, "composer/"+pkg+"/") {
		if err != nil {
			return nil, nil, err
		}
		if strings.HasSuffix(info.Key, ".zip") {
			keys = append(keys, info.Key)
		}
	}
	for _, key := range keys {
		seg := strings.TrimSuffix(key[strings.LastIndex(key, "/")+1:], ".zip")
		normalized, derr := storage.UnescapeSegment(seg)
		if derr != nil {
			skipped = append(skipped, fmt.Errorf("composer: unexpected key %q", key))
			continue
		}
		data, rerr := s.readZip(ctx, pkg, normalized)
		if errors.Is(rerr, context.Canceled) || errors.Is(rerr, context.DeadlineExceeded) {
			return nil, nil, rerr
		}
		var v Version
		if rerr == nil {
			v, rerr = s.entryFromZip(ctx, pkg, normalized, data, sumsOf(data))
		}
		if rerr != nil {
			skipped = append(skipped, fmt.Errorf("composer: stored archive %q skipped: %w", key, rerr))
			continue
		}
		vs = append(vs, v)
	}
	return vs, skipped, nil
}

// entryFromZip builds the index entry of a stored zip with digests d.
func (s *StorageSource) entryFromZip(ctx context.Context, pkg, normalized string, data []byte, d sums) (Version, error) {
	version := prettyVersion(normalized)
	if rc, _, err := s.d.Get(ctx, metaKey(pkg, normalized)); err == nil {
		var sc sidecar
		if json.NewDecoder(io.LimitReader(rc, 1<<16)).Decode(&sc) == nil && sc.SHA256 == d.sha256 {
			if n, err := NormalizeVersion(sc.Version); err == nil && n == normalized {
				version = sc.Version
			}
		}
		rc.Close()
	}
	v, _, err := s.inspect(pkg, version, data, nil, d)
	return v, err
}

func prettyVersion(normalized string) string {
	core, rest, hasRest := strings.Cut(normalized, "-")
	parts := strings.Split(core, ".")
	for len(parts) > 3 && parts[len(parts)-1] == "0" {
		parts = parts[:len(parts)-1]
	}
	v := strings.Join(parts, ".")
	if hasRest {
		v += "-" + rest
	}
	if n, err := NormalizeVersion(v); err != nil || n != normalized {
		return normalized
	}
	return v
}

type rebuilt struct {
	vs  []Version
	err error // skipped archives
}

const rebuildTimeout = 2 * time.Minute

// rebuild rewrites the package index from the stored zips, unless an index
// appeared in the meantime, which is used as is. Archives that cannot be read
// are left out and reported in the returned error (the index is still
// written); it wraps resolve.ErrNotFound when there are no archives.
//
// It is shared per package: concurrent callers wait for one rebuild. It runs
// detached from the first caller's context (bounded by rebuildTimeout) so that
// caller giving up does not fail the others; each caller still stops waiting
// when its own ctx ends.
func (s *StorageSource) rebuild(ctx context.Context, pkg string) ([]Version, error) {
	ch := s.rebuilds.DoChan(pkg, func() (any, error) {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rebuildTimeout)
		defer cancel()
		if vs, _, err := s.loadIndex(rctx, pkg); err == nil {
			return rebuilt{vs: vs}, nil
		}
		vs, skipped, err := s.doRebuild(rctx, pkg)
		return rebuilt{vs: vs, err: errors.Join(skipped...)}, err
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		r := res.Val.(rebuilt)
		return r.vs, r.err
	}
}

// doRebuild takes the index etag before listing the zips, so an upload that
// completes while it scans changes the etag and makes the write retry instead
// of being overwritten.
func (s *StorageSource) doRebuild(ctx context.Context, pkg string) ([]Version, []error, error) {
	for range indexRetries {
		etag := ""
		if info, err := s.d.Stat(ctx, indexKey(pkg)); err == nil {
			etag = info.ETag
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, nil, err
		}
		vs, skipped, err := s.scan(ctx, pkg)
		if err != nil {
			return nil, nil, err
		}
		if len(vs) == 0 {
			if len(skipped) > 0 {
				return nil, nil, fmt.Errorf("composer: no readable archive for %s: %w", pkg, errors.Join(skipped...))
			}
			return nil, nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, pkg)
		}
		err = s.writeIndex(ctx, pkg, vs, etag)
		if errors.Is(err, storage.ErrPrecondition) {
			continue
		}
		return vs, skipped, err
	}
	return nil, nil, fmt.Errorf("composer: index of %s changed concurrently %d times", pkg, indexRetries)
}

// Versions returns the stored versions of name, highest first (see
// compareNormalized). Uploads are never dev versions, so dev=true yields an
// empty list for a known name. A missing or corrupt index is rebuilt from the
// zips; an unknown name costs one Get of index.json plus one List.
func (s *StorageSource) Versions(ctx context.Context, name string, dev bool) ([]Version, error) {
	pkg, err := lookupName(name)
	if err != nil {
		return nil, err
	}
	vs, err := s.versions(ctx, pkg)
	if err != nil || !dev {
		return vs, err
	}
	return []Version{}, nil
}

func (s *StorageSource) versions(ctx context.Context, pkg string) ([]Version, error) {
	vs, _, err := s.loadIndex(ctx, pkg)
	if errors.Is(err, storage.ErrNotFound) || errors.Is(err, errCorruptIndex) {
		vs, err = s.rebuild(ctx, pkg)
		if len(vs) > 0 { // skipped archives are not fatal here
			err = nil
		}
	}
	if err != nil {
		return nil, err
	}
	// Indexes are written sorted; one written otherwise is sorted here. A
	// rebuilt list is shared with concurrent callers, so sort a copy.
	if !slices.IsSortedFunc(vs, highestFirst) {
		vs = slices.Clone(vs)
		slices.SortStableFunc(vs, highestFirst)
	}
	return vs, nil
}

// highestFirst orders versions by their normalised form, highest first.
func highestFirst(a, b Version) int { return compareNormalized(normalizedOf(b), normalizedOf(a)) }

// Dist serves the stored zip for the version whose normalised form equals
// that of version and whose reference (sha256) equals reference.
func (s *StorageSource) Dist(ctx context.Context, name, version, reference string) (Artifact, error) {
	normalized, err := NormalizeVersion(version)
	if err != nil {
		return Artifact{}, fmt.Errorf("%w: %w", resolve.ErrNotFound, err)
	}
	pkg, err := lookupName(name)
	if err != nil {
		return Artifact{}, err
	}
	vs, err := s.versions(ctx, pkg)
	if err != nil {
		return Artifact{}, err
	}
	if !slices.ContainsFunc(vs, func(v Version) bool { return normalizedOf(v) == normalized && v.Reference == reference }) {
		return Artifact{}, fmt.Errorf("%w: %s %s", resolve.ErrNotFound, name, version)
	}
	rc, info, err := s.d.Get(ctx, zipKey(pkg, normalized))
	if errors.Is(err, storage.ErrNotFound) {
		return Artifact{}, fmt.Errorf("%w: %s %s", resolve.ErrNotFound, name, version)
	}
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Body: rc, Size: info.Size}, nil
}

// Health is OK if the store answers a Stat (a miss counts as success).
func (s *StorageSource) Health(ctx context.Context) []metrics.Health {
	h := metrics.Health{Name: s.name, OK: true, Detail: "store reachable"}
	if err := storage.Reachable(ctx, s.d); err != nil {
		h.OK, h.Detail = false, "unreachable"
		if s.unhealthy.CompareAndSwap(false, true) {
			s.log.Warn("composer storage source unreachable", "source", s.name, "error", err)
		}
	} else {
		s.unhealthy.Store(false)
	}
	return []metrics.Health{h}
}
