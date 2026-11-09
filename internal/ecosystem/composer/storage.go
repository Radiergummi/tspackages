package composer

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/identity"
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
	name   string
	claims []string
	d      storage.Driver
	rec    *records.Store
	limits archive.Limits
}

var _ Source = (*StorageSource)(nil)

func NewStorageSource(name string, claims []string, d storage.Driver, rec *records.Store, l archive.Limits) *StorageSource {
	return &StorageSource{name: name, claims: claims, d: d, rec: rec, limits: l}
}

func (s *StorageSource) Name() string     { return s.name }
func (s *StorageSource) Claims() []string { return s.claims }
func (s *StorageSource) Type() string     { return "storage" }

type index struct {
	Versions []Version `json:"versions"`
}

func zipKey(name, normalized string) string {
	return "composer/" + name + "/" + storage.EscapeSegment(normalized) + ".zip"
}

func indexKey(name string) string { return "composer/" + name + "/index.json" }

// Upload validates zipData as a dist for name at version and stores it. The
// name inside composer.json must match the URL name (content binding), any
// version inside it must match too, and dev versions are refused. It returns
// ErrVersionExists, *archive.Error or *UploadError for client mistakes.
func (s *StorageSource) Upload(ctx context.Context, caller identity.Caller, name, version string, zipData []byte) (Version, error) {
	if int64(len(zipData)) > s.limits.MaxBytes {
		return Version{}, &archive.Error{Reason: fmt.Sprintf("archive exceeds %d bytes", s.limits.MaxBytes)}
	}
	pkg, err := Normalize(name)
	if err != nil {
		return Version{}, rejectUpload("%v", err)
	}
	v, normalized, err := s.inspect(pkg, version, zipData)
	if err != nil {
		return Version{}, err
	}

	if _, err := s.d.PutIfAbsent(ctx, zipKey(pkg, normalized), bytes.NewReader(zipData)); err != nil {
		if errors.Is(err, storage.ErrExists) {
			return Version{}, fmt.Errorf("%w: %s %s", ErrVersionExists, pkg, version)
		}
		return Version{}, err
	}

	sha1sum := sha1.Sum(zipData)
	if err := s.rec.PutProvenance(ctx, records.Provenance{
		Ecosystem:  "composer",
		Package:    pkg,
		Version:    version,
		Source:     s.name,
		SourceType: "storage",
		SHA1:       hex.EncodeToString(sha1sum[:]),
		SHA256:     v.Reference,
		Uploader:   records.UploaderFrom(caller),
	}); err != nil {
		return Version{}, err
	}
	if err := s.rec.PutAudit(ctx, records.Audit{
		Action:    "publish",
		Ecosystem: "composer",
		Package:   pkg,
		Version:   version,
		SHA256:    v.Reference,
		Uploader:  *records.UploaderFrom(caller),
	}); err != nil {
		return Version{}, err
	}
	if err := s.addToIndex(ctx, pkg, v); err != nil {
		return Version{}, err
	}
	return v, nil
}

// inspect validates a zip and builds its index entry; it is shared by Upload
// and Rebuild so both derive identical entries.
func (s *StorageSource) inspect(pkg, version string, zipData []byte) (Version, string, error) {
	normalized, err := NormalizeVersion(version)
	if err != nil {
		return Version{}, "", rejectUpload("%v", err)
	}
	if strings.HasSuffix(normalized, "-dev") || strings.HasPrefix(normalized, "dev-") {
		return Version{}, "", rejectUpload("dev versions cannot be uploaded: %q", version)
	}
	zr, err := archive.InspectZip(zipData, s.limits)
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
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil || meta == nil {
		return Version{}, "", rejectUpload("composer.json is not a valid JSON object")
	}
	declared, _ := meta["name"].(string)
	if strings.ToLower(declared) != pkg {
		return Version{}, "", rejectUpload("composer.json name %q does not match %q", declared, pkg)
	}
	if jv, ok := meta["version"]; ok {
		jvs, _ := jv.(string)
		if jn, err := NormalizeVersion(jvs); err != nil || jn != normalized {
			return Version{}, "", rejectUpload("composer.json version %v does not match %q", jv, version)
		}
	}

	sha256sum := sha256.Sum256(zipData)
	sha1sum := sha1.Sum(zipData)
	ref := hex.EncodeToString(sha256sum[:])
	delete(meta, "source") // never let the archive name its own origin or dist
	meta["name"] = pkg
	meta["version"] = version
	meta["version_normalized"] = normalized
	meta["dist"] = map[string]any{"type": "zip", "reference": ref, "shasum": hex.EncodeToString(sha1sum[:])}
	return Version{Package: meta, Version: version, Reference: ref}, normalized, nil
}

// addToIndex adds v to the package index, retrying when a concurrent upload
// changed it.
func (s *StorageSource) addToIndex(ctx context.Context, pkg string, v Version) error {
	for range indexRetries {
		idx, etag, err := s.loadIndex(ctx, pkg)
		if errors.Is(err, storage.ErrNotFound) {
			// No index yet: derive it from the stored zips (which include v),
			// so versions uploaded while the index was lost are not dropped.
			if idx, err = s.scan(ctx, pkg); err != nil {
				return err
			}
			etag = ""
		} else if err != nil {
			return err
		}
		idx = upsert(idx, v)
		err = s.writeIndex(ctx, pkg, idx, etag)
		if errors.Is(err, storage.ErrPrecondition) {
			continue
		}
		return err
	}
	return fmt.Errorf("composer: index of %s changed concurrently %d times", pkg, indexRetries)
}

func upsert(vs []Version, v Version) []Version {
	n := normalizedOf(v)
	if slices.ContainsFunc(vs, func(x Version) bool { return normalizedOf(x) == n }) {
		return vs
	}
	return append(vs, v)
}

func normalizedOf(v Version) string {
	s, _ := v.Package["version_normalized"].(string)
	return s
}

// loadIndex returns storage.ErrNotFound (wrapped) when there is no index.
func (s *StorageSource) loadIndex(ctx context.Context, pkg string) ([]Version, string, error) {
	rc, info, err := s.d.Get(ctx, indexKey(pkg))
	if err != nil {
		return nil, "", err
	}
	defer rc.Close()
	var idx index
	if err := json.NewDecoder(rc).Decode(&idx); err != nil {
		return nil, "", fmt.Errorf("composer: corrupt index for %s: %w", pkg, err)
	}
	return idx.Versions, info.ETag, nil
}

func (s *StorageSource) writeIndex(ctx context.Context, pkg string, vs []Version, etag string) error {
	body, err := json.Marshal(index{Versions: vs})
	if err != nil {
		return err
	}
	_, err = s.d.PutIfMatch(ctx, indexKey(pkg), bytes.NewReader(body), etag)
	return err
}

var zipKeyEncoding = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding(base32.NoPadding)

// scan rebuilds the version entries from the stored zips. The spelling of a
// version as originally uploaded is not recoverable from the zip: entries get
// the normalised version with trailing ".0" parts trimmed ("1.2.0.0" becomes
// "1.2.0"). Dist lookups ignore the spelling.
func (s *StorageSource) scan(ctx context.Context, pkg string) ([]Version, error) {
	var keys []string
	for info, err := range s.d.List(ctx, "composer/"+pkg+"/") {
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(info.Key, ".zip") {
			keys = append(keys, info.Key)
		}
	}
	var out []Version
	for _, key := range keys {
		seg := strings.TrimSuffix(key[strings.LastIndex(key, "/")+1:], ".zip")
		dec, err := zipKeyEncoding.DecodeString(seg)
		if err != nil {
			return nil, fmt.Errorf("composer: unexpected key %q", key)
		}
		rc, _, err := s.d.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		v, _, err := s.inspect(pkg, prettyVersion(string(dec)), data)
		if err != nil {
			return nil, fmt.Errorf("composer: stored archive %q is invalid: %w", key, err)
		}
		out = append(out, v)
	}
	return out, nil
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

// Rebuild rewrites the package index from the stored zips. It returns an
// error wrapping resolve.ErrNotFound when there are none.
func (s *StorageSource) Rebuild(ctx context.Context, name string) error {
	pkg, err := Normalize(name)
	if err != nil {
		return fmt.Errorf("%w: %v", resolve.ErrNotFound, err)
	}
	_, err = s.rebuild(ctx, pkg)
	return err
}

func (s *StorageSource) rebuild(ctx context.Context, pkg string) ([]Version, error) {
	for range indexRetries {
		etag := ""
		if info, err := s.d.Stat(ctx, indexKey(pkg)); err == nil {
			etag = info.ETag
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		vs, err := s.scan(ctx, pkg)
		if err != nil {
			return nil, err
		}
		if len(vs) == 0 {
			return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, pkg)
		}
		err = s.writeIndex(ctx, pkg, vs, etag)
		if errors.Is(err, storage.ErrPrecondition) {
			continue
		}
		return vs, err
	}
	return nil, fmt.Errorf("composer: index of %s changed concurrently %d times", pkg, indexRetries)
}

// Versions returns the stored versions of name, highest first (see
// compareNormalized). A missing index is rebuilt from the zips.
func (s *StorageSource) Versions(ctx context.Context, name string) ([]Version, error) {
	pkg, err := Normalize(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", resolve.ErrNotFound, err)
	}
	vs, _, err := s.loadIndex(ctx, pkg)
	if errors.Is(err, storage.ErrNotFound) {
		vs, err = s.rebuild(ctx, pkg)
	}
	if err != nil {
		return nil, err
	}
	vs = slices.Clone(vs)
	slices.SortStableFunc(vs, func(a, b Version) int {
		return compareNormalized(normalizedOf(b), normalizedOf(a))
	})
	return vs, nil
}

// Dist serves the stored zip for the version whose normalised form equals
// that of version and whose reference (sha256) equals reference.
func (s *StorageSource) Dist(ctx context.Context, name, version, reference string) (Artifact, error) {
	normalized, err := NormalizeVersion(version)
	if err != nil {
		return Artifact{}, fmt.Errorf("%w: %v", resolve.ErrNotFound, err)
	}
	vs, err := s.Versions(ctx, name)
	if err != nil {
		return Artifact{}, err
	}
	i := slices.IndexFunc(vs, func(v Version) bool { return normalizedOf(v) == normalized && v.Reference == reference })
	if i < 0 {
		return Artifact{}, fmt.Errorf("%w: %s %s", resolve.ErrNotFound, name, version)
	}
	pkg, _ := Normalize(name)
	rc, info, err := s.d.Get(ctx, zipKey(pkg, normalized))
	if errors.Is(err, storage.ErrNotFound) {
		return Artifact{}, fmt.Errorf("%w: %s %s", resolve.ErrNotFound, name, version)
	}
	if err != nil {
		return Artifact{}, err
	}
	dist, _ := vs[i].Package["dist"].(map[string]any)
	shasum, _ := dist["shasum"].(string)
	return Artifact{Body: rc, Size: info.Size, SHA1: shasum}, nil
}

// Packages lists every stored package name; storage is always enumerable.
func (s *StorageSource) Packages(ctx context.Context) ([]string, bool, error) {
	seen := map[string]bool{}
	for info, err := range s.d.List(ctx, "composer/") {
		if err != nil {
			return nil, false, err
		}
		if p := strings.Split(info.Key, "/"); len(p) == 4 {
			seen[p[1]+"/"+p[2]] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	slices.Sort(names)
	return names, true, nil
}
