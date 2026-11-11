package pypi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/digest"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

// indexRetries bounds If-Match retries of a project index write.
const indexRetries = 8

// StorageSource holds uploaded distributions in a store. Files are
// immutable; a project's index is rebuildable from the files' sidecars.
//
// Layout, with every segment through storage.EscapeSegment:
//
//	pypi/<name>/index.json                         {"files": [storedFile...]}
//	pypi/<name>/<canonical>/<filename>             the file
//	pypi/<name>/<canonical>/<filename>.json        its sidecar (storedFile)
//	pypi/<name>/<canonical>/<filename>.metadata    its core metadata, if static
//	pypi/<name>/<canonical>/<filename>.attestations
//	pypi/<name>/<canonical>/~sdist                 claim: the release's sdist
//	pypi/<name>/<canonical>/~wheel-<tags>          claim: its wheel for <tags>
type StorageSource struct {
	name   string
	claims []string
	d      storage.Driver
	rec    *records.Store
	limits archive.Limits
	log    *slog.Logger
}

var (
	_ Uploader = (*StorageSource)(nil)
	_ Lister   = (*StorageSource)(nil)
)

// NewStorageSource returns a storage source over d. log nil means
// slog.Default().
func NewStorageSource(name string, claims []string, d storage.Driver, rec *records.Store, l archive.Limits, log *slog.Logger) *StorageSource {
	if log == nil {
		log = slog.Default()
	}
	return &StorageSource{name: name, claims: claims, d: d, rec: rec, limits: l, log: log}
}

func (s *StorageSource) Name() string     { return s.name }
func (s *StorageSource) Claims() []string { return s.claims }

// storedFile is a file's sidecar and index entry.
type storedFile struct {
	Filename       string    `json:"filename"`
	Version        string    `json:"version"` // canonical
	SHA256         string    `json:"sha256"`
	RequiresPython string    `json:"requires_python,omitempty"`
	Size           int64     `json:"size"`
	UploadTime     time.Time `json:"upload_time"`
	CoreMetadata   string    `json:"core_metadata,omitempty"`
}

func (f storedFile) file() File {
	return File{Filename: f.Filename, SHA256: f.SHA256, RequiresPython: f.RequiresPython, Yanked: false,
		UploadTime: f.UploadTime, Size: f.Size, CoreMetadata: f.CoreMetadata}
}

func projectPrefix(name string) string { return "pypi/" + storage.EscapeSegment(name) + "/" }
func indexKey(name string) string      { return projectPrefix(name) + "index.json" }
func releasePrefix(name, canonical string) string {
	return projectPrefix(name) + storage.EscapeSegment(canonical) + "/"
}
func fileKey(name, canonical, filename string) string {
	return releasePrefix(name, canonical) + storage.EscapeSegment(filename)
}

// distribution is an upload's filename taken apart.
type distribution struct {
	name, version string // normalised name, canonical version
	display       string // normalised version as written, for records
	sdist         bool
	tags          string // wheels: python-abi-platform, lowercased
}

func parseDistribution(filename string) (distribution, error) {
	if w, err := ParseWheelFilename(filename); err == nil {
		n, err := Normalize(w.Name)
		if err != nil {
			return distribution{}, err
		}
		v, err := ParseVersion(w.Version)
		if err != nil {
			return distribution{}, err
		}
		return distribution{name: n, version: v.Canonical(), display: v.String(), tags: strings.ToLower(strings.Join(w.Tags, "-"))}, nil
	}
	n, ver, err := ParseSdistFilename(filename)
	if err != nil {
		return distribution{}, fmt.Errorf("%q is neither a wheel nor a .tar.gz sdist", filename)
	}
	name, _ := Normalize(n) // ParseSdistFilename checked it
	v, _ := ParseVersion(ver)
	return distribution{name: name, version: v.Canonical(), display: v.String(), sdist: true}, nil
}

// Upload checks a distribution against its form fields and its own metadata
// and stores it.
func (s *StorageSource) Upload(ctx context.Context, caller identity.Caller, u Upload) (File, error) {
	name, err := Normalize(u.Name)
	if err != nil {
		return File{}, &UploadError{err.Error()}
	}
	formVersion, err := ParseVersion(u.Version)
	if err != nil {
		return File{}, &UploadError{err.Error()}
	}
	dist, err := parseDistribution(u.Filename)
	if err != nil {
		return File{}, &UploadError{err.Error()}
	}
	if dist.name != name || dist.version != formVersion.Canonical() {
		return File{}, &UploadError{fmt.Sprintf("filename %q does not match project %q version %q", u.Filename, u.Name, u.Version)}
	}
	data, err := io.ReadAll(io.LimitReader(u.Content, s.limits.MaxBytes+1))
	if err != nil {
		return File{}, err
	}
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	if u.SHA256 != "" && !strings.EqualFold(u.SHA256, sha) {
		return File{}, &UploadError{"sha256_digest does not match the uploaded file"}
	}
	rawMeta, err := s.inspect(data, dist)
	if err != nil {
		return File{}, err
	}
	meta, err := ParseMetadata(rawMeta)
	if err != nil {
		return File{}, &UploadError{err.Error()}
	}
	metaName, err := Normalize(meta.Name)
	if err != nil || metaName != name {
		return File{}, &UploadError{fmt.Sprintf("metadata names %q, not %q", meta.Name, name)}
	}
	if mv, err := ParseVersion(meta.Version); err != nil || mv.Canonical() != dist.version {
		return File{}, &UploadError{fmt.Sprintf("metadata has version %q, not %q", meta.Version, u.Version)}
	}

	if err := s.claim(ctx, name, dist, u.Filename); err != nil {
		return File{}, err
	}
	key := fileKey(name, dist.version, u.Filename)
	if _, err := s.d.PutIfAbsent(ctx, key, bytes.NewReader(data)); errors.Is(err, storage.ErrExists) {
		if err := s.resumable(ctx, key, sha); err != nil {
			return File{}, err
		}
	} else if err != nil {
		return File{}, err
	}
	sf := storedFile{Filename: u.Filename, Version: dist.version, SHA256: sha, RequiresPython: meta.RequiresPython,
		Size: int64(len(data)), UploadTime: time.Now().UTC()}
	if staticMetadata(dist, meta) {
		sf.CoreMetadata = digestOf(rawMeta)
		if err := s.putIfAbsent(ctx, key+".metadata", rawMeta); err != nil {
			return File{}, err
		}
	}
	if len(u.Attestations) > 0 {
		if err := s.putIfAbsent(ctx, key+".attestations", u.Attestations); err != nil {
			return File{}, err
		}
	}
	sidecar, _ := json.Marshal(sf)
	if err := s.putIfAbsent(ctx, key+".json", sidecar); err != nil {
		return File{}, err
	}
	if err := s.addToIndex(ctx, name, sf); err != nil {
		return File{}, err
	}
	up := records.UploaderFrom(caller)
	if err := s.rec.PutProvenance(ctx, records.Provenance{
		Ecosystem: ecoName, Package: name, Version: dist.display, Source: s.name, SourceType: "storage",
		SHA256: sha, Uploader: &up,
	}); err != nil {
		return File{}, fmt.Errorf("record provenance: %w", err)
	}
	if err := s.rec.PutAudit(ctx, records.Audit{Time: time.Now().UTC(), Action: "publish", Ecosystem: ecoName,
		Package: name, Version: dist.display, SHA256: sha, Uploader: up}); err != nil {
		return File{}, fmt.Errorf("record audit: %w", err)
	}
	return sf.file(), nil
}

// inspect checks the archive and returns its core metadata: a wheel's
// <name>-<version>.dist-info/METADATA or an sdist's <top>/PKG-INFO.
func (s *StorageSource) inspect(data []byte, dist distribution) ([]byte, error) {
	if !dist.sdist {
		zr, err := archive.InspectZip(data, s.limits)
		if err != nil {
			return nil, err
		}
		var found []byte
		for _, f := range zr.File {
			dir, base, ok := strings.Cut(f.Name, "/")
			if !ok || base != "METADATA" || !strings.HasSuffix(dir, ".dist-info") {
				continue
			}
			if found != nil {
				return nil, &UploadError{"wheel has more than one .dist-info/METADATA"}
			}
			rc, err := f.Open()
			if err != nil {
				return nil, &archive.Error{Reason: "wheel METADATA is unreadable"}
			}
			found, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, &archive.Error{Reason: "wheel METADATA is unreadable"}
			}
		}
		if found == nil {
			return nil, &UploadError{"wheel has no .dist-info/METADATA"}
		}
		return found, nil
	}
	files, err := archive.InspectTarGz(bytes.NewReader(data), s.limits, func(name string) bool {
		dir, base, ok := strings.Cut(name, "/")
		return ok && dir != "" && base == "PKG-INFO"
	})
	if err != nil {
		return nil, err
	}
	if len(files) != 1 {
		return nil, &UploadError{"sdist must hold exactly one <name>-<version>/PKG-INFO"}
	}
	for _, b := range files {
		return b, nil
	}
	return nil, nil
}

// staticMetadata reports whether the metadata can be served as the file's
// core metadata: always for wheels, for sdists only from metadata 2.2 on
// with static dependencies (PEP 643).
func staticMetadata(dist distribution, m Metadata) bool {
	if !dist.sdist {
		return true
	}
	v, err := ParseVersion(m.MetadataVersion)
	if err != nil || versionLess(v, "2.2") {
		return false
	}
	return !slices.ContainsFunc(m.Dynamic, func(f string) bool { return strings.EqualFold(f, "Requires-Dist") })
}

func versionLess(v Version, than string) bool {
	t, _ := ParseVersion(than)
	for i := range max(len(v.release), len(t.release)) {
		a, b := 0, 0
		if i < len(v.release) {
			a = v.release[i]
		}
		if i < len(t.release) {
			b = t.release[i]
		}
		if a != b {
			return a < b
		}
	}
	return false
}

func digestOf(b []byte) string { _, s := digest.Of(b); return s }

// claim reserves the release's sdist, or its wheel for these tags, for
// filename. A claim already held by the same filename is a retry.
func (s *StorageSource) claim(ctx context.Context, name string, dist distribution, filename string) error {
	key := releasePrefix(name, dist.version) + "~sdist"
	if !dist.sdist {
		key = releasePrefix(name, dist.version) + storage.EscapeSegment("~wheel-"+dist.tags)
	}
	if _, err := s.d.PutIfAbsent(ctx, key, strings.NewReader(filename)); err == nil {
		return nil
	} else if !errors.Is(err, storage.ErrExists) {
		return err
	}
	rc, _, err := s.d.Get(ctx, key)
	if err != nil {
		return err
	}
	defer rc.Close()
	held, err := io.ReadAll(io.LimitReader(rc, 1024))
	if err != nil {
		return err
	}
	if string(held) != filename {
		return ErrFileExists
	}
	return nil
}

// resumable decides about a file that is already stored: a finished upload
// (its sidecar exists) makes this one a duplicate; an interrupted one with the
// same bytes is completed by this one.
func (s *StorageSource) resumable(ctx context.Context, key, sha string) error {
	if _, err := s.d.Stat(ctx, key+".json"); err == nil {
		return ErrFileExists
	} else if !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	rc, _, err := s.d.Get(ctx, key)
	if err != nil {
		return err
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != sha {
		return ErrFileExists
	}
	return nil
}

func (s *StorageSource) putIfAbsent(ctx context.Context, key string, b []byte) error {
	if _, err := s.d.PutIfAbsent(ctx, key, bytes.NewReader(b)); err != nil && !errors.Is(err, storage.ErrExists) {
		return err
	}
	return nil
}

func (s *StorageSource) readSidecar(ctx context.Context, fileKey string) (storedFile, error) {
	rc, _, err := s.d.Get(ctx, fileKey+".json")
	if err != nil {
		return storedFile{}, err
	}
	defer rc.Close()
	var sf storedFile
	err = json.NewDecoder(io.LimitReader(rc, 1<<20)).Decode(&sf)
	return sf, err
}

type indexDoc struct {
	Files []storedFile `json:"files"`
}

func (s *StorageSource) loadIndex(ctx context.Context, name string) ([]storedFile, string, error) {
	rc, info, err := s.d.Get(ctx, indexKey(name))
	if err != nil {
		return nil, "", err
	}
	defer rc.Close()
	var doc indexDoc
	if err := json.NewDecoder(rc).Decode(&doc); err != nil || len(doc.Files) == 0 {
		return nil, info.ETag, errCorruptIndex
	}
	return doc.Files, info.ETag, nil
}

var errCorruptIndex = errors.New("pypi: corrupt or empty index")

// scan rebuilds a project's file list from the sidecars.
func (s *StorageSource) scan(ctx context.Context, name string) ([]storedFile, error) {
	var out []storedFile
	for info, err := range s.d.List(ctx, projectPrefix(name)) {
		if err != nil {
			return nil, err
		}
		if !strings.HasSuffix(info.Key, ".json") || strings.HasSuffix(info.Key, "/index.json") {
			continue
		}
		sf, err := s.readSidecar(ctx, strings.TrimSuffix(info.Key, ".json"))
		if err != nil {
			s.log.Warn("pypi: skipping unreadable sidecar", "source", s.name, "key", info.Key, "error", err)
			continue
		}
		out = append(out, sf)
	}
	return out, nil
}

func (s *StorageSource) addToIndex(ctx context.Context, name string, sf storedFile) error {
	for range indexRetries {
		files, etag, err := s.loadIndex(ctx, name)
		switch {
		case errors.Is(err, storage.ErrNotFound), errors.Is(err, errCorruptIndex):
			// The sidecars (sf's included) are the record; derive from them.
			if files, err = s.scan(ctx, name); err != nil {
				return err
			}
		case err != nil:
			return err
		}
		if !slices.ContainsFunc(files, func(f storedFile) bool { return f.Filename == sf.Filename }) {
			files = append(files, sf)
		}
		body, _ := json.Marshal(indexDoc{Files: files})
		_, err = s.d.PutIfMatch(ctx, indexKey(name), bytes.NewReader(body), etag)
		if errors.Is(err, storage.ErrPrecondition) {
			continue
		}
		return err
	}
	return fmt.Errorf("pypi: index of %s changed concurrently %d times", name, indexRetries)
}

func (s *StorageSource) files(ctx context.Context, name string) ([]storedFile, error) {
	files, _, err := s.loadIndex(ctx, name)
	if errors.Is(err, storage.ErrNotFound) || errors.Is(err, errCorruptIndex) {
		files, err = s.scan(ctx, name)
	}
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, name)
	}
	return files, nil
}

// Project lists the stored files of name.
func (s *StorageSource) Project(ctx context.Context, name string) (Project, error) {
	files, err := s.files(ctx, name)
	if err != nil {
		return Project{}, err
	}
	p := Project{Name: name}
	for _, f := range files {
		p.Files = append(p.Files, f.file())
		if !slices.Contains(p.Versions, f.Version) {
			p.Versions = append(p.Versions, f.Version)
		}
	}
	return p, nil
}

func (s *StorageSource) lookup(ctx context.Context, name, filename string) (storedFile, error) {
	files, err := s.files(ctx, name)
	if err != nil {
		return storedFile{}, err
	}
	i := slices.IndexFunc(files, func(f storedFile) bool { return f.Filename == filename })
	if i < 0 {
		return storedFile{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, filename)
	}
	return files[i], nil
}

func (s *StorageSource) open(ctx context.Context, key string) (Artifact, error) {
	rc, info, err := s.d.Get(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		// Listed in the index but missing: a store fault, not a miss.
		return Artifact{}, fmt.Errorf("pypi: indexed object %s is missing", key)
	}
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Body: rc, Size: info.Size}, nil
}

// File streams a stored file.
func (s *StorageSource) File(ctx context.Context, name, filename string) (Artifact, error) {
	f, err := s.lookup(ctx, name, filename)
	if err != nil {
		return Artifact{}, err
	}
	return s.open(ctx, fileKey(name, f.Version, filename))
}

// Metadata streams a file's core metadata when it was stored.
func (s *StorageSource) Metadata(ctx context.Context, name, filename string) (Artifact, error) {
	f, err := s.lookup(ctx, name, filename)
	if err != nil {
		return Artifact{}, err
	}
	if f.CoreMetadata == "" {
		return Artifact{}, fmt.Errorf("%w: no metadata for %s", resolve.ErrNotFound, filename)
	}
	return s.open(ctx, fileKey(name, f.Version, filename)+".metadata")
}

// Provenance is not served: uploaded attestations are kept but not verified.
func (s *StorageSource) Provenance(_ context.Context, _, filename string) (Artifact, error) {
	return Artifact{}, fmt.Errorf("%w: no provenance for %s", resolve.ErrNotFound, filename)
}

// Names lists the projects with an index.
func (s *StorageSource) Names(ctx context.Context) ([]string, error) {
	var names []string
	for info, err := range s.d.List(ctx, "pypi/") {
		if err != nil {
			return nil, err
		}
		seg, rest, ok := strings.Cut(strings.TrimPrefix(info.Key, "pypi/"), "/")
		if !ok || rest != "index.json" {
			continue
		}
		if n, err := storage.UnescapeSegment(seg); err == nil {
			names = append(names, n)
		}
	}
	return names, nil
}

// Health reports whether the store answers.
func (s *StorageSource) Health(ctx context.Context) []metrics.Health {
	if err := storage.Reachable(ctx, s.d); err != nil {
		return []metrics.Health{{Name: s.name, OK: false, Detail: "store unreachable"}}
	}
	return []metrics.Health{{Name: s.name, OK: true, Detail: "store reachable"}}
}
