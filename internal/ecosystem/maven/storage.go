package maven

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

const (
	// updateRetries bounds If-Match retries of an index or file write.
	updateRetries = 8

	maxIndexBytes   = 32 << 20
	maxSidecarBytes = 64 << 10

	sidecarSuffix = ".json"
	// maxFileName is the longest stored file name in bytes: its escaped
	// form plus sidecarSuffix must fit one key segment.
	maxFileName = (storage.MaxSegment - len(sidecarSuffix)) * 5 / 8
)

// StorageSource holds deployed artifacts in a store. Release files are
// written once; SNAPSHOT files may be overwritten. A version is listed in
// artifact-level metadata once its POM is stored; an artifact's index is
// rebuildable from the ~pom claims and the POMs' sidecars.
//
// Layout, with every coordinate and file name through storage.EscapeSegment:
//
//	maven/<g>/<a>/index.json             {"versions": {"<v>": indexEntry}}
//	maven/<g>/<a>/<v>/~pom               claim: the sha256 of the version's first POM
//	maven/<g>/<a>/<v>/files/<file>       the file
//	maven/<g>/<a>/<v>/files/<file>.json  its sidecar
//	maven/~case/<lower g:a>              claim: "<g>:<a>" in the case first deployed
type StorageSource struct {
	name      string
	claims    []string
	d         storage.Driver
	rec       *records.Store
	maxUpload int64
	log       *slog.Logger

	mu   sync.Mutex
	meta map[string]renderedMeta // artifact-level metadata by "<g>:<a>"
}

// renderedMeta is artifact-level metadata rendered from the index with
// this ETag.
type renderedMeta struct {
	etag string
	body []byte
}

var _ Deployer = (*StorageSource)(nil)

// NewStorageSource returns a storage source over d. Deployed files are
// capped at maxUpload bytes. log nil means slog.Default().
func NewStorageSource(name string, claims []string, d storage.Driver, rec *records.Store, maxUpload int64, log *slog.Logger) *StorageSource {
	if log == nil {
		log = slog.Default()
	}
	return &StorageSource{name: name, claims: claims, d: d, rec: rec, maxUpload: maxUpload, log: log, meta: map[string]renderedMeta{}}
}

func (s *StorageSource) Name() string     { return s.name }
func (s *StorageSource) Claims() []string { return s.claims }

// sidecar is a stored file's record. ETag is the file's ETag when the
// sidecar was written: a file whose ETag differs holds other bytes (a
// SNAPSHOT overwrite between its file and sidecar writes).
type sidecar struct {
	Size     int64            `json:"size"`
	Digests  sidecarDigests   `json:"digests"`
	Uploaded time.Time        `json:"uploaded"`
	Uploader records.Uploader `json:"uploader"`
	ETag     string           `json:"etag"`
}

type sidecarDigests struct {
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
	MD5    string `json:"md5"`
}

func (d sidecarDigests) digests() Digests {
	return Digests(d)
}

// indexEntry is a version with a stored POM: when its newest POM was
// stored, and the packaging that POM declares.
type indexEntry struct {
	POM       time.Time `json:"pom"`
	Packaging string    `json:"packaging"`
}

type indexDoc struct {
	Versions map[string]indexEntry `json:"versions"`
}

func artifactPrefix(c Coords) string {
	return "maven/" + storage.EscapeSegment(c.Group) + "/" + storage.EscapeSegment(c.Artifact) + "/"
}
func indexKey(c Coords) string { return artifactPrefix(c) + "index.json" }
func versionPrefix(c Coords) string {
	return artifactPrefix(c) + storage.EscapeSegment(c.Version) + "/"
}
func pomClaimKey(c Coords) string { return versionPrefix(c) + "~pom" }
func filesPrefix(c Coords) string { return versionPrefix(c) + "files/" }
func fileKey(c Coords, file string) string {
	return filesPrefix(c) + storage.EscapeSegment(file)
}
func sidecarKey(c Coords, file string) string { return fileKey(c, file) + sidecarSuffix }
func caseKey(c Coords) string                 { return "maven/~case/" + storage.EscapeSegment(c.Key()) }

// fileParts splits a file name ParsePath accepted for c into its version
// (c.Version, or the timestamped version of a SNAPSHOT file), classifier and
// extension.
func fileParts(c Coords, name string) (value, classifier, ext string) {
	rest := strings.TrimPrefix(name, c.Artifact+"-")
	if r, ok := strings.CutPrefix(rest, c.Version); ok {
		value, rest = c.Version, r
	} else {
		base := strings.TrimSuffix(c.Version, snapshotSfx)
		r = strings.TrimPrefix(rest, base+"-")
		m := timestampRE.FindString(r)
		value, rest = base+"-"+m, r[len(m):]
	}
	if cl, after, ok := strings.Cut(rest, "."); ok && strings.HasPrefix(cl, "-") {
		classifier, rest = cl[1:], "."+after
	}
	return value, classifier, strings.TrimPrefix(rest, ".")
}

// Deploy stores one PUT. Checksums are compared with the stored file's
// (an uploaded maven-metadata.xml's only checked for form) and discarded;
// an uploaded maven-metadata.xml is inspected and discarded; a POM or
// .module is inspected; every other file is stored as uploaded.
func (s *StorageSource) Deploy(ctx context.Context, c identity.Caller, p Path, body *os.File, size int64) error {
	switch {
	case p.Checksum != "":
		return s.checkChecksum(ctx, p, body)
	case p.Kind != KindFile:
		_, err := InspectMetadataUpload(body, p)
		return err
	case size > s.maxUpload:
		return &RequestError{Status: 413, Title: "Payload Too Large", Detail: fmt.Sprintf("%s exceeds %d bytes", p.File, s.maxUpload)}
	case len(p.Coords.Group)+1+len(p.Coords.Artifact) > MaxPart:
		// "<g>:<a>" is one key segment of the case claim and the records.
		return badRequest("%s:%s is longer than %d bytes", p.Coords.Group, p.Coords.Artifact, MaxPart)
	case len(p.File) > maxFileName:
		return badRequest("file name %s is longer than %d bytes", p.File, maxFileName)
	}
	if err := s.guardCase(ctx, p.Coords); err != nil {
		return err
	}
	_, classifier, ext := fileParts(p.Coords, p.File)
	isPOM := classifier == "" && ext == "pom"
	var info POMInfo
	var err error
	switch {
	case isPOM:
		info, err = InspectPOM(body, p)
	case classifier == "" && ext == "module":
		err = InspectModule(body, p)
	}
	if err != nil {
		return err
	}
	sc, previous, err := s.storeFile(ctx, c, p, body)
	if err != nil {
		return err
	}
	if isPOM {
		if _, err := s.d.PutIfAbsent(ctx, pomClaimKey(p.Coords), strings.NewReader(sc.Digests.SHA256)); err != nil && !errors.Is(err, storage.ErrExists) {
			return err
		}
	}
	// Records go before the index: being indexed is what lists a version,
	// so a retry after any failure up to here completes the deploy.
	pkg := p.Coords.Group + ":" + p.Coords.Artifact
	up := records.UploaderFrom(c)
	if err := s.rec.PutProvenance(ctx, records.Provenance{
		Ecosystem: ecoName, Package: pkg, Version: p.Coords.Version, File: p.File, Source: s.name, SourceType: "storage",
		SHA1: sc.Digests.SHA1, SHA256: sc.Digests.SHA256, Uploader: &up,
	}); err != nil {
		return fmt.Errorf("record provenance: %w", err)
	}
	if err := s.rec.PutAudit(ctx, records.Audit{Time: time.Now().UTC(), Action: "deploy", Ecosystem: ecoName,
		Package: pkg, Version: p.Coords.Version, File: p.File, SHA256: sc.Digests.SHA256, Uploader: up, Previous: previous}); err != nil {
		return fmt.Errorf("record audit: %w", err)
	}
	if isPOM {
		return s.addToIndex(ctx, p.Coords, sc.Uploaded, info.Packaging)
	}
	return nil
}

// checkChecksum compares an uploaded checksum of a file with the file's
// stored digests; one of maven-metadata.xml is checked only for form, as
// tspackages serves its own metadata.
func (s *StorageSource) checkChecksum(ctx context.Context, p Path, body io.Reader) error {
	if p.Kind != KindFile {
		return InspectChecksumUpload(body, p.Checksum, Digests{})
	}
	d, err := s.Digests(ctx, p)
	if errors.Is(err, resolve.ErrNotFound) {
		return badRequest("upload %s first", p.File)
	}
	if err != nil {
		return err
	}
	return InspectChecksumUpload(body, p.Checksum, d)
}

// guardCase refuses coordinates that differ only in case from ones deployed
// before: clients on case-insensitive filesystems could not keep both.
func (s *StorageSource) guardCase(ctx context.Context, c Coords) error {
	exact := c.Group + ":" + c.Artifact
	held, err := s.reserve(ctx, caseKey(c), exact)
	if err != nil {
		return err
	}
	if held != exact {
		return &RequestError{Status: 409, Title: "Conflict", Detail: exact + " differs only in case from " + held}
	}
	return nil
}

// reserve stores value at key unless the key exists, and returns the value
// held there.
func (s *StorageSource) reserve(ctx context.Context, key, value string) (string, error) {
	if _, err := s.d.PutIfAbsent(ctx, key, strings.NewReader(value)); !errors.Is(err, storage.ErrExists) {
		return value, err
	}
	held, _, err := s.get(ctx, key, 1024)
	return string(held), err
}

// storeFile stores body as p's file, then its sidecar, and returns the
// sidecar in effect and, when it replaced a SNAPSHOT file, the replaced
// sha256. The same bytes again are a success that keeps the first sidecar;
// other bytes are ErrExists for a release file and replace a SNAPSHOT file.
// A stored file is compared by its sidecar when the sidecar was written for
// it, by its bytes otherwise. A concurrent change of the file or its
// sidecar reruns the attempt. The file and sidecar writes run to their end
// when the client leaves.
func (s *StorageSource) storeFile(ctx context.Context, c identity.Caller, p Path, body *os.File) (sidecar, string, error) {
	rewind := func() error { _, err := body.Seek(0, io.SeekStart); return err }
	if err := rewind(); err != nil {
		return sidecar{}, "", err
	}
	h := NewHasher()
	size, err := io.Copy(h, body)
	if err != nil {
		return sidecar{}, "", err
	}
	d := h.Digests()
	sc := sidecar{Size: size, Digests: sidecarDigests(d),
		Uploaded: time.Now().UTC(), Uploader: records.UploaderFrom(c)}
	wctx := context.WithoutCancel(ctx)
	fk, sk := fileKey(p.Coords, p.File), sidecarKey(p.Coords, p.File)
	// writeSidecar records sc for the file with fileETag, replacing the
	// sidecar with sidecarETag ("" for none).
	writeSidecar := func(fileETag, sidecarETag string) error {
		sc.ETag = fileETag
		b, err := json.Marshal(sc)
		if err != nil {
			return err
		}
		_, err = s.d.PutIfMatch(wctx, sk, bytes.NewReader(b), sidecarETag)
		return err
	}
	for attempt := range updateRetries {
		cur, sInfo, err := s.readSidecar(ctx, sk)
		noSidecar := errors.Is(err, storage.ErrNotFound)
		if err != nil && !noSidecar {
			return sidecar{}, "", err
		}
		if err := rewind(); err != nil {
			return sidecar{}, "", err
		}
		info, err := s.d.PutIfAbsent(wctx, fk, body)
		if err == nil {
			// A sidecar left without its file (removed by an operator) is
			// replaced.
			err = writeSidecar(info.ETag, sInfo.ETag)
			if errors.Is(err, storage.ErrPrecondition) {
				if err := pause(ctx, attempt); err != nil {
					return sidecar{}, "", err
				}
				continue
			}
			return sc, "", err
		}
		if !errors.Is(err, storage.ErrExists) {
			return sidecar{}, "", err
		}
		info, err = s.d.Stat(ctx, fk)
		if errors.Is(err, storage.ErrNotFound) {
			continue
		}
		if err != nil {
			return sidecar{}, "", err
		}
		stored, fETag := cur.Digests.SHA256, info.ETag
		current := !noSidecar && cur.ETag == fETag
		if !current {
			// Stored without a sidecar for these bytes: compare the bytes.
			sd, info, err := s.hashStored(ctx, fk)
			if errors.Is(err, storage.ErrNotFound) {
				continue
			}
			if err != nil {
				return sidecar{}, "", err
			}
			stored, fETag = sd.SHA256, info.ETag
		}
		if stored == sc.Digests.SHA256 {
			if current {
				return cur, "", nil
			}
			err := writeSidecar(fETag, sInfo.ETag)
			if errors.Is(err, storage.ErrPrecondition) {
				continue
			}
			return sc, "", err
		}
		if !p.Snapshot {
			return sidecar{}, "", fmt.Errorf("%s %w", p.File, ErrExists)
		}
		if err := rewind(); err != nil {
			return sidecar{}, "", err
		}
		info, err = s.d.PutIfMatch(wctx, fk, body, fETag)
		if err == nil {
			err = writeSidecar(info.ETag, sInfo.ETag)
		}
		if errors.Is(err, storage.ErrPrecondition) {
			if err := pause(ctx, attempt); err != nil {
				return sidecar{}, "", err
			}
			continue
		}
		return sc, stored, err
	}
	return sidecar{}, "", fmt.Errorf("maven: %s changed concurrently %d times", fk, updateRetries)
}

// hashStored returns the digests of a stored object.
func (s *StorageSource) hashStored(ctx context.Context, key string) (Digests, storage.Info, error) {
	rc, info, err := s.d.Get(ctx, key)
	if err != nil {
		return Digests{}, info, err
	}
	defer rc.Close()
	h := NewHasher()
	if _, err := io.Copy(h, rc); err != nil {
		return Digests{}, info, err
	}
	return h.Digests(), info, nil
}

func (s *StorageSource) readSidecar(ctx context.Context, key string) (sidecar, storage.Info, error) {
	b, info, err := s.get(ctx, key, maxSidecarBytes)
	if err != nil {
		return sidecar{}, storage.Info{}, err
	}
	var sc sidecar
	if err := json.Unmarshal(b, &sc); err != nil {
		return sidecar{}, storage.Info{}, fmt.Errorf("maven: sidecar %s: %w", key, err)
	}
	return sc, info, nil
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
		err = fmt.Errorf("maven: %s exceeds %d bytes", key, limit)
	}
	return b, info, err
}

// readIndex returns the versions of c's artifact with a stored POM and the
// ETag of its index. A missing or corrupt index is rebuilt from the ~pom
// claims; rebuilt is then true and etag is the corrupt document's ETag, or
// "" when there is none.
func (s *StorageSource) readIndex(ctx context.Context, c Coords) (idx map[string]indexEntry, etag string, rebuilt bool, err error) {
	b, info, err := s.get(ctx, indexKey(c), maxIndexBytes)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, "", false, err
	}
	var doc indexDoc
	if err == nil && json.Unmarshal(b, &doc) == nil && len(doc.Versions) > 0 {
		return doc.Versions, info.ETag, false, nil
	}
	idx, err = s.scan(ctx, c)
	return idx, info.ETag, true, err
}

// scan rebuilds an artifact's index from its versions' ~pom claims.
func (s *StorageSource) scan(ctx context.Context, c Coords) (map[string]indexEntry, error) {
	prefix := artifactPrefix(c)
	idx := map[string]indexEntry{}
	for info, err := range s.d.List(ctx, prefix) {
		if err != nil {
			return nil, err
		}
		seg, ok := strings.CutSuffix(strings.TrimPrefix(info.Key, prefix), "/~pom")
		if !ok || strings.Contains(seg, "/") {
			continue
		}
		v, err := storage.UnescapeSegment(seg)
		if err != nil {
			continue
		}
		e, err := s.rebuildEntry(ctx, Coords{c.Group, c.Artifact, v}, info.ModTime)
		if err != nil {
			return nil, err
		}
		idx[v] = e
	}
	return idx, nil
}

// rebuildEntry finds the newest POM of version c and reads its packaging;
// claimed is the ~pom claim's time, used when no POM sidecar is found.
func (s *StorageSource) rebuildEntry(ctx context.Context, c Coords, claimed time.Time) (indexEntry, error) {
	prefix := filesPrefix(c)
	var newest string
	var e indexEntry
	for info, err := range s.d.List(ctx, prefix) {
		if err != nil {
			return indexEntry{}, err
		}
		seg, ok := strings.CutSuffix(strings.TrimPrefix(info.Key, prefix), sidecarSuffix)
		if !ok {
			continue
		}
		name, err := storage.UnescapeSegment(seg)
		if err != nil {
			continue
		}
		if _, classifier, ext := fileParts(c, name); classifier != "" || ext != "pom" {
			continue
		}
		sc, _, err := s.readSidecar(ctx, info.Key)
		if err != nil {
			s.log.Warn("maven: skipping unreadable sidecar", "source", s.name, "key", info.Key, "error", err)
			continue
		}
		if newest == "" || sc.Uploaded.After(e.POM) {
			newest, e.POM = name, sc.Uploaded
		}
	}
	if newest == "" {
		s.log.Warn("maven: version claimed without a POM sidecar", "source", s.name, "coords", c.Group+":"+c.Artifact+":"+c.Version)
		return indexEntry{POM: claimed}, nil
	}
	rc, _, err := s.d.Get(ctx, fileKey(c, newest))
	if err != nil {
		return indexEntry{}, fmt.Errorf("maven: POM %s of %s:%s: %w", newest, c.Group, c.Artifact, err)
	}
	defer rc.Close()
	info, err := InspectPOM(rc, Path{Kind: KindFile, Coords: c, File: newest, Snapshot: IsSnapshot(c.Version)})
	if err != nil {
		s.log.Warn("maven: stored POM no longer inspects", "source", s.name, "file", newest, "error", err)
	}
	e.Packaging = info.Packaging
	return e, nil
}

// addToIndex lists version c with a POM stored at pom, writing a rebuilt
// index even when c was already in it. A newer POM of a listed version
// moves its time.
func (s *StorageSource) addToIndex(ctx context.Context, c Coords, pom time.Time, packaging string) error {
	return s.update(ctx, indexKey(c), func() ([]byte, string, bool, error) {
		idx, etag, rebuilt, err := s.readIndex(ctx, c)
		if err != nil {
			return nil, "", false, err
		}
		e, ok := idx[c.Version]
		newer := !ok || pom.After(e.POM)
		if !newer && !rebuilt {
			return nil, "", false, nil
		}
		if newer {
			idx[c.Version] = indexEntry{POM: pom, Packaging: packaging}
		}
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
		if err := pause(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("maven: %s changed concurrently %d times", key, updateRetries)
}

// pause waits a jittered backoff before attempt+1: CI may deploy several
// files or versions at once.
func pause(ctx context.Context, attempt int) error {
	select {
	case <-time.After(time.Duration(rand.Int64N(int64(attempt+1) * int64(20*time.Millisecond)))): //nolint:gosec // jitter, not a secret
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// File serves a stored file. Release and timestamped SNAPSHOT files are
// immutable to clients. A file whose sidecar was written for other bytes is
// served without digests and not immutable.
func (s *StorageSource) File(ctx context.Context, p Path) (File, error) {
	if len(p.File) > maxFileName {
		return File{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, p)
	}
	sc, _, err := s.readSidecar(ctx, sidecarKey(p.Coords, p.File))
	if errors.Is(err, storage.ErrNotFound) {
		return File{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, p)
	}
	if err != nil {
		return File{}, err
	}
	key := fileKey(p.Coords, p.File)
	rc, info, err := s.d.Get(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		// A sidecar without its file: a store fault, not a miss.
		return File{}, fmt.Errorf("maven: stored object %s is missing", key)
	}
	if err != nil {
		return File{}, err
	}
	f := File{Body: rc, Size: info.Size, Modified: sc.Uploaded}
	if sc.ETag == info.ETag {
		value, _, _ := fileParts(p.Coords, p.File)
		f.Digests, f.Immutable = sc.Digests.digests(), !p.Snapshot || value != p.Coords.Version
	}
	return f, nil
}

// Digests returns a stored file's digests from its sidecar, or from its
// bytes when the sidecar was written for other bytes.
func (s *StorageSource) Digests(ctx context.Context, p Path) (Digests, error) {
	if len(p.File) > maxFileName {
		return Digests{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, p)
	}
	sc, _, err := s.readSidecar(ctx, sidecarKey(p.Coords, p.File))
	if errors.Is(err, storage.ErrNotFound) {
		return Digests{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, p)
	}
	if err != nil {
		return Digests{}, err
	}
	key := fileKey(p.Coords, p.File)
	info, err := s.d.Stat(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		return Digests{}, fmt.Errorf("maven: stored object %s is missing", key)
	}
	if err != nil {
		return Digests{}, err
	}
	if sc.ETag == info.ETag {
		return sc.Digests.digests(), nil
	}
	d, _, err := s.hashStored(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		return Digests{}, fmt.Errorf("maven: stored object %s is missing", key)
	}
	return d, err
}

// Metadata renders artifact-level metadata from the index (group-level
// metadata is not served: such a path has no index) and version-level
// metadata from the SNAPSHOT version's timestamped files.
func (s *StorageSource) Metadata(ctx context.Context, p Path) ([]byte, error) {
	if p.Kind == KindVersionMetadata {
		return s.versionMetadata(ctx, p)
	}
	return s.artifactMetadata(ctx, p)
}

// artifactMetadata renders the artifact's metadata, from memory while the
// index's ETag is unchanged.
func (s *StorageSource) artifactMetadata(ctx context.Context, p Path) ([]byte, error) {
	c := p.Coords
	id := c.Group + ":" + c.Artifact
	if info, err := s.d.Stat(ctx, indexKey(c)); err == nil {
		s.mu.Lock()
		m, ok := s.meta[id]
		s.mu.Unlock()
		if ok && m.etag == info.ETag {
			return m.body, nil
		}
	}
	idx, etag, rebuilt, err := s.readIndex(ctx, c)
	if err != nil {
		return nil, err
	}
	if len(idx) == 0 {
		return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, p)
	}
	vs := make([]VersionInfo, 0, len(idx))
	for v, e := range idx {
		vs = append(vs, VersionInfo{Version: v, POM: e.POM})
	}
	b := RenderArtifactMetadata(c.Group, c.Artifact, vs)
	if !rebuilt {
		s.mu.Lock()
		s.meta[id] = renderedMeta{etag: etag, body: b}
		s.mu.Unlock()
	}
	return b, nil
}

// versionMetadata renders a SNAPSHOT version's metadata from the names of
// its timestamped files and the sidecars of the newest per classifier and
// extension.
func (s *StorageSource) versionMetadata(ctx context.Context, p Path) ([]byte, error) {
	c := p.Coords
	type ce struct{ classifier, extension string }
	newest := map[ce]SnapshotFile{}
	names := map[ce]string{}
	prefix := filesPrefix(c)
	for info, err := range s.d.List(ctx, prefix) {
		if err != nil {
			return nil, err
		}
		seg, ok := strings.CutSuffix(strings.TrimPrefix(info.Key, prefix), sidecarSuffix)
		if !ok {
			continue
		}
		name, err := storage.UnescapeSegment(seg)
		if err != nil {
			continue
		}
		value, classifier, ext := fileParts(c, name)
		if value == c.Version {
			continue // not timestamped
		}
		f, k := SnapshotFile{Classifier: classifier, Extension: ext, Value: value}, ce{classifier, ext}
		if cur, ok := newest[k]; !ok || newerSnapshot(f, cur) > 0 {
			newest[k], names[k] = f, name
		}
	}
	if len(newest) == 0 {
		return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, p)
	}
	files := make([]SnapshotFile, 0, len(newest))
	for k, f := range newest {
		sc, _, err := s.readSidecar(ctx, sidecarKey(c, names[k]))
		if err != nil {
			return nil, err
		}
		f.Updated = sc.Uploaded
		files = append(files, f)
	}
	return RenderVersionMetadata(c.Group, c.Artifact, c.Version, files), nil
}

// Health reports whether the store answers.
func (s *StorageSource) Health(ctx context.Context) []metrics.Health {
	h := metrics.Health{Name: s.name, Ecosystem: ecoName, OK: true, Detail: "store reachable"}
	if err := storage.Reachable(ctx, s.d); err != nil {
		h.OK, h.Detail = false, "store unreachable"
	}
	return []metrics.Health{h}
}
