package apt

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
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/lru"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

const (
	// updateRetries bounds If-Match retries of an index write.
	updateRetries = 8

	maxIndexBytes   = 64 << 20
	maxSidecarBytes = 1 << 20
)

// StorageSource holds uploaded .deb files in a store. A file is written once
// and may belong to several suites; a suite's index lists its members and is
// rebuildable from the member objects and the files' sidecars.
//
// Layout, with every name, version (without epoch), architecture, suite and
// component through storage.EscapeSegment:
//
//	apt/<src>/pool/<name>/<version>/<arch>/deb        the file
//	apt/<src>/pool/<name>/<version>/<arch>/deb.json   its sidecar
//	apt/<src>/pool/<name>/<version>/<arch>/~claim     the sha256 of the first upload
//	apt/<src>/dists/<suite>/<component>/members/<name>/<version>/<arch>   empty: the file is in the suite
//	apt/<src>/dists/<suite>/index.json                {"members": [...]}
//
// What a caller sees of a suite is rendered and signed per visible set; see
// render.go for the renderings and by-hash files kept in cache.
type StorageSource struct {
	name   string
	claims []string
	d      storage.Driver
	cache  *storage.Cache
	rec    *records.Store
	signer *Signer
	log    *slog.Logger
	now    func() time.Time // replaced in tests

	rendered *lru.Cache[*rendering]
	// renderLocks serialize the renderings of a viewer (each viewer maps to
	// one lock), so a viewer's Dates rise in the order they are served.
	renderLocks [renderLockStripes]chan struct{}
}

var _ Uploader = (*StorageSource)(nil)

// NewStorageSource returns a storage source over d that keeps its signed
// renderings and by-hash files in cache. log nil means slog.Default().
func NewStorageSource(name string, claims []string, d storage.Driver, cache *storage.Cache, rec *records.Store, signer *Signer, log *slog.Logger) *StorageSource {
	if log == nil {
		log = slog.Default()
	}
	s := &StorageSource{name: name, claims: claims, d: d, cache: cache, rec: rec, signer: signer, log: log, now: time.Now,
		rendered: lru.New(maxRenderedBytes, (*rendering).size)}
	for i := range s.renderLocks {
		s.renderLocks[i] = make(chan struct{}, 1)
	}
	return s
}

func (s *StorageSource) Name() string     { return s.name }
func (s *StorageSource) Claims() []string { return s.claims }

// member is a file in a suite's component.
type member struct {
	Component string
	Deb       Deb // Version with its epoch
	Fields    Stanza
	Size      int64
	SHA256    string
	Uploaded  time.Time
}

// sidecar is a stored file's record.
type sidecar struct {
	Fields   [][2]string      `json:"fields"`
	Size     int64            `json:"size"`
	SHA256   string           `json:"sha256"`
	Uploaded time.Time        `json:"uploaded"`
	Uploader records.Uploader `json:"uploader"`
}

// indexMember is a member in index.json: what suite needs without reading
// the sidecars.
type indexMember struct {
	Component string      `json:"component"`
	Name      string      `json:"name"`
	Version   string      `json:"version"` // with epoch
	Arch      string      `json:"arch"`
	Fields    [][2]string `json:"fields"`
	Size      int64       `json:"size"`
	SHA256    string      `json:"sha256"`
	Uploaded  time.Time   `json:"uploaded"`
}

type indexDoc struct {
	Members []indexMember `json:"members"`
}

func pairs(s Stanza) [][2]string {
	out := make([][2]string, len(s))
	for i, f := range s {
		out[i] = [2]string{f.Name, f.Value}
	}
	return out
}

func stanza(p [][2]string) Stanza {
	out := make(Stanza, len(p))
	for i, f := range p {
		out[i] = Field{f[0], f[1]}
	}
	return out
}

func (m indexMember) member() member {
	return member{Component: m.Component, Deb: Deb{m.Name, m.Version, m.Arch}, Fields: stanza(m.Fields),
		Size: m.Size, SHA256: m.SHA256, Uploaded: m.Uploaded}
}

func (m indexMember) id() string {
	return m.Component + "/" + m.Name + "_" + StripEpoch(m.Version) + "_" + m.Arch
}

func poolPrefix(src string, d Deb) string {
	return "apt/" + src + "/pool/" + storage.EscapeSegment(d.Name) + "/" + storage.EscapeSegment(StripEpoch(d.Version)) +
		"/" + storage.EscapeSegment(d.Arch) + "/"
}

func memberSegments(d Deb) string {
	return storage.EscapeSegment(d.Name) + "/" + storage.EscapeSegment(StripEpoch(d.Version)) + "/" + storage.EscapeSegment(d.Arch)
}

func suitePrefix(src, suite string) string {
	return "apt/" + src + "/dists/" + storage.EscapeSegment(suite) + "/"
}

func memberKey(src, suite, component string, d Deb) string {
	return suitePrefix(src, suite) + storage.EscapeSegment(component) + "/members/" + memberSegments(d)
}

// Upload stores body, a file ctl describes, and lists it in suite/component.
// The same bytes again are a success (created false) that completes whatever
// an earlier attempt left undone; other bytes are ErrExists. The writes run
// to their end when the client leaves.
func (s *StorageSource) Upload(ctx context.Context, c identity.Caller, suite, component string, ctl Control, body *os.File, _ int64) (bool, error) {
	d := ctl.Deb
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	h := sha256.New()
	n, err := io.Copy(h, body)
	if err != nil {
		return false, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	wctx := context.WithoutCancel(ctx)
	pk := poolPrefix(s.name, d)

	created := true
	if _, err := s.d.PutIfAbsent(wctx, pk+"~claim", strings.NewReader(sum)); errors.Is(err, storage.ErrExists) {
		created = false
		held, _, err := s.get(ctx, pk+"~claim", 1024)
		if err != nil {
			return false, err
		}
		if string(held) != sum {
			return false, fmt.Errorf("%s %w", d.FileName(), ErrExists)
		}
	} else if err != nil {
		return false, err
	}

	// A claim held by an earlier attempt may lack its bytes or sidecar.
	if err := s.putIfMissing(wctx, pk+"deb", created, func() (io.Reader, error) {
		_, err := body.Seek(0, io.SeekStart)
		return body, err
	}); err != nil {
		return false, err
	}
	// The sidecar marks a completed file, so its records are written first:
	// a retry after a records failure writes them again.
	scKey := pk + "deb.json"
	sc := sidecar{Fields: pairs(ctl.Fields), Size: n, SHA256: sum, Uploaded: time.Now().UTC(), Uploader: records.UploaderFrom(c)}
	missing, err := s.missing(ctx, scKey, created)
	if err != nil {
		return false, err
	}
	wrote := false
	if missing {
		if wrote, err = s.putSidecar(wctx, d, scKey, sc); err != nil {
			return false, err
		}
	}
	// The index entry carries the stored sidecar's time, which may be an
	// earlier attempt's.
	if !wrote {
		stored, _, err := s.readSidecar(ctx, scKey)
		if err != nil {
			return false, err
		}
		sc = stored
	}
	mk := memberKey(s.name, suite, component, d)
	missing, err = s.missing(ctx, mk, created)
	if err != nil {
		return false, err
	}
	if missing {
		if err := s.rec.PutAudit(wctx, records.Audit{Time: time.Now().UTC(), Action: "suite-add", Ecosystem: ecoName, Package: d.Name,
			Version: d.Version, File: suite + "/" + component, SHA256: sum, Uploader: records.UploaderFrom(c)}); err != nil {
			return false, fmt.Errorf("record audit: %w", err)
		}
		if _, err := s.d.PutIfAbsent(wctx, mk, bytes.NewReader(nil)); err != nil && !errors.Is(err, storage.ErrExists) {
			return false, err
		}
	}
	im := indexMember{Component: component, Name: d.Name, Version: d.Version, Arch: d.Arch,
		Fields: sc.Fields, Size: sc.Size, SHA256: sc.SHA256, Uploaded: sc.Uploaded}
	if err := s.addToIndex(wctx, suite, im); err != nil {
		return false, err
	}
	return created, nil
}

// putIfMissing writes the object at key from open() unless it exists; fresh
// says no earlier attempt can have written it.
func (s *StorageSource) putIfMissing(ctx context.Context, key string, fresh bool, open func() (io.Reader, error)) error {
	if !fresh {
		if _, err := s.d.Stat(ctx, key); err == nil {
			return nil
		} else if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
	}
	r, err := open()
	if err != nil {
		return err
	}
	if _, err := s.d.PutIfAbsent(ctx, key, r); err != nil && !errors.Is(err, storage.ErrExists) {
		return err
	}
	return nil
}

// missing reports whether key is absent; fresh says no earlier attempt can
// have written it.
func (s *StorageSource) missing(ctx context.Context, key string, fresh bool) (bool, error) {
	if fresh {
		return true, nil
	}
	_, err := s.d.Stat(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		return true, nil
	}
	return false, err
}

// putSidecar records sc's provenance and upload, then writes it at key. It
// reports whether it wrote it: one another attempt wrote meanwhile is kept.
func (s *StorageSource) putSidecar(ctx context.Context, d Deb, key string, sc sidecar) (bool, error) {
	up := sc.Uploader
	if err := s.rec.PutProvenance(ctx, records.Provenance{
		Ecosystem: ecoName, Package: d.Name, Version: d.Version, File: d.FileName(), Source: s.name, SourceType: "storage",
		SHA256: sc.SHA256, Uploader: &up,
	}); err != nil {
		return false, fmt.Errorf("record provenance: %w", err)
	}
	if err := s.rec.PutAudit(ctx, records.Audit{Time: sc.Uploaded, Action: "upload", Ecosystem: ecoName, Package: d.Name,
		Version: d.Version, File: d.FileName(), SHA256: sc.SHA256, Uploader: up}); err != nil {
		return false, fmt.Errorf("record audit: %w", err)
	}
	b, err := json.Marshal(sc)
	if err != nil {
		return false, err
	}
	_, err = s.d.PutIfAbsent(ctx, key, bytes.NewReader(b))
	if errors.Is(err, storage.ErrExists) {
		return false, nil
	}
	return err == nil, err
}

func (s *StorageSource) readSidecar(ctx context.Context, key string) (sidecar, storage.Info, error) {
	b, info, err := s.get(ctx, key, maxSidecarBytes)
	if err != nil {
		return sidecar{}, storage.Info{}, err
	}
	var sc sidecar
	if err := json.Unmarshal(b, &sc); err != nil {
		return sidecar{}, storage.Info{}, fmt.Errorf("apt: sidecar %s: %w", key, err)
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
		err = fmt.Errorf("apt: %s exceeds %d bytes", key, limit)
	}
	return b, info, err
}

// readIndex returns suite's members and the ETag of its index. A missing or
// corrupt index is rebuilt from the member objects; rebuilt is then true and
// etag is the corrupt document's ETag, or "" when there is none.
func (s *StorageSource) readIndex(ctx context.Context, suite string) (idx []indexMember, etag string, rebuilt bool, err error) {
	b, info, err := s.get(ctx, suitePrefix(s.name, suite)+"index.json", maxIndexBytes)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, "", false, err
	}
	var doc indexDoc
	if err == nil && json.Unmarshal(b, &doc) == nil {
		return doc.Members, info.ETag, false, nil
	}
	idx, err = s.scan(ctx, suite)
	return idx, info.ETag, true, err
}

// scan lists suite's member objects with their sidecars. A member whose
// sidecar or bytes are missing is skipped.
func (s *StorageSource) scan(ctx context.Context, suite string) ([]indexMember, error) {
	prefix := suitePrefix(s.name, suite)
	var out []indexMember
	for info, err := range s.d.List(ctx, prefix) {
		if err != nil {
			return nil, err
		}
		compSeg, seg, ok := strings.Cut(strings.TrimPrefix(info.Key, prefix), "/members/")
		if !ok || strings.Contains(compSeg, "/") {
			continue
		}
		component, err := storage.UnescapeSegment(compSeg)
		if err != nil {
			continue
		}
		parts := strings.Split(seg, "/")
		if len(parts) != 3 {
			continue
		}
		var v [3]string
		for i, p := range parts {
			if v[i], err = storage.UnescapeSegment(p); err != nil {
				break
			}
		}
		if err != nil {
			continue
		}
		d := Deb{v[0], v[1], v[2]}
		pk := poolPrefix(s.name, d)
		sc, _, err := s.readSidecar(ctx, pk+"deb.json")
		if err != nil {
			s.log.Warn("apt: skipping member without a readable sidecar", "source", s.name, "key", info.Key, "error", err)
			continue
		}
		if _, err := s.d.Stat(ctx, pk+"deb"); err != nil {
			s.log.Warn("apt: skipping member without its file", "source", s.name, "key", info.Key, "error", err)
			continue
		}
		ver, ok := stanza(sc.Fields).Get("Version")
		if !ok || StripEpoch(ver) != d.Version {
			s.log.Warn("apt: skipping member whose sidecar disagrees with its key", "source", s.name, "key", info.Key)
			continue
		}
		out = append(out, indexMember{Component: component, Name: d.Name, Version: ver, Arch: d.Arch,
			Fields: sc.Fields, Size: sc.Size, SHA256: sc.SHA256, Uploaded: sc.Uploaded})
	}
	return out, nil
}

// addToIndex lists im in suite's index, writing a rebuilt index even when im
// was already in it.
func (s *StorageSource) addToIndex(ctx context.Context, suite string, im indexMember) error {
	key := suitePrefix(s.name, suite) + "index.json"
	return s.update(ctx, key, func() ([]byte, string, bool, error) {
		idx, etag, rebuilt, err := s.readIndex(ctx, suite)
		if err != nil {
			return nil, "", false, err
		}
		listed := slices.ContainsFunc(idx, func(m indexMember) bool { return m.id() == im.id() })
		if listed && !rebuilt {
			return nil, "", false, nil
		}
		if !listed {
			idx = append(idx, im)
		}
		b, err := json.Marshal(indexDoc{Members: idx})
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
	return fmt.Errorf("apt: %s changed concurrently %d times", key, updateRetries)
}

// pause waits a jittered backoff before attempt+1: CI may upload several
// files at once.
func pause(ctx context.Context, attempt int) error {
	select {
	case <-time.After(time.Duration(rand.Int64N(int64(attempt+1) * int64(20*time.Millisecond)))): //nolint:gosec // jitter, not a secret
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// suite returns the members of suite, ordered by component, name, version
// and architecture, and the ETag of its index. A missing or corrupt index is
// rebuilt and stored; a suite without members has no index and no ETag.
func (s *StorageSource) suite(ctx context.Context, suite string) ([]member, string, error) {
	key := suitePrefix(s.name, suite) + "index.json"
	for attempt := range updateRetries {
		idx, etag, rebuilt, err := s.readIndex(ctx, suite)
		if err != nil {
			return nil, "", err
		}
		if rebuilt && len(idx) > 0 {
			b, err := json.Marshal(indexDoc{Members: idx})
			if err != nil {
				return nil, "", err
			}
			info, err := s.d.PutIfMatch(ctx, key, bytes.NewReader(b), etag)
			if errors.Is(err, storage.ErrPrecondition) {
				if err := pause(ctx, attempt); err != nil {
					return nil, "", err
				}
				continue
			}
			if err != nil {
				return nil, "", err
			}
			etag = info.ETag
		}
		slices.SortFunc(idx, func(a, b indexMember) int { return strings.Compare(a.sortKey(), b.sortKey()) })
		out := make([]member, len(idx))
		for i, m := range idx {
			out[i] = m.member()
		}
		return out, etag, nil
	}
	return nil, "", fmt.Errorf("apt: %s changed concurrently %d times", key, updateRetries)
}

func (m indexMember) sortKey() string {
	return m.Component + "\x00" + m.Name + "\x00" + m.Version + "\x00" + m.Arch
}

// Pool serves pool/<name>/<file> when acc may read the package: a file the
// caller may not read is a miss.
func (s *StorageSource) Pool(ctx context.Context, acc ReadAccess, p Path) (Blob, error) {
	miss := fmt.Errorf("%w: %s", resolve.ErrNotFound, p.Rel)
	segs := strings.Split(p.Rel, "/")
	if len(segs) != 3 || segs[0] != "pool" {
		return Blob{}, miss
	}
	d, err := ParseFileName(segs[2])
	if err != nil || d.Name != segs[1] || acc.Name == nil || !acc.Name(d.Name) {
		return Blob{}, miss
	}
	pk := poolPrefix(s.name, d)
	sc, _, err := s.readSidecar(ctx, pk+"deb.json")
	if errors.Is(err, storage.ErrNotFound) {
		return Blob{}, miss
	}
	if err != nil {
		return Blob{}, err
	}
	rc, info, err := s.d.Get(ctx, pk+"deb")
	if errors.Is(err, storage.ErrNotFound) {
		// A sidecar without its file: a store fault, not a miss.
		return Blob{}, fmt.Errorf("apt: stored object %sdeb is missing", pk)
	}
	if err != nil {
		return Blob{}, err
	}
	return Blob{Body: rc, Size: info.Size, ETag: `"sha256-` + sc.SHA256 + `"`, Modified: sc.Uploaded, Immutable: true}, nil
}

// Health reports whether the store answers.
func (s *StorageSource) Health(ctx context.Context) []metrics.Health {
	h := metrics.Health{Name: s.name, Ecosystem: ecoName, OK: true, Detail: "store reachable"}
	if err := storage.Reachable(ctx, s.d); err != nil {
		h.OK, h.Detail = false, "store unreachable"
	}
	return []metrics.Health{h}
}
