package apt

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

const (
	// maxRenderedBytes caps the renderings held in memory.
	maxRenderedBytes = 64 << 20
	// maxSignedBytes caps a stored signature document.
	maxSignedBytes = 3 * MaxRelease
	// maxByHashHeader caps the first line of a by-hash object.
	maxByHashHeader = 16 << 20
	// renderLockStripes is how many locks serialize renderings: a viewer
	// always takes the same one, unrelated viewers may share one.
	renderLockStripes = 64
)

// A rendering is a suite as one viewer sees it: its indexes and the
// Release with its signatures. A viewer is a caller's node, one apt client
// state; what it sees is a visible set, the suite's members it may read.
// The rendering's identity is the sha256 of the suite, the index ETag, the
// sorted member IDs and the signing key's fingerprint.
//
// apt ignores a Release older than the one it has, and sends the Date it
// was served as If-Modified-Since, so a viewer's Date only rises. A
// viewer's rendering keeps its Date while its identity stays the same; any
// other identity gets the next Date: now, or a second after the viewer's
// previous Date when now is not later. Dates belong to the viewer, not to
// the identity: a viewer that returns to an identity it saw before (a rule
// revoked and granted again, an index rebuilt to an earlier state), or
// reaches one another viewer saw first, gets the next Date too.
//
// Renderings live in memory and, in the cache store,
//
//	apt/<src>/rendered/<viewer>/signed          the identity, Date, the Release's sha256, InRelease and Release.gpg
//	apt/<src>/byhash/<suite>/<sha256>           {"suite", "members"} line, then an index file's bytes
//
// where <viewer> is the sha256 of the viewer and the suite. Indexes are
// deterministic for a visible set and rendered again after an eviction;
// signatures are not, so a stored one is served while the viewer's
// identity is the same. By-hash files are written with each rendering and kept
// until the cache evicts them, so a client that read an InRelease can still
// fetch its indexes after an upload; each request checks the caller may
// read every package in the file. One evicted while its rendering is still
// served is stored again from that rendering when a caller asks for it.
type rendering struct {
	id         string
	date       time.Time
	release    []byte
	inRelease  []byte
	releaseGPG []byte
	indexes    map[string][]byte   // path below dists/<suite>/
	members    map[string][]string // index path: member IDs of its stanzas
}

func (r *rendering) size() int64 {
	n := int64(len(r.release) + len(r.inRelease) + len(r.releaseGPG))
	for p, b := range r.indexes {
		n += int64(len(p) + len(b))
		for _, id := range r.members[p] {
			n += int64(len(id))
		}
	}
	return n
}

// signedDoc is a viewer's latest rendering of a suite: its identity, Date
// and signed Release.
type signedDoc struct {
	ID            string    `json:"id"`
	Date          time.Time `json:"date"`
	ReleaseSHA256 string    `json:"release_sha256"`
	InRelease     []byte    `json:"inrelease"`
	ReleaseGPG    []byte    `json:"release_gpg"`
}

// byHashHeader is the first line of a by-hash object.
type byHashHeader struct {
	Suite   string   `json:"suite"`
	Members []string `json:"members"`
}

func (s *StorageSource) renderedKey(viewer string) string {
	return "apt/" + s.name + "/rendered/" + viewer + "/signed"
}

func (s *StorageSource) byHashKey(suite, sum string) string {
	return "apt/" + s.name + "/byhash/" + storage.EscapeSegment(suite) + "/" + sum
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func etagOf(b []byte) string { return `"` + hexSHA256(b) + `"` }

func bytesBlob(b []byte, modified time.Time) Blob {
	return Blob{Body: io.NopCloser(bytes.NewReader(b)), Size: int64(len(b)), ETag: etagOf(b), Modified: modified}
}

// Release serves the InRelease, Release or Release.gpg of suite as acc sees it.
func (s *StorageSource) Release(ctx context.Context, acc ReadAccess, suite, which string) (Blob, error) {
	pick := map[string]func(*rendering) []byte{
		"InRelease":   func(r *rendering) []byte { return r.inRelease },
		"Release":     func(r *rendering) []byte { return r.release },
		"Release.gpg": func(r *rendering) []byte { return r.releaseGPG },
	}[which]
	if pick == nil {
		return Blob{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, which)
	}
	r, err := s.current(ctx, acc, suite)
	if err != nil {
		return Blob{}, err
	}
	return bytesBlob(pick(r), r.date), nil
}

// Dist serves an index of suite as acc sees it.
func (s *StorageSource) Dist(ctx context.Context, acc ReadAccess, suite, rel string) (Blob, error) {
	r, err := s.current(ctx, acc, suite)
	if err != nil {
		return Blob{}, err
	}
	b, ok := r.indexes[rel]
	if !ok {
		return Blob{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, rel)
	}
	return bytesBlob(b, r.date), nil
}

// ByHash serves rel, "<component>/binary-<arch>/by-hash/SHA256/<sum>", when
// a rendering of suite stored an index with that hash and acc may read every
// package in it, or when an index of acc's current rendering has that hash
// (an entry the cache evicted is then stored again).
func (s *StorageSource) ByHash(ctx context.Context, acc ReadAccess, suite, rel, sum string) (Blob, error) {
	miss := fmt.Errorf("%w: %s", resolve.ErrNotFound, rel)
	dir, ok := strings.CutSuffix(rel, "/by-hash/SHA256/"+sum)
	comp, binArch, _ := strings.Cut(dir, "/")
	arch, isBin := strings.CutPrefix(binArch, "binary-")
	if !ok || !isBin || !ValidSuite(comp) || !ValidArch(arch) || !ValidSuite(suite) || !isHex64(sum) || acc.Name == nil {
		return Blob{}, miss
	}
	b, found, err := s.storedByHash(ctx, acc, suite, sum)
	if err != nil || found {
		return b, err
	}
	r, err := s.current(ctx, acc, suite)
	if errors.Is(err, resolve.ErrNotFound) {
		return Blob{}, miss
	}
	if err != nil {
		return Blob{}, err
	}
	for path, idx := range r.indexes {
		if hexSHA256(idx) != sum {
			continue
		}
		if err := s.storeIndex(context.WithoutCancel(ctx), suite, r, path); err != nil {
			s.log.Warn("apt: storing a by-hash file failed", "source", s.name, "suite", suite, "error", err)
		}
		return Blob{Body: io.NopCloser(bytes.NewReader(idx)), Size: int64(len(idx)), ETag: `"` + sum + `"`, Immutable: true}, nil
	}
	return Blob{}, miss
}

// storedByHash serves the stored by-hash file sum of suite when acc may read
// every package in it; found is false when there is none acc may read.
func (s *StorageSource) storedByHash(ctx context.Context, acc ReadAccess, suite, sum string) (Blob, bool, error) {
	rc, size, err := s.cache.Open(ctx, s.byHashKey(suite, sum))
	if errors.Is(err, storage.ErrNotFound) {
		return Blob{}, false, nil
	}
	if err != nil {
		return Blob{}, false, err
	}
	br := bufio.NewReader(rc)
	line, err := readLine(br, maxByHashHeader)
	var h byHashHeader
	if err == nil {
		err = json.Unmarshal(line, &h)
	}
	if err != nil {
		rc.Close()
		return Blob{}, false, fmt.Errorf("apt: by-hash object %s: %w", sum, err)
	}
	if h.Suite != suite {
		rc.Close()
		return Blob{}, false, nil
	}
	for _, id := range h.Members {
		if !acc.Name(memberName(id)) {
			rc.Close()
			return Blob{}, false, nil
		}
	}
	body := struct {
		io.Reader
		io.Closer
	}{br, rc}
	return Blob{Body: body, Size: size - int64(len(line)) - 1, ETag: `"` + sum + `"`, Immutable: true}, true, nil
}

// memberName is the package name in a member ID,
// "<component>/<name>_<version>_<arch>".
func memberName(id string) string {
	_, rest, _ := strings.Cut(id, "/")
	name, _, _ := strings.Cut(rest, "_")
	return name
}

// current returns the rendering of suite for acc's viewer, rendering and
// signing it and storing its indexes by hash when no copy is kept.
// A suite without members is a miss.
func (s *StorageSource) current(ctx context.Context, acc ReadAccess, suite string) (*rendering, error) {
	ms, etag, err := s.suite(ctx, suite)
	if err != nil {
		return nil, err
	}
	if len(ms) == 0 {
		return nil, fmt.Errorf("%w: suite %s", resolve.ErrNotFound, suite)
	}
	var visible []member
	for _, m := range ms {
		if acc.Name != nil && acc.Name(m.Deb.Name) {
			visible = append(visible, m)
		}
	}
	id := renderingID(suite, etag, visible, s.signer.Fingerprint())
	viewer := hexSHA256([]byte(acc.Viewer + "\n" + suite))
	// One rendering at a time per viewer, so its Dates rise in the order
	// they are served: a request waits for the viewer's rendering in
	// progress, then takes the viewer's current rendering if it is of its
	// own identity, and renders its own otherwise.
	lock := s.renderLocks[viewerStripe(viewer)]
	select {
	case lock <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-lock }()
	var last time.Time
	if r, ok := s.rendered.Get(viewer); ok {
		if r.id == id {
			return r, nil
		}
		last = r.date
	}
	r, err := s.render(context.WithoutCancel(ctx), suite, id, viewer, last, ms, visible)
	if err != nil {
		return nil, err
	}
	if err := s.storeByHash(context.WithoutCancel(ctx), suite, r); err != nil {
		// Served anyway: apt falls back to the canonical path after a
		// by-hash miss, and ByHash stores an entry of the current
		// rendering again when asked for it.
		s.log.Warn("apt: storing by-hash files failed", "source", s.name, "suite", suite, "error", err)
	}
	s.rendered.Put(viewer, r)
	return r, nil
}

// viewerStripe maps a viewer key (hex sha256) to its render lock.
func viewerStripe(viewer string) int {
	b, err := hex.DecodeString(viewer[:2])
	if err != nil || len(b) == 0 {
		return 0
	}
	return int(b[0]) % renderLockStripes
}

func memberID(m member) string {
	return indexMember{Component: m.Component, Name: m.Deb.Name, Version: m.Deb.Version, Arch: m.Deb.Arch}.id()
}

func renderingID(suite, etag string, visible []member, fingerprint string) string {
	ids := make([]string, len(visible))
	for i, m := range visible {
		ids[i] = memberID(m)
	}
	slices.Sort(ids)
	h := sha256.New()
	h.Write([]byte(suite + "\n" + etag + "\n" + fingerprint + "\n" + strings.Join(ids, "\n")))
	return hex.EncodeToString(h.Sum(nil))
}

// render builds the rendering id of visible, a subset of the suite's
// members ms in suite order, for viewer, and dates and signs its Release;
// last is the Date of the viewer's rendering in memory, if any.
func (s *StorageSource) render(ctx context.Context, suite, id, viewer string, last time.Time, ms, visible []member) (*rendering, error) {
	var comps, archs []string
	for _, m := range ms {
		comps = append(comps, m.Component)
	}
	r := &rendering{id: id, indexes: map[string][]byte{}, members: map[string][]string{}}
	stanzas := make([][]byte, len(visible))
	for i, m := range visible {
		var b bytes.Buffer
		if err := WriteStanza(&b, indexStanza(m)); err != nil {
			s.log.Error("apt: leaving out of the index a member whose fields cannot be written",
				"source", s.name, "suite", suite, "member", memberID(m), "error", err)
			continue
		}
		stanzas[i] = b.Bytes()
		if m.Deb.Arch != "all" {
			archs = append(archs, m.Deb.Arch)
		}
	}
	slices.Sort(comps)
	comps = slices.Compact(comps)
	slices.Sort(archs)
	archs = slices.Compact(archs)
	indexArchs := archs
	if len(indexArchs) == 0 {
		indexArchs = []string{"all"}
	}

	var hashes []FileHash
	for _, comp := range comps {
		for _, arch := range indexArchs {
			var pkgs bytes.Buffer
			var ids []string
			for i, m := range visible {
				if stanzas[i] == nil || m.Component != comp || (m.Deb.Arch != arch && m.Deb.Arch != "all") {
					continue
				}
				if pkgs.Len() > 0 {
					pkgs.WriteByte('\n')
				}
				pkgs.Write(stanzas[i])
				ids = append(ids, memberID(m))
			}
			gz, err := gzipBytes(pkgs.Bytes())
			if err != nil {
				return nil, err
			}
			p := comp + "/binary-" + arch + "/Packages"
			for path, b := range map[string][]byte{p: pkgs.Bytes(), p + ".gz": gz} {
				r.indexes[path], r.members[path] = b, ids
				hashes = append(hashes, FileHash{Path: path, Size: int64(len(b)), SHA256: hexSHA256(b)})
			}
		}
	}

	doc := ReleaseDoc{
		Fields: Stanza{
			{"Origin", "tspackages"}, {"Label", s.name}, {"Suite", suite}, {"Codename", suite}, {"Date", ""},
			{"Architectures", strings.Join(append([]string{"all"}, archs...), " ")},
			{"Components", strings.Join(comps, " ")}, {"Acquire-By-Hash", ""},
		},
		ByHash: true, SHA256: hashes,
	}
	if err := s.sign(ctx, viewer, last, r, doc); err != nil {
		return nil, err
	}
	return r, nil
}

// indexStanza is m's paragraph in a Packages file.
func indexStanza(m member) Stanza {
	var out Stanza
	for _, name := range PublishableFields {
		if v, ok := m.Fields.Get(name); ok {
			out = append(out, Field{name, v})
		}
	}
	return append(out,
		Field{"Filename", "pool/" + m.Deb.Name + "/" + m.Deb.FileName()},
		Field{"Size", strconv.FormatInt(m.Size, 10)},
		Field{"SHA256", m.SHA256})
}

// gzipBytes compresses b with a header that carries no name or time, so the
// same b always compresses to the same bytes.
func gzipBytes(b []byte) ([]byte, error) {
	var out bytes.Buffer
	zw, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// sign dates doc, sets it as r's Release and signs it: with the viewer's
// stored Date and signatures when they are for r's identity and last is
// not after them, otherwise with the next Date after the stored one and
// last, storing the new signatures.
func (s *StorageSource) sign(ctx context.Context, viewer string, last time.Time, r *rendering, doc ReleaseDoc) error {
	key := s.renderedKey(viewer)
	var prev signedDoc
	rc, _, err := s.cache.Get(ctx, key)
	switch {
	case err == nil:
		b, err := io.ReadAll(io.LimitReader(rc, maxSignedBytes+1))
		rc.Close()
		if err != nil {
			return err
		}
		if len(b) > maxSignedBytes || json.Unmarshal(b, &prev) != nil {
			prev = signedDoc{}
		}
	case !errors.Is(err, storage.ErrNotFound):
		return err
	}
	if prev.ID == r.id && !last.After(prev.Date) {
		doc.Date = prev.Date
		if rel := doc.Render(); hexSHA256(rel) == prev.ReleaseSHA256 {
			r.date, r.release, r.inRelease, r.releaseGPG = prev.Date, rel, prev.InRelease, prev.ReleaseGPG
			return nil
		}
	}
	// The Release states the Date in seconds; Last-Modified agrees with it.
	r.date = s.now().UTC().Truncate(time.Second)
	for _, t := range []time.Time{prev.Date, last} {
		if !r.date.After(t) {
			r.date = t.UTC().Add(time.Second)
		}
	}
	doc.Date = r.date
	r.release = doc.Render()
	if r.inRelease, err = s.signer.ClearSign(r.release); err != nil {
		return err
	}
	if r.releaseGPG, err = s.signer.DetachSign(r.release); err != nil {
		return err
	}
	metrics.ObserveAptSignature(s.name)
	b, err := json.Marshal(signedDoc{ID: r.id, Date: r.date, ReleaseSHA256: hexSHA256(r.release), InRelease: r.inRelease, ReleaseGPG: r.releaseGPG})
	if err != nil {
		return err
	}
	if err := s.cache.Put(ctx, key, bytes.NewReader(b)); err != nil {
		// Served anyway: the viewer's next rendering is dated after this one
		// while this one is in memory.
		s.log.Warn("apt: storing a Release signature failed", "source", s.name, "error", err)
	}
	return nil
}

// storeByHash stores each of r's indexes by its hash.
func (s *StorageSource) storeByHash(ctx context.Context, suite string, r *rendering) error {
	for path := range r.indexes {
		if err := s.storeIndex(ctx, suite, r, path); err != nil {
			return err
		}
	}
	return nil
}

// storeIndex stores r's index at path by its hash.
func (s *StorageSource) storeIndex(ctx context.Context, suite string, r *rendering, path string) error {
	b := r.indexes[path]
	hdr, err := json.Marshal(byHashHeader{Suite: suite, Members: r.members[path]})
	if err != nil {
		return err
	}
	body := io.MultiReader(bytes.NewReader(hdr), strings.NewReader("\n"), bytes.NewReader(b))
	return s.cache.Put(ctx, s.byHashKey(suite, hexSHA256(b)), body)
}
