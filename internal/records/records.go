// Package records writes provenance and audit records to the state store.
package records

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/digest"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/storage"
)

// Uploader identifies who published an artifact.
type Uploader struct {
	Login        string   `json:"login,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	NodeName     string   `json:"node_name,omitempty"`
	NodeStableID string   `json:"node_stable_id,omitempty"`
}

// UploaderFrom copies the identifying fields of a caller.
func UploaderFrom(c identity.Caller) Uploader {
	return Uploader{
		Login:        c.Login,
		Tags:         append([]string(nil), c.Tags...),
		NodeName:     c.NodeName,
		NodeStableID: c.NodeStableID,
	}
}

// Provenance records where an artifact came from.
type Provenance struct {
	Ecosystem      string    `json:"ecosystem"`
	Package        string    `json:"package"`
	Version        string    `json:"version"`
	File           string    `json:"file,omitempty"` // the file within the version, where a version has several
	Source         string    `json:"source"`
	SourceType     string    `json:"source_type"`
	UpstreamURL    string    `json:"upstream_url,omitempty"`
	Remote         string    `json:"remote,omitempty"`
	Commit         string    `json:"commit,omitempty"`
	DeclaredDigest string    `json:"declared_digest,omitempty"` // "sha1:…", "sha256:…", "sha512:…" or ""
	SHA1           string    `json:"sha1,omitempty"`
	SHA256         string    `json:"sha256"`
	Uploader       *Uploader `json:"uploader,omitempty"`
	// Attestation is the identity of a verified attestation (e.g. a Sigstore
	// certificate identity); empty when none.
	Attestation string    `json:"attestation,omitempty"`
	Created     time.Time `json:"created"`
}

// Audit records one write action.
type Audit struct {
	Time      time.Time `json:"time"`
	Action    string    `json:"action"` // "publish", "deploy", "dist-tag" or "dist-tag-commit"
	Ecosystem string    `json:"ecosystem"`
	Package   string    `json:"package"`
	Version   string    `json:"version"`
	File      string    `json:"file,omitempty"` // the file within the version, where a version has several
	SHA256    string    `json:"sha256"`
	Uploader  Uploader  `json:"uploader"`
	// Attestation is the identity of a verified attestation (e.g. a Sigstore
	// certificate identity); empty when none.
	Attestation string `json:"attestation,omitempty"`
	// Tag and Previous are set on "dist-tag" records: the tag moved to Version
	// and the version it pointed at before ("" if it was new).
	Tag      string `json:"tag,omitempty"`
	Previous string `json:"previous,omitempty"`
	// Attempt groups the "dist-tag" records of one try at a dist-tags write.
	// They are written before the write; a "dist-tag-commit" record with
	// the same Attempt says the write stuck. Records of an attempt without
	// one most likely lost a concurrent write, but may have taken effect
	// (a crash or a failed commit record after the write): the dist-tags
	// document is the truth.
	Attempt string `json:"attempt,omitempty"`
}

type Store struct{ d storage.Driver }

func New(d storage.Driver) *Store { return &Store{d: d} }

func provKey(ecosystem, pkg, version, file, sha256 string) (string, error) {
	if !digest.IsHex(sha256, 64) {
		return "", fmt.Errorf("records: invalid sha256 %q", sha256)
	}
	prefix := provPrefix(ecosystem, pkg, version)
	if file != "" {
		prefix = fileProvPrefix(ecosystem, pkg, version, file)
	}
	return prefix + sha256 + ".json", nil
}

func provPrefix(ecosystem, pkg, version string) string {
	return "provenance/" + ecosystem + "/" + storage.EscapeSegment(pkg) + "/" + storage.EscapeSegment(version) + "/"
}

// fileProvPrefix holds the records of one file of a version. The file is
// named by its name's sha256, which fits a key segment whatever its length.
func fileProvPrefix(ecosystem, pkg, version, file string) string {
	sum := sha256.Sum256([]byte(file))
	return provPrefix(ecosystem, pkg, version) + "files/" + hex.EncodeToString(sum[:]) + "/"
}

// PutProvenance stores p once. An existing record for the same digest (and
// file, when p names one) wins; a differing new record for it is silently
// dropped.
func (s *Store) PutProvenance(ctx context.Context, p Provenance) error {
	key, err := provKey(p.Ecosystem, p.Package, p.Version, p.File, p.SHA256)
	if err != nil {
		return err
	}
	if p.Created.IsZero() {
		p.Created = time.Now().UTC()
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if _, err := s.d.PutIfAbsent(ctx, key, bytes.NewReader(body)); err != nil && !errors.Is(err, storage.ErrExists) {
		return err
	}
	return nil
}

// GetProvenance returns the version-level record (one without a file) for
// sha256, or storage.ErrNotFound if there is none.
func (s *Store) GetProvenance(ctx context.Context, ecosystem, pkg, version, sha256 string) (Provenance, error) {
	key, err := provKey(ecosystem, pkg, version, "", sha256)
	if err != nil {
		return Provenance{}, err
	}
	return s.readProvenance(ctx, key)
}

// FileProvenance returns every record of one file of a version, one per
// digest, in no particular order.
func (s *Store) FileProvenance(ctx context.Context, ecosystem, pkg, version, file string) ([]Provenance, error) {
	var out []Provenance
	for info, err := range s.d.List(ctx, fileProvPrefix(ecosystem, pkg, version, file)) {
		if err != nil {
			return nil, err
		}
		p, err := s.readProvenance(ctx, info.Key)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *Store) readProvenance(ctx context.Context, key string) (Provenance, error) {
	var p Provenance
	rc, _, err := s.d.Get(ctx, key)
	if err != nil {
		return p, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(raw, &p)
	return p, err
}

// ProvenanceDigests returns the sha256 digests that have a version-level
// provenance record (one without a file), from the record keys alone.
func (s *Store) ProvenanceDigests(ctx context.Context, ecosystem, pkg, version string) ([]string, error) {
	prefix := provPrefix(ecosystem, pkg, version)
	var out []string
	for info, err := range s.d.List(ctx, prefix) {
		if err != nil {
			return nil, err
		}
		if sha256, ok := strings.CutSuffix(strings.TrimPrefix(info.Key, prefix), ".json"); ok && digest.IsHex(sha256, 64) {
			out = append(out, sha256)
		}
	}
	return out, nil
}

// PutAudit stores a at audit/<date>/<unixnano>-<random>.json.
func (s *Store) PutAudit(ctx context.Context, a Audit) error {
	if a.Action == "" {
		return errors.New("records: audit action is empty")
	}
	if a.SHA256 != "" || a.Action == "publish" {
		if !digest.IsHex(a.SHA256, 64) {
			return fmt.Errorf("records: invalid sha256 %q", a.SHA256)
		}
	}
	if a.Time.IsZero() {
		a.Time = time.Now()
	}
	a.Time = a.Time.UTC()
	var r [4]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	key := "audit/" + a.Time.Format("2006/01/02") + "/" + strconv.FormatInt(a.Time.UnixNano(), 10) + "-" + hex.EncodeToString(r[:]) + ".json"
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = s.d.PutIfAbsent(ctx, key, bytes.NewReader(body))
	return err
}
