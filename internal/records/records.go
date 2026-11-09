// Package records writes provenance and audit records to the state store.
package records

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
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
func UploaderFrom(c identity.Caller) *Uploader {
	return &Uploader{
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
	Source         string    `json:"source"`
	SourceType     string    `json:"source_type"`
	UpstreamURL    string    `json:"upstream_url,omitempty"`
	Remote         string    `json:"remote,omitempty"`
	Commit         string    `json:"commit,omitempty"`
	DeclaredDigest string    `json:"declared_digest,omitempty"` // "sha1:…", "sha256:…" or ""
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
	Action    string    `json:"action"` // "publish"
	Ecosystem string    `json:"ecosystem"`
	Package   string    `json:"package"`
	Version   string    `json:"version"`
	SHA256    string    `json:"sha256"`
	Uploader  Uploader  `json:"uploader"`
	// Attestation is the identity of a verified attestation (e.g. a Sigstore
	// certificate identity); empty when none.
	Attestation string `json:"attestation,omitempty"`
}

type Store struct{ d storage.Driver }

func New(d storage.Driver) *Store { return &Store{d: d} }

func provKey(ecosystem, pkg, version, sha256 string) (string, error) {
	if !digest.IsHex(sha256, 64) {
		return "", fmt.Errorf("records: invalid sha256 %q", sha256)
	}
	return "provenance/" + ecosystem + "/" + storage.EscapeSegment(pkg) + "/" +
		storage.EscapeSegment(version) + "/" + sha256 + ".json", nil
}

// PutProvenance stores p once. An existing record for the same digest wins; a
// differing new record for it is silently dropped.
func (s *Store) PutProvenance(ctx context.Context, p Provenance) error {
	key, err := provKey(p.Ecosystem, p.Package, p.Version, p.SHA256)
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

// GetProvenance returns storage.ErrNotFound if there is no such record.
func (s *Store) GetProvenance(ctx context.Context, ecosystem, pkg, version, sha256 string) (Provenance, error) {
	var p Provenance
	key, err := provKey(ecosystem, pkg, version, sha256)
	if err != nil {
		return p, err
	}
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
