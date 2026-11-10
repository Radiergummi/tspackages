package records

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/storage"
)

func newStore(t *testing.T) (*Store, storage.Driver) {
	t.Helper()
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return New(d), d
}

var sum = strings.Repeat("c", 64)

func TestProvenanceIdempotent(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	p := Provenance{
		Ecosystem: "composer", Package: "Matchory/SDK", Version: "1.0.0/rc",
		Source: "gh", SourceType: "git", SHA256: sum,
		Attestation: "sigstore:id", Uploader: new(UploaderFrom(identity.Caller{Login: "a@b", Tags: []string{"tag:x"}, NodeName: "n", NodeStableID: "s"})),
	}
	if err := s.PutProvenance(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.PutProvenance(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetProvenance(ctx, "composer", "Matchory/SDK", "1.0.0/rc", sum)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "gh" || got.Uploader == nil || got.Uploader.NodeStableID != "s" || got.Created.IsZero() || got.Attestation != "sigstore:id" {
		t.Fatalf("got %+v", got)
	}
	if _, err := s.GetProvenance(ctx, "composer", "x/y", "1", sum); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestProvenanceBadDigest(t *testing.T) {
	s, _ := newStore(t)
	err := s.PutProvenance(context.Background(), Provenance{Ecosystem: "composer", Package: "a/b", Version: "1", SHA256: "ABC"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuditKeysUnique(t *testing.T) {
	s, d := newStore(t)
	ctx := context.Background()
	for range 100 {
		if err := s.PutAudit(ctx, Audit{Action: "publish", Ecosystem: "composer", Package: "a/b", Version: "1", SHA256: sum,
			Uploader: Uploader{Login: "x"}, Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	for info, err := range d.List(ctx, "audit/2026/01/02/") {
		if err != nil {
			t.Fatal(err)
		}
		_ = info
		n++
	}
	if n != 100 {
		t.Fatalf("keys = %d", n)
	}
}

func TestAuditValidationAndAttestation(t *testing.T) {
	s, d := newStore(t)
	ctx := context.Background()
	ok := Audit{Action: "publish", SHA256: sum, Attestation: "id", Time: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}
	for name, a := range map[string]Audit{
		"no action":      {SHA256: sum},
		"publish no sha": {Action: "publish"},
		"bad sha":        {Action: "publish", SHA256: "XYZ"},
		"other bad sha":  {Action: "other", SHA256: "XYZ"},
	} {
		if err := s.PutAudit(ctx, a); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := s.PutAudit(ctx, Audit{Action: "other"}); err != nil {
		t.Fatalf("empty sha on non-artifact action: %v", err)
	}
	if err := s.PutAudit(ctx, ok); err != nil {
		t.Fatal(err)
	}
	for info, err := range d.List(ctx, "audit/2026/01/02/") {
		if err != nil {
			t.Fatal(err)
		}
		rc, _, err := d.Get(ctx, info.Key)
		if err != nil {
			t.Fatal(err)
		}
		var a Audit
		err = json.NewDecoder(rc).Decode(&a)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if a.Attestation != "id" {
			t.Fatalf("attestation = %q", a.Attestation)
		}
	}
}

func TestListProvenance(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	other := strings.Repeat("d", 64)
	for _, p := range []Provenance{
		{Ecosystem: "composer", Package: "Acme/A", Version: "1.0.0", Source: "up", SHA256: sum, Commit: "r1"},
		{Ecosystem: "composer", Package: "Acme/A", Version: "1.0.0", Source: "up", SHA256: other, Commit: "r1"},
		{Ecosystem: "composer", Package: "Acme/A", Version: "1.0.0-rc", Source: "up", SHA256: sum},
		{Ecosystem: "composer", Package: "Acme/AB", Version: "1.0.0", Source: "up", SHA256: sum},
	} {
		if err := s.PutProvenance(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListProvenance(ctx, "composer", "Acme/A", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Commit != "r1" || got[1].Commit != "r1" || got[0].SHA256 == got[1].SHA256 {
		t.Fatalf("got %+v", got)
	}
	if got, err := s.ListProvenance(ctx, "composer", "x/y", "1"); err != nil || len(got) != 0 {
		t.Fatalf("unknown version: %v %v", got, err)
	}
}
