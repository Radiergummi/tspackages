package records

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
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

func TestProvenanceDigests(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	other := strings.Repeat("d", 64)
	for _, p := range []Provenance{
		{Ecosystem: "composer", Package: "Acme/A", Version: "1.0.0", Source: "up", SHA256: sum},
		{Ecosystem: "composer", Package: "Acme/A", Version: "1.0.0", Source: "up", SHA256: other},
		{Ecosystem: "composer", Package: "Acme/A", Version: "1.0.0-rc", Source: "up", SHA256: sum},
		{Ecosystem: "composer", Package: "Acme/AB", Version: "1.0.0", Source: "up", SHA256: sum},
	} {
		if err := s.PutProvenance(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ProvenanceDigests(ctx, "composer", "Acme/A", "1.0.0")
	slices.Sort(got)
	if err != nil || !slices.Equal(got, []string{sum, other}) {
		t.Fatalf("got %v %v", got, err)
	}
	if got, err := s.ProvenanceDigests(ctx, "composer", "x/y", "1"); err != nil || len(got) != 0 {
		t.Fatalf("unknown version: %v %v", got, err)
	}
}

func TestAuditDistTag(t *testing.T) {
	s, d := newStore(t)
	ctx := context.Background()
	at := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	for _, a := range []Audit{
		{Action: "dist-tag", Ecosystem: "npm", Package: "@a/b", Tag: "beta", Previous: "1.0.0", Version: "1.1.0", Time: at},
		{Action: "publish", Ecosystem: "npm", Package: "@a/b", Version: "1.0.0", SHA256: sum, Time: at},
	} {
		if err := s.PutAudit(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	seen := 0
	for info, err := range d.List(ctx, "audit/2026/01/02/") {
		if err != nil {
			t.Fatal(err)
		}
		rc, _, err := d.Get(ctx, info.Key)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		var a Audit
		if err := json.Unmarshal(raw, &a); err != nil {
			t.Fatal(err)
		}
		hasTag := strings.Contains(string(raw), `"tag"`) || strings.Contains(string(raw), `"previous"`)
		switch a.Action {
		case "dist-tag":
			if a.Tag != "beta" || a.Previous != "1.0.0" || a.Version != "1.1.0" {
				t.Fatalf("dist-tag = %+v", a)
			}
		case "publish":
			if hasTag {
				t.Fatalf("publish record has tag keys: %s", raw)
			}
		}
		seen++
	}
	if seen != 2 {
		t.Fatalf("records = %d", seen)
	}
}

func TestFileField(t *testing.T) {
	s, d := newStore(t)
	ctx := context.Background()
	p := Provenance{Ecosystem: "maven", Package: "com.acme:lib", Version: "1.0", File: "lib-1.0.jar", Source: "central", SHA256: sum}
	if err := s.PutProvenance(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.FileProvenance(ctx, "maven", "com.acme:lib", "1.0", "lib-1.0.jar")
	if err != nil || len(got) != 1 || got[0].File != "lib-1.0.jar" {
		t.Fatalf("got %+v, %v", got, err)
	}
	// A record written without a file (every earlier ecosystem) has no key.
	other := strings.Repeat("d", 64)
	if err := s.PutProvenance(ctx, Provenance{Ecosystem: "npm", Package: "a", Version: "1.0.0", SHA256: other}); err != nil {
		t.Fatal(err)
	}
	rc, _, err := d.Get(ctx, provPrefix("npm", "a", "1.0.0")+other+".json")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(rc)
	rc.Close()
	if strings.Contains(string(raw), `"file"`) {
		t.Fatalf("record without file has the key: %s", raw)
	}
	at := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	if err := s.PutAudit(ctx, Audit{Action: "publish", Ecosystem: "maven", Package: "com.acme:lib", Version: "1.0", File: "lib-1.0.pom", SHA256: sum, Time: at}); err != nil {
		t.Fatal(err)
	}
	for info, err := range d.List(ctx, "audit/2026/01/03/") {
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
		if err != nil || a.File != "lib-1.0.pom" {
			t.Fatalf("audit = %+v, %v", a, err)
		}
	}
}

// TestFileProvenanceKeyedByFile: files of one version with the same bytes
// each keep their record, and FileProvenance lists one file's records only.
func TestFileProvenanceKeyedByFile(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	other := strings.Repeat("d", 64)
	for _, p := range []Provenance{
		{File: "lib-1.0-sources.jar", SHA256: sum},
		{File: "lib-1.0-javadoc.jar", SHA256: sum},
		{File: "lib-1.0-javadoc.jar", SHA256: other},
		{File: strings.Repeat("Ä", 200), SHA256: sum}, // longer than a key segment once escaped
	} {
		p.Ecosystem, p.Package, p.Version, p.Source = "maven", "com.acme:lib", "1.0", "central"
		if err := s.PutProvenance(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	for file, want := range map[string][]string{
		"lib-1.0-sources.jar":    {sum},
		"lib-1.0-javadoc.jar":    {sum, other},
		strings.Repeat("Ä", 200): {sum},
		"lib-1.0.jar":            nil,
	} {
		got, err := s.FileProvenance(ctx, "maven", "com.acme:lib", "1.0", file)
		if err != nil {
			t.Fatal(err)
		}
		var sums []string
		for _, p := range got {
			if p.File != file {
				t.Errorf("%s: record for %s", file, p.File)
			}
			sums = append(sums, p.SHA256)
		}
		slices.Sort(sums)
		if !slices.Equal(sums, want) {
			t.Errorf("%s: sha256s = %v, want %v", file[:min(len(file), 20)], sums, want)
		}
	}
	// File records are not version-level records.
	if d, err := s.ProvenanceDigests(ctx, "maven", "com.acme:lib", "1.0"); err != nil || len(d) != 0 {
		t.Errorf("ProvenanceDigests = %v, %v", d, err)
	}
}
