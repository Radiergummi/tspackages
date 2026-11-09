package pins

import (
	"context"
	"strings"
	"testing"

	"github.com/radiergummi/tspackages/internal/storage"
)

var (
	sha1a = strings.Repeat("a", 40)
	sha1b = strings.Repeat("b", 40)
)

func newStore(t *testing.T) *Store {
	t.Helper()
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return New(d)
}

func TestPinFirstSight(t *testing.T) {
	s := newStore(t)
	got, moved, err := s.Pin(context.Background(), "composer", "gh", "https://x/y.git", "v1.0.0", sha1a)
	if err != nil || moved || got != sha1a {
		t.Fatalf("got %q moved=%v err=%v", got, moved, err)
	}
	if len(s.Moved()) != 0 {
		t.Fatal("unexpected moved entries")
	}
}

func TestPinMoved(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, _, err := s.Pin(ctx, "composer", "gh", "r", "v1", sha1a); err != nil {
		t.Fatal(err)
	}
	got, moved, err := s.Pin(ctx, "composer", "gh", "r", "v1", sha1b)
	if err != nil || !moved || got != sha1a {
		t.Fatalf("got %q moved=%v err=%v", got, moved, err)
	}
	// repeated detection de-duplicates
	if _, _, err := s.Pin(ctx, "composer", "gh", "r", "v1", sha1b); err != nil {
		t.Fatal(err)
	}
	m := s.Moved()
	if len(m) != 1 || m[0].Pinned != sha1a || m[0].Seen != sha1b || m[0].Tag != "v1" {
		t.Fatalf("moved = %+v", m)
	}
}

func TestPinTagWithSlash(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tag := "release/2026-01"
	if _, _, err := s.Pin(ctx, "composer", "gh", "r", tag, sha1a); err != nil {
		t.Fatal(err)
	}
	got, moved, err := s.Pin(ctx, "composer", "gh", "r", tag, sha1a)
	if err != nil || moved || got != sha1a {
		t.Fatalf("got %q moved=%v err=%v", got, moved, err)
	}
}

func TestPinRejectsBadSHA(t *testing.T) {
	s := newStore(t)
	for _, sha := range []string{"", "abc", strings.ToUpper(sha1a), strings.Repeat("g", 40)} {
		if _, _, err := s.Pin(context.Background(), "composer", "gh", "r", "v1", sha); err == nil {
			t.Fatalf("sha %q accepted", sha)
		}
	}
	if _, _, err := s.Pin(context.Background(), "composer", "gh", "r", "v1", strings.Repeat("a", 64)); err != nil {
		t.Fatalf("sha256 rejected: %v", err)
	}
}

func TestPinCorruptFileNotOverwritten(t *testing.T) {
	d, _ := storage.NewFS(t.TempDir())
	s := New(d)
	key := "pins/composer/gh/" + storage.EscapeSegment("r") + "/" + storage.EscapeSegment("v1") + ".json"
	if _, err := d.Put(context.Background(), key, strings.NewReader("{garbage")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Pin(context.Background(), "composer", "gh", "r", "v1", sha1a); err == nil {
		t.Fatal("expected error")
	}
}
