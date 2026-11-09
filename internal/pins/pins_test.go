package pins

import (
	"context"
	"io"
	"slices"
	"strings"
	"sync"
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
	rc, _, err := d.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "{garbage" {
		t.Fatalf("pin overwritten: %q", got)
	}
}

func TestPinConcurrent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	shas := []string{sha1a, sha1b}
	got := make([]string, 2)
	moved := make([]bool, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			got[i], moved[i], err = s.Pin(ctx, "composer", "gh", "r", "v1", shas[i])
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got[0] != got[1] || moved[0] == moved[1] {
		t.Fatalf("got=%v moved=%v", got, moved)
	}
	if len(s.Moved()) != 1 {
		t.Fatalf("moved = %+v", s.Moved())
	}
}

func TestMovedSortedAndCopied(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tag := range []string{"b", "a", "c"} {
		s.Pin(ctx, "composer", "gh", "r", tag, sha1a)
		s.Pin(ctx, "composer", "gh", "r", tag, sha1b)
	}
	s.Pin(ctx, "composer", "aa", "r", "z", sha1a)
	s.Pin(ctx, "composer", "aa", "r", "z", sha1b)
	m := s.Moved()
	var order []string
	for _, x := range m {
		order = append(order, x.Source+"/"+x.Tag)
	}
	if !slices.Equal(order, []string{"aa/z", "gh/a", "gh/b", "gh/c"}) {
		t.Fatalf("order = %v", order)
	}
	m[0].Tag = "mutated"
	m[1] = MovedTag{}
	if got := s.Moved(); got[0].Tag != "z" || got[1].Tag != "a" {
		t.Fatalf("store affected: %+v", got)
	}
}

func TestListScopedAndSorted(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	sha := strings.Repeat("a", 40)
	for _, c := range [][3]string{{"src", "r1", "v2"}, {"src", "r1", "v1"}, {"src", "r2", "v9"}, {"other", "r1", "v7"}} {
		if _, _, err := s.Pin(ctx, "composer", c[0], c[1], c[2], sha); err != nil {
			t.Fatal(err)
		}
	}
	got, _, err := s.List(ctx, "composer", "src", "r1")
	if err != nil || len(got) != 2 || got[0].Tag != "v1" || got[1].Tag != "v2" || got[0].SHA != sha || got[0].FirstSeen.IsZero() {
		t.Fatalf("List = %+v, %v", got, err)
	}
	if got, _, err := s.List(ctx, "composer", "src", "none"); err != nil || len(got) != 0 {
		t.Fatalf("empty List = %+v, %v", got, err)
	}
}

type countingDriver struct {
	storage.Driver
	gets int
}

func (c *countingDriver) Get(ctx context.Context, key string) (io.ReadCloser, storage.Info, error) {
	c.gets++
	return c.Driver.Get(ctx, key)
}

func TestListCachesPins(t *testing.T) {
	fs, _ := storage.NewFS(t.TempDir())
	cd := &countingDriver{Driver: fs}
	ctx := context.Background()
	for _, tag := range []string{"v1", "v2"} {
		if _, _, err := New(fs).Pin(ctx, "composer", "src", "r", tag, sha1a); err != nil {
			t.Fatal(err)
		}
	}
	s := New(cd)
	if got, _, err := s.List(ctx, "composer", "src", "r"); err != nil || len(got) != 2 || cd.gets != 2 {
		t.Fatalf("first List: %v %v gets=%d", got, err, cd.gets)
	}
	if got, _, err := s.List(ctx, "composer", "src", "r"); err != nil || len(got) != 2 || cd.gets != 2 {
		t.Fatalf("second List: %v %v gets=%d", got, err, cd.gets)
	}
}

func TestListSkipsCorruptPins(t *testing.T) {
	d, _ := storage.NewFS(t.TempDir())
	s := New(d)
	ctx := context.Background()
	if _, _, err := s.Pin(ctx, "composer", "src", "r", "v1", sha1a); err != nil {
		t.Fatal(err)
	}
	key := "pins/composer/src/" + storage.EscapeSegment("r") + "/" + storage.EscapeSegment("v2") + ".json"
	if _, err := d.Put(ctx, key, strings.NewReader("{garbage")); err != nil {
		t.Fatal(err)
	}
	got, corrupt, err := s.List(ctx, "composer", "src", "r")
	if err != nil || len(got) != 1 || got[0].Tag != "v1" || len(corrupt) != 1 {
		t.Fatalf("List = %+v corrupt=%v err=%v", got, corrupt, err)
	}
}
