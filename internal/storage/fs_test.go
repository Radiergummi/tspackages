package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestFS(t *testing.T) {
	d, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runDriverSuite(t, d)
}

// The S3 driver cannot cheaply detect a key that is also a prefix of another
// key, so this behaviour is asserted for fs only.
func TestFSKeyPrefixConflict(t *testing.T) {
	ctx := context.Background()
	d, _ := NewFS(t.TempDir())
	put(t, d, "pre/a", "x")
	if _, err := d.Put(ctx, "pre", bytes.NewReader(nil)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Put over directory: %v", err)
	}
	if _, err := d.PutIfAbsent(ctx, "pre", bytes.NewReader(nil)); !errors.Is(err, ErrExists) {
		t.Errorf("PutIfAbsent over directory: %v", err)
	}
	put(t, d, "file", "x")
	if _, err := d.Put(ctx, "file/child", bytes.NewReader(nil)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Put below file: %v", err)
	}
	if _, _, err := d.Get(ctx, "file/child"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get below file: %v", err)
	}
	if _, _, err := d.Get(ctx, "pre"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get of directory: %v", err)
	}
}

// Sidecar, lock and temp files use "#", which keys cannot contain, so keys
// ending in .lock, .etag or .tmp are ordinary keys.
func TestFSSidecarNamesCannotCollide(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	d, _ := NewFS(root)
	keys := []string{"x", "x.lock", "x.etag", "x.tmp", "a.lock/b", "a.etag/b", "a.tmp/b"}
	for _, k := range keys {
		put(t, d, k, "v-"+k)
	}
	for _, k := range keys {
		rc, _, err := d.Get(ctx, k)
		if err != nil {
			t.Fatalf("Get(%q): %v", k, err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if string(b) != "v-"+k {
			t.Errorf("Get(%q) = %q", k, b)
		}
	}
	var listed []string
	for info, err := range d.List(ctx, "") {
		if err != nil {
			t.Fatal(err)
		}
		listed = append(listed, info.Key)
	}
	slices.Sort(keys)
	if !slices.Equal(listed, keys) {
		t.Errorf("List = %v, want %v", listed, keys)
	}
	if _, err := os.Stat(filepath.Join(root, "x#etag")); err != nil {
		t.Errorf("sidecar: %v", err)
	}
}

func TestFSReadsCreateNothing(t *testing.T) {
	root := t.TempDir()
	d, _ := NewFS(root)
	ctx := context.Background()
	d.Get(ctx, "no/such/key")
	d.Stat(ctx, "no/such/key")
	d.Delete(ctx, "no/such/key")
	if ents, _ := os.ReadDir(root); len(ents) != 1 || ents[0].Name() != lockDir {
		t.Fatalf("root holds more than %s: %v", lockDir, ents)
	}
	if locks, _ := os.ReadDir(filepath.Join(root, lockDir)); len(locks) != 0 {
		t.Fatalf("reads of missing keys took locks: %v", locks)
	}
}

func TestFSStaleSidecarIgnored(t *testing.T) {
	root := t.TempDir()
	d, _ := NewFS(root)
	first := put(t, d, "k", "one")
	// Simulate a crash after the new object was renamed but before its sidecar.
	side, _ := os.ReadFile(filepath.Join(root, "k#etag"))
	second := put(t, d, "k", "two!")
	os.WriteFile(filepath.Join(root, "k#etag"), side, 0o644)
	st, err := d.Stat(context.Background(), "k")
	if err != nil || st.ETag != second.ETag || st.ETag == first.ETag {
		t.Fatalf("stat=%+v err=%v first=%q second=%q", st, err, first.ETag, second.ETag)
	}
}

// Lock files are a fixed set, so churn (a cache evicting) leaves nothing behind.
func TestFSLeavesNoPerKeyFiles(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	d, _ := NewFS(root)
	for i := range 300 {
		key := fmt.Sprintf("k/%d", i)
		put(t, d, key, "x")
		rc, _, err := d.Get(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		rc.Close()
		if err := d.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "k"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("left behind: %d files, e.g. %s", len(entries), entries[0].Name())
	}
	locks, _ := os.ReadDir(filepath.Join(root, "#locks"))
	if len(locks) > 256 {
		t.Fatalf("%d lock files", len(locks))
	}
	put(t, d, "k/live", "x")
	var keys []string
	for info, err := range d.List(ctx, "") {
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, info.Key)
	}
	if !slices.Equal(keys, []string{"k/live"}) {
		t.Fatalf("List = %v", keys)
	}
}

func TestFSRemovesStaleTempFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "a")
	os.MkdirAll(dir, 0o755)
	stale, fresh := filepath.Join(dir, "1#tmp"), filepath.Join(dir, "2#tmp")
	for _, p := range []string{stale, fresh} {
		os.WriteFile(p, []byte("x"), 0o644)
	}
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(stale, old, old)
	if _, err := NewFS(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale temp file kept: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh temp file removed (it may be another instance's write): %v", err)
	}
}

// Stores hold private packages and audit records: owner-only, like work_dir.
func TestFSIsOwnerOnly(t *testing.T) {
	root := t.TempDir()
	d, _ := NewFS(root)
	put(t, d, "a/b", "x")
	for p, want := range map[string]os.FileMode{
		filepath.Join(root, "a"):           0o700,
		filepath.Join(root, "a", "b"):      0o600,
		filepath.Join(root, "a", "b#etag"): 0o600,
		filepath.Join(root, lockDir):       0o700,
	} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", p, got, want)
		}
	}
}

func TestFSGetRange(t *testing.T) {
	d, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	testGetRange(t, d)
}

func testGetRange(t *testing.T, d Driver) {
	t.Helper()
	ctx := context.Background()
	if _, err := d.Put(ctx, "k", strings.NewReader("0123456789")); err != nil {
		t.Fatal(err)
	}
	rg, ok := d.(RangeGetter)
	if !ok {
		t.Fatalf("%T is not a RangeGetter", d)
	}
	for _, c := range []struct {
		off, n int64
		want   string
	}{{2, 3, "234"}, {7, -1, "789"}, {0, -1, "0123456789"}} {
		rc, err := rg.GetRange(ctx, "k", c.off, c.n)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if string(b) != c.want {
			t.Errorf("GetRange(%d, %d) = %q, want %q", c.off, c.n, b, c.want)
		}
	}
	if _, err := rg.GetRange(ctx, "missing", 0, 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing key: %v", err)
	}
}
