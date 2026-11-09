package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
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
	if _, err := os.Stat(filepath.Join(root, "x#lock")); err != nil {
		t.Errorf("lock file: %v", err)
	}
}

func TestFSReadsCreateNothing(t *testing.T) {
	root := t.TempDir()
	d, _ := NewFS(root)
	ctx := context.Background()
	d.Get(ctx, "no/such/key")
	d.Stat(ctx, "no/such/key")
	d.Delete(ctx, "no/such/key")
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Fatalf("root not empty: %v", ents)
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
