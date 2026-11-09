package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestCache(t *testing.T, max int64) (*Cache, Driver) {
	t.Helper()
	d, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCache(context.Background(), d, max, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, d
}

func cachePut(t *testing.T, c *Cache, key string) {
	t.Helper()
	if err := c.Put(context.Background(), key, strings.NewReader("0123456789")); err != nil {
		t.Fatal(err)
	}
}

func cacheHas(c *Cache, key string) bool {
	rc, _, err := c.Get(context.Background(), key)
	if err != nil {
		return false
	}
	rc.Close()
	return true
}

func TestCacheEvictsLRU(t *testing.T) {
	c, _ := newTestCache(t, 30)
	for _, k := range []string{"a", "b", "c"} {
		cachePut(t, c, k)
	}
	rc, _, err := c.Get(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	cachePut(t, c, "d")

	if cacheHas(c, "b") {
		t.Error("b should have been evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if !cacheHas(c, k) {
			t.Errorf("%s should remain", k)
		}
	}
}

func TestCacheGetMissing(t *testing.T) {
	c, _ := newTestCache(t, 30)
	_, _, err := c.Get(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestCacheAge(t *testing.T) {
	c, _ := newTestCache(t, 30)
	cachePut(t, c, "a")
	rc, age, err := c.Get(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if age < 0 || age >= time.Second {
		t.Fatalf("age = %v", age)
	}
	b, _ := io.ReadAll(rc)
	if string(b) != "0123456789" {
		t.Fatalf("body = %q", b)
	}
}

func TestCacheOversizeNotCached(t *testing.T) {
	c, d := newTestCache(t, 5)
	if err := c.Put(context.Background(), "big", strings.NewReader("0123456789")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Stat(context.Background(), "big"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oversize entry left in driver: %v", err)
	}
	if cacheHas(c, "big") {
		t.Fatal("oversize entry served")
	}
}

func TestCacheOverwriteAdjustsSize(t *testing.T) {
	c, _ := newTestCache(t, 20)
	cachePut(t, c, "a")
	cachePut(t, c, "a")
	cachePut(t, c, "b")
	if !cacheHas(c, "a") || !cacheHas(c, "b") {
		t.Fatal("overwrite double-counted size")
	}
}

func TestCacheIndexRebuild(t *testing.T) {
	d, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Lexical order is a, b, c but age order is c (oldest), a, b.
	now := time.Now()
	for k, age := range map[string]time.Duration{"a": 2 * time.Hour, "b": time.Hour, "c": 3 * time.Hour} {
		if _, err := d.Put(ctx, k, strings.NewReader("0123456789")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(filepath.Join(d.(*fsDriver).root, k), now, now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	c, err := NewCache(ctx, d, 30, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.total != 30 || len(c.entries) != 3 {
		t.Fatalf("total=%d entries=%d", c.total, len(c.entries))
	}
	cachePut(t, c, "d")
	if cacheHas(c, "c") {
		t.Error("oldest entry c should be evicted after rebuild")
	}
	for _, k := range []string{"a", "b", "d"} {
		if !cacheHas(c, k) {
			t.Errorf("%s should remain", k)
		}
	}
}

func TestCacheRebuildTrims(t *testing.T) {
	c, d := newTestCache(t, 30)
	for _, k := range []string{"a", "b", "c"} {
		cachePut(t, c, k)
	}
	c2, err := NewCache(context.Background(), d, 20, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c2.total != 20 || len(c2.entries) != 2 {
		t.Fatalf("total=%d entries=%d", c2.total, len(c2.entries))
	}
}

// failKeyDelete fails Delete for one key.
type failKeyDelete struct {
	Driver
	key string
}

func (f failKeyDelete) Delete(ctx context.Context, key string) error {
	if key == f.key {
		return errors.New("boom")
	}
	return f.Driver.Delete(ctx, key)
}

func TestCacheEvictDeleteFailure(t *testing.T) {
	d, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, err := NewCache(ctx, failKeyDelete{d, "a"}, 20, nil)
	if err != nil {
		t.Fatal(err)
	}
	cachePut(t, c, "a")
	cachePut(t, c, "b")
	if err := c.Put(ctx, "c", strings.NewReader("0123456789")); err == nil {
		t.Fatal("want error from failed eviction of a")
	}
	if _, ok := c.entries["a"]; !ok || c.total != 30 {
		t.Fatalf("a must stay indexed and counted: total=%d", c.total)
	}
	// Progress continues: a is now most recently used, so b is evicted next.
	cachePut(t, c, "d")
	if _, ok := c.entries["b"]; ok {
		t.Fatal("b should have been evicted despite a's failure")
	}
}

func TestCacheOversizeDeleteFailureStaysIndexed(t *testing.T) {
	d, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCache(context.Background(), failKeyDelete{d, "big"}, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The delete fails twice (oversize check, then eviction): error surfaces.
	if err := c.Put(context.Background(), "big", strings.NewReader("0123456789")); err == nil {
		t.Fatal("want delete error")
	}
	if _, ok := c.entries["big"]; !ok || c.total != 10 {
		t.Fatalf("orphaned object must stay indexed: total=%d", c.total)
	}
}

func TestCacheConcurrent(t *testing.T) {
	const maxSize = 50
	c, d := newTestCache(t, maxSize)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 40 {
				n := (i + j) % 10
				k := fmt.Sprintf("k%d", n)
				body := strings.Repeat("x", 1+(i+j)%12) // size varies per write
				_ = c.Put(ctx, k, strings.NewReader(body))
				if rc, _, err := c.Get(ctx, k); err == nil {
					rc.Close()
				}
			}
		}()
	}
	wg.Wait()

	var disk int64
	for info, err := range d.List(ctx, "") {
		if err != nil {
			t.Fatal(err)
		}
		disk += info.Size
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.total > maxSize {
		t.Errorf("total %d exceeds max %d", c.total, maxSize)
	}
	if c.total != disk {
		t.Errorf("index total %d != bytes on disk %d", c.total, disk)
	}
}

func TestNewCacheTrimFailureDoesNotFailStartup(t *testing.T) {
	d, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, k := range []string{"a", "b"} {
		if _, err := d.Put(ctx, k, strings.NewReader("0123456789")); err != nil {
			t.Fatal(err)
		}
	}
	var logs bytes.Buffer
	c, err := NewCache(ctx, failKeyDelete{d, "a"}, 10, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("startup failed on a trim delete: %v", err)
	}
	if c.total != 20 || !strings.Contains(logs.String(), "boom") {
		t.Fatalf("total=%d logs=%s", c.total, logs.String())
	}
}
