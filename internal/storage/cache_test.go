package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	c, err := NewCache(context.Background(), d, max)
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
	c, d := newTestCache(t, 30)
	for _, k := range []string{"a", "b", "c"} {
		cachePut(t, c, k)
	}
	c2, err := NewCache(context.Background(), d, 30)
	if err != nil {
		t.Fatal(err)
	}
	if c2.total != 30 || len(c2.entries) != 3 {
		t.Fatalf("total=%d entries=%d", c2.total, len(c2.entries))
	}
	cachePut(t, c2, "d")
	if cacheHas(c2, "a") {
		t.Error("oldest entry a should be evicted after rebuild")
	}
}

type failDelete struct{ Driver }

func (failDelete) Delete(context.Context, string) error { return errors.New("boom") }

func TestCacheEvictDeleteFailure(t *testing.T) {
	d, _ := NewFS(t.TempDir())
	c, err := NewCache(context.Background(), failDelete{d}, 10)
	if err != nil {
		t.Fatal(err)
	}
	cachePut(t, c, "a")
	if err := c.Put(context.Background(), "b", strings.NewReader("0123456789")); err == nil {
		t.Fatal("want error from failed eviction")
	}
	if _, ok := c.entries["a"]; !ok {
		t.Fatal("a must stay indexed after failed delete")
	}
}

func TestCacheConcurrent(t *testing.T) {
	c, _ := newTestCache(t, 50)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 20 {
				k := fmt.Sprintf("k%d", (i+j)%10)
				_ = c.Put(context.Background(), k, strings.NewReader("0123456789"))
				if rc, _, err := c.Get(context.Background(), k); err == nil {
					rc.Close()
				}
			}
		}()
	}
	wg.Wait()
}
