package lru

import (
	"sync"
	"testing"
)

func TestEvictsLeastRecentlyUsedBySize(t *testing.T) {
	c := New(10, func(s string) int64 { return int64(len(s)) })
	c.Put("a", "aaaa")
	c.Put("b", "bbbb")
	if _, ok := c.Get("a"); !ok { // a is now the most recently used
		t.Fatal("a missing")
	}
	c.Put("c", "cccc") // 12 bytes: b goes
	if _, ok := c.Get("b"); ok {
		t.Error("b kept past the cap")
	}
	for _, k := range []string{"a", "c"} {
		if _, ok := c.Get(k); !ok {
			t.Errorf("%s evicted", k)
		}
	}
	c.Put("a", "a") // replacing a value updates the size
	c.Put("d", "dddd")
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.Get(k); !ok {
			t.Errorf("%s evicted after replace", k)
		}
	}
	c.Delete("c")
	if _, ok := c.Get("c"); ok {
		t.Error("c kept after Delete")
	}
	c.Put("big", "0123456789x") // larger than the cap: not kept, nothing else lost
	if _, ok := c.Get("big"); ok {
		t.Error("value over the cap kept")
	}
	if _, ok := c.Get("d"); !ok {
		t.Error("d evicted by a value over the cap")
	}
}

func TestConcurrent(t *testing.T) {
	c := New(100, func(int) int64 { return 1 })
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 1000 {
				k := string(rune('a' + (i+j)%26))
				c.Put(k, j)
				c.Get(k)
				if j%7 == 0 {
					c.Delete(k)
				}
			}
		})
	}
	wg.Wait()
}
