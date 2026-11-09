package storage

import (
	"container/list"
	"context"
	"errors"
	"io"
	"sort"
	"sync"
	"time"
)

// Cache is a size-capped LRU over a Driver. Entries are evictable: callers must
// be able to refetch anything they put here. Age is measured from the write
// time, not from the last access.
type Cache struct {
	d       Driver
	maxSize int64

	mu      sync.Mutex
	lru     *list.List // front = most recently used; values are *cacheEntry
	entries map[string]*list.Element
	total   int64
}

type cacheEntry struct {
	key  string
	size int64
}

// NewCache builds the LRU index from the objects already in d, treating older
// ModTimes as less recently used.
func NewCache(ctx context.Context, d Driver, maxSize int64) (*Cache, error) {
	var infos []Info
	for info, err := range d.List(ctx, "") {
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	sort.SliceStable(infos, func(i, j int) bool { return infos[i].ModTime.Before(infos[j].ModTime) })

	c := &Cache{d: d, maxSize: maxSize, lru: list.New(), entries: make(map[string]*list.Element)}
	for _, info := range infos {
		c.entries[info.Key] = c.lru.PushFront(&cacheEntry{key: info.Key, size: info.Size})
		c.total += info.Size
	}
	return c, nil
}

// Get opens key and marks it as used. A missing key returns ErrNotFound.
func (c *Cache) Get(ctx context.Context, key string) (io.ReadCloser, time.Duration, error) {
	rc, info, err := c.d.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			c.forget(key)
		}
		return nil, 0, err
	}
	c.mu.Lock()
	if el, ok := c.entries[key]; ok {
		c.lru.MoveToFront(el)
	}
	c.mu.Unlock()
	return rc, max(time.Since(info.ModTime), 0), nil
}

// Put stores r under key, then evicts least-recently-used entries until the
// total is at most maxSize. An entry larger than maxSize is not kept; Put
// returns nil. If an eviction fails, the entry stays indexed and the error is
// returned.
func (c *Cache) Put(ctx context.Context, key string, r io.Reader) error {
	info, err := c.d.Put(ctx, key, r)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if info.Size > c.maxSize {
		c.removeLocked(key)
		return c.d.Delete(ctx, key)
	}
	if el, ok := c.entries[key]; ok {
		c.total += info.Size - el.Value.(*cacheEntry).size
		el.Value.(*cacheEntry).size = info.Size
		c.lru.MoveToFront(el)
	} else {
		c.entries[key] = c.lru.PushFront(&cacheEntry{key: key, size: info.Size})
		c.total += info.Size
	}

	for c.total > c.maxSize {
		el := c.lru.Back()
		victim := el.Value.(*cacheEntry)
		if err := c.d.Delete(ctx, victim.key); err != nil {
			return err
		}
		c.removeLocked(victim.key)
	}
	return nil
}

func (c *Cache) forget(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(key)
}

func (c *Cache) removeLocked(key string) {
	if el, ok := c.entries[key]; ok {
		c.total -= el.Value.(*cacheEntry).size
		c.lru.Remove(el)
		delete(c.entries, key)
	}
}
