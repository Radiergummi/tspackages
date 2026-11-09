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
//
// Writers are serialised per key (driver write plus index update, and
// eviction deletes of that key), so the index total always matches the
// objects on disk. The index mutex is never held across driver I/O.
type Cache struct {
	d       Driver
	maxSize int64

	mu      sync.Mutex
	lru     *list.List // front = most recently used; values are *cacheEntry
	entries map[string]*list.Element
	total   int64

	kmu   sync.Mutex
	locks map[string]*keyLock
}

type cacheEntry struct {
	key  string
	size int64
}

type keyLock struct {
	mu   sync.Mutex
	refs int
}

// NewCache builds the LRU index from the objects already in d, treating older
// ModTimes as less recently used, and evicts the oldest until it fits maxSize.
func NewCache(ctx context.Context, d Driver, maxSize int64) (*Cache, error) {
	var infos []Info
	for info, err := range d.List(ctx, "") {
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	sort.SliceStable(infos, func(i, j int) bool { return infos[i].ModTime.Before(infos[j].ModTime) })

	c := &Cache{
		d: d, maxSize: maxSize,
		lru: list.New(), entries: make(map[string]*list.Element),
		locks: make(map[string]*keyLock),
	}
	for _, info := range infos {
		c.entries[info.Key] = c.lru.PushFront(&cacheEntry{key: info.Key, size: info.Size})
		c.total += info.Size
	}
	if err := c.evict(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cache) lockKey(key string) func() {
	c.kmu.Lock()
	l, ok := c.locks[key]
	if !ok {
		l = &keyLock{}
		c.locks[key] = l
	}
	l.refs++
	c.kmu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		c.kmu.Lock()
		if l.refs--; l.refs == 0 {
			delete(c.locks, key)
		}
		c.kmu.Unlock()
	}
}

// Get opens key and marks it as used. A missing key returns ErrNotFound.
func (c *Cache) Get(ctx context.Context, key string) (io.ReadCloser, time.Duration, error) {
	rc, info, err := c.d.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			c.forget(ctx, key)
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
// total is at most maxSize.
//
// The object's size is only known from the driver after the write, so an entry
// larger than maxSize is written and then deleted again; Put returns nil. That
// also replaces (and so removes) any previous entry under the same key. If that
// delete fails, the object stays indexed as most recently used.
//
// A failed eviction delete re-inserts the victim as most recently used with
// its size counted and eviction moves on; the joined errors are returned. The
// total can then exceed maxSize until a later Put succeeds in evicting.
func (c *Cache) Put(ctx context.Context, key string, r io.Reader) error {
	unlock := c.lockKey(key)
	info, err := c.d.Put(ctx, key, r)
	if err != nil {
		unlock()
		return err
	}
	if info.Size > c.maxSize {
		if err := c.d.Delete(ctx, key); err == nil {
			c.forgetIndexed(key)
			unlock()
			return nil
		}
		// Delete failed: keep the object accounted for, as below.
	}
	c.mu.Lock()
	if el, ok := c.entries[key]; ok {
		c.total += info.Size - el.Value.(*cacheEntry).size
		el.Value.(*cacheEntry).size = info.Size
		c.lru.MoveToFront(el)
	} else {
		c.entries[key] = c.lru.PushFront(&cacheEntry{key: key, size: info.Size})
		c.total += info.Size
	}
	c.mu.Unlock()
	unlock()

	return c.evict(ctx)
}

// evict removes least-recently-used entries from the index until the total
// fits, then deletes their objects without holding the index mutex.
func (c *Cache) evict(ctx context.Context) error {
	c.mu.Lock()
	var victims []cacheEntry
	for c.total > c.maxSize && c.lru.Len() > 0 {
		v := *c.lru.Back().Value.(*cacheEntry)
		c.removeLocked(v.key)
		victims = append(victims, v)
	}
	c.mu.Unlock()

	var errs []error
	for _, v := range victims {
		if err := c.deleteVictim(ctx, v); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Cache) deleteVictim(ctx context.Context, v cacheEntry) error {
	defer c.lockKey(v.key)()

	c.mu.Lock()
	_, rewritten := c.entries[v.key]
	c.mu.Unlock()
	if rewritten {
		return nil // a newer Put owns the object now
	}
	err := c.d.Delete(ctx, v.key)
	if err != nil {
		c.mu.Lock()
		c.entries[v.key] = c.lru.PushFront(&v)
		c.total += v.size
		c.mu.Unlock()
	}
	return err
}

// forget drops key from the index if the object is really gone.
func (c *Cache) forget(ctx context.Context, key string) {
	defer c.lockKey(key)()
	if _, err := c.d.Stat(ctx, key); errors.Is(err, ErrNotFound) {
		c.forgetIndexed(key)
	}
}

func (c *Cache) forgetIndexed(key string) {
	c.mu.Lock()
	c.removeLocked(key)
	c.mu.Unlock()
}

func (c *Cache) removeLocked(key string) {
	if el, ok := c.entries[key]; ok {
		c.total -= el.Value.(*cacheEntry).size
		c.lru.Remove(el)
		delete(c.entries, key)
	}
}
