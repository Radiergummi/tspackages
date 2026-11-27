// Package lru is an in-memory cache bounded by the total size of its values.
package lru

import (
	"container/list"
	"sync"
)

// Cache keeps values by key while their total size is at most max, dropping
// the least recently used first. It is safe for concurrent use.
type Cache[V any] struct {
	max  int64
	size func(V) int64

	mu    sync.Mutex
	total int64
	order *list.List // front = most recently used; values are *entry[V]
	byKey map[string]*list.Element
}

type entry[V any] struct {
	key  string
	v    V
	size int64
}

// New returns a cache of at most max bytes, measuring each value with size.
func New[V any](max int64, size func(V) int64) *Cache[V] {
	return &Cache[V]{max: max, size: size, order: list.New(), byKey: map[string]*list.Element{}}
}

// Get returns the value for key and marks it used.
func (c *Cache[V]) Get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byKey[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*entry[V]).v, true
}

// Put stores v for key, replacing any value there. A value larger than the
// whole cache is not kept, and the key's old value is dropped.
func (c *Cache[V]) Put(key string, v V) {
	n := c.size(v)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(key)
	if n > c.max {
		return
	}
	c.byKey[key] = c.order.PushFront(&entry[V]{key: key, v: v, size: n})
	c.total += n
	for c.total > c.max {
		c.removeLocked(c.order.Back().Value.(*entry[V]).key)
	}
}

// Delete drops the value for key, if any.
func (c *Cache[V]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(key)
}

func (c *Cache[V]) removeLocked(key string) {
	if el, ok := c.byKey[key]; ok {
		c.order.Remove(el)
		delete(c.byKey, key)
		c.total -= el.Value.(*entry[V]).size
	}
}
