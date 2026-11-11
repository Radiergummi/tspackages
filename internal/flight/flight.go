// Package flight runs one upstream call per key for concurrent callers.
package flight

import (
	"context"
	"errors"

	"golang.org/x/sync/singleflight"
)

// Do runs fn once for all concurrent callers with the same key, with the
// context of the caller that started it. Every caller stops waiting when its
// own context ends; one whose result was cut short by another caller's
// cancellation tries again.
func Do[T any](ctx context.Context, g *singleflight.Group, key string, fn func() (T, error)) (T, error) {
	for {
		select {
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		case r := <-g.DoChan(key, func() (any, error) { return fn() }):
			if r.Shared && errors.Is(r.Err, context.Canceled) && ctx.Err() == nil {
				continue
			}
			t, _ := r.Val.(T)
			return t, r.Err
		}
	}
}
