package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"testing"
)

func put(t *testing.T, d Driver, key, body string) Info {
	t.Helper()
	info, err := d.Put(context.Background(), key, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("Put(%q): %v", key, err)
	}
	return info
}

func read(t *testing.T, d Driver, key string) (string, Info) {
	t.Helper()
	rc, info, err := d.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get(%q): %v", key, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), info
}

func runDriverSuite(t *testing.T, d Driver) {
	ctx := context.Background()

	t.Run("PutGetRoundTrip", func(t *testing.T) {
		pi := put(t, d, "rt/obj", "hello world")
		body, info := read(t, d, "rt/obj")
		if body != "hello world" || info.Size != 11 || pi.Size != 11 {
			t.Fatalf("body=%q info=%+v put=%+v", body, info, pi)
		}
		if info.ETag == "" || info.Key != "rt/obj" {
			t.Fatalf("info=%+v", info)
		}
		st, err := d.Stat(ctx, "rt/obj")
		if err != nil || st.Size != 11 || st.ETag != info.ETag {
			t.Fatalf("stat=%+v err=%v", st, err)
		}
		if err := d.Delete(ctx, "rt/obj"); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Stat(ctx, "rt/obj"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("after delete: %v", err)
		}
	})

	t.Run("PutIfAbsentTwice", func(t *testing.T) {
		if _, err := d.PutIfAbsent(ctx, "pia/k", bytes.NewReader([]byte("first"))); err != nil {
			t.Fatal(err)
		}
		_, err := d.PutIfAbsent(ctx, "pia/k", bytes.NewReader([]byte("second")))
		if !errors.Is(err, ErrExists) {
			t.Fatalf("err=%v", err)
		}
		if body, _ := read(t, d, "pia/k"); body != "first" {
			t.Fatalf("body=%q", body)
		}
	})

	t.Run("PutIfAbsentConcurrent", func(t *testing.T) {
		const n = 16
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = d.PutIfAbsent(ctx, "conc/k", bytes.NewReader([]byte(fmt.Sprintf("body-%d", i))))
			}()
		}
		wg.Wait()
		winner, exists := -1, 0
		for i, err := range errs {
			switch {
			case err == nil:
				if winner != -1 {
					t.Fatal("more than one winner")
				}
				winner = i
			case errors.Is(err, ErrExists):
				exists++
			default:
				t.Fatalf("goroutine %d: %v", i, err)
			}
		}
		if winner == -1 || exists != n-1 {
			t.Fatalf("winner=%d exists=%d", winner, exists)
		}
		if body, _ := read(t, d, "conc/k"); body != fmt.Sprintf("body-%d", winner) {
			t.Fatalf("body=%q winner=%d", body, winner)
		}
	})

	t.Run("PutIfMatch", func(t *testing.T) {
		first, err := d.PutIfMatch(ctx, "pim/k", bytes.NewReader([]byte("v1")), "")
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := d.PutIfMatch(ctx, "pim/k", bytes.NewReader([]byte("x")), ""); !errors.Is(err, ErrPrecondition) {
			t.Fatalf("empty etag on existing: %v", err)
		}
		second, err := d.PutIfMatch(ctx, "pim/k", bytes.NewReader([]byte("v2")), first.ETag)
		if err != nil {
			t.Fatalf("current etag: %v", err)
		}
		if second.ETag == "" || second.ETag == first.ETag {
			t.Fatalf("etags: %q -> %q", first.ETag, second.ETag)
		}
		if _, err := d.PutIfMatch(ctx, "pim/k", bytes.NewReader([]byte("v3")), first.ETag); !errors.Is(err, ErrPrecondition) {
			t.Fatalf("stale etag: %v", err)
		}
		if _, err := d.PutIfMatch(ctx, "pim/missing", bytes.NewReader([]byte("v")), "deadbeef"); !errors.Is(err, ErrPrecondition) {
			t.Fatalf("etag on missing: %v", err)
		}
		if body, _ := read(t, d, "pim/k"); body != "v2" {
			t.Fatalf("body=%q", body)
		}
	})

	t.Run("InvalidKeys", func(t *testing.T) {
		for _, k := range []string{"../x", "a//b", "/a", "a/./b", "a/..", `a\b`, "a/", "", "a b"} {
			if _, _, err := d.Get(ctx, k); !errors.Is(err, ErrInvalidKey) {
				t.Errorf("Get(%q): %v", k, err)
			}
			if _, err := d.Put(ctx, k, bytes.NewReader(nil)); !errors.Is(err, ErrInvalidKey) {
				t.Errorf("Put(%q): %v", k, err)
			}
		}
	})

	t.Run("ListPrefix", func(t *testing.T) {
		want := map[string]bool{"a/1": true, "a/b/2": true, "a/b/c/3": true}
		for k := range want {
			put(t, d, k, "x")
		}
		put(t, d, "ab/4", "x")
		put(t, d, "z/5", "x")
		got := map[string]bool{}
		for info, err := range d.List(ctx, "a/") {
			if err != nil {
				t.Fatal(err)
			}
			got[info.Key] = true
		}
		if len(got) != len(want) {
			t.Fatalf("got %v", got)
		}
		for k := range want {
			if !got[k] {
				t.Fatalf("missing %q in %v", k, got)
			}
		}
	})

	t.Run("GetMissing", func(t *testing.T) {
		if _, _, err := d.Get(ctx, "nope/missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("PutIfMatchConcurrent", func(t *testing.T) {
		base := put(t, d, "pimc/k", "base")
		const n = 16
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = d.PutIfMatch(ctx, "pimc/k", bytes.NewReader([]byte(fmt.Sprintf("w-%d", i))), base.ETag)
			}()
		}
		wg.Wait()
		winner, lost := -1, 0
		for i, err := range errs {
			switch {
			case err == nil:
				if winner != -1 {
					t.Fatal("more than one winner")
				}
				winner = i
			case errors.Is(err, ErrPrecondition):
				lost++
			default:
				t.Fatalf("writer %d: %v", i, err)
			}
		}
		if winner == -1 || lost != n-1 {
			t.Fatalf("winner=%d lost=%d", winner, lost)
		}
		if body, _ := read(t, d, "pimc/k"); body != fmt.Sprintf("w-%d", winner) {
			t.Fatalf("body=%q", body)
		}
	})

	t.Run("DeleteMissing", func(t *testing.T) {
		if err := d.Delete(ctx, "del/never-existed"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ListInvalidPrefix", func(t *testing.T) {
		for _, p := range []string{"../x", "a//b", "/a", `a\b`} {
			var got error
			for _, err := range d.List(ctx, p) {
				got = err
				break
			}
			if !errors.Is(got, ErrInvalidKey) {
				t.Errorf("List(%q): %v", p, got)
			}
		}
	})

	t.Run("ListOrder", func(t *testing.T) {
		keys := []string{"ord/b", "ord/x/y", "ord/x.y", "ord/x-y", "ord/a", "ord/x_y", "ord/0"}
		for _, k := range keys {
			put(t, d, k, "x")
		}
		sort.Strings(keys)
		var got []string
		for info, err := range d.List(ctx, "ord/") {
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, info.Key)
		}
		if fmt.Sprint(got) != fmt.Sprint(keys) {
			t.Fatalf("got %v, want %v", got, keys)
		}
	})

	t.Run("GetCancelledContext", func(t *testing.T) {
		put(t, d, "ctx/k", "x")
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, _, err := d.Get(cctx, "ctx/k"); !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestValidKey(t *testing.T) {
	for _, k := range []string{"a", "a/b", "A.b_c~d+e-f/x"} {
		if err := ValidKey(k); err != nil {
			t.Errorf("%q: %v", k, err)
		}
	}
	long := make([]byte, 1025)
	for i := range long {
		long[i] = 'a'
	}
	if err := ValidKey(string(long)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("long: %v", err)
	}
}

func TestEscapeSegment(t *testing.T) {
	s := EscapeSegment("v1.0/üß?")
	if err := ValidKey(s); err != nil {
		t.Fatal(err)
	}
	if EscapeSegment("") != "" {
		t.Fatal("empty")
	}
}
