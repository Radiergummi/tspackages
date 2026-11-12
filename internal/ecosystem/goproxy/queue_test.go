package goproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// startQueue runs q until the test ends.
func startQueue(t *testing.T, q *queue) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { q.run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func testQueue(t *testing.T, workers int) *queue {
	t.Helper()
	q := newQueue(workers, time.Minute, slog.New(slog.DiscardHandler))
	startQueue(t, q)
	return q
}

func key(path, version string) jobKey {
	return jobKey{Remote: "https://example.com/r.git", Commit: "c-" + version, Path: path, Version: version}
}

// blocker enqueues an on-demand job that holds a worker until release is
// closed; it returns once a worker has taken it.
func blocker(t *testing.T, q *queue, name string) (release func()) {
	t.Helper()
	started, ch := make(chan struct{}), make(chan struct{})
	q.enqueue(key("blocker/"+name, "v1.0.0"), "blocker/"+name, jobOnDemand, func(context.Context) error {
		close(started)
		<-ch
		return nil
	})
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("blocker never started")
	}
	return func() { close(ch) }
}

// recorder records the order in which jobs run.
type recorder struct {
	mu    sync.Mutex
	order []string
}

func (r *recorder) job(name string) func(context.Context) error {
	return func(context.Context) error {
		r.mu.Lock()
		r.order = append(r.order, name)
		r.mu.Unlock()
		return nil
	}
}

func (r *recorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.order...)
}

// drain waits for a sentinel on-demand job: every on-demand job enqueued
// before it has been taken and, with one free worker, finished.
func drain(t *testing.T, q *queue) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tk := q.enqueue(key("sentinel", "v0.0.1"), "sentinel", jobOnDemand, func(context.Context) error { return nil })
	if err := tk.Wait(ctx); err != nil {
		t.Fatalf("sentinel: %v", err)
	}
}

func wait(t *testing.T, tk *Ticket) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := tk.Wait(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("job never finished")
	}
	return err
}

func equal(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}

func TestQueueDeduplicates(t *testing.T) {
	q := testQueue(t, 1)
	release := blocker(t, q, "b")
	var r recorder
	k := key("example.com/a", "v1.0.0")
	q.enqueue(k, "example.com/a", jobPass, r.job("first"))
	tk := q.enqueue(k, "example.com/a", jobPass, r.job("second"))
	if !q.queued(k) {
		t.Fatal("not queued")
	}
	release()
	if err := wait(t, tk); err != nil {
		t.Fatal(err)
	}
	equal(t, r.got(), []string{"first"})
	if q.queued(k) {
		t.Fatal("still queued after success")
	}
}

func TestOnDemandFirst(t *testing.T) {
	q := testQueue(t, 2)
	release1 := blocker(t, q, "1")
	release2 := blocker(t, q, "2")
	defer release2()
	var r recorder
	for _, v := range []string{"v1.0.0", "v1.1.0", "v1.2.0"} {
		q.enqueue(key("example.com/a", v), "example.com/a", jobPass, r.job("pass "+v))
	}
	q.enqueue(key("example.com/b", "v0.1.0"), "example.com/b", jobOnDemand, r.job("on-demand"))
	release1()
	drain(t, q)
	got := r.got()
	if len(got) == 0 || got[0] != "on-demand" {
		t.Fatalf("order %v, want on-demand first", got)
	}
}

func TestPromote(t *testing.T) {
	q := testQueue(t, 1)
	release := blocker(t, q, "b")
	var r recorder
	var tickets []*Ticket
	for _, m := range []string{"a", "b", "c"} {
		tickets = append(tickets, q.enqueue(key("example.com/"+m, "v1.0.0"), "example.com/"+m, jobPass, r.job(m)))
	}
	// The promoted job keeps its run function.
	q.enqueue(key("example.com/c", "v1.0.0"), "example.com/c", jobOnDemand, r.job("c again"))
	release()
	for _, tk := range tickets {
		if err := wait(t, tk); err != nil {
			t.Fatal(err)
		}
	}
	equal(t, r.got(), []string{"c", "a", "b"})
}

func TestNewestFirstRoundRobin(t *testing.T) {
	q := testQueue(t, 1)
	release := blocker(t, q, "b")
	var r recorder
	var tickets []*Ticket
	add := func(mod, v string) {
		tickets = append(tickets, q.enqueue(key(mod, v), mod, jobPass, r.job(mod+"@"+v)))
	}
	add("a", "v1.0.0")
	add("a", "v1.2.0")
	add("b", "v0.1.0")
	release()
	for _, tk := range tickets {
		if err := wait(t, tk); err != nil {
			t.Fatal(err)
		}
	}
	equal(t, r.got(), []string{"a@v1.2.0", "b@v0.1.0", "a@v1.0.0"})
}

func TestAbandonedOnDemandDropped(t *testing.T) {
	q := testQueue(t, 1)
	release := blocker(t, q, "b")
	var r recorder

	dropped := key("example.com/x", "v1.0.0")
	q.enqueue(dropped, "example.com/x", jobOnDemand, r.job("dropped")).Leave()
	if q.queued(dropped) {
		t.Fatal("abandoned on-demand job still queued")
	}

	// Two waiters: the job stays until both left.
	twice := key("example.com/t", "v1.0.0")
	t1 := q.enqueue(twice, "example.com/t", jobOnDemand, r.job("twice"))
	t2 := q.enqueue(twice, "example.com/t", jobOnDemand, r.job("twice"))
	t1.Leave()
	t1.Leave() // idempotent
	if !q.queued(twice) {
		t.Fatal("job dropped while a waiter remains")
	}
	t2.Leave()

	q.enqueue(key("example.com/r", "v1.0.0"), "example.com/r", jobRepair, r.job("repair")).Leave()
	pk := key("example.com/p", "v1.0.0")
	q.enqueue(pk, "example.com/p", jobPass, r.job("promoted"))
	q.enqueue(pk, "example.com/p", jobOnDemand, r.job("promoted")).Leave()
	ok := key("example.com/o", "v1.0.0")
	tk := q.enqueue(ok, "example.com/o", jobOnDemand, r.job("on-demand then pass"))
	q.enqueue(ok, "example.com/o", jobPass, r.job("on-demand then pass"))
	tk.Leave()

	release()
	drain(t, q)
	equal(t, r.got(), []string{"repair", "promoted", "on-demand then pass"})
}

func TestRetryBackoffKept(t *testing.T) {
	q := newQueue(1, time.Minute, slog.New(slog.DiscardHandler))
	q.backoffMin = time.Hour
	startQueue(t, q)
	k := key("example.com/a", "v1.0.0")
	runs := 0
	started := make(chan struct{}, 1)
	fail := func(context.Context) error {
		runs++
		started <- struct{}{}
		return io.ErrUnexpectedEOF
	}
	q.enqueue(k, "example.com/a", jobPass, fail)
	<-started
	drain(t, q) // the one worker finished the failing job before the sentinel

	q.mu.Lock()
	nb := q.jobs[k].notBefore
	q.mu.Unlock()
	if !nb.After(time.Now().Add(50 * time.Minute)) {
		t.Fatalf("notBefore %v, want about an hour from now", nb)
	}
	q.enqueue(k, "example.com/a", jobPass, fail)
	q.mu.Lock()
	nb2 := q.jobs[k].notBefore
	q.mu.Unlock()
	if !nb2.Equal(nb) {
		t.Fatalf("pass enqueue reset backoff: %v, was %v", nb2, nb)
	}
	if !q.queued(k) {
		t.Fatal("job not queued while backing off")
	}
	drain(t, q)
	if runs != 1 { // drain orders this read after the job's runs
		t.Fatalf("ran %d times, want 1", runs)
	}
}

func TestRetrySucceeds(t *testing.T) {
	q := newQueue(1, time.Minute, slog.New(slog.DiscardHandler))
	q.backoffMin = time.Millisecond
	startQueue(t, q)
	runs := 0
	tk := q.enqueue(key("example.com/a", "v1.0.0"), "example.com/a", jobOnDemand, func(context.Context) error {
		runs++
		if runs < 3 {
			return io.ErrUnexpectedEOF
		}
		return nil
	})
	if err := wait(t, tk); err != nil {
		t.Fatal(err)
	}
	if runs != 3 {
		t.Fatalf("ran %d times, want 3", runs)
	}
}

func TestBackoffDoubles(t *testing.T) {
	min, max := 10*time.Second, 10*time.Minute
	var got []time.Duration
	d := time.Duration(0)
	for range 8 {
		d = nextBackoff(d, min, max)
		got = append(got, d)
	}
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 320 * time.Second, 10 * time.Minute, 10 * time.Minute}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoffs %v, want %v", got, want)
		}
	}
	q := newQueue(2, 10*time.Minute, slog.New(slog.DiscardHandler))
	if q.backoffMin != min || q.backoffMax != max || q.timeout != 10*time.Minute || q.workers != 2 {
		t.Fatalf("defaults: %+v", q)
	}
}

func TestRefusalFinal(t *testing.T) {
	q := testQueue(t, 1)
	runs := 0
	k := key("example.com/a", "v1.0.0")
	tk := q.enqueue(k, "example.com/a", jobOnDemand, func(context.Context) error {
		runs++
		return &RefusalError{Reason: "go.mod not found"}
	})
	err := wait(t, tk)
	var re *RefusalError
	if !errors.As(err, &re) || re.Reason != "go.mod not found" {
		t.Fatalf("Wait = %v, want the refusal", err)
	}
	drain(t, q)
	if runs != 1 || q.queued(k) {
		t.Fatalf("runs %d, queued %v; want 1, false", runs, q.queued(k))
	}
}

func TestTimeoutFromStart(t *testing.T) {
	const timeout = 100 * time.Millisecond
	q := newQueue(1, timeout, slog.New(slog.DiscardHandler))
	q.backoffMin = time.Hour
	startQueue(t, q)
	release := blocker(t, q, "b")

	type result struct {
		deadline             time.Time
		errAtStart, errAtEnd error
	}
	res := make(chan result, 1)
	q.enqueue(key("example.com/a", "v1.0.0"), "example.com/a", jobOnDemand, func(ctx context.Context) error {
		r := result{errAtStart: ctx.Err()}
		r.deadline, _ = ctx.Deadline()
		<-ctx.Done()
		r.errAtEnd = ctx.Err()
		res <- r
		return ctx.Err()
	})
	// Queued for twice the timeout: a timeout counted from enqueue would
	// have expired before the job starts.
	time.Sleep(2 * timeout)
	released := time.Now()
	release()
	var r result
	select {
	case r = <-res:
	case <-time.After(10 * time.Second):
		t.Fatal("job never timed out")
	}
	if r.errAtStart != nil {
		t.Fatalf("job started with %v", r.errAtStart)
	}
	if !r.deadline.After(released) {
		t.Fatalf("deadline %v not after the job could start (%v)", r.deadline, released)
	}
	if !errors.Is(r.errAtEnd, context.DeadlineExceeded) {
		t.Fatalf("job ended with %v, want its timeout", r.errAtEnd)
	}
}

func TestWaitCtx(t *testing.T) {
	q := testQueue(t, 1)
	release := blocker(t, q, "b")
	ran := make(chan struct{})
	tk := q.enqueue(key("example.com/a", "v1.0.0"), "example.com/a", jobOnDemand, func(context.Context) error {
		close(ran)
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tk.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait = %v, want context.Canceled", err)
	}
	release()
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("job did not run after its waiter's ctx ended")
	}
}

func TestWaitQueueStopped(t *testing.T) {
	q := newQueue(1, time.Minute, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { q.run(ctx); close(done) }()
	release := blocker(t, q, "b")
	tk := q.enqueue(key("example.com/a", "v1.0.0"), "example.com/a", jobOnDemand, func(context.Context) error { return nil })
	cancel()
	release()
	<-done
	if err := wait(t, tk); !errors.Is(err, errQueueStopped) {
		t.Fatalf("Wait = %v, want errQueueStopped", err)
	}
}
