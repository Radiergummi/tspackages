package goproxy

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"golang.org/x/mod/semver"
)

// jobKey identifies one build: a module path and version at a commit, built
// from Dir, the module's configured dir (a pass enqueues before findModule
// has found the zip's directory).
type jobKey struct{ Remote, Commit, Dir, Path, Version string }

type jobKind int

const (
	jobPass     jobKind = iota // enqueued by a pass; nobody waits
	jobOnDemand                // a requested tag version or pseudo-version zip
	jobRepair                  // rebuild of a stored version's missing zip
)

// errQueueStopped is a Ticket's result when the queue stopped before the job
// finished.
var errQueueStopped = errors.New("build queue stopped")

// errJobDropped is the result of an on-demand job whose waiters all left.
var errJobDropped = errors.New("build dropped: nobody waits for it")

type job struct {
	key    jobKey
	module string
	run    func(context.Context) error

	pass    bool // enqueued by a pass: never dropped
	repair  bool // never dropped
	demand  bool // in the on-demand FIFO rather than its module's pass list
	waiters int  // tickets of on-demand and repair callers that have not left

	running   bool
	backoff   time.Duration
	notBefore time.Time

	done chan struct{} // closed with err set once the job is final
	err  error
}

// droppable reports whether nobody needs the job any more: created on
// demand, never enqueued by a pass, not a repair, and every waiter left.
func (j *job) droppable() bool {
	return !j.pass && !j.repair && j.waiters == 0 && !j.running
}

// Ticket lets an on-demand caller wait for its job.
type Ticket struct {
	q      *queue
	j      *job
	waiter bool
	left   bool // guarded by q.mu
}

// Wait returns the job's final error: nil, or its *RefusalError. It returns
// ctx.Err() when ctx ends first (the job keeps its place until Leave) and
// errQueueStopped when the queue stopped first.
func (t *Ticket) Wait(ctx context.Context) error {
	select {
	case <-t.j.done:
		return t.j.err
	case <-ctx.Done():
		return ctx.Err()
	case <-t.q.stopped:
		select {
		case <-t.j.done:
			return t.j.err
		default:
			return errQueueStopped
		}
	}
}

// Leave records that the caller stopped waiting. An on-demand job whose
// waiters all left before a worker took it is dropped.
func (t *Ticket) Leave() {
	q := t.q
	q.mu.Lock()
	defer q.mu.Unlock()
	if !t.waiter || t.left {
		return
	}
	t.left = true
	t.j.waiters--
	if t.j.droppable() && q.jobs[t.j.key] == t.j {
		q.finish(t.j, errJobDropped)
	}
}

// queue is one git source's build queue: a set of jobs keyed by jobKey, run
// by a fixed number of workers. On-demand and repair jobs run first, in
// FIFO order; pass jobs run newest version first per module, round-robin
// across modules. Readers can thus delay pass work indefinitely; that is
// acceptable, since readers are authorised and rate-limited.
type queue struct {
	workers    int
	timeout    time.Duration // per job, from when a worker takes it
	backoffMin time.Duration // first retry delay, doubling up to backoffMax
	backoffMax time.Duration
	log        *slog.Logger

	mu      sync.Mutex
	cond    *sync.Cond
	jobs    map[jobKey]*job   // queued, running or backing off
	demand  []*job            // on-demand and repair jobs, FIFO
	pass    map[string][]*job // pass jobs per module, not promoted
	modules []string          // modules with pass jobs, round-robin order
	next    int               // index into modules of the next module to serve

	stopped chan struct{} // closed when run returns
}

func newQueue(workers int, timeout time.Duration, log *slog.Logger) *queue {
	q := &queue{
		workers:    workers,
		timeout:    timeout,
		backoffMin: 10 * time.Second,
		backoffMax: 10 * time.Minute,
		log:        log,
		jobs:       make(map[jobKey]*job),
		pass:       make(map[string][]*job),
		stopped:    make(chan struct{}),
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// enqueue adds the job for k or, when k is already queued, registers kind on
// it: run is then ignored, a pass never duplicates it nor resets its
// backoff, and an on-demand or repair enqueue promotes a pass job to the
// on-demand FIFO (it stays registered as pass work). module groups pass
// work for round-robin. A job finishes when run returns nil or a
// *RefusalError; any other error is retried after a backoff of backoffMin
// doubling to backoffMax, and the job stays queued.
func (q *queue) enqueue(k jobKey, module string, kind jobKind, run func(context.Context) error) *Ticket {
	q.mu.Lock()
	defer q.mu.Unlock()
	j := q.jobs[k]
	if j == nil {
		j = &job{key: k, module: module, run: run, done: make(chan struct{})}
		q.jobs[k] = j
		if kind == jobPass {
			q.addPass(j)
		} else {
			j.demand = true
			q.demand = append(q.demand, j)
		}
	} else if kind != jobPass && !j.demand {
		q.removePass(j)
		j.demand = true
		q.demand = append(q.demand, j)
	}
	t := &Ticket{q: q, j: j}
	switch kind {
	case jobPass:
		j.pass = true
	case jobRepair:
		j.repair = true
		fallthrough
	default:
		j.waiters++
		t.waiter = true
	}
	q.cond.Broadcast()
	return t
}

// queued reports whether k is queued, running or backing off.
func (q *queue) queued(k jobKey) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.jobs[k] != nil
}

// run starts the workers. Jobs run on ctx, each with q.timeout from when a
// worker takes it. run returns when ctx ended and the workers stopped.
func (q *queue) run(ctx context.Context) {
	stop := context.AfterFunc(ctx, q.wake)
	defer stop()
	var wg sync.WaitGroup
	for range q.workers {
		wg.Go(func() { q.work(ctx) })
	}
	wg.Wait()
	close(q.stopped)
}

func (q *queue) wake() {
	q.mu.Lock()
	q.cond.Broadcast()
	q.mu.Unlock()
}

func (q *queue) work(ctx context.Context) {
	for {
		q.mu.Lock()
		var j *job
		for {
			if ctx.Err() != nil {
				q.mu.Unlock()
				return
			}
			if j = q.pick(time.Now()); j != nil {
				break
			}
			q.cond.Wait()
		}
		j.running = true
		q.mu.Unlock()

		jctx, cancel := context.WithTimeout(ctx, q.timeout)
		err := j.run(jctx)
		cancel()

		q.mu.Lock()
		j.running = false
		var refusal *RefusalError
		switch {
		case err == nil || errors.As(err, &refusal):
			q.finish(j, err)
		case j.droppable():
			q.finish(j, errJobDropped)
		default:
			j.backoff = nextBackoff(j.backoff, q.backoffMin, q.backoffMax)
			j.notBefore = time.Now().Add(j.backoff)
			time.AfterFunc(j.backoff, q.wake)
			if ctx.Err() != nil {
				break // shutting down: the job stays queued, unreported
			}
			q.log.Warn("go build failed; retrying", "module", j.key.Path, "version", j.key.Version,
				"commit", j.key.Commit, "retry_in", j.backoff, "error", err)
		}
		q.cond.Broadcast()
		q.mu.Unlock()
	}
}

// nextBackoff doubles prev, starting at lo and capped at hi.
func nextBackoff(prev, lo, hi time.Duration) time.Duration {
	if prev < lo {
		return lo
	}
	return min(2*prev, hi)
}

// pick returns the next job a worker may take, or nil. q.mu is held.
func (q *queue) pick(now time.Time) *job {
	ready := func(j *job) bool { return !j.running && !j.notBefore.After(now) }
	for _, j := range q.demand {
		if ready(j) {
			return j
		}
	}
	for i := range q.modules {
		m := q.modules[(q.next+i)%len(q.modules)]
		var best *job
		for _, j := range q.pass[m] {
			if ready(j) && (best == nil || semver.Compare(j.key.Version, best.key.Version) > 0) {
				best = j
			}
		}
		if best != nil {
			q.next = (q.next + i + 1) % len(q.modules)
			return best
		}
	}
	return nil
}

// finish removes j from the queue and hands err to its tickets. q.mu is held.
func (q *queue) finish(j *job, err error) {
	delete(q.jobs, j.key)
	if j.demand {
		q.demand = slices.DeleteFunc(q.demand, func(o *job) bool { return o == j })
	} else {
		q.removePass(j)
	}
	j.err = err
	close(j.done)
}

func (q *queue) addPass(j *job) {
	if len(q.pass[j.module]) == 0 {
		q.modules = append(q.modules, j.module)
	}
	q.pass[j.module] = append(q.pass[j.module], j)
}

func (q *queue) removePass(j *job) {
	list := slices.DeleteFunc(q.pass[j.module], func(o *job) bool { return o == j })
	if len(list) > 0 {
		q.pass[j.module] = list
		return
	}
	delete(q.pass, j.module)
	i := slices.Index(q.modules, j.module)
	if i < 0 {
		return
	}
	q.modules = slices.Delete(q.modules, i, i+1)
	if i < q.next {
		q.next--
	}
	if q.next >= len(q.modules) {
		q.next = 0
	}
}
