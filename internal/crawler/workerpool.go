package crawler

import (
	"context"
	"sync"
)

// WorkerPool runs a fixed number of goroutines over a shared, growing frontier
// of URLs.
//
// The workers are both consumers and producers: handling one URL can discover
// more, so the pool cannot stop the moment the queue is empty — another worker
// may be mid-fetch and about to enqueue new URLs. Instead it tracks outstanding
// work with a WaitGroup and shuts the workers down only once every enqueued URL
// has been fully handled.
type WorkerPool struct {
	concurrency int
	handle      func(ctx context.Context, url string)

	q  *Queue
	vs *VisitedSet
	mu sync.Mutex

	pending sync.WaitGroup // enqueued-but-not-yet-handled URLs
}

// NewWorkerPool returns a pool of `workers` goroutines that call handle once
// per URL popped from q. vs dedups the frontier: a URL already in the set is
// never enqueued twice. handle may enqueue more URLs via the pool's Enqueue.
func NewWorkerPool(workers int, q *Queue, vs *VisitedSet, handle func(ctx context.Context, url string)) *WorkerPool {
	if workers < 1 {
		workers = 1 // nothing would consume the queue, so Run would never return
	}
	return &WorkerPool{
		concurrency: workers,
		handle:      handle,
		q:           q,
		vs:          vs,
	}
}

func (wp *WorkerPool) Enqueue(url string) {
	if !wp.vs.Add(url) {
		return
	}
	wp.pending.Add(1)
	wp.q.Enqueue(url)
}

// Run seeds the frontier, starts the workers, and blocks until the crawl is
// finished and every worker has exited.
//
// The shutdown order is load-bearing: pending only reaches zero once every
// enqueued URL has been handled *and* the links it discovered are themselves
// enqueued, so that is the first moment it is safe to close the queue. Closing
// releases the workers parked in Pop; workers.Wait then confirms they are gone
// before Run hands control back to the caller.
func (wp *WorkerPool) Run(ctx context.Context, seeds ...string) {
	for _, seed := range seeds {
		wp.Enqueue(seed)
	}

	// Counts goroutines, unlike wp.pending which counts URLs. The two cannot be
	// merged: the work must finish before the workers are allowed to exit.
	var workers sync.WaitGroup
	for i := 0; i < wp.concurrency; i++ {
		workers.Go(func() { wp.worker(ctx) })
	}

	wp.pending.Wait() // no work in flight, and nobody left to produce more
	wp.q.Close()      // wake the workers so they can see there is nothing left
	workers.Wait()
}

// worker pops URLs until the queue is closed and drained.
func (wp *WorkerPool) worker(ctx context.Context) {
	for {
		url, ok := wp.q.Pop()
		if !ok {
			return
		}
		wp.handleOne(ctx, url)
	}
}

// handleOne runs the caller's handler for one URL and retires it from pending.
//
// The Done is deferred so a panic in handle cannot strand the counter, which
// would hang Run forever rather than surfacing the panic. On cancellation the
// URL is still retired: the frontier drains without being fetched, letting the
// crawl wind down through the normal shutdown path.
func (wp *WorkerPool) handleOne(ctx context.Context, url string) {
	defer wp.pending.Done()
	if ctx.Err() != nil {
		return
	}
	wp.handle(ctx, url)
}
