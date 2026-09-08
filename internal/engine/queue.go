package engine

import (
	"sync"

	"github.com/terrdv/vet/internal/checks"
)

// queue is the frontier of injection points waiting to be tested. It is the
// same mutex + cond + closed-flag structure as crawler.Queue, holding Targets
// instead of URLs.
//
// It is deliberately unbounded. The crawler pushes into it from every worker
// while it walks the site, and the engine drains it at the pace of the check
// suite — which is always slower, since one target costs several requests
// against a target that costs the crawler one fetch. A bounded handoff would
// therefore block a crawl worker inside handle, while that worker still holds a
// pending count, and the crawl would proceed at the engine's speed. A Target is
// a handful of strings, so the memory this trades away is not worth having.
type queue struct {
	mx     sync.Mutex
	cond   *sync.Cond
	items  []checks.Target
	closed bool
}

func newQueue() *queue {
	q := &queue{}
	q.cond = sync.NewCond(&q.mx) // must share the mutex Pop's waiters release
	return q
}

func (q *queue) Push(t checks.Target) {
	q.mx.Lock()
	defer q.mx.Unlock()
	if q.closed {
		return
	}
	q.items = append(q.items, t)
	q.cond.Signal()
}

// Pop blocks until a target is available or the queue is closed and empty.
// False means the second: no more work is coming and the caller should exit.
func (q *queue) Pop() (checks.Target, bool) {
	q.mx.Lock()
	defer q.mx.Unlock()

	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}

	if len(q.items) == 0 {
		return checks.Target{}, false
	}

	t := q.items[0]
	q.items = q.items[1:]

	return t, true
}

// Close declares that no further targets will be pushed. Workers still drain
// whatever is left before Pop starts reporting false.
func (q *queue) Close() {
	q.mx.Lock()
	defer q.mx.Unlock()
	q.closed = true
	q.cond.Broadcast()
}
