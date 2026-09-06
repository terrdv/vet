package crawler

import "sync"

type Queue struct {
	mx     sync.Mutex
	pages  []string
	cond   *sync.Cond
	closed bool
}

func NewQueue() *Queue {
	q := &Queue{}
	q.cond = sync.NewCond(&q.mx) // must share the mutex Pop's waiters release
	return q
}

func (q *Queue) Enqueue(url string) {
	q.mx.Lock()
	defer q.mx.Unlock()
	if q.closed {
		return
	}
	q.pages = append(q.pages, url)
	q.cond.Signal()
}

func (q *Queue) Pop() (string, bool) {
	q.mx.Lock()
	defer q.mx.Unlock()

	for len(q.pages) == 0 && !q.closed {
		q.cond.Wait()
	}

	if len(q.pages) == 0 {
		return "", false
	}

	url := q.pages[0]
	q.pages = q.pages[1:]

	return url, true
}

// TryPop removes the next URL without blocking, reporting false when the queue
// is empty right now. That is only a safe stop condition for a single-threaded
// crawl, where an empty queue really does mean the traversal is finished. The
// concurrent pool must use Pop instead: with several workers, empty means "the
// others are mid-fetch and about to refill it".
func (q *Queue) TryPop() (string, bool) {
	q.mx.Lock()
	defer q.mx.Unlock()

	if len(q.pages) == 0 {
		return "", false
	}

	url := q.pages[0]
	q.pages = q.pages[1:]

	return url, true
}

func (q *Queue) Close() {
	q.mx.Lock()
	defer q.mx.Unlock()
	q.closed = true
	q.cond.Broadcast()
}
