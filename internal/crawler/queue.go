package crawler

import "sync"

type Queue struct {
	mx    sync.Mutex
	pages []string
}

func NewQueue() *Queue {
	return &Queue{}
}

func (q *Queue) Enqueue(url string) {
	q.mx.Lock()
	defer q.mx.Unlock()
	q.pages = append(q.pages, url)
}

func (q *Queue) Pop() (string, bool) {
	q.mx.Lock()
	defer q.mx.Unlock()

	if len(q.pages) == 0 {
		return "", false
	}

	url := q.pages[0]
	q.pages = q.pages[1:]
	return url, true
}
