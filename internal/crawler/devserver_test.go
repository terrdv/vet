package crawler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// devServer models a local development server, which is what vet actually
// points at. The three properties that matter, and that a generic web server
// does not have:
//
//   - a small hard concurrency limit. Flask's dev server is single-threaded by
//     default; Django's runserver and Rails in dev handle a handful at once;
//     a Next.js or Vite dev server is one Node process. Requests past the limit
//     do not fail, they queue — so extra scan workers buy nothing and only make
//     the queue longer.
//   - slow responses. Dev mode disables caching, reloads classes per request,
//     and runs debug middleware, so 50-300ms per page is normal where
//     production would serve in 5ms.
//   - cold routes. Compile-on-demand servers pay a large one-off cost the first
//     time each route is hit, which lands entirely on the scanner because the
//     scanner is usually the first thing to touch every route.
type devServer struct {
	*httptest.Server

	pages       int
	concurrency int           // simultaneous requests the server will handle
	renderTime  time.Duration // per-request work: template + query
	coldCompile time.Duration // one-off cost the first time a route is hit

	sem chan struct{}

	hits        atomic.Int64
	inFlight    atomic.Int64
	maxInFlight atomic.Int64
	queueWait   recorder // time requests spent waiting for a free server slot

	mu       sync.Mutex
	compiled map[int]bool
}

func newDevServer(pages, concurrency int, renderTime, coldCompile time.Duration) *devServer {
	d := &devServer{
		pages:       pages,
		concurrency: concurrency,
		renderTime:  renderTime,
		coldCompile: coldCompile,
		sem:         make(chan struct{}, concurrency),
		compiled:    map[int]bool{},
	}
	d.Server = httptest.NewServer(http.HandlerFunc(d.serve))
	return d
}

func (d *devServer) serve(w http.ResponseWriter, r *http.Request) {
	d.hits.Add(1)

	// Queue for a server slot, exactly as a request does behind a dev server's
	// limited worker pool. The wait is the signal that the scan is outrunning
	// the app rather than testing it.
	wait := time.Now()
	d.sem <- struct{}{}
	d.queueWait.record(time.Since(wait))
	defer func() { <-d.sem }()

	n := d.inFlight.Add(1)
	for {
		m := d.maxInFlight.Load()
		if n <= m || d.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}
	defer d.inFlight.Add(-1)

	id := 0
	if r.URL.Path != "/" {
		v, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/p/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		id = v
	}

	d.mu.Lock()
	cold := !d.compiled[id]
	d.compiled[id] = true
	d.mu.Unlock()

	if cold && d.coldCompile > 0 {
		time.Sleep(d.coldCompile)
	}
	time.Sleep(d.renderTime)

	w.Header().Set("Content-Type", "text/html")
	d.renderPage(w, id)
}

// renderPage writes a page shaped like a real app's: navigation, links that
// carry query parameters, and one or more forms. The forms are what vet is
// looking for — every named field is a candidate injection point.
func (d *devServer) renderPage(w http.ResponseWriter, id int) {
	var b strings.Builder
	fmt.Fprintf(&b, "<html><body><h1>Item %d</h1><nav>", id)
	for i := 1; i <= 6; i++ {
		next := (id*6 + i) % d.pages
		// Query parameters here are injection points too, and vet does not
		// currently record them — see TestQueryParamsAreMissed.
		fmt.Fprintf(&b, `<a href="/p/%d?sort=name&page=2">Item %d</a>`, next, next)
	}
	b.WriteString("</nav>")
	b.WriteString(`<form action="/search" method="get"><input name="q"><input name="category"></form>`)
	if id%3 == 0 {
		b.WriteString(`<form action="/login" method="post"><input name="username"><input name="password"></form>`)
	}
	if id%5 == 0 {
		b.WriteString(`<form action="/comment" method="post"><textarea name="body"></textarea><input name="author"></form>`)
	}
	for i := 0; i < 25; i++ {
		b.WriteString("<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>")
	}
	b.WriteString("</body></html>")
	w.Write([]byte(b.String()))
}
