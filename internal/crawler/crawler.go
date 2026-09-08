package crawler

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// fetchTimeout bounds a single page fetch. Without it one unresponsive endpoint
// pins a worker forever, and enough of those deadlock the pool in a way that
// looks exactly like a termination bug.
const fetchTimeout = 10 * time.Second

type Crawler struct {
	q    *Queue
	v    *VisitedSet
	pool *WorkerPool

	client *http.Client

	// scopeHost is set once in Crawl before any worker starts, then only read.
	scopeHost string

	// sink, if set, receives each page's forms as they are discovered, so a
	// consumer can start testing them before the crawl finishes. Same discipline
	// as scopeHost: set once before the crawl starts, then only read. It is
	// called from every worker, so it must be safe for concurrent use.
	sink func([]Form)

	mu    sync.Mutex
	forms []Form
}

func NewCrawl() *Crawler {
	// Go's default transport keeps 2 idle connections per host. Against a local
	// dev server that answers in under a millisecond, connections go idle
	// constantly and all but two are closed, so the next request dials again --
	// burning an ephemeral port each time, and eventually failing fetches that
	// handle silently discards. The detection engine makes that far worse: it
	// issues several payload requests per field, all of them fast.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 64

	return &Crawler{
		q:      NewQueue(),
		v:      NewVisitedSet(), // initializes the map so Add won't panic
		client: &http.Client{Timeout: fetchTimeout, Transport: tr},
	}
}

// Client returns the HTTP client the crawl uses, so whatever tests the forms it
// finds can run on the same connection pool instead of opening a second one
// against the same host.
func (c *Crawler) Client() *http.Client { return c.client }

// OnForms registers a sink for injection points, called once per page with the
// forms found on it. Set it before starting a crawl; both Crawl and
// CrawlSequential publish through it.
func (c *Crawler) OnForms(fn func([]Form)) { c.sink = fn }

// Forms returns the injection points discovered by the last Crawl.
func (c *Crawler) Forms() []Form {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.forms
}

func (c *Crawler) addForms(fs []Form) {
	if len(fs) == 0 {
		return
	}

	c.mu.Lock()
	c.forms = append(c.forms, fs...)
	c.mu.Unlock() // not deferred: a sink running under the lock would serialize
	//               every worker that discovers a form

	if c.sink != nil {
		c.sink(fs)
	}
}

// Crawl discovers the attack surface reachable from domain, using workers
// concurrent fetchers. It returns once the whole in-scope surface has been
// visited; the results are available from Forms.
func (c *Crawler) Crawl(ctx context.Context, domain string, workers int) {
	// The seed's host defines scope: we only follow links on the same host.
	seed, err := url.Parse(domain)
	if err != nil {
		return
	}
	c.scopeHost = seed.Host

	// Assigned before Run starts the workers, which is the only reason handle
	// can read c.pool and c.scopeHost without synchronization.
	c.pool = NewWorkerPool(workers, c.q, c.v, c.handle)

	// Run seeds the frontier itself, so the visited set must not be pre-marked
	// here: Enqueue would treat the seed as already seen and crawl nothing.
	c.pool.Run(ctx, domain)
}

// handle fetches one page, records its forms, and feeds the in-scope links it
// finds back into the frontier. It runs on every worker concurrently.
func (c *Crawler) handle(ctx context.Context, rawURL string) {
	// The page's own URL is the base for resolving relative hrefs and actions.
	base, err := url.Parse(rawURL)
	if err != nil {
		return // skip URLs we can't parse
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return // skip fetch failures
	}
	defer resp.Body.Close()

	extractedURLs, extractedForms, err := Extract(base, resp.Body)
	if err != nil {
		return
	}

	c.addForms(extractedForms)

	// Feed discovered links back into the frontier. Enqueue does the dedup, so
	// these calls must all happen before handle returns: the pool retires this
	// URL on return, and the children have to be counted before that.
	for _, link := range extractedURLs {
		lu, err := url.Parse(link)
		if err != nil {
			continue
		}
		if lu.Host != c.scopeHost {
			continue // out of scope -> never enqueue
		}
		lu.Fragment = "" // "#section" is the same page; canonicalize it away
		c.pool.Enqueue(lu.String())
	}
}
