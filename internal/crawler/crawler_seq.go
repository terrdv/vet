package crawler

import (
	"context"
	"net/http"
	"net/url"
)

// CrawlSequential is the original single-threaded crawl, kept alongside the
// concurrent one so the two can be compared directly. It walks the same
// frontier with the same scope and dedup rules, on one goroutine.
//
// The whole difference between the two is the stop condition. Here an empty
// queue genuinely means the crawl is over: this goroutine is the only producer,
// so if it has nothing left to pop, nothing else can ever appear. That
// reasoning fails the moment a second worker exists, which is why the
// concurrent version needs a WaitGroup to detect termination instead.
//
// Use a fresh Crawler for each run: the queue and visited set carry over, so a
// second crawl on the same value would find every URL already visited.
func (c *Crawler) CrawlSequential(ctx context.Context, domain string) {
	// The seed's host defines scope: we only follow links on the same host.
	seed, err := url.Parse(domain)
	if err != nil {
		return
	}
	scopeHost := seed.Host

	c.q.Enqueue(domain)
	c.v.Add(domain)

	for {
		// TryPop, not Pop: this loop wants "empty right now" to end the crawl,
		// whereas Pop would block waiting for work that is never coming.
		rawURL, ok := c.q.TryPop()
		if !ok {
			break // queue empty -> stop (this is your "while not empty")
		}

		if ctx.Err() != nil {
			return
		}

		// Parse the string into a *url.URL for Extract's base (relative-link resolution).
		base, err := url.Parse(rawURL)
		if err != nil {
			continue // skip URLs we can't parse
		}

		// Fetch the page. resp.Body IS the io.Reader we hand to Extract.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			continue
		}
		resp, err := c.client.Do(req)
		if err != nil {
			continue // skip fetch failures
		}

		extractedURLs, extractedForms, err := Extract(base, resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		c.addForms(extractedForms)

		// Feed discovered links back into the frontier: in-scope + unseen only.
		for _, link := range extractedURLs {
			lu, err := url.Parse(link)
			if err != nil {
				continue
			}
			if lu.Host != scopeHost {
				continue // out of scope -> never enqueue
			}
			lu.Fragment = "" // "#section" is the same page; canonicalize it away
			canon := lu.String()

			if !c.v.Add(canon) {
				continue // Add returns false if already visited -> dedup
			}
			c.q.Enqueue(canon)
		}
	}
}
