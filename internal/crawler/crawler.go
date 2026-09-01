package crawler

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"
	"golang.org/x/net/html"
)

// Ensure imports are referenced until the implementation lands.
var (
	_ = sync.WaitGroup{}
	_ = time.Second
	_ = html.Parse
)


type Crawler struct {
	q     *Queue
	v     *VisitedSet
	forms []Form
}

func NewCrawl() *Crawler {
	return &Crawler{
		q: NewQueue(),
		v: NewVisitedSet(), // initializes the map so Add won't panic
	}
}

// Forms returns the injection points discovered by the last Crawl.
func (c *Crawler) Forms() []Form {
	return c.forms
}

func (c *Crawler) Crawl(ctx context.Context, domain string) {
	// The seed's host defines scope: we only follow links on the same host.
	seed, err := url.Parse(domain)
	if err != nil {
		return
	}
	scopeHost := seed.Host

	c.q.Enqueue(domain)
	c.v.Add(domain)

	for {
		rawURL, ok := c.q.Pop()
		if !ok {
			break // queue empty -> stop (this is your "while not empty")
		}

		// Parse the string into a *url.URL for Extract's base (relative-link resolution).
		base, err := url.Parse(rawURL)
		if err != nil {
			continue // skip URLs we can't parse
		}

		// Fetch the page. resp.Body IS the io.Reader we hand to Extract.
		resp, err := http.Get(rawURL)
		if err != nil {
			continue // skip fetch failures
		}

		extractedURLs, extractedForms, err := Extract(base, resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		c.forms = append(c.forms, extractedForms...)

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








