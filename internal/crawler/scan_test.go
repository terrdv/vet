package crawler

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// scanRun performs one full crawl of a dev server and returns what a vet user
// cares about: how long the scan took, how many injection points it found, and
// whether the scan was outrunning the app.
type scanRun struct {
	elapsed   time.Duration
	forms     int
	fetch     stats
	queueWait stats
	reused    int64
	fresh     int64
	errs      int64
	maxInFlt  int64
}

func scan(t *testing.T, srv *devServer, workers, idleConns int) scanRun {
	t.Helper()

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = idleConns
	tt := &timingTransport{base: tr, rec: &recorder{}}

	c := NewCrawl()
	c.client = &http.Client{Timeout: fetchTimeout, Transport: tt}

	seed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.scopeHost = seed.Host
	c.pool = NewWorkerPool(workers, c.q, c.v, c.handle)

	start := time.Now()
	c.pool.Run(context.Background(), srv.URL)
	elapsed := time.Since(start)

	reused, fresh, errs := tt.counts()
	return scanRun{
		elapsed:   elapsed,
		forms:     len(c.Forms()),
		fetch:     tt.rec.stats(),
		queueWait: srv.queueWait.stats(),
		reused:    reused,
		fresh:     fresh,
		errs:      errs,
		maxInFlt:  srv.maxInFlight.Load(),
	}
}

// TestScanVsDevServerConcurrency is the headline measurement for this tool.
//
// It sweeps scan workers against dev servers with different concurrency
// limits. The result to read is where each row stops improving: that is the
// server's limit, not the scanner's, and every worker past it only adds queue
// time. Scanning your own dev server has no politeness constraint, but there is
// still no reason to run 32 workers at a server that handles 4.
//
//	go test ./internal/crawler -run TestScanVsDevServerConcurrency -v
func TestScanVsDevServerConcurrency(t *testing.T) {
	const (
		pages  = 120
		render = 25 * time.Millisecond // dev mode: no caching, reload per request
	)

	for _, serverConc := range []int{1, 2, 4, 8} {
		t.Logf("--- dev server handling %d request(s) at a time, %v per render", serverConc, render)
		t.Logf("    %-9s %9s %9s %9s %10s %8s", "workers", "scan time", "pages/s", "fetch p50", "queue p50", "in-flight")

		for _, workers := range []int{1, 2, 4, 8, 16, 32} {
			srv := newDevServer(pages, serverConc, render, 0)
			r := scan(t, srv, workers, 64)
			fetched := srv.hits.Load()
			srv.Close()

			t.Logf("    %-9d %9s %9.1f %9s %10s %8d",
				workers,
				r.elapsed.Round(time.Millisecond),
				float64(fetched)/r.elapsed.Seconds(),
				r.fetch.p50.Round(time.Millisecond),
				r.queueWait.p50.Round(time.Millisecond),
				r.maxInFlt)
		}
	}
}
