package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terrdv/vet/internal/checks"
	"github.com/terrdv/vet/internal/crawler"
	"github.com/terrdv/vet/internal/finding"
)

// vulnApp is a small server-rendered app with one reflected-XSS bug. Every page
// links onward and carries the same search form, which is the shape that makes
// dedup matter: the crawler will hand the engine that form once per page.
type vulnApp struct {
	*httptest.Server

	pages  int
	render time.Duration

	hits     atomic.Int64
	searches atomic.Int64 // requests that actually tested the form
}

func newVulnApp(t *testing.T, pages int, render time.Duration) *vulnApp {
	t.Helper()

	a := &vulnApp{pages: pages, render: render}
	mux := http.NewServeMux()

	// The bug: q comes back into page text unescaped.
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		a.hits.Add(1)
		a.searches.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>Results for %s</p></body></html>", r.URL.Query().Get("q"))
	})

	// The same form escaped, so a run has something it must *not* report.
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		a.hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>Results for %s</p></body></html>",
			strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(r.URL.Query().Get("q")))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a.hits.Add(1)
		time.Sleep(a.render)

		id := 0
		if r.URL.Path != "/" {
			v, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/p/"))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			id = v
		}

		var b strings.Builder
		b.WriteString("<html><body>")
		for i := 1; i <= 3; i++ {
			fmt.Fprintf(&b, `<a href="/p/%d">next</a>`, (id*3+i)%a.pages)
		}
		// Repeated verbatim on every page: one bug, not `pages` bugs.
		b.WriteString(`<form action="/search" method="get"><input name="q"><input name="lang"></form>`)
		b.WriteString(`<form action="/safe" method="get"><input name="q"></form>`)
		b.WriteString("</body></html>")

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(b.String()))
	})

	a.Server = httptest.NewServer(mux)
	t.Cleanup(a.Close)
	return a
}

// run wires a crawler and an engine exactly as runScan does and returns once
// both are finished.
func run(t *testing.T, a *vulnApp, crawlWorkers, checkWorkers int, onFinding func(finding.Finding)) *Engine {
	t.Helper()

	c := crawler.NewCrawl()
	eng := New(c.Client(), checkWorkers, checks.ReflectedXSS{})
	if onFinding != nil {
		eng.OnFinding(onFinding)
	}

	eng.Start(context.Background())
	c.OnForms(eng.SubmitForms)

	c.Crawl(context.Background(), a.URL, crawlWorkers)

	eng.Close()
	eng.Wait()
	return eng
}

func TestEngineFindsReflectedXSS(t *testing.T) {
	a := newVulnApp(t, 12, 0)

	var mu sync.Mutex
	var streamed []finding.Finding
	eng := run(t, a, 4, 4, func(f finding.Finding) {
		mu.Lock()
		streamed = append(streamed, f)
		mu.Unlock()
	})

	got := eng.Findings()
	if len(got) == 0 {
		t.Fatal("no findings: /search reflects q into page text unescaped")
	}
	if len(streamed) != len(got) {
		t.Errorf("OnFinding fired %d time(s) for %d finding(s)", len(streamed), len(got))
	}

	for _, f := range got {
		if f.Check != "xss-reflected" {
			t.Errorf("unexpected check %q", f.Check)
		}
		if f.Confidence != finding.Confirmed {
			t.Errorf("%s: confidence %q, want confirmed", f.Param, f.Confidence)
		}
		if !strings.HasSuffix(f.URL, "/search") {
			t.Errorf("finding on %s: only /search is vulnerable", f.URL)
		}
		if f.Param != "q" {
			t.Errorf("finding on param %q: only q is reflected", f.Param)
		}
	}
}

// TestEngineDedupsTargets is the reason Submit keeps a seen set. The same form
// is rendered on every page, so without dedup the engine tests it once per page
// and multiplies its request volume by the size of the site.
func TestEngineDedupsTargets(t *testing.T) {
	const pages = 20
	a := newVulnApp(t, pages, 0)

	eng := run(t, a, 4, 4, nil)

	// 3 fields across the two forms (q + lang on /search, q on /safe), each
	// discovered once per page by the crawler.
	if n := len(eng.Findings()); n != 1 {
		t.Errorf("got %d findings, want 1: the one bug is reported once", n)
	}
	if n := eng.Targets(); n != 3 {
		t.Errorf("tested %d targets, want 3 (q+lang on /search, q on /safe), not 3 per page", n)
	}

	// One probe for each of the 3 fields, plus confirmation payloads for the two
	// that reflect. Anything near pages*3 means every page re-queued the form.
	const ceiling = 12
	if n := a.searches.Load(); n > ceiling {
		t.Errorf("%d payload requests across %d pages; want <= %d (the same form on every page is one target)",
			n, pages, ceiling)
	} else {
		t.Logf("%d payload requests for %d crawled pages", n, pages)
	}
}

// TestEngineStreamsDuringCrawl is the whole point of the concurrent shape: a
// finding has to reach the user while the crawl is still running, not after it.
func TestEngineStreamsDuringCrawl(t *testing.T) {
	// Slow pages, so the crawl cannot finish before the engine has tested the
	// form it found on page one.
	a := newVulnApp(t, 40, 20*time.Millisecond)

	c := crawler.NewCrawl()
	eng := New(c.Client(), 4, checks.ReflectedXSS{})

	var crawlDone atomic.Bool
	first := make(chan struct{})
	var once sync.Once
	var duringCrawl atomic.Bool

	eng.OnFinding(func(finding.Finding) {
		once.Do(func() {
			duringCrawl.Store(!crawlDone.Load())
			close(first)
		})
	})

	eng.Start(context.Background())
	c.OnForms(eng.SubmitForms)
	c.Crawl(context.Background(), a.URL, 2)
	crawlDone.Store(true)

	eng.Close()
	eng.Wait()

	select {
	case <-first:
	default:
		t.Fatal("no finding was streamed at all")
	}
	if !duringCrawl.Load() {
		t.Error("first finding arrived only after the crawl returned; the engine is not running alongside it")
	}
}

// TestEngineCancellation checks the wind-down path: a cancelled context must
// stop the work without stranding a worker on the queue.
func TestEngineCancellation(t *testing.T) {
	a := newVulnApp(t, 200, 5*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	c := crawler.NewCrawl()
	eng := New(c.Client(), 4, checks.ReflectedXSS{})
	eng.Start(ctx)
	c.OnForms(eng.SubmitForms)

	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	done := make(chan struct{})
	go func() {
		c.Crawl(ctx, a.URL, 4)
		eng.Close()
		eng.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("crawl+engine did not wind down after cancellation")
	}
}

// TestSubmitFormsGroupsSiblings covers the regrouping that makes Target.Params
// fillable: Extract flattens a form into one Form per field, and only the
// per-page batch says which of them belong to the same submission.
func TestSubmitFormsGroupsSiblings(t *testing.T) {
	e := New(nil, 1)
	e.SubmitForms([]crawler.Form{
		{Action: "http://x/login", Method: "post", Field: "username"},
		{Action: "http://x/login", Method: "post", Field: "password"},
		{Action: "http://x/search", Method: "", Field: "q"},
	})
	e.Close()

	var got []checks.Target
	for {
		tgt, ok := e.q.Pop()
		if !ok {
			break
		}
		got = append(got, tgt)
	}

	want := []checks.Target{
		{URL: "http://x/login", Method: "POST", Field: "username", Params: map[string]string{"password": placeholder}},
		{URL: "http://x/login", Method: "POST", Field: "password", Params: map[string]string{"username": placeholder}},
		{URL: "http://x/search", Method: "GET", Field: "q", Params: map[string]string{}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].URL != want[i].URL || got[i].Method != want[i].Method || got[i].Field != want[i].Field {
			t.Errorf("target %d = %s %s field=%s, want %s %s field=%s",
				i, got[i].Method, got[i].URL, got[i].Field, want[i].Method, want[i].URL, want[i].Field)
			continue
		}
		if len(got[i].Params) != len(want[i].Params) {
			t.Errorf("target %d params = %v, want %v", i, got[i].Params, want[i].Params)
			continue
		}
		for k, v := range want[i].Params {
			if got[i].Params[k] != v {
				t.Errorf("target %d params = %v, want %v", i, got[i].Params, want[i].Params)
				break
			}
		}
	}
}

// TestEngineRecordsCheckErrors covers the difference between "clean" and
// "could not tell". A dead endpoint produces no findings either way; only the
// error list distinguishes the two.
func TestEngineRecordsCheckErrors(t *testing.T) {
	// Closed immediately, so every request to it is refused.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()

	e := New(&http.Client{Timeout: time.Second}, 2, checks.ReflectedXSS{})
	e.Start(context.Background())
	e.Submit(checks.Target{URL: dead.URL + "/search", Method: "GET", Field: "q"})
	e.Close()
	e.Wait()

	if n := len(e.Findings()); n != 0 {
		t.Errorf("got %d findings from an unreachable host", n)
	}
	errs := e.Errors()
	if len(errs) != 1 {
		t.Fatalf("got %d check errors, want 1: an unreachable endpoint is untested, not clean", len(errs))
	}
	if errs[0].Check != "xss-reflected" || errs[0].Param != "q" {
		t.Errorf("error lost its target: %+v", errs[0])
	}
	t.Logf("reported as: %s", errs[0].Error())
}

// TestEngineCancellationIsNotACheckError keeps a cancelled run from filling the
// report with failures that are the scan's own doing, not the target's.
func TestEngineCancellationIsNotACheckError(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	e := New(&http.Client{Timeout: time.Second}, 2, checks.ReflectedXSS{})
	e.Start(ctx)
	e.Submit(checks.Target{URL: dead.URL + "/search", Method: "GET", Field: "q"})
	e.Close()
	e.Wait()

	if n := len(e.Errors()); n != 0 {
		t.Errorf("got %d check errors from a cancelled run; teardown is not the target's failure", n)
	}
}
