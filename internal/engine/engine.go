// Package engine runs the detection suite against the injection points the
// crawler discovers.
//
// It is built to run *alongside* a crawl rather than after one. The crawler
// publishes each page's forms as it finds them, the engine turns them into
// targets and starts testing immediately, so the first findings land while the
// crawler is still walking the site.
//
// Termination is the interesting part, and it is simpler here than in the
// crawler. A crawl worker is both consumer and producer — handling a URL
// discovers more URLs — which is why the pool needs a counter of outstanding
// work to know when it is finished. An engine worker only ever consumes: testing
// a target never produces another one. So "the queue is closed and drained" is a
// sufficient stop condition, and the only thing the caller has to get right is
// when to close, which is the moment the crawl returns.
package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/terrdv/vet/internal/checks"
	"github.com/terrdv/vet/internal/crawler"
	"github.com/terrdv/vet/internal/finding"
)

// placeholder is what the engine submits for the fields it is not currently
// testing. Something has to go in them — most forms reject a submission with
// fields missing — and it has to be inert, since it lands in whatever the target
// logs or stores.
const placeholder = "vet"

// CheckError is one check that could not reach a conclusion on one target --
// the endpoint was unreachable, the request timed out, the response never
// arrived. It is kept because "could not test" is not "clean", and a scan that
// silently drops these reports coverage it never had.
type CheckError struct {
	Check  string
	URL    string
	Method string
	Param  string
	Err    error
}

func (e CheckError) Error() string {
	return fmt.Sprintf("%s: %s %s param=%s: %v", e.Check, e.Method, e.URL, e.Param, e.Err)
}

type Engine struct {
	checks  []checks.Check
	client  checks.Doer
	workers int

	q    *queue
	seen *crawler.VisitedSet

	// targets counts what survived dedup, which is the only honest measure of
	// how much of the surface was tested: the crawler reports one Form per
	// field per page, so the same form on a hundred pages is a hundred forms
	// and a handful of injection points.
	targets atomic.Int64

	// onFinding is set once before Start and then only read. It is called from
	// every worker, so it must be safe for concurrent use.
	onFinding func(finding.Finding)

	// Counts goroutines, not targets: unlike the crawler's pool the engine
	// needs no count of outstanding work, because the queue closing is already
	// proof that no more can arrive.
	wg sync.WaitGroup

	mu       sync.Mutex
	findings []finding.Finding
	errs     []CheckError
}

// New returns an engine that will run every check in cs against every target it
// is given, using workers concurrent goroutines.
//
// client is the engine's only route to the network, and it should be the same
// one the crawler is using: the two run at once against a single host, so
// sharing the client means sharing one connection pool rather than competing
// for ephemeral ports with two.
func New(client checks.Doer, workers int, cs ...checks.Check) *Engine {
	if workers < 1 {
		workers = 1 // nothing would drain the queue, so Wait would never return
	}
	return &Engine{
		checks:  cs,
		client:  client,
		workers: workers,
		q:       newQueue(),
		seen:    crawler.NewVisitedSet(),
	}
}

// OnFinding registers a callback invoked once per finding, as it is confirmed.
// That is the point of running concurrently with the crawl: results reach the
// user during the scan instead of in a batch at the end. Call it before Start.
func (e *Engine) OnFinding(fn func(finding.Finding)) { e.onFinding = fn }

// Start launches the workers and returns immediately. They block on an empty
// queue, so it is safe — and expected — to call this before any target exists.
func (e *Engine) Start(ctx context.Context) {
	for i := 0; i < e.workers; i++ {
		e.wg.Go(func() { e.worker(ctx) })
	}
}

// Close declares the target stream finished. After a crawl this is safe the
// moment Crawl returns: every form is published from inside the pool's handler,
// which retires its URL from the pending count only on return, so a finished
// crawl proves no further form can be announced.
func (e *Engine) Close() { e.q.Close() }

// Wait blocks until every submitted target has been tested and the workers have
// exited. Close must have been called, or there is nothing to wait for.
func (e *Engine) Wait() { e.wg.Wait() }

// Targets returns the number of distinct injection points queued so far.
func (e *Engine) Targets() int { return int(e.targets.Load()) }

// Errors returns the checks that could not reach a conclusion. A scan with a
// non-empty result here tested less of the surface than its finding count
// suggests.
func (e *Engine) Errors() []CheckError {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]CheckError(nil), e.errs...)
}

// Findings returns everything confirmed so far. Safe to call during a run,
// though the answer only stops changing after Wait.
func (e *Engine) Findings() []finding.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]finding.Finding(nil), e.findings...)
}

// Submit queues one injection point, ignoring one already seen. Safe to call
// from many goroutines: it is the crawler's workers that call it.
func (e *Engine) Submit(t checks.Target) {
	method := strings.ToUpper(t.Method)
	if method == "" {
		method = "GET"
	}
	// VisitedSet is documented for URLs, but it is a mutex-guarded string set
	// and this is the same job: keep a growing frontier finite.
	if !e.seen.Add(method + " " + t.URL + " " + t.Field) {
		return
	}
	e.targets.Add(1)
	e.q.Push(t)
}

// SubmitForms is the crawler's sink: it takes one page's forms and queues an
// injection point for each field.
//
// The batch is what makes Params fillable. Extract flattens a <form> into one
// crawler.Form per field and drops the grouping, but every form on a page
// arrives here together, so regrouping by (method, action) recovers which
// fields belong to the same submission — and a field is rarely testable alone,
// since the endpoint behind it usually wants the whole form.
//
// The siblings carry a placeholder rather than their real values, because
// extractForm never reads the value= attribute. A form gated on a hidden CSRF
// token will still be rejected; capturing default values is what fixes that.
func (e *Engine) SubmitForms(fs []crawler.Form) {
	type key struct{ method, action string }

	var order []key
	fields := map[key][]string{}
	for _, f := range fs {
		method := strings.ToUpper(f.Method)
		if method == "" {
			method = "GET"
		}
		k := key{method, f.Action}
		if _, ok := fields[k]; !ok {
			order = append(order, k) // stable output, so tests can rely on it
		}
		fields[k] = append(fields[k], f.Field)
	}

	for _, k := range order {
		group := fields[k]
		for i, field := range group {
			params := make(map[string]string, len(group)-1)
			for j, other := range group {
				if i != j {
					params[other] = placeholder
				}
			}
			e.Submit(checks.Target{
				URL:    k.action,
				Method: k.method,
				Field:  field,
				Params: params,
			})
		}
	}
}

// worker tests targets until the queue is closed and drained.
func (e *Engine) worker(ctx context.Context) {
	for {
		t, ok := e.q.Pop()
		if !ok {
			return
		}
		// Keep draining on cancellation rather than returning: the queue empties
		// without being tested and the run winds down through the normal path.
		if ctx.Err() != nil {
			continue
		}
		e.test(ctx, t)
	}
}

// test runs every check against one injection point.
//
// The checks run one after another even though the engine is concurrent. One
// target is one endpoint, and parallelism across targets already keeps the
// workers busy; stacking a whole suite's payloads onto a single endpoint at once
// only buries the app under requests it will answer more slowly.
func (e *Engine) test(ctx context.Context, t checks.Target) {
	for _, c := range e.checks {
		fs, err := c.Run(ctx, e.client, t)

		// A check can return findings *and* an error: it confirmed what it
		// could before the endpoint stopped answering. Both are recorded.
		e.record(fs)

		// Cancellation is the run being torn down, not the target refusing to
		// answer, so it is not this target's failure to report.
		if err != nil && ctx.Err() == nil {
			e.recordErr(CheckError{
				Check: c.Name(), URL: t.URL, Method: t.Method, Param: t.Field, Err: err,
			})
		}
	}
}

func (e *Engine) recordErr(ce CheckError) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errs = append(e.errs, ce)
}

func (e *Engine) record(fs []finding.Finding) {
	if len(fs) == 0 {
		return
	}
	e.mu.Lock()
	e.findings = append(e.findings, fs...)
	e.mu.Unlock() // not deferred: the callback must not run under the lock

	if e.onFinding != nil {
		for _, f := range fs {
			e.onFinding(f)
		}
	}
}
