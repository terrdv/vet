package crawler

import (
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"sort"
	"sync"
	"time"
)

// Shared measurement helpers for the scan benchmarks.
//
// vet scans local dev servers, so the numbers that matter are not the ones a
// web-scale crawler cares about. There is no network latency to hide behind on
// loopback, the target is usually a single process with a small worker count,
// and it belongs to the developer running the scan — so the risk is not being
// rude to a stranger's site, it is swamping the app you are trying to test.

// recorder collects latency samples from concurrent workers.
type recorder struct {
	mu      sync.Mutex
	samples []time.Duration
}

func (r *recorder) record(d time.Duration) {
	r.mu.Lock()
	r.samples = append(r.samples, d)
	r.mu.Unlock()
}

type stats struct {
	n                        int
	p50, p90, p99, max, mean time.Duration
}

func (r *recorder) stats() stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := append([]time.Duration(nil), r.samples...)
	if len(s) == 0 {
		return stats{}
	}
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	var total time.Duration
	for _, d := range s {
		total += d
	}
	at := func(q float64) time.Duration {
		i := int(q * float64(len(s)))
		if i >= len(s) {
			i = len(s) - 1
		}
		return s[i]
	}
	return stats{n: len(s), p50: at(0.50), p90: at(0.90), p99: at(0.99), max: s[len(s)-1], mean: total / time.Duration(len(s))}
}

// timingTransport records per-request latency and connection reuse.
//
// Connection accounting matters more here than it would against a remote host.
// On loopback a request completes in microseconds, so connections go idle
// constantly, and Go's default MaxIdleConnsPerHost of 2 closes all but two of
// them — leaving the next request to dial again. Enough of that and the scan
// exhausts the machine's ephemeral ports.
type timingTransport struct {
	base http.RoundTripper
	rec  *recorder

	mu       sync.Mutex
	errs     int64
	reused   int64
	fresh    int64
	tlsTotal time.Duration
}

func (t *timingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var tlsStart time.Time
	trace := &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) {
			t.mu.Lock()
			if i.Reused {
				t.reused++
			} else {
				t.fresh++
			}
			t.mu.Unlock()
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			t.mu.Lock()
			t.tlsTotal += time.Since(tlsStart)
			t.mu.Unlock()
		},
	}
	r = r.WithContext(httptrace.WithClientTrace(r.Context(), trace))

	start := time.Now()
	resp, err := t.base.RoundTrip(r)
	t.rec.record(time.Since(start))
	if err != nil {
		t.mu.Lock()
		t.errs++
		t.mu.Unlock()
	}
	return resp, err
}

func (t *timingTransport) counts() (reused, fresh, errs int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reused, t.fresh, t.errs
}
