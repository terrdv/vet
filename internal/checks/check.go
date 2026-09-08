// Package checks is vet's detection engine: one file per vulnerability class,
// each exposing a Check that the engine runs against every injection point the
// crawler discovered.
package checks

import (
	"context"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/terrdv/vet/internal/finding"
)

// Doer is the subset of *http.Client the checks depend on. Taking the
// interface keeps politeness out of the checks themselves: the engine hands
// them whatever client already enforces scope and rate limiting, and tests
// hand them a stub.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Target is a single injection point: one field of one endpoint, plus the
// other fields that have to be submitted alongside it for the request to be
// accepted. It is a crawler.Form once the engine has paired it back up with
// the rest of its form.
type Target struct {
	URL    string            // absolute URL of the endpoint (the form action)
	Method string            // "GET" or "POST"; empty means GET
	Field  string            // the field under test
	Params map[string]string // the other fields, submitted unchanged
}

// Check is one vulnerability class. Implementations must be safe to call
// concurrently on different targets — the engine runs the suite in parallel —
// which in practice means holding no per-run state on the receiver.
type Check interface {
	// Name is the stable identifier that appears in Finding.Check.
	Name() string

	// Run tests one injection point and returns everything it confirmed there.
	// No finding is the normal result. An error means the check could not
	// reach a conclusion (the endpoint was unreachable, say), which is not the
	// same as concluding the target is clean.
	Run(ctx context.Context, client Doer, t Target) ([]finding.Finding, error)
}

// maxBodyBytes caps how much of a response a check reads. A scan touches every
// endpoint on a domain, so an unbounded read turns one large download into the
// memory ceiling for the whole run; a reflection past a megabyte is not worth
// that risk.
const maxBodyBytes = 1 << 20

// request builds one submission of the target with value substituted for the
// field under test. GET targets carry the fields in the query string, merged
// over anything already in the URL; POST targets carry them form-encoded.
func (t Target) request(ctx context.Context, value string) (*http.Request, error) {
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, err
	}

	method := strings.ToUpper(t.Method)
	if method == "" {
		method = http.MethodGet
	}

	if method != http.MethodPost {
		q := u.Query()
		for k, v := range t.Params {
			q.Set(k, v)
		}
		q.Set(t.Field, value) // last, so it wins over a same-named param
		u.RawQuery = q.Encode()
		return http.NewRequestWithContext(ctx, method, u.String(), nil)
	}

	form := url.Values{}
	for k, v := range t.Params {
		form.Set(k, v)
	}
	form.Set(t.Field, value)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// response is one submission's result. It carries more than the body because
// the checks disagree about what counts as evidence: reflected XSS reads the
// markup, error-based SQLi reads the body whatever its type, boolean-based
// compares status codes, and time-based has no body evidence at all — the
// duration is the finding.
//
// Deciding what disqualifies a response is therefore each check's job, not this
// helper's. An earlier version returned a nil body for anything that was not
// HTML, which is right for XSS and silently wrong for everything else: an API
// answering `{"error":"...SQL syntax..."}` would have been read as clean.
type response struct {
	body        []byte
	status      int
	contentType string
	duration    time.Duration
}

// isHTML reports whether a browser would parse this response as markup, which
// is what makes a reflection in it an XSS finding rather than a curiosity.
func (r response) isHTML() bool { return isHTML(r.contentType) }

// submit sends one value for the field under test and reads the response.
func submit(ctx context.Context, client Doer, t Target, value string) (response, error) {
	req, err := t.request(ctx, value)
	if err != nil {
		return response{}, err
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))

	// Drain whatever is left so the connection goes back to the pool: a scan
	// makes thousands of these and a fresh handshake for each is slow enough to
	// look like rate limiting to the target. Bounded, so one huge download
	// cannot stall the worker reading it.
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))

	return response{
		body: body,
		// Measured after the body is read, so it covers a server that answers
		// its headers immediately and then stalls — which is exactly the shape
		// a time-based payload produces.
		duration:    time.Since(start),
		status:      resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
	}, err
}

// isHTML reports whether a Content-Type will be parsed as markup by a browser.
// An absent type counts: browsers sniff it, so an attacker gets HTML anyway.
func isHTML(ctype string) bool {
	if strings.TrimSpace(ctype) == "" {
		return true
	}
	mt, _, err := mime.ParseMediaType(ctype)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(ctype, ";", 2)[0]))
	}
	return mt == "text/html" || mt == "application/xhtml+xml" || mt == ""
}
