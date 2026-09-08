package checks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/net/html"

	"github.com/terrdv/vet/internal/finding"
)

// ReflectedXSS detects reflected cross-site scripting: input that comes back
// in the response as *markup* rather than as text.
//
// It works in two steps, because "the response contains my payload" is not
// evidence of anything — an app that correctly escapes `<script>` still echoes
// those exact characters back, just encoded.
//
//  1. Probe. Send a harmless random marker and find where it comes back, and
//     in what HTML context: page text, an attribute value, inside a <script>,
//     inside a comment. The context is what decides whether a payload can
//     break out at all and what it has to look like.
//  2. Confirm. Send a context-specific payload carrying a second marker as a
//     brand-new element or attribute name, then parse the response and look
//     for that element/attribute in the tree. If the parser agrees the marker
//     is an element, the input reached the response as markup — which is the
//     bug. If it was escaped, the marker comes back as text and the parse
//     finds nothing.
//
// The payloads deliberately inject an inert unknown element rather than a real
// `alert(1)`: it is the same proof of markup injection without leaving live
// script in whatever the target logs, renders, or stores.
//
// The check runs without a browser, so it cannot see DOM-based XSS — sinks
// reached by client-side JavaScript never appear in the server's HTML.
type ReflectedXSS struct{}

// Compile-time proof this satisfies the engine's contract.
var _ Check = ReflectedXSS{}

func (ReflectedXSS) Name() string { return "xss-reflected" }

// maxContexts caps how many distinct reflection contexts one field is worth
// testing. A field echoed into a hundred table rows is one bug reported a
// hundred times, and every context costs requests against a live target.
const maxContexts = 4

func (x ReflectedXSS) Run(ctx context.Context, client Doer, t Target) ([]finding.Finding, error) {
	canary := marker()

	probe, err := submit(ctx, client, t, canary)
	if err != nil {
		return nil, err // unreachable: no conclusion, which is not "clean"
	}
	if !probe.isHTML() {
		// A reflection in JSON or in an image is not a reflected-XSS finding,
		// and parsing one as HTML only invents them.
		return nil, nil
	}

	var out []finding.Finding
	seen := make(map[reflection]bool)
	for _, r := range findReflections(probe.body, canary) {
		if seen[r] {
			continue // same context again: the same bug, not a new one
		}
		seen[r] = true
		if len(seen) > maxContexts {
			break
		}

		f, err := x.confirm(ctx, client, t, r)
		if err != nil {
			return out, err
		}
		if f != nil {
			out = append(out, *f)
		}
	}
	return out, nil
}

// confirm sends the payloads that fit one reflection context and returns a
// finding for the first one the response parses as markup. Nil means the
// reflection is there but escaped — the app is doing its job.
func (x ReflectedXSS) confirm(ctx context.Context, client Doer, t Target, r reflection) (*finding.Finding, error) {
	for _, p := range payloadsFor(r) {
		resp, err := submit(ctx, client, t, p.value)
		if err != nil {
			return nil, err
		}
		if !resp.isHTML() || !p.confirmedBy(resp.body) {
			continue
		}

		method := strings.ToUpper(t.Method)
		if method == "" {
			method = "GET"
		}
		return &finding.Finding{
			Check:      x.Name(),
			Severity:   finding.High,
			Confidence: finding.Confirmed,
			URL:        t.URL,
			Method:     method,
			Param:      t.Field,
			Payload:    p.value,
			Evidence:   excerpt(resp.body, p.marker),
			Detail: fmt.Sprintf("%q is reflected %s and is not escaped there: the payload came back parsed as %s, so an attacker controls markup on this page.",
				t.Field, r.describe(), p.proves()),
		}, nil
	}
	return nil, nil
}

// payload is one attempt at breaking out of a reflection context, plus the
// thing the response has to contain for the attempt to count as proof.
type payload struct {
	value  string // what gets submitted as the field's value
	marker string // the element or attribute name the payload injects
	asAttr bool   // marker is an attribute name rather than an element name
}

func (p payload) confirmedBy(body []byte) bool {
	if p.asAttr {
		return hasAttr(body, p.marker)
	}
	return hasElement(body, p.marker)
}

func (p payload) proves() string {
	if p.asAttr {
		return "a new attribute on an existing element"
	}
	return "a new element"
}

// payloadsFor builds the escape sequence for one context, cheapest first. Each
// one is the minimum needed to get out of where the reflection sits: close the
// enclosing quote, tag, raw-text element or comment, then open an element the
// parser has to treat as new markup.
func payloadsFor(r reflection) []payload {
	m := marker()
	q := ""
	if r.quote != 0 {
		q = string(r.quote)
	}

	switch r.kind {
	case ctxText:
		return []payload{{value: "<" + m + ">", marker: m}}

	case ctxRawText:
		// Inside <script>/<style>/<textarea>/<title>, `<` is not markup; only
		// the element's own end tag gets out.
		return []payload{{value: "</" + r.tag + "><" + m + ">", marker: m}}

	case ctxComment:
		return []payload{{value: "--><" + m + ">", marker: m}}

	case ctxAttrValue:
		// The leading "x" matters for unquoted values, where the injected
		// space is what terminates the value — a payload starting with that
		// space would be skipped as pre-value whitespace instead.
		return []payload{
			{value: "x" + q + "><" + m + ">", marker: m},
			// Falls back to staying inside the tag: enough for onerror=,
			// which is XSS just the same, and it survives filters that only
			// strip angle brackets.
			{value: "x" + q + " " + m + "=1", marker: m, asAttr: true},
		}

	case ctxAttrName:
		// Already inside a tag's markup, so there is no quote to close first.
		return []payload{
			{value: "><" + m + ">", marker: m},
			{value: " " + m + "=1", marker: m, asAttr: true},
		}
	}
	return nil
}

// hasElement reports whether the parsed document contains an element with this
// name. Escaped input cannot produce one: `&lt;vet1234&gt;` parses as text.
func hasElement(body []byte, name string) bool {
	return anyNode(body, func(n *html.Node) bool {
		return n.Type == html.ElementNode && n.Data == name
	})
}

// hasAttr reports whether any element carries an attribute with this name.
func hasAttr(body []byte, name string) bool {
	return anyNode(body, func(n *html.Node) bool {
		if n.Type != html.ElementNode {
			return false
		}
		for _, a := range n.Attr {
			if a.Key == name {
				return true
			}
		}
		return false
	})
}

func anyNode(body []byte, pred func(*html.Node) bool) bool {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return false
	}
	var walk func(*html.Node) bool
	walk = func(n *html.Node) bool {
		if pred(n) {
			return true
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if walk(c) {
				return true
			}
		}
		return false
	}
	return walk(doc)
}

// marker returns a token that survives a round trip unchanged and is legal as
// an HTML element name: letters and digits only, starting with a letter, so no
// escaper has a reason to touch it and no parser has a reason to reject it. It
// is random per call so a reflection can never be confused with a marker left
// over from an earlier request against the same app.
func marker() string {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Randomness only keeps markers distinct within a scan, so a fixed
		// fallback is worse than a random one but better than failing a scan.
		return "vet0000000000"
	}
	return "vet" + hex.EncodeToString(b[:])
}

// excerpt returns a short one-line window of the response around the marker,
// so a finding can be eyeballed without re-running the request by hand.
func excerpt(body []byte, mark string) string {
	const window = 60

	i := bytes.Index(body, []byte(mark))
	if i < 0 {
		return ""
	}
	start := max(i-window, 0)
	end := min(i+len(mark)+window, len(body))

	return strings.Join(strings.Fields(string(body[start:end])), " ")
}
