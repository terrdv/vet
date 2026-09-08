package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// echoServer stands in for a target app. Each route reflects the "q" parameter
// into a different HTML context, escaping it or not, which is the only thing
// the check is supposed to be able to tell apart.
func echoServer(t *testing.T) *httptest.Server {
	t.Helper()

	page := func(body string) string {
		return "<!doctype html><html><body>" + body + "</body></html>"
	}
	// noAngles is the filter an app reaches for first: it kills the classic
	// <script> payload but leaves attribute breakout wide open.
	noAngles := strings.NewReplacer("<", "", ">", "")

	mux := http.NewServeMux()
	route := func(path string, render func(q string) string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query().Get("q")
			if r.Method == http.MethodPost {
				q = r.FormValue("q")
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, render(q))
		})
	}

	route("/text", func(q string) string { return page("<p>Results for " + q + "</p>") })
	route("/text-escaped", func(q string) string {
		return page("<p>Results for " + html.EscapeString(q) + "</p>")
	})
	route("/attr", func(q string) string { return page(`<input name="s" value="` + q + `">`) })
	route("/attr-single", func(q string) string { return page(`<input name="s" value='` + q + `'>`) })
	route("/attr-unquoted", func(q string) string { return page(`<input name="s" value=` + q + `>`) })
	route("/attr-escaped", func(q string) string {
		return page(`<input name="s" value="` + html.EscapeString(q) + `">`)
	})
	route("/attr-no-angles", func(q string) string {
		return page(`<input name="s" value="` + noAngles.Replace(q) + `">`)
	})
	route("/script", func(q string) string { return page(`<script>var s = "` + q + `";</script>`) })
	route("/comment", func(q string) string { return page("<!-- searched: " + q + " -->") })
	route("/clean", func(string) string { return page("<p>no reflection here</p>") })

	// Reflected, but never rendered as a page: not a reflected-XSS finding.
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"q":%q}`, r.URL.Query().Get("q"))
	})

	// Only answers when the whole form is submitted, which is what Target.Params
	// is for: a field is rarely testable on its own.
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method != http.MethodPost || r.FormValue("token") != "abc" {
			fmt.Fprint(w, page("<p>bad request</p>"))
			return
		}
		fmt.Fprint(w, page("<p>hello "+r.FormValue("user")+"</p>"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestReflectedXSS(t *testing.T) {
	srv := echoServer(t)

	tests := []struct {
		name  string
		path  string
		vuln  bool
		attrs bool // the finding should come from attribute injection, not a new element
	}{
		{name: "html text", path: "/text", vuln: true},
		{name: "html text escaped", path: "/text-escaped"},
		{name: "double-quoted attribute", path: "/attr", vuln: true},
		{name: "single-quoted attribute", path: "/attr-single", vuln: true},
		{name: "unquoted attribute", path: "/attr-unquoted", vuln: true},
		{name: "attribute escaped", path: "/attr-escaped"},
		{name: "angle brackets stripped", path: "/attr-no-angles", vuln: true, attrs: true},
		{name: "script block", path: "/script", vuln: true},
		{name: "html comment", path: "/comment", vuln: true},
		{name: "no reflection", path: "/clean"},
		{name: "json response", path: "/json"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := Target{URL: srv.URL + tc.path, Method: "GET", Field: "q"}

			found, err := ReflectedXSS{}.Run(context.Background(), srv.Client(), target)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			if !tc.vuln {
				if len(found) != 0 {
					t.Fatalf("reported %d finding(s) on a safe endpoint: %v", len(found), found)
				}
				return
			}

			if len(found) != 1 {
				t.Fatalf("got %d findings, want exactly 1: %v", len(found), found)
			}
			f := found[0]
			if f.Check != "xss-reflected" || f.Param != "q" || f.URL != target.URL {
				t.Errorf("finding does not identify the injection point: %+v", f)
			}
			if f.Payload == "" || f.Evidence == "" {
				t.Errorf("finding is not reproducible without a payload and evidence: %+v", f)
			}
			// An attribute-only breakout still lands markup in the response;
			// only the *shape* of the proof differs.
			if wantAttr := strings.Contains(f.Detail, "attribute on an existing element"); wantAttr != tc.attrs {
				t.Errorf("proof shape = attribute:%v, want attribute:%v (%s)", wantAttr, tc.attrs, f.Detail)
			}
		})
	}
}

// A field usually only reaches its sink when the rest of its form comes along,
// and POST bodies are not query strings.
func TestReflectedXSSPostWithParams(t *testing.T) {
	srv := echoServer(t)

	target := Target{
		URL:    srv.URL + "/form",
		Method: "POST",
		Field:  "user",
		Params: map[string]string{"token": "abc"},
	}

	found, err := ReflectedXSS{}.Run(context.Background(), srv.Client(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(found), found)
	}
	if found[0].Method != "POST" || found[0].Param != "user" {
		t.Errorf("finding does not describe the request that produced it: %+v", found[0])
	}
}

// The check must never be talked out of a request by an unreachable target:
// "could not test" is not "clean".
func TestReflectedXSSUnreachableIsAnError(t *testing.T) {
	srv := echoServer(t)
	client := srv.Client()
	srv.Close()

	_, err := ReflectedXSS{}.Run(context.Background(), client, Target{URL: srv.URL + "/text", Field: "q"})
	if err == nil {
		t.Fatal("Run reported no error for an unreachable target")
	}
}

func TestFindReflections(t *testing.T) {
	const canary = "vet0123456789"

	tests := []struct {
		name string
		body string
		want reflection
	}{
		{"text", "<p>hi " + canary + "</p>", reflection{kind: ctxText}},
		{"double quoted", `<input value="` + canary + `">`,
			reflection{kind: ctxAttrValue, tag: "input", attr: "value", quote: '"'}},
		{"single quoted", `<a href='/x?q=` + canary + `'>go</a>`,
			reflection{kind: ctxAttrValue, tag: "a", attr: "href", quote: '\''}},
		{"unquoted", `<input value=` + canary + ` disabled>`,
			reflection{kind: ctxAttrValue, tag: "input", attr: "value"}},
		{"attribute name", `<div data-` + canary + `="1">x</div>`,
			reflection{kind: ctxAttrName, tag: "div"}},
		{"script", `<script>var s = "` + canary + `";</script>`,
			reflection{kind: ctxRawText, tag: "script"}},
		{"textarea", `<textarea>` + canary + `</textarea>`,
			reflection{kind: ctxRawText, tag: "textarea"}},
		{"comment", `<!-- ` + canary + ` -->`, reflection{kind: ctxComment}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findReflections([]byte(tc.body), canary)
			if len(got) != 1 {
				t.Fatalf("got %d reflections, want 1: %+v", len(got), got)
			}
			if got[0] != tc.want {
				t.Errorf("got %+v, want %+v", got[0], tc.want)
			}
		})
	}
}

// An escaped reflection is still a reflection: the check has to find it to
// classify it, and only the confirmation step is allowed to clear it.
func TestFindReflectionsSeesEncodedInput(t *testing.T) {
	const canary = "vet0123456789"

	got := findReflections([]byte("<p>&lt;"+canary+"&gt;</p>"), canary)
	if len(got) != 1 || got[0].kind != ctxText {
		t.Fatalf("got %+v, want one text reflection", got)
	}
}

// The check reports one bug per context, not one per echo.
func TestRunDedupsRepeatedContexts(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<ul><li>"+q+"</li><li>"+q+"</li><li>"+q+"</li></ul>")
	}))
	defer srv.Close()

	found, err := ReflectedXSS{}.Run(context.Background(), srv.Client(), Target{URL: srv.URL, Field: "q"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("got %d findings for one bug echoed three times: %v", len(found), found)
	}
	if requests != 2 { // one probe, one payload
		t.Errorf("sent %d requests, want 2", requests)
	}
}

func TestScanTagAttrs(t *testing.T) {
	raw := `<input type="text" name='n' value=abc disabled data-x="1">`

	got := scanTagAttrs([]byte(raw))
	want := []struct {
		name  string
		quote byte
		value string
	}{
		{"type", '"', "text"},
		{"name", '\'', "n"},
		{"value", 0, "abc"},
		{"disabled", 0, ""},
		{"data-x", '"', "1"},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d attributes, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		a := got[i]
		value := raw[a.start:a.end]
		if a.valued {
			if a.name != w.name || a.quote != w.quote || value != w.value {
				t.Errorf("attr %d = %s %q (quote %q), want %s %q (quote %q)", i, a.name, value, a.quote, w.name, w.value, w.quote)
			}
			continue
		}
		if w.value != "" || a.name != w.name {
			t.Errorf("attr %d = bare %s, want %s=%q", i, a.name, w.name, w.value)
		}
	}
}
