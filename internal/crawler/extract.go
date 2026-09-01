package crawler

import (
	"io"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

type Form struct {
	Action string // ACTION
	Method string // HTTP METHOD
	Field  string // INJECTION POINT
}

// Extract parses one page's HTML and returns the absolute links found on it
// and the forms' injection points. base is the URL the page was fetched from,
// used to resolve relative hrefs/actions into absolute URLs.
func Extract(base *url.URL, body io.Reader) ([]string, []Form, error) {
	doc, err := html.Parse(body)
	if err != nil {
		return nil, nil, err
	}

	var links []string
	var forms []Form

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				if href, ok := attr(n, "href"); ok {
					if abs := resolve(base, href); abs != "" {
						links = append(links, abs)
					}
				}
			case "form":
				forms = append(forms, extractForm(base, n)...)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	return links, forms, nil
}

// extractForm turns one <form> node into one Form per named input field.
func extractForm(base *url.URL, form *html.Node) []Form {
	action, _ := attr(form, "action")
	action = resolve(base, action)
	if action == "" {
		action = base.String() // forms with no action submit to the current page
	}

	method := "GET"
	if m, ok := attr(form, "method"); ok && m != "" {
		method = strings.ToUpper(m)
	}

	var out []Form
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input", "textarea", "select":
				if name, ok := attr(n, "name"); ok && name != "" {
					out = append(out, Form{Action: action, Method: method, Field: name})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(form)
	return out
}

// attr returns the value of the named attribute and whether it was present.
func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

// resolve turns a possibly-relative href into an absolute URL string against
// base. Returns "" if the href can't be parsed.
func resolve(base *url.URL, href string) string {
	if href == "" {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}
