package checks

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

// ctxKind is the HTML context a reflection landed in. It is the whole reason
// the check probes before it attacks: `<` is markup in page text, inert inside
// a <script>, and useless inside an attribute until the quote around it is
// closed, so each context needs a different escape sequence — and a payload
// built for the wrong one comes back clean from a page that is vulnerable.
type ctxKind int

const (
	ctxText      ctxKind = iota // between tags, where `<` starts an element
	ctxRawText                  // inside <script>/<style>/<title>/<textarea>
	ctxComment                  // inside <!-- ... -->
	ctxAttrValue                // inside an attribute's value
	ctxAttrName                 // inside a tag's markup: a tag or attribute name
)

// reflection is one place the probe came back, and the context it came back
// in. It is comparable on purpose: Run dedups on it, so a field echoed into
// fifty identical table cells is tested once.
type reflection struct {
	kind  ctxKind
	tag   string // the element the reflection sits in or on
	attr  string // the attribute holding it, for ctxAttrValue
	quote byte   // the quote delimiting that value: '"', '\'', or 0 if unquoted
}

func (r reflection) describe() string {
	switch r.kind {
	case ctxRawText:
		return fmt.Sprintf("inside a <%s> element", r.tag)
	case ctxComment:
		return "inside an HTML comment"
	case ctxAttrValue:
		q := "an unquoted"
		switch r.quote {
		case '"':
			q = "a double-quoted"
		case '\'':
			q = "a single-quoted"
		}
		return fmt.Sprintf("in %s %s= attribute on <%s>", q, r.attr, r.tag)
	case ctxAttrName:
		return fmt.Sprintf("inside the markup of a <%s> tag", r.tag)
	default:
		return "in the page body"
	}
}

// findReflections locates every occurrence of the probe in the response and
// classifies the context it landed in.
//
// The classification runs on the tokenizer's *raw* bytes, never on its decoded
// text or attribute values. That distinction is the check: the decoded view
// cannot tell `<` from `&lt;`, which is exactly the difference between a
// vulnerable page and a correctly escaped one.
func findReflections(body []byte, canary string) []reflection {
	needle := []byte(canary)

	var out []reflection
	var rawTag string // the raw-text element currently open, if any

	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return out // io.EOF, or malformed input we have read as far as we can
		}

		// Raw has to be copied before TagName/Text, which reuse the buffer.
		raw := append([]byte(nil), z.Raw()...)
		hit := bytes.Contains(raw, needle)

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if tt == html.StartTagToken && isRawText(tag) {
				rawTag = tag
			}
			if hit {
				out = append(out, tagReflections(raw, needle, tag)...)
			}

		case html.EndTagToken:
			name, _ := z.TagName()
			if string(name) == rawTag {
				rawTag = ""
			}

		case html.TextToken:
			if !hit {
				continue
			}
			if rawTag != "" {
				out = append(out, reflection{kind: ctxRawText, tag: rawTag})
			} else {
				out = append(out, reflection{kind: ctxText})
			}

		case html.CommentToken:
			if hit {
				out = append(out, reflection{kind: ctxComment})
			}
		}
	}
}

// isRawText reports whether an element's content is tokenized as raw text or
// RCDATA, where markup does not start until the element's own end tag. The set
// mirrors the one the tokenizer itself switches on.
func isRawText(tag string) bool {
	switch tag {
	case "iframe", "noembed", "noframes", "noscript", "plaintext", "script", "style", "textarea", "title", "xmp":
		return true
	}
	return false
}

// tagReflections classifies every occurrence of the probe inside one tag's raw
// bytes: either it sits in an attribute's value, or it is part of the tag's own
// markup — a tag name or an attribute name.
func tagReflections(raw, needle []byte, tag string) []reflection {
	attrs := scanTagAttrs(raw)

	var out []reflection
	for i := 0; ; {
		j := bytes.Index(raw[i:], needle)
		if j < 0 {
			return out
		}
		at := i + j
		i = at + len(needle)

		if a, ok := attrAt(attrs, at); ok {
			out = append(out, reflection{kind: ctxAttrValue, tag: tag, attr: a.name, quote: a.quote})
			continue
		}
		out = append(out, reflection{kind: ctxAttrName, tag: tag})
	}
}

// attrSpan is one attribute of a tag, located in the tag's raw bytes.
type attrSpan struct {
	name       string
	quote      byte // '"', '\'', or 0 when the value is unquoted
	start, end int  // byte offsets of the value within the raw tag
	valued     bool // false for a bare attribute like <input disabled>
}

// scanTagAttrs walks a raw start tag and returns where each attribute's value
// begins and ends, and what quotes it.
//
// The tokenizer's own TagAttr would be easier, but it hands back *decoded*
// values with no offsets and no quote character — and this check needs the
// quote (to know what the payload has to close) and the offsets (to know which
// value a reflection actually fell inside).
func scanTagAttrs(raw []byte) []attrSpan {
	n := len(raw)

	i := 1 // past '<'
	if i < n && raw[i] == '/' {
		i++
	}
	for i < n && !isTagSpace(raw[i]) && raw[i] != '>' && raw[i] != '/' {
		i++ // tag name
	}

	var out []attrSpan
	for i < n {
		for i < n && (isTagSpace(raw[i]) || raw[i] == '/') {
			i++
		}
		if i >= n || raw[i] == '>' {
			return out
		}

		nameStart := i
		for i < n && !isTagSpace(raw[i]) && raw[i] != '=' && raw[i] != '>' && raw[i] != '/' {
			i++
		}
		a := attrSpan{name: strings.ToLower(string(raw[nameStart:i]))}

		for i < n && isTagSpace(raw[i]) {
			i++
		}
		if i >= n || raw[i] != '=' {
			out = append(out, a) // bare attribute; whatever follows is the next one
			continue
		}
		i++ // '='
		for i < n && isTagSpace(raw[i]) {
			i++
		}
		if i >= n {
			return out // truncated tag
		}

		a.valued = true
		if c := raw[i]; c == '"' || c == '\'' {
			a.quote = c
			i++
			a.start = i
			for i < n && raw[i] != c {
				i++
			}
			a.end = i
			if i < n {
				i++ // closing quote
			}
		} else {
			a.start = i
			for i < n && !isTagSpace(raw[i]) && raw[i] != '>' {
				i++
			}
			a.end = i
		}
		out = append(out, a)
	}
	return out
}

// attrAt returns the attribute whose value covers offset i, if any.
func attrAt(attrs []attrSpan, i int) (attrSpan, bool) {
	for _, a := range attrs {
		if a.valued && i >= a.start && i < a.end {
			return a, true
		}
	}
	return attrSpan{}, false
}

// isTagSpace reports whether c separates tokens inside a tag, using HTML's
// definition of whitespace rather than Unicode's.
func isTagSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}
