// Package finding defines the schema every check reports through. It is the
// shared contract between the detection engine and the CLI: checks only ever
// produce Findings, and both `vet check` and `vet scan` only ever print them.
package finding

import "fmt"

// Severity is how much a finding matters if it is real.
type Severity string

const (
	Info   Severity = "info"
	Low    Severity = "low"
	Medium Severity = "medium"
	High   Severity = "high"
)

// Confidence is how sure the check is that the finding *is* real. It is kept
// separate from Severity because the two move independently: a high-severity
// class like XSS is still only worth reporting when the check confirmed it,
// and the CLI needs to be able to say which of the two it is.
type Confidence string

const (
	// Tentative means the check saw a signal it could not verify — worth a
	// human look, not worth acting on unread.
	Tentative Confidence = "tentative"
	// Confirmed means the check proved the effect it was testing for, e.g. it
	// injected markup and read it back parsed as markup.
	Confirmed Confidence = "confirmed"
)

// Finding is one vulnerability, at one injection point, found by one check.
type Finding struct {
	Check      string     // Check.Name of whatever produced this
	Severity   Severity   //
	Confidence Confidence //
	URL        string     // endpoint tested
	Method     string     // HTTP method used to reach it
	Param      string     // the field that carried the payload
	Payload    string     // exactly what was sent, so it can be replayed by hand
	Evidence   string     // the part of the response that proves it
	Detail     string     // one line on why this is a finding
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s %s %s param=%s (%s)\n  payload: %s\n  evidence: %s\n  %s",
		f.Severity, f.Check, f.Method, f.URL, f.Param, f.Confidence, f.Payload, f.Evidence, f.Detail)
}
