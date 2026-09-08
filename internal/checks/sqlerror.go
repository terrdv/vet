package checks

import (
	"context"
	"regexp"
	"strings"

	"github.com/terrdv/vet/internal/finding"
)

// SQLError detects error-based SQL injection: input that reaches a SQL query
// unescaped, proven by making the query fail to parse.
//
// Like ReflectedXSS, it refuses to conclude from a single response — "the page
// contains a database error" is not evidence, because a page can carry that
// text for reasons that have nothing to do with the field under test. It works
// by difference instead:
//
//  1. Baseline. Submit a benign value and record whether the response already
//     shows a database error. A page that always errors proves nothing.
//  2. Break. Submit the same value with one extra quote, which leaves any SQL
//     string it lands in unterminated. A *new* database error here is the
//     signal — the field's value is being concatenated into a query.
//  3. Confirm. Submit the value with the quote balanced. If the error the break
//     produced now disappears, the quote reached the parser: that is the bug.
//     If it persists, the error was noise (a filter, an always-error route) and
//     the check stays silent rather than guess.
//
// Unlike the XSS check it does not require an HTML response. A database error
// leaks from a JSON API just as readily as from a rendered page, and reading
// that body is exactly what the shared submit helper was reshaped to allow.
//
// The check is error-based only: it sees nothing when the app swallows the
// error. Blind injection — inferred from a boolean difference or a time delay —
// is a separate check.
type SQLError struct{}

// Compile-time proof this satisfies the engine's contract.
var _ Check = SQLError{}

func (SQLError) Name() string { return "sql-error" }

// dbErrors are the fingerprints a database driver leaves in a response when a
// query fails to parse — one or more per engine vet expects to meet on a local
// dev stack. They are matched against the raw body, so an error rendered into
// an HTML page and one returned as JSON are caught the same way.
var dbErrors = []*regexp.Regexp{
	// MySQL / MariaDB
	regexp.MustCompile(`(?i)you have an error in your sql syntax`),
	regexp.MustCompile(`(?i)warning:.*?\bmysqli?(_|\b)`),
	regexp.MustCompile(`(?i)valid mysql result|MySqlException`),
	// PostgreSQL
	regexp.MustCompile(`(?i)unterminated quoted string at or near`),
	regexp.MustCompile(`(?i)pg::(syntax|undefined)|PSQLException|org\.postgresql`),
	// Microsoft SQL Server
	regexp.MustCompile(`(?i)unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)microsoft (odbc|ole db|sql server)|SqlException`),
	// Oracle
	regexp.MustCompile(`ORA-\d{5}`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
	// SQLite
	regexp.MustCompile(`(?i)sqlite3?::|sqlite3\.operationalerror|unrecognized token`),
}

// sqlProbes pair a value that breaks out of a quoted SQL string with the value
// that balances it again. The break has to error and the balance has to not;
// neither half means anything without the other.
//
// Both single- and double-quote styles are tried because which one delimits the
// string is the app's choice, not ours, and a payload in the wrong quote sails
// through a vulnerable query untouched.
var sqlProbes = []struct {
	breaking string
	balanced string
}{
	{breaking: "'", balanced: "''"},
	{breaking: `"`, balanced: `""`},
}

// benign is the value the baseline and every probe are built on. A bare number
// is accepted by the widest range of fields — id lookups, pagination, search —
// without tripping validation that would mask the injection.
const benign = "1"

func (s SQLError) Run(ctx context.Context, client Doer, t Target) ([]finding.Finding, error) {
	base, err := submit(ctx, client, t, benign)
	if err != nil {
		return nil, err // unreachable: no conclusion, which is not "clean"
	}
	// An error already present without any bad input cannot be attributed to a
	// probe, so it is subtracted from every comparison below.
	baseErr := matchDBError(base.body)

	for _, p := range sqlProbes {
		broken, err := submit(ctx, client, t, benign+p.breaking)
		if err != nil {
			return nil, err
		}
		sig := matchDBError(broken.body)
		if sig == "" || sig == baseErr {
			continue // no new error -> this quote style isn't reaching a query
		}

		// The unbalanced quote errored; confirm it was ours by repairing it.
		balanced, err := submit(ctx, client, t, benign+p.balanced)
		if err != nil {
			return nil, err
		}
		if matchDBError(balanced.body) != "" {
			continue // still errors when balanced -> not our quote; do not report
		}

		method := strings.ToUpper(t.Method)
		if method == "" {
			method = "GET"
		}
		return []finding.Finding{{
			Check:      s.Name(),
			Severity:   finding.High,
			Confidence: finding.Confirmed,
			URL:        t.URL,
			Method:     method,
			Param:      t.Field,
			Payload:    benign + p.breaking,
			Evidence:   excerpt(broken.body, sig),
			Detail: "an unbalanced quote produced a database error that the balanced " +
				"quote did not, so this field's value reaches a SQL query unescaped.",
		}}, nil
	}
	return nil, nil
}

// matchDBError returns the first database-error fingerprint found in body, or ""
// if none is present. The returned string is the matched text, so it can be
// handed straight to excerpt to window the evidence around it.
func matchDBError(body []byte) string {
	for _, re := range dbErrors {
		if m := re.Find(body); m != nil {
			return string(m)
		}
	}
	return ""
}
