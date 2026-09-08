package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sqlApp stands in for a target with a mix of routes: one genuinely injectable,
// several that must NOT be reported. The whole point of the differential is
// telling them apart, so the safe routes are as important as the bug.
func sqlApp(t *testing.T) *httptest.Server {
	t.Helper()

	const mysqlErr = "You have an error in your SQL syntax; check the manual near"

	mux := http.NewServeMux()

	// Vulnerable: the value is concatenated straight into a quoted string, so an
	// odd quote breaks the query and a balanced one does not.
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Count(id, "'")%2 == 1 {
			fmt.Fprintf(w, "<html><body>%s '%s' at line 1</body></html>", mysqlErr, id)
			return
		}
		fmt.Fprintf(w, "<html><body><p>Item %s</p></body></html>", id)
	})

	// Same bug, but the error leaks as JSON. The check must not require HTML.
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "application/json")
		if strings.Count(id, "'")%2 == 1 {
			fmt.Fprintf(w, `{"error":%q}`, mysqlErr+" '"+id+"'")
			return
		}
		fmt.Fprintf(w, `{"id":%q}`, id)
	})

	// Escaped: the value is neutralised before it reaches SQL, so no quote count
	// ever produces an error. Must stay silent.
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		id := strings.ReplaceAll(r.URL.Query().Get("id"), "'", "''")
		fmt.Fprintf(w, "<html><body><p>Item %s</p></body></html>", id)
	})

	// Always errors, regardless of input. A naive grep reports this; the
	// differential must not, because a balanced quote errors here too.
	mux.HandleFunc("/broken", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>%s (unrelated)</body></html>", mysqlErr)
	})

	// Contains the error text as static content — a docs page, say. No input
	// reaches any query. Must stay silent.
	mux.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body><h1>Common errors</h1><p>%s ...</p></body></html>`, mysqlErr)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestSQLErrorDetection(t *testing.T) {
	srv := sqlApp(t)
	client := srv.Client()

	cases := []struct {
		name     string
		path     string
		wantFind bool
	}{
		{"injectable html", "/item", true},
		{"injectable json", "/api", true},
		{"escaped", "/safe", false},
		{"always errors", "/broken", false},
		{"error text is static content", "/docs", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SQLError{}.Run(context.Background(), client, Target{
				URL:    srv.URL + tc.path,
				Method: "GET",
				Field:  "id",
			})
			if err != nil {
				t.Fatalf("Run errored: %v", err)
			}

			switch {
			case tc.wantFind && len(got) == 0:
				t.Error("expected a finding, got none: the differential missed a real injection")
			case !tc.wantFind && len(got) != 0:
				t.Errorf("expected no finding, got %d: %s", len(got), got[0].Detail)
			}

			if tc.wantFind && len(got) == 1 {
				f := got[0]
				if f.Check != "sql-error" {
					t.Errorf("check = %q, want sql-error", f.Check)
				}
				if f.Confidence != "confirmed" {
					t.Errorf("confidence = %q, want confirmed", f.Confidence)
				}
				if f.Param != "id" {
					t.Errorf("param = %q, want id", f.Param)
				}
				if f.Evidence == "" {
					t.Error("evidence is empty; a finding should quote the error it saw")
				}
				t.Logf("%s -> payload %q, evidence: %s", tc.path, f.Payload, f.Evidence)
			}
		})
	}
}

// TestSQLErrorUnreachableIsAnError mirrors the XSS check's contract: a dead
// endpoint is "could not tell", not "clean", so Run returns an error rather
// than a silent nil — which is what lets the engine record it as a CheckError.
func TestSQLErrorUnreachableIsAnError(t *testing.T) {
	srv := sqlApp(t)
	url := srv.URL
	srv.Close() // now every request is refused

	_, err := SQLError{}.Run(context.Background(), http.DefaultClient, Target{
		URL:    url + "/item",
		Method: "GET",
		Field:  "id",
	})
	if err == nil {
		t.Fatal("expected an error from an unreachable host, got nil")
	}
}
