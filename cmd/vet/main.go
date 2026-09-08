// Command vet is the CLI entrypoint for the vet web vulnerability checker.
//
// It exposes two subcommands that share one detection engine:
//
//	vet check --target <url> --scope <host> --params <a,b>   # targeted mode
//	vet scan  --domain <url> --scope <host>                  # crawl mode
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/terrdv/vet/internal/checks"
	"github.com/terrdv/vet/internal/crawler"
	"github.com/terrdv/vet/internal/engine"
	"github.com/terrdv/vet/internal/finding"
)

const usage = `vet - web vulnerability checker

Usage:
  vet <command> [flags]

Commands:
  check   Test a single endpoint's fields (targeted mode)
  scan    Discover and test every endpoint across a domain (crawl mode)

Run "vet <command> -h" for command-specific flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	ctx := context.Background()

	var err error
	switch os.Args[1] {
	case "check":
		err = runCheck(ctx, os.Args[2:])
	case "scan":
		err = runScan(ctx, os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "vet: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "vet:", err)
		os.Exit(1)
	}
}

// runCheck implements targeted mode: test the named params on a single endpoint.
func runCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	target := fs.String("target", "", "endpoint URL to test (required)")
	scope := fs.String("scope", "", "host:port allowed in scope (required)")
	params := fs.String("params", "", "comma-separated fields to test (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" || *scope == "" || *params == "" {
		fs.Usage()
		return fmt.Errorf("check: --target, --scope and --params are required")
	}

	// TODO: build httpx client (scope + rate limit), parse params, run engine.
	return fmt.Errorf("check: not implemented (target=%s scope=%s params=%s)", *target, *scope, *params)
}

// runScan implements crawl mode: discover a domain's surface, then test it.
func runScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	domain := fs.String("domain", "", "domain root URL to crawl (required)")
	scope := fs.String("scope", "", "host:port allowed in scope (required)")
	workers := fs.Int("workers", 8, "number of concurrent crawl workers")
	checkWorkers := fs.Int("check-workers", 4, "number of concurrent detection workers; peak load on the target is --workers plus this")
	sequential := fs.Bool("sequential", false, "use the single-threaded crawler (ignores --workers)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" || *scope == "" {
		fs.Usage()
		return fmt.Errorf("scan: --domain and --scope are required")
	}

	c := crawler.NewCrawl()

	// The engine shares the crawler's client, so the two phases share one
	// connection pool rather than competing for ephemeral ports against the
	// same host while they run side by side.
	eng := engine.New(c.Client(), *checkWorkers, checks.ReflectedXSS{})
	eng.OnFinding(func(f finding.Finding) { fmt.Println(f) })

	// Both must be in place before the crawl starts: the workers park on an
	// empty queue, and the sink is only read from here on.
	eng.Start(ctx)
	c.OnForms(eng.SubmitForms)

	if *sequential {
		c.CrawlSequential(ctx, *domain)
	} else {
		c.Crawl(ctx, *domain, *workers)
	}

	// The crawl is the only producer of targets, so a finished crawl is exactly
	// the moment it is safe to say no more are coming.
	eng.Close()
	eng.Wait()

	// Forms is one row per field per page, so the same form site-wide inflates
	// it; Targets is what the engine actually tested after dedup.
	fmt.Printf("\n%d form field(s) discovered, %d distinct injection point(s) tested, %d finding(s)\n",
		len(c.Forms()), eng.Targets(), len(eng.Findings()))

	// Reported separately and never folded into the finding count: these are
	// injection points the scan could not reach a conclusion on, so the surface
	// actually covered is smaller than the line above implies.
	if errs := eng.Errors(); len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d check(s) could not reach a conclusion:\n", len(errs))
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "  "+e.Error())
		}
	}
	return nil
}
