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

	"github.com/terrdv/vet-mcp/internal/crawler"
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" || *scope == "" {
		fs.Usage()
		return fmt.Errorf("scan: --domain and --scope are required")
	}

	_ = *workers // TODO: concurrency not wired up yet

	c := crawler.NewCrawl()
	c.Crawl(ctx, *domain)

	forms := c.Forms()
	fmt.Printf("discovered %d injection point(s):\n", len(forms))
	for _, f := range forms {
		fmt.Printf("  %-4s %s  field=%s\n", f.Method, f.Action, f.Field)
	}
	return nil
}
