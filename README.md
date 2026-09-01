# Vet

**A web vulnerability checker whole domain.**

Vet tests web inputs for injection flaws like XSS and SQLi and for missing protections
like rate limiting. **Target** to check a single endpoint's fields, or
**crawl** to test every endpoint across a domain. Both are
available through a **CLI** and through an **MCP server**.

---

**Targeted** — Supply one endpoint and the fields to test.

```bash
vet check --target http://localhost:8080/login --scope localhost:8080 --params username,password
```

**Crawl** — Supply a domain. Vet discovers endpoints and forms across it (respecting
scope), then runs the full detection suite on every injection point it finds. Longer
running; produces a report over the whole surface.

```bash
vet scan --domain http://localhost:8080 --scope localhost:8080
```

---

## What it checks (WIP)

| Check | Strategy | Notes |
|-------|----------|-------|
| **Reflected XSS** | N/A | N/A |
| **SQLi (error-based)** | N/A | N/A |
| **SQLi (boolean-based)** | N/A | N/A |
| **SQLi (time-based / blind)** | N/A | N/A |
| **Missing rate limiting** | N/A | N/A |


### How detection actually works

N/A for now

---

## The crawler

Crawl mode is a concurrent worker pool that discovers a domain's attack surface:

- **Scope enforcement at the frontier** — URLs outside the allowlist are never enqueued.
- **Canonicalization + dedup** — `?id=1` and `?id=2` aren't scanned as separate pages forever; a visited set (guarded for concurrent access) keeps the crawl finite.
- **Form + link discovery** — extracts links to follow and forms/params to test.
- **Politeness** — per-host rate limiting and backoff so a scan doesn't look like an attack.
- **Clean termination** — the crawl ends when there's no work in flight *and* no worker about to produce more (workers are both consumers and producers of URLs — getting this right is the crux).

The crawler's only job is to *find* injection points; testing them is the detection
engine's job. Keeping them separate is what makes both modes fall out of one codebase.

> Note: crawl mode currently follows server-rendered links and forms. JavaScript-rendered
> single-page apps (which need a headless browser) are a later addition — server-rendered
> targets like DVWA are fully covered.

---

## Project structure

```
vet-mcp/
├── cmd/
│   ├── vet/          # CLI entrypoint — check + scan subcommands, calls engine
│   └── vet-mcp/      # MCP server entrypoint — tool handlers, calls engine
└── internal/
    ├── engine/       # orchestration: run checks against injection points, collect findings
    ├── checks/       # one file per vulnerability class (pluggable Check interface)
    ├── crawler/      # concurrent attack-surface discovery, feeds the engine
    ├── httpx/        # HTTP client wrapper: rate limiting + scope enforcement
    └── finding/      # the finding schema (shared contract for CLI + MCP output)
```

---

