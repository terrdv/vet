# Vet

**A vulnerability scanner for the app running on your localhost.**

Vet crawls your dev server, finds every form field it can reach, and attacks each one. It
reports proven vulnerabilities.

**Target** a single endpoint's fields, or **crawl** the whole domain. Both run from the CLI.

---

## How it works

### The crawler

The crawler follows links from a seed URL until it has seen every in-scope page,
collecting the form fields on each.

`--sequential` selects the single-threaded one.

<table>
<tr>
<td width="50%" align="center"><b>Single-threaded</b></td>
<td width="50%" align="center"><b>Concurrent</b></td>
</tr>
<tr>
<td><img src="docs/images/crawl-sequential.svg" alt="Single-threaded crawl" width="100%"></td>
<td><img src="docs/images/crawl-concurrent.svg" alt="Concurrent crawl" width="100%"></td>
</tr>
</table>

With one goroutine, an empty queue indicates the crawl is over. With N workers an empty queue is 
not sufficient proof that the crawl is over so termination is tracked by a counter of
outstanding URLs. A URL is counted when it's enqueued and decremented only after the links
it discovered are themselves counted, so the count cannot reach zero while the crawl is
still running.

- **Scope enforcement at the frontier** — URLs outside the allowlist are never enqueued.
- **Canonicalization + dedup** — `?id=1` and `?id=2` aren't scanned as separate pages forever; a visited set (guarded for concurrent access) keeps the crawl finite.
- **Form + link discovery** — extracts links to follow and forms/params to test.

The crawler's only job is to *find* injection points; testing them is the detection
engine's job. Keeping them separate is what makes both modes fall out of one codebase.

> Note: crawl mode currently follows server-rendered links and forms. JavaScript-rendered
> single-page apps (which need a headless browser) are a later addition — server-rendered
> targets like DVWA are fully covered.

### The detection engine

The engine runs *alongside* the crawl. The crawler publishes each page's
forms the moment it parses them, the engine turns them into injection points and starts
testing.

- **Dedup at the queue** — the crawler reports one form per field *per page*, so a search
  box in a site-wide header arrives once for every page on the site. The engine keys
  injection points on `method + url + field`, which is the difference between 4 targets
  and 64 on a 16-page app.
- **Fields tested together** — Form extraction flattens a `<form>` into one
  record per field, a page's forms are published as one batch, so regrouping them by `(method, action)` 
  recovers which fields belong to the same submission.
- **One client, one pool** — the crawl and the engine hammer a single host at the same
  time, so they share an HTTP client. Two pools would only compete for ephemeral ports.
- **Serial checks per target, parallel across targets** — parallelism across endpoints
  already keeps the workers busy; stacking a whole suite onto one endpoint at once just
  buries the app.

---

## Usage

**Targeted** — Supply one endpoint and the fields to test.

```bash
vet check --target http://localhost:8080/login --scope localhost:8080 --params username,password
```

**Crawl** — Supply a domain. Vet discovers endpoints and forms across it (respecting
scope) and runs the detection suite on each injection point *as it is found*, so findings
print during the scan rather than at the end.

```bash
vet scan --domain http://localhost:8080 --scope localhost:8080
```

`--workers` sizes the crawl and `--check-workers` the detection suite; peak load on the
target is the sum of the two, so there is no point setting either past what the app can
actually serve at once.

---

## What it checks (WIP)

| Check | Strategy | Notes |
|-------|----------|-------|
| **Reflected XSS** | Probe with a random marker to locate the reflection *and its HTML context*, then send a context-specific payload and re-parse the response. | Confirmed only when the parser agrees the marker came back as a **new element or attribute**. |
| **SQLi (error-based)** | N/A | N/A |
| **SQLi (boolean-based)** | N/A | N/A |
| **SQLi (time-based / blind)** | N/A | N/A |

---

## Project structure

```
vet/
├── cmd/
│   └── vet/          # CLI entrypoint — check + scan subcommands, calls engine
├── docs/images/      # diagrams used by this README
└── internal/
    ├── engine/       # orchestration: run checks against injection points, collect findings
    ├── checks/       # one file per vulnerability class (pluggable Check interface)
    ├── crawler/      # concurrent attack-surface discovery, feeds the engine
    └── finding/      # the finding schema (shared contract for check + scan output)
```

---

