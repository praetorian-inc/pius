# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run a single test
go test -v -run TestRegister_PanicsOnDuplicate ./pkg/plugins

# Run tests for a specific package
go test ./pkg/plugins/cidrs

# Build the binary
go build -o pius ./cmd/pius

# Run the CLI
go run ./cmd/pius run --org "Acme Corp" --domain acme.com
go run ./cmd/pius list
```

## Architecture

### Plugin System

Pius uses a self-registering plugin architecture. All plugins implement `pkg/plugins.Plugin` and register themselves via `init()` functions:

```go
func init() {
    plugins.Register("plugin-name", func() plugins.Plugin {
        return &MyPlugin{}
    })
}
```

The registry (`pkg/plugins/registry.go`) stores `PluginFactory` functions, ensuring each caller gets fresh instances.

### Plugin Interface

Every plugin must implement:
- `Name()` - unique identifier
- `Description()` - human-readable description
- `Category()` - "cidr" or "domain"
- `Phase()` - 0 (independent), 1 (discovers handles), or 2 (resolves handles)
- `Mode()` - "passive" (OSINT) or "active" (sends probes)
- `Accepts(Input)` - returns false to self-disable (missing API keys, inputs, etc.)
- `Run(ctx, Input)` - executes discovery, must respect context cancellation

### Two-Phase Pipeline

The runner (`pkg/runner/run.go`) executes plugins in phases:

1. **Phase 1**: Plugins discover RIR org handles (emit `FindingCIDRHandle`)
2. **Enrichment**: Handles are injected into `Input.Meta` (e.g., `arin_handles`, `ripe_handles`)
3. **Phase 2**: Plugins resolve handles to CIDRs using enriched meta
4. **Independent (Phase 0)**: Run concurrently with all phases

### Finding Types

- `FindingCIDRHandle` - internal, filtered from output
- `FindingCIDR` - discovered CIDR block
- `FindingDomain` - discovered domain name
- `FindingPreseed` - discovered organizational seed (company name, email); emitted as `capmodel.Preseed` via `invoke.go`

### Plugin Patterns

**RDAP plugins** (`pkg/plugins/cidrs/rdap.go`): Use `httpDoer` interface for testability. Phase 2 plugins that query RIR RDAP APIs.

**RPSL plugins** (`pkg/plugins/cidrs/rpsl_plugin.go`): Download and parse RIR RPSL databases. Use the cache system (`pkg/cache/`) with 24-hour TTL.

**Domain plugins** (`pkg/plugins/domains/`): Independent (Phase 0) plugins querying various sources (crt.sh, passive DNS, etc.).

**Active plugins**: Set `Mode()` to "active". Run only with `--mode active` or `--mode all`.

### HTTP Client

Use `pkg/client.Client` for HTTP requests. Provides:
- Automatic retries with exponential backoff
- 429/5xx handling
- 10MB response limit
- User-Agent header

### Cache System

`pkg/cache/Cache` manages local file caching for RPSL databases:
- Files stored in `~/.pius/cache/`
- 24-hour TTL, atomic writes
- Falls back to stale cache on download failure

### Confidence Scoring

For name-resolution plugins where mapping may be ambiguous, use `plugins.SetConfidence(finding, score)`. Findings between 0.35-0.65 get `needs_review` flag.

### Reverse-WHOIS Verify-After-Retrieve

The reverse-whois domain plugins (`reverse-whois` over ViewDNS, `whoxy-reverse-whois` over Whoxy) do **not** trust the third-party API's match list at face value. Candidate domains returned by the API are corroborated against the query org before scoring, in `reverse_whois_verify.go`:

- **`registrantResolver`** resolves each candidate's registrant org — **RDAP primary** (`github.com/openrdap/rdap`, pooled per-worker `*rdap.Client` via a pre-filled fixed-size channel that survives GC — a shared client is unsafe for concurrent `Do`, and `sync.Pool` evicted warm clients mid-pass (ENG-5376)), **WHOIS fallback** (`whoisclient.go`) when RDAP yields nothing. `registrantOrgFromDomain` reads the registrant entity's jCard `org` (falling back to `fn`).
- **`verifyCandidates`** compares the resolved registrant org against the query org (normalized similarity) and assigns per-candidate confidence rather than one flat score:
  - corroborated (similarity ≥ 0.60) → `confReverseWhoisCorroborated` = 0.60
  - masked / unresolved registrant → `confReverseWhoisUnverified` = 0.50 (`needs_review`)
  - mismatch → `confReverseWhoisMismatch` = 0.40 (`needs_review`)
  - **De-rank, never drop:** every candidate is still emitted; scores stay within the `needs_review` band `[0.35, 0.65)` so nothing is silently removed from the graph.
- Work is bounded: `maxReverseWhoisCandidates` (500) cap, `reverseWhoisWorkers` (6) concurrency, per-lookup `reverseWhoisLookupTimeout` (10s), and a pass-wide `reverseWhoisTotalBudget` (90s) derived from the caller `ctx`. Budget expiry is recall-safe (emit what resolved); a caller-cancelled `ctx` aborts with the error.
- **Incomplete lookups are observable, not silent:** a WHOIS leg that could not finish its referral chain — deadline expiry mid-chain, a referral hop whose transport failed, or the hop budget exhausted with a referral still pending — still returns its salvaged post-referral record with a `nil` error (recall unchanged), but now **reports why it is partial**: `whoisQuery` returns a `whoisIncompleteness` reason that `viaWHOIS` stamps onto `registrantResult.Incomplete`. The reason is classified on the failure's **cause, not on where it was noticed** — a hop error that unwraps to `context.DeadlineExceeded`/`context.Canceled` is `deadline_expired`, anything else is `referral_failed`. That distinction is load-bearing: `readAllWithContext` and `dialer.DialContext` both surface a budget expiry as an ordinary transport error, so classifying by call site would report every timeout as a transport failure and invert the operator's remedy (pace the WHOIS leg vs. resize the budget). The flag is **purely observational and never enters scoring** — an unresolved registrant scores `confReverseWhoisUnverified` (0.50) whether the lookup was truncated or the domain genuinely has no registrant org on record, so the two states are distinguishable to an operator without being ranked differently. `verifyCandidates` tallies the per-candidate reasons index-disjointly (no mutex, no atomic — the pass stays lock-free, with `g.Wait()` as the only happens-before barrier) and emits **one** record per pass: `slog.Warn` with the per-reason breakdown when the pass was degraded, `slog.Info` when it was clean. Recovered worker panics get their own bucket, never conflated with a WHOIS incompleteness. A pass counts as degraded when any reason bucket is non-zero **or** when `attempted < candidates`, so the `maxReverseWhoisCandidates` cap silently truncating verification is itself a reported degradation rather than a "pass complete". Field names are deliberate: `attempted` counts candidates a lookup was *started* for (not resolved — `candidates=14 attempted=14 lookup_failed=14` is a coherent record), and the budget denominator is `budget_ms` so a sub-second budget cannot floor to a misconfigured-looking `0` (ENG-5405).
- **Untrusted-referral hardening:** WHOIS referral servers are read from untrusted WHOIS text, so `whoisRaw` dials through an SSRF-safe `net.Dialer.Control` guard (`ssrfSafeControl`) that rejects loopback/link-local/private/CGNAT targets post-DNS-resolution, and responses are byte-capped at `maxWhoisResponseBytes` (1 MiB).

## Adding a New Plugin

1. Create file in `pkg/plugins/cidrs/` or `pkg/plugins/domains/`
2. Implement the `Plugin` interface
3. Register via `init()` with `plugins.Register()`
4. For HTTP operations, use `httpDoer` interface pattern for testability
5. Write tests using `httptest.Server` for mocking
