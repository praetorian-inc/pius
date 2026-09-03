# AGENTS.md

This is the canonical agent instruction file for this repository. It provides guidance to any coding agent working with this code — Claude Code, Codex, and Gemini all load it. `CLAUDE.md` is a one-line pointer to this file, and `.gemini/settings.json` names it for Gemini.

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
- `Category()` - "cidr", "domain", or "ip"
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
- `FindingIPWhoisResult` - structured RDAP/TCP-43 allocation data for an IP or CIDR

### Plugin Patterns

**RDAP plugins** (`pkg/plugins/cidrs/rdap.go`): Use `httpDoer` interface for testability. Phase 2 plugins that query RIR RDAP APIs.

**RPSL plugins** (`pkg/plugins/cidrs/rpsl_plugin.go`): Download and parse RIR RPSL databases. Use the cache system (`pkg/cache/`) with 24-hour TTL.

**Domain plugins** (`pkg/plugins/domains/`): Independent (Phase 0) plugins querying various sources (crt.sh, passive DNS, etc.).

**IP plugins** (`pkg/plugins/ips/`): Independent (Phase 0) plugins enriching IP and CIDR inputs from public registration services. IP WHOIS uses RDAP first and falls back to TCP-43 using the original IP when RDAP lacks a useful direct identity.

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

For name-resolution plugins where mapping may be ambiguous, attach evidence with `plugins.AddConfidence(finding, score, justification)` — **one call per independently observed signal**, never one call carrying a pre-summed score. The evidence list is what Guard surfaces to a human, so a single opaque entry throws away exactly the information it exists to carry.

**What counts as a separate entry.** The test is whether the signals are independent evidence *of ownership*, not whether they are countable occurrences. `github-org` decomposes into four entries because a blog-domain match, a name-similarity match, a login-token match and repo activity can each be right while the others are wrong. Repeats of one observation do not: `censys-org` scores crossing its 5-host threshold as a single `ConfidenceHigh` entry, and `builtwith` emits one entry listing every matching analytics identifier, because a certificate seen on more hosts and a second tracker on the same marketing stack are more of the same sighting rather than corroboration from a new direction. Watch the arithmetic when deciding — additive entries reach the 100 cap fast (two BuiltWith identifiers would have summed to 120), and capping to full certainty on a repeated signal is worse than one honest entry.

- Confidence scores are integers from 0 to 100. `plugins.AddConfidence` clamps each entry to that range, and `plugins.TotalConfidence(f)` clamps their sum to the same range. **No entries means 0**, not 100 — absence of evidence is not confidence.
- `plugins.NeedsReview(f)` is derived, never stored: `len(f.Confidences) == 0 || TotalConfidence(f) < ConfidenceHigh`. It reads off the total, so an unscored finding needs review just like an explicitly-zero one. **It therefore cannot distinguish "never assessed" from "assessed and found wanting"** — anything that must test `len(f.Confidences)` directly. The Guard adapter does, because only an unscored finding may fall back to a downstream default. So does terminal output in `run.go`, which annotates only scored findings: most output comes from plugins that never score, and labelling those `needs-review [confidence:0]` would report an assessment that never happened.
- Confidence never lives in `Finding.Data`. `Data` is source-specific metadata only.
- Entries are summed as integers, so threshold comparisons are exact; `30 + 35` always lands on `ConfidenceHigh` (`65`).

### Reverse-WHOIS Corroborate-After-Retrieve

The reverse-WHOIS domain plugins (`viewdns-reverse-whois`, `whoxy-reverse-whois`, and `whoisfreaks-reverse-whois`) only retrieve candidates. They never perform inline WHOIS lookups. Every emitted domain receives one 50-point baseline entry for the reverse-WHOIS API result and carries its typed pivots in `Data["whois_parameters"]` as `{field, value}` objects. Canonical fields are `company`, `name`, and `email`. Organization names are queried against both the company and registrant-name/owner indexes where the provider distinguishes them, and legal-suffix punctuation aliases (`L.P.` / `LP`) are issued as additional exact queries.

`domainFindings` in `pkg/plugins/domains/domain_helpers.go` owns normalization, plausibility filtering, deduplication, and baseline scoring. When Whoxy returns one normalized domain for multiple queries, the finding keeps the union of those parameters in deterministic first-seen order but still receives only one baseline confidence entry. Empty and privacy/redaction values are never serialized as provenance.

Guard stores this provenance on the candidate asset. Its asynchronous `whois` capability later retrieves the domain's live record, compares only like-typed origin/live values, and adds at most one corroboration bonus. Pius therefore must not add a corroboration bonus or pass reverse-WHOIS provenance into a WHOIS lookup.

WHOIS referral servers are read from untrusted WHOIS text, so `tcp43RawDial` dials through an SSRF-safe `net.Dialer.Control` guard (`netutil.SSRFSafeControl`) that rejects loopback/link-local/private/CGNAT targets post-DNS-resolution. Responses are byte-capped at `maxResponseBytes` (1 MiB) and the chain is hop-capped at `maxReferrals` (5).

## Adding a New Plugin

1. Create file in `pkg/plugins/cidrs/` or `pkg/plugins/domains/`
2. Implement the `Plugin` interface
3. Register via `init()` with `plugins.Register()`
4. For HTTP operations, use `httpDoer` interface pattern for testability
5. Write tests using `httptest.Server` for mocking
