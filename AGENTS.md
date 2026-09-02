# AGENTS.md

This is the canonical agent instruction file for this repository. Any coding
agent working here loads it. `CLAUDE.md` is a one-line pointer to this file, and
`.gemini/settings.json` lists it as a context file. Architecture reference that
the code itself answers has moved to `docs/agents/architecture.md`.

## Build and Test Commands

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...
make test                     # the same, with -race

# Run a single test
go test -v -run TestRegister_PanicsOnDuplicate ./pkg/plugins

# Run tests for a specific package
go test ./pkg/plugins/cidrs

# Build the binary
go build -o pius ./cmd/pius
make build                    # version-stamped, into the build dir

# Run the CLI
go run ./cmd/pius run --org "Acme Corp" --domain acme.com
go run ./cmd/pius list
```

CI (`.github/workflows/ci.yml`) delegates to a shared reusable Go workflow.
On pull requests it runs only when Go sources, `go.mod`, `go.sum`, lint config,
or `Makefile` change; pushes to `main` and `workflow_dispatch` have no path filter.
`make lint` runs golangci-lint; the repo carries no lint config file, so defaults apply.

## Architecture

The reference — plugin interface, pipeline phases, finding types, HTTP client,
cache — is `docs/agents/architecture.md`; the doc comments in
`pkg/plugins/plugin.go` are the primary source. Three things the tree does not
surface on its own:

- Plugins self-register in `init()` via `plugins.Register`, but only packages
  blank-imported in `pkg/plugins/all/all.go` are loaded. A plugin in a new
  package is silently absent until it is added there.
- The pipeline has four phases: 0 (independent), 1 (discovers RIR handles),
  2 (resolves handles to CIDRs), 3 (consumes `Meta["cidrs"]` and
  `Meta["discovered_domains"]`), driven by `pkg/runner/run.go`. The `Phase()`
  comment in `pkg/plugins/plugin.go` still lists only 0–2; the runner is
  authoritative.
- `Accepts` returning false is how a plugin self-disables (missing API key,
  missing input). It is not an error, and `Run` returning `(nil, nil)` is not
  one either.

## Confidence Scoring

For name-resolution plugins where mapping may be ambiguous, attach evidence with `plugins.AddConfidence(finding, score, justification)` (`pkg/plugins/confidence.go`) — **one call per independently observed signal**, never one call carrying a pre-summed score. The evidence list is what Guard surfaces to a human, so a single opaque entry throws away exactly the information it exists to carry.

**What counts as a separate entry.** The test is whether the signals are independent evidence *of ownership*, not whether they are countable occurrences. `github-org` decomposes into four entries because a blog-domain match, a name-similarity match, a login-token match and repo activity can each be right while the others are wrong. Repeats of one observation do not: `censys-org` scores crossing its 5-host threshold as a single `ConfidenceHigh` entry, and `builtwith` emits one entry listing every matching analytics identifier, because a certificate seen on more hosts and a second tracker on the same marketing stack are more of the same sighting rather than corroboration from a new direction. Watch the arithmetic when deciding — additive entries reach the 100 cap fast (two BuiltWith identifiers would have summed to 120), and capping to full certainty on a repeated signal is worse than one honest entry.

- Confidence scores are integers from 0 to 100. `plugins.AddConfidence` clamps each entry to that range, and `plugins.TotalConfidence(f)` clamps their sum to the same range. **No entries means 0**, not 100 — absence of evidence is not confidence.
- `plugins.NeedsReview(f)` is derived, never stored: `len(f.Confidences) == 0 || TotalConfidence(f) < ConfidenceHigh`. It reads off the total, so an unscored finding needs review just like an explicitly-zero one. **It therefore cannot distinguish "never assessed" from "assessed and found wanting"** — anything that must test `len(f.Confidences)` directly. Downstream consumers in Guard (outside this repo) do, because only an unscored finding may fall back to a default. So does `pkg/runner/run.go`: terminal output annotates only scored findings, because most output comes from plugins that never score and labelling those `needs-review [confidence:0]` would report an assessment that never happened; and only scored domains below `ConfidenceLow` are withheld from Phase 3 seeding.
- Confidence never lives in `Finding.Data`. `Data` is source-specific metadata only.
- Entries are summed as integers, so threshold comparisons are exact; `30 + 35` always lands on `ConfidenceHigh` (`65`).

## Reverse-WHOIS Corroborate-After-Retrieve

The reverse-WHOIS domain plugins (`viewdns-reverse-whois` and `whoxy-reverse-whois`) only retrieve candidates. They never perform inline WHOIS lookups. Every emitted domain receives one 50-point baseline entry for the reverse-WHOIS API result and carries its typed pivots in `Data["reverse_whois_parameters"]` as `{field, value}` objects. Canonical fields are `company`, `name`, and `email`.

`reverseWhoisFindings` in `pkg/plugins/domains/domain_helpers.go` owns normalization, plausibility filtering, deduplication, and baseline scoring. When Whoxy returns one normalized domain for multiple queries, the finding keeps the union of those parameters in deterministic first-seen order but still receives only one baseline confidence entry. Empty and privacy/redaction values are never serialized as provenance.

Guard stores this provenance on the candidate asset. Its asynchronous `whois` capability later retrieves the domain's live record, compares only like-typed origin/live values, and adds at most one corroboration bonus. Pius therefore must not add a corroboration bonus or pass reverse-WHOIS provenance into a WHOIS lookup.

WHOIS referral servers are read from untrusted WHOIS text, so `tcp43RawDial` in `pkg/whois/tcp43.go` dials through an SSRF-safe `net.Dialer.Control` guard (`netutil.SSRFSafeControl`, `pkg/lib/netutil/ssrf.go`) that rejects loopback/link-local/private/CGNAT targets post-DNS-resolution. Responses are byte-capped at `maxResponseBytes` (1 MiB) and the chain is hop-capped at `maxReferrals` (5).

## Adding a New Plugin

1. Create the file in `pkg/plugins/cidrs/`, `pkg/plugins/domains/`, or
   `pkg/plugins/ips/`. A new package must also be blank-imported in
   `pkg/plugins/all/all.go` or it never registers.
2. Implement the `Plugin` interface from `pkg/plugins/plugin.go` and register
   in `init()` with `plugins.Register`. Duplicate names panic.
3. Use the client in `pkg/client/client.go` for HTTP (retries, size cap,
   User-Agent). In tests, serve fixtures from an `httptest.Server` and inject
   `client.NewWithHTTPClient(srv.Client())`, as `pkg/plugins/cidrs/rdap_run_test.go`
   does; `client.NewNoRetry()` skips backoff delays. `pkg/plugins/domains/wikidata.go`
   shows the alternative `httpDoer` interface seam.
4. If the plugin resolves a name to an identifier, score it under Confidence
   Scoring above.
