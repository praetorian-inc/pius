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

**RPSL plugins** (`pkg/plugins/cidrs/rpsl.go`): Download and parse RIR RPSL databases via the cache system (`pkg/cache/`, 24-hour TTL). One `RPSLPlugin` type serves every RPSL registry; per-registry differences live entirely in an `rpslConfig`, built by a `<registry>Config()` helper that both `init()` and the exported constructor read so the registered plugin and an injected one cannot drift apart.

`RPSLPlugin` handles two record kinds from the same parse:

- **`inetnum:`** carries a start-end range, expanded to one finding per covering IPv4 CIDR by `cidr.ConvertIPv4RangeToCIDR`.
- **`inet6num:`** carries a prefix directly, so the prefix **is** the finding value — emitted exactly as the registry published it. `netip.ParsePrefix` is a validity gate only; its parsed value is discarded, and a prefix it rejects is skipped rather than aborting the file. There is deliberately no IPv6 range-to-CIDR converter to route through.

Both kinds share one finding builder and one justification renderer, so `Data` keys (`handle`, `org`, `registry`, `netname` — always set, empty string included) and the `confRPSLHandleInetnum` score cannot diverge between them. The justification says `range` for an inetnum and `prefix` for an inet6num; only the range form appends the `; the range contains CIDR %q` tail, because an inet6num record has no range and claiming one would be false.

Registries differ in how they ship v6, which `rpslConfig.cacheURL6` encodes: AFRINIC's combined dump already contains its inet6num records (`cacheURL6` empty, one download), while APNIC splits them into a second file. That **secondary fetch is best-effort** — losing it costs IPv6 recall and logs a warning, but must not discard the IPv4 records already in hand. The **primary fetch is not**: its failure returns an error, because an empty result would otherwise read as "this org owns no space in this registry".

`Run` guards a nil cache before any cache dereference. The `Accepts()`-based self-disable is not sufficient on its own: an embedder whose runner interface exposes only `Run` never calls `Accepts()`, and a cache that failed to construct would nil-dereference inside `GetOrDownload`.

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

`cache.New()` uses the shared package-level `downloadClient`. `cache.NewWithHTTPClient(hc)` takes an embedder's own client instead; **a nil `hc` is valid** and falls back to that same shared client. The fallback is resolved lazily, at download time rather than at construction, so it stays a live reference to `downloadClient` rather than a snapshot of it — a test that swaps the package client's transport still affects a cache built before the swap. The cache directory needs no parameter: it derives from `os.UserHomeDir()`, so `t.Setenv("HOME", t.TempDir())` is already the directory seam.

### Dependency Injection Seams

Embedders (notably the Guard capability adapters) construct plugins directly rather than through the registry, so each CIDR plugin exposes a constructor taking the transport it should use. `init()` registration routes through the same constructor, which is what keeps the two paths from drifting.

- `NewReverseRIRPlugin(*client.Client)`, `NewARINPlugin`, `NewRIPEPlugin`, `NewLACNICPlugin` — take a `*client.Client`; a nil argument falls back to a fresh `client.New()` via `doerOrDefault`.
- `NewAPNICPlugin(*http.Client)`, `NewAFRINICPlugin(*http.Client)` — take a raw `*http.Client` because their dependency is the cache, not the retrying API client, and return `(*RPSLPlugin, error)`: a cache that cannot be created is reported rather than swallowed into a plugin that silently self-disables.

When adding a plugin with an outbound dependency, expose the seam the same way — constructor-injected, nil-tolerant, and read by `init()` — rather than reaching for a package-level singleton at call time.

### Confidence Scoring

For name-resolution plugins where mapping may be ambiguous, attach evidence with `plugins.AddConfidence(finding, score, justification)` — **one call per independently observed signal**, never one call carrying a pre-summed score. The evidence list is what Guard surfaces to a human, so a single opaque entry throws away exactly the information it exists to carry.

**What counts as a separate entry.** The test is whether the signals are independent evidence *of ownership*, not whether they are countable occurrences. `github-org` decomposes into four entries because a blog-domain match, a name-similarity match, a login-token match and repo activity can each be right while the others are wrong. Repeats of one observation do not: `censys-org` scores crossing its 5-host threshold as a single `ConfidenceHigh` entry, and `builtwith` emits one entry listing every matching analytics identifier, because a certificate seen on more hosts and a second tracker on the same marketing stack are more of the same sighting rather than corroboration from a new direction. Watch the arithmetic when deciding — additive entries reach the 100 cap fast (two BuiltWith identifiers would have summed to 120), and capping to full certainty on a repeated signal is worse than one honest entry.

- Confidence scores are integers from 0 to 100. `plugins.AddConfidence` clamps each entry to that range, and `plugins.TotalConfidence(f)` clamps their sum to the same range. **No entries means 0**, not 100 — absence of evidence is not confidence.
- `plugins.NeedsReview(f)` is derived, never stored: `len(f.Confidences) == 0 || TotalConfidence(f) < ConfidenceHigh`. It reads off the total, so an unscored finding needs review just like an explicitly-zero one. **It therefore cannot distinguish "never assessed" from "assessed and found wanting"** — anything that must test `len(f.Confidences)` directly. The Guard adapter does, because only an unscored finding may fall back to a downstream default. So does terminal output in `run.go`, which annotates only scored findings: most output comes from plugins that never score, and labelling those `needs-review [confidence:0]` would report an assessment that never happened.
- Confidence never lives in `Finding.Data`. `Data` is source-specific metadata only.
- Entries are summed as integers, so threshold comparisons are exact; `30 + 35` always lands on `ConfidenceHigh` (`65`).

### Reverse-WHOIS Corroborate-After-Retrieve

The reverse-whois domain plugins (`viewdns-reverse-whois` over ViewDNS, `whoxy-reverse-whois` over Whoxy) do **not** trust the third-party API's match list at face value — but they no longer verify inline either. Each plugin emits its candidate domains with the query attached as `Data["pivot_org"]` (`domainFindings` in `domain_helpers.go`); corroboration happens later, when the `whois` capability runs over each discovered domain and compares that domain's own registrant against the pivot.

- **`whois.Corroborate(pivotOrg, resolvedOrg)`** (`pkg/whois/normalize.go`) returns one of `"match"`, `"mismatch"`, or `"unverifiable"`, which `whois.go` stamps onto the finding as `whoisFindingData.Corroboration`. An empty pivot returns `""` — nothing was asked, so nothing is claimed. A privacy-redacted or absent registrant is `"unverifiable"`, never `"mismatch"`: absence of evidence is not disagreement.
- **The metric is Jaccard, not containment (ENG-5172).** `OrgSimilarity` strips legal suffixes (`data.LegalSuffixes`, so "Acme Inc." and "Acme" compare equal) and then scores `strutil.JaccardTokenSets` — shared distinct tokens ÷ **union**, so *both* sides' distinguishing tokens count against the score. This is the load-bearing correction: under the previous containment metric (`strutil.TokenSimilarity`, which divides by the **shorter** set) a single-token pivot org scored a full `1.0` against any registrant that merely *contained* it, so `Acme` "matched" `Acme Enterprises LLC`. Under Jaccard that is `1/2 = 0.5` → `unverifiable`. Genuine equality after suffix stripping (`Acme` vs `Acme Corp` → `{acme}` vs `{acme}`) still scores `1.0` and still matches.
- **Containment is under-specification, not disagreement.** Because Jaccard divides by the union, a short pivot fully contained in a longer registrant sinks on length asymmetry alone — `Walmart` vs `{walmart, global, enterprises, holdings}` is `1/4 = 0.25`, under the mismatch floor — so a bare threshold would report a plausible subsidiary as a **contradiction**, a worse verdict than an unresolved lookup. `strutil.TokenSetContained` gates the mismatch arm: containment in **either** direction (the pivot may be the longer name) falls through to `"unverifiable"`. Reporting `"mismatch"` requires that each side contribute a token the other lacks.
- **Thresholds are 0.60 (match) and 0.30 (mismatch)**, with the mismatch test strictly-less-than. A pivot or registrant that reduces to zero tokens after suffix stripping (an all-suffix org like `"Co., Ltd."`) is `"unverifiable"` — similarity is undefined, not zero.
- **`github_org`'s name-similarity signal deliberately keeps containment.** It calls `strutil.TokenSimilarity` and uses the result as a **weight** (`0.25 * similarity`) on a weak hint, not as a threshold gate, so a display name containing the target org name is the signal it wants to reward at full weight. The two callers score differently on purpose; the reason is recorded at the call site in `github_org.go`.
- **Untrusted-referral hardening:** WHOIS referral servers are read from untrusted WHOIS text, so `tcp43RawDial` dials through an SSRF-safe `net.Dialer.Control` guard (`netutil.SSRFSafeControl`) that rejects loopback/link-local/private/CGNAT targets post-DNS-resolution. Responses are byte-capped at `maxResponseBytes` (1 MiB) and the chain is hop-capped at `maxReferrals` (5).

## Adding a New Plugin

1. Create file in `pkg/plugins/cidrs/` or `pkg/plugins/domains/`
2. Implement the `Plugin` interface
3. Register via `init()` with `plugins.Register()`
4. For HTTP operations, use `httpDoer` interface pattern for testability
5. Write tests using `httptest.Server` for mocking
