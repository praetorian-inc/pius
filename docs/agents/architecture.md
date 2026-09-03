# Pius architecture reference

Relocated from `AGENTS.md`. This is background the code answers on its own; the
doc comments in `pkg/plugins/plugin.go` and the runner in `pkg/runner/run.go`
are the primary sources, and they win whenever this file disagrees with them.

## Plugin System

Pius uses a self-registering plugin architecture. All plugins implement the
`Plugin` interface in `pkg/plugins/plugin.go` and register themselves via
`init()` functions:

```go
func init() {
    plugins.Register("plugin-name", func() plugins.Plugin {
        return &MyPlugin{}
    })
}
```

The registry (`pkg/plugins/registry.go`) stores `PluginFactory` functions,
ensuring each caller gets fresh instances. Registration only happens for
packages that are blank-imported in `pkg/plugins/all/all.go`; today those are
`pkg/plugins/cidrs/`, `pkg/plugins/domains/`, and `pkg/plugins/ips/`.

## Plugin Interface

Every plugin must implement:

- `Name()` - unique identifier
- `Description()` - human-readable description
- `Category()` - "cidr", "domain", or "ip"
- `Phase()` - 0 (independent), 1 (discovers handles), 2 (resolves handles),
  or 3 (consumes discovered CIDRs and domains)
- `Mode()` - "passive" (OSINT) or "active" (sends probes)
- `Accepts(Input)` - returns false to self-disable (missing API keys, inputs, etc.)
- `Run(ctx, Input)` - executes discovery, must respect context cancellation;
  `(nil, nil)` means "nothing to contribute" and is not an error

The interface is composed of `Descriptor`, `Classifier`, and `Runner` in
`pkg/plugins/plugin.go`. Its `Phase()` comment still lists only 0–2; the runner
below is authoritative.

## Pipeline Phases

The runner (`pkg/runner/run.go`, `runPipeline` and `partitionByPhase`) executes
plugins in phases:

1. **Phase 1**: Plugins discover RIR org handles (emit `FindingCIDRHandle`)
2. **Enrichment**: Handles are injected into `Input.Meta` (e.g., `arin_handles`,
   `ripe_handles`)
3. **Phase 2**: Plugins resolve handles to CIDRs using enriched meta
4. **Enrichment**: Discovered CIDRs are injected as `Meta["cidrs"]` and
   discovered domains as `Meta["discovered_domains"]`. A domain that carries
   confidence entries totalling below `ConfidenceLow` is withheld from the
   domain list; unscored domains pass through.
5. **Phase 3**: Plugins consume those lists (`reverse-ip` reads `cidrs`;
   `dns-permutation` reads `discovered_domains`; `builtwith` is also Phase 3).
6. **Independent (Phase 0)**: Run concurrently with all phases

## Finding Types

Defined in `pkg/plugins/plugin.go`:

- `FindingCIDRHandle` - internal, filtered from output
- `FindingCIDR` - discovered CIDR block
- `FindingDomain` - discovered domain name
- `FindingPreseed` - discovered organizational seed (company name, email,
  person name); emitted by the `gleif`, `whois`, `censys-org`, and `ip-whois`
  plugins. The former conversion layer that mapped it to a Guard model type
  was removed from this repo; Guard now consumes the finding downstream.
- `FindingIPWhoisResult` - structured RDAP/TCP-43 allocation data for an IP or
  CIDR

## Plugin Patterns

**RDAP plugins** (`pkg/plugins/cidrs/rdap.go`): Phase 2 plugins that query RIR
RDAP APIs. They hold a `*client.Client`; tests inject
`client.NewWithHTTPClient(srv.Client())` against an `httptest.Server`
(`pkg/plugins/cidrs/rdap_run_test.go`).

**RPSL plugins** (`pkg/plugins/cidrs/rpsl.go`): Download and parse RIR RPSL
databases through the cache in `pkg/cache/cache.go` (24-hour `DefaultTTL`).
A cache-init failure is how the standalone plugin self-disables.

**Domain plugins** (`pkg/plugins/domains/`): Mostly independent (Phase 0)
plugins querying various sources (crt.sh, passive DNS, etc.). Three are
Phase 3 consumers: `builtwith`, `dns-permutation`, `reverse-ip`.

**IP plugins** (`pkg/plugins/ips/`): Independent (Phase 0) plugins enriching IP
and CIDR inputs from public registration services. IP WHOIS
(`pkg/plugins/ips/whois.go`, backed by `LookupNetwork` in
`pkg/whois/network.go`) queries RDAP first and runs the TCP-43 leg only when
the RDAP result has no preferred direct contact.

**Active plugins**: Set `Mode()` to "active". Run only with `--mode active` or
`--mode all`; the default mode is passive.

## HTTP Client

Use the client in `pkg/client/client.go` for HTTP requests. Provides:

- Automatic retries with exponential backoff on 429/5xx
- 10 MB response limit (`maxResponseSize`)
- User-Agent header
- `NewNoRetry()` for tests, and `NewWithHTTPClient()` to inject a transport

## Cache System

`cache.Cache` in `pkg/cache/cache.go` manages local file caching for RPSL
databases:

- Files stored under the home directory in the `CacheDirName` folder
  (`.pius` then `cache`)
- 24-hour TTL (`DefaultTTL`), atomic writes via temp file and rename
- Falls back to stale cache on download failure

`pkg/cache/apicache.go` provides `APICache`, a per-plugin API response cache
sharing the same directory and TTL.
