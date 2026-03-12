<img width="2976" height="1440" alt="Pius - Organizational asset discovery for domains and IP ranges" src="https://github.com/user-attachments/assets/a8b3ce13-5a7e-46fa-895e-c983182c9468" />

# Pius - Organizational Asset Discovery

> Discover domains and IP ranges owned by any organization using certificate transparency, RIR registries, passive DNS, and more.

[![CI](https://github.com/praetorian-inc/pius/actions/workflows/ci.yaml/badge.svg)](https://github.com/praetorian-inc/pius/actions/workflows/ci.yaml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/praetorian-inc/pius)](go.mod)
[![License](https://img.shields.io/github/license/praetorian-inc/pius)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/praetorian-inc/pius)](https://goreportcard.com/report/github.com/praetorian-inc/pius)
[![GitHub Release](https://img.shields.io/github/v/release/praetorian-inc/pius?include_prereleases&sort=semver)](https://github.com/praetorian-inc/pius/releases)

**Pius** is a Go-based organizational asset discovery tool for security professionals. Given a company name and optional domain or ASN hints, it discovers the full attack surface — domains from certificate transparency and passive DNS, and IP ranges from all five regional Internet registries (RIRs).

Unlike ad-hoc scripts, Pius is built for production use — concurrent plugin execution, multi-tier caching, graceful degradation, and passive-first defaults come out of the box.

## Table of Contents

- [Why Pius](#why-pius)
- [Features](#features)
- [Quick Start](#quick-start)
- [Plugins](#plugins)
  - [Domain Plugins](#domain-plugins)
  - [CIDR Plugins](#cidr-plugins)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Usage](#usage)
  - [Basic Discovery](#basic-discovery)
  - [CIDR Discovery](#cidr-discovery)
  - [Output Formats](#output-formats)
  - [Plugin Selection](#plugin-selection)
- [Configuration](#configuration)
- [FAQ](#faq)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Why Pius

| Feature | Pius | amass | subfinder |
|---------|------|-------|-----------|
| Language | Go | Go | Go |
| Single binary | Yes | Yes | Yes |
| RIR CIDR discovery | Yes (all 5 RIRs) | Partial | No |
| Phase pipeline | Yes (handle → CIDR) | No | No |
| Confidence scoring | Yes | No | No |
| Passive mode default | Yes | Yes | Yes |
| Cache layer | Yes (24h) | No | No |

## Features

| Feature | Description |
|---------|-------------|
| **16 Discovery Plugins** | 9 domain plugins + 7 CIDR plugins covering certificate transparency, passive DNS, WHOIS, RDAP, RPSL, and BGP tables |
| **All 5 RIRs** | ARIN (North America), RIPE (Europe/Middle East), APNIC (Asia-Pacific), AFRINIC (Africa), LACNIC (Latin America) |
| **Three-Phase Pipeline** | Phase 1 discovers RIR org handles; Phase 2 resolves handles to CIDRs; Phase 0 runs independently |
| **Confidence Scoring** | Ambiguous name-to-asset mappings are scored and flagged for review rather than silently dropped |
| **Multi-Tier Cache** | API responses cached 24h as JSON; RPSL databases cached 24h as decompressed local files |
| **Passive Mode Default** | Only OSINT sources queried by default; active plugins (DNS brute-force, zone transfer) opt-in |
| **Flexible Output** | Terminal table, JSON array, and NDJSON (newline-delimited) formats |
| **Single Binary** | Go-based tool compiles to one portable executable with no runtime dependencies |

## Quick Start

### Installation

Requires Go 1.25.0 or later.

```bash
go install github.com/praetorian-inc/pius/cmd/pius@latest
```

Or build from source:

```bash
git clone https://github.com/praetorian-inc/pius.git
cd pius
go build -o pius ./cmd/pius
```

### Basic Usage

```bash
# Discover domains and CIDRs for an organization (passive mode)
pius run --org "Acme Corp"

# Add a domain hint to unlock more plugins
pius run --org "Acme Corp" --domain acme.com

# Include active plugins (DNS brute-force, zone transfer)
pius run --org "Acme Corp" --domain acme.com --mode all
```

### Example Output

```
[domain] acme.com (crt-sh)
[domain] api.acme.com (crt-sh)
[domain] staging.acme.com (passive-dns)
[domain] acme.com (reverse-whois) ⚠ needs-review [confidence:0.42]
[cidr] 203.0.113.0/24 (arin)
[cidr] 198.51.100.0/22 (ripe)
```

### List Available Plugins

```bash
pius list
```

## Plugins

### Domain Plugins

All domain plugins run in Phase 0 (independent, concurrent). They emit discovered domain names.

| Plugin | Data Source | Auth Required | Mode | Notes |
|--------|-------------|---------------|------|-------|
| `crt-sh` | Certificate Transparency logs | None | Passive | Deduplicates wildcard entries |
| `apollo` | Apollo.io enrichment API | `APOLLO_API_KEY` | Passive | Caches results 24h; 0.85 confidence for domain queries |
| `github-org` | GitHub organization search | `GITHUB_TOKEN` (optional) | Passive | Confidence-scored; 0.65 threshold to emit |
| `gleif` | GLEIF LEI corporate registry | None | Passive | Discovers parent/subsidiary domains |
| `passive-dns` | SecurityTrails passive DNS | `SECURITYTRAILS_API_KEY` | Passive | Historical subdomain records |
| `reverse-whois` | ViewDNS reverse WHOIS | `VIEWDNS_API_KEY` | Passive | 0.75 confidence; registrant email matching |
| `censys-org` | Censys Platform API v3 | `CENSYS_API_TOKEN` | **Active** | Searches host/cert data by org; emits domains + CIDRs; requires Starter+ plan; caches 24h |
| `dns-brute` | Local DNS resolver | None | **Active** | 50 concurrent goroutines; embedded wordlist |
| `dns-zone-transfer` | DNS AXFR | None | **Active** | Extracts A, AAAA, CNAME, MX, SRV records |

### CIDR Plugins

CIDR discovery uses a two-phase pipeline: Phase 1 discovers RIR organization handles, Phase 2 resolves those handles to CIDR blocks.

| Plugin | Phase | Data Source | Protocol | RIR Coverage |
|--------|-------|-------------|----------|--------------|
| `asn-bgp` | 0 (independent) | RIPE RIS BGP tables | HTTP REST | Global (announced prefixes) |
| `whois` | 1 (handle discovery) | All 5 RIRs | HTTP REST | ARIN, RIPE, APNIC, AFRINIC, LACNIC |
| `edgar` | 1 (handle discovery) | SEC EDGAR filings | HTTP REST | Global public companies |
| `arin` | 2 (resolution) | ARIN RDAP | RDAP (RFC 7483) | North America |
| `ripe` | 2 (resolution) | RIPE RDAP | RDAP (RFC 7483) | Europe, Middle East, Central Asia |
| `lacnic` | 2 (resolution) | LACNIC RDAP | RDAP (RFC 7483) | Latin America & Caribbean |
| `apnic` | 2 (resolution) | APNIC RPSL database | Cached gzip file | Asia-Pacific |
| `afrinic` | 2 (resolution) | AFRINIC RPSL database | Cached gzip file | Africa |

## How It Works

Pius uses a three-phase concurrent pipeline to discover organizational assets:

```
pius run --org "Acme Corp" --domain acme.com
              │
              ▼
       Plugin Registry
    (init() auto-registration)
              │
   ┌──────────┴─────────────────────────────┐
   │ Phase 0 (concurrent, independent)      │
   │  crt-sh   apollo   github-org   gleif  │
   │  passive-dns   reverse-whois           │
   │  censys-org*   dns-brute*              │
   │  dns-zone-transfer*   asn-bgp          │
   └──────────┬─────────────────────────────┘
              │ Emits domains + CIDRs directly
   ┌──────────┴─────────────────────────────┐
   │ Phase 1 (concurrent)                   │
   │  whois   edgar                         │
   └──────────┬─────────────────────────────┘
              │ Emits RIR org handles
              ▼
       enrichWithHandles()
   Input.Meta["arin_handles"] = "ACME-1"
   Input.Meta["ripe_handles"] = "ORG-ACME-RIPE"
              │
   ┌──────────┴─────────────────────────────┐
   │ Phase 2 (concurrent)                   │
   │  arin   ripe   apnic   afrinic  lacnic │
   └──────────┬─────────────────────────────┘
              │ Emits CIDR blocks
              ▼
       filterOutput()
   (strips internal handle findings)
              │
              ▼
      Domains + CIDRs

* active mode only
```

### Discovery Pipeline

1. **Phase 0 — Independent**: Domain and CIDR plugins with no cross-plugin dependencies run concurrently from the start
2. **Phase 1 — Handle Discovery**: `whois` queries all 5 RIRs for organization handles; `edgar` pattern-matches SEC filings
3. **Handle Enrichment**: Discovered handles are grouped by registry and injected into the pipeline input
4. **Phase 2 — Handle Resolution**: RDAP plugins (ARIN, RIPE, LACNIC) fetch CIDR blocks per handle; RPSL plugins (APNIC, AFRINIC) parse locally-cached registry databases
5. **Output Filtering**: Internal `cidr-handle` findings are removed; only domains and CIDRs reach the user

## Architecture

```
cmd/pius/               CLI entrypoint (Cobra-based)
pkg/
  cache/                Two-tier caching: API responses (JSON) + RPSL databases (gzip)
  cidr/                 IP range → CIDR conversion and /24 subnet splitting
  client/               Shared HTTP client with retries and 10 MB response limit
  plugins/              Plugin interface, registry, confidence scoring
    all/                Blank imports to trigger all plugin init() registrations
    cidrs/              CIDR discovery plugin implementations
    domains/            Domain discovery plugin implementations
  runner/               Pipeline orchestration, mode filtering, output formatting
```

### Key Design Decisions

- **Three-phase pipeline** separates RIR handle discovery (Phase 1) from CIDR resolution (Phase 2), enabling accurate multi-RIR lookups
- **Plugin-style registration** using Go `init()` functions — new plugins require zero changes to the runner
- **Confidence scoring** for ambiguous name-matching plugins (GitHub org search, reverse WHOIS, Apollo) distinguishes high-confidence results from ones that need human review
- **Two-tier caching** optimizes for different data profiles: small API responses as JSON (apollo, github-org) and large RPSL registry dumps as decompressed local files (APNIC, AFRINIC)
- **Graceful degradation** throughout — plugin errors are logged but never fail the pipeline; partial results are always returned

## Usage

### Basic Discovery

```bash
# Passive discovery (default) — safe for continuous monitoring
pius run --org "Acme Corp"

# Add domain hint to unlock crt-sh, dns-brute, passive-dns, zone-transfer
pius run --org "Acme Corp" --domain acme.com

# Add ASN hint to directly query BGP tables
pius run --org "Acme Corp" --asn AS12345

# All hints combined
pius run --org "Acme Corp" --domain acme.com --asn AS12345
```

### CIDR Discovery

```bash
# Passive CIDR discovery via all 5 RIRs
pius run --org "Acme Corp" --mode passive --plugins whois,arin,ripe,apnic,afrinic,lacnic

# Direct BGP lookup from ASN (no handle resolution needed)
pius run --org "Acme Corp" --asn AS12345 --plugins asn-bgp
```

### Output Formats

```bash
# Terminal table (default) — human-readable
pius run --org "Acme Corp"

# JSON array — structured output for parsing
pius run --org "Acme Corp" --output json

# NDJSON — one object per line, ideal for streaming/piping
pius run --org "Acme Corp" --output ndjson

# Pipe NDJSON to jq for filtering
pius run --org "Acme Corp" --output ndjson | jq 'select(.type == "cidr")'
```

### Plugin Selection

```bash
# Run only specific plugins
pius run --org "Acme Corp" --plugins crt-sh,apollo,arin

# Disable specific plugins (run everything else)
pius run --org "Acme Corp" --disable edgar,dns-brute

# Active mode — includes DNS brute-force and zone transfer
pius run --org "Acme Corp" --domain acme.com --mode active

# All modes — passive + active combined
pius run --org "Acme Corp" --domain acme.com --mode all

# Adjust concurrency (default: 5)
pius run --org "Acme Corp" --concurrency 10
```

## Configuration

### Environment Variables

Plugins that require API keys check for them in `Accepts()` before running. If the environment variable is missing, the plugin is silently skipped.

| Variable | Plugin | Required | Notes |
|----------|--------|----------|-------|
| `APOLLO_API_KEY` | `apollo` | Yes | Apollo.io API key |
| `CENSYS_API_TOKEN` | `censys-org` | Yes | Censys Personal Access Token ([generate here](https://search.censys.io/account/api)); requires Starter+ plan |
| `GITHUB_TOKEN` | `github-org` | No | Raises rate limit from 60 to 5000 req/hr |
| `SECURITYTRAILS_API_KEY` | `passive-dns` | Yes | SecurityTrails API key |
| `VIEWDNS_API_KEY` | `reverse-whois` | Yes | ViewDNS.info API key |

### Cache

Pius caches data under `~/.pius/cache/` automatically. No configuration is needed.

| Cache Type | Used By | TTL | Format |
|-----------|---------|-----|--------|
| API response cache | `apollo`, `censys-org`, `github-org` | 24 hours | JSON per key |
| RPSL registry database | `apnic`, `afrinic` | 24 hours | Decompressed gzip |

To clear the cache:

```bash
rm -rf ~/.pius/cache/
```

### CLI Reference

```
Usage:
  pius run [flags]
  pius list

run flags:
  -o, --org string          Organization name to search (required)
  -d, --domain string       Known domain hint (optional)
      --asn string          Known ASN hint, e.g. AS12345 (optional)
      --plugins string      Comma-separated plugin whitelist (default: all)
      --disable string      Comma-separated plugin blacklist
      --concurrency int     Max concurrent plugins (default: 5)
  -f, --output string       Output format: terminal, json, ndjson (default: terminal)
      --mode string         Plugin mode: passive, active, all (default: passive)
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Success — discovery completed |
| 1 | Runtime error |

## FAQ

### Which plugins run by default?

All passive plugins that accept the provided input run by default. Passive plugins with API key requirements (apollo, passive-dns, reverse-whois) are silently skipped if their environment variable is not set. Active plugins (dns-brute, dns-zone-transfer) only run with `--mode active` or `--mode all`.

### How does the three-phase pipeline work?

Phase 0 plugins (domain plugins + asn-bgp) run immediately and concurrently. Phase 1 plugins (whois, edgar) discover RIR organization handles from the company name. The runner then injects those handles into the input as metadata, and Phase 2 plugins (arin, ripe, apnic, afrinic, lacnic) resolve each handle to CIDR blocks. This separation enables accurate multi-RIR coverage while keeping plugins loosely coupled.

### What does `needs-review` mean in the output?

Some plugins use confidence scoring to rank ambiguous matches. For example, `github-org` scores organization candidates based on name similarity and domain matching. Findings with confidence between 0.35 and 0.65 are emitted with a `needs-review` flag rather than being silently discarded. Findings below 0.35 are dropped as noise.

### How do I add a new plugin?

1. Create a Go file in `pkg/plugins/domains/` or `pkg/plugins/cidrs/`
2. Implement the `plugins.Plugin` interface (7 methods: `Name`, `Description`, `Category`, `Phase`, `Mode`, `Accepts`, `Run`)
3. Register in an `init()` function:
   ```go
   func init() {
       plugins.Register("my-plugin", func() plugins.Plugin {
           return &MyPlugin{client: client.New()}
       })
   }
   ```
4. Import the package in `pkg/plugins/all/all.go`

See existing plugins like `crt_sh.go` or `arin.go` for reference implementations.

### Can I run Pius without any API keys?

Yes. The following plugins require no authentication and run with only `--org`:

- `crt-sh` (needs `--domain`)
- `gleif`
- `whois`
- `edgar`
- `arin`, `ripe`, `apnic`, `afrinic`, `lacnic`
- `asn-bgp` (needs `--asn`)
- `github-org` (optional `GITHUB_TOKEN`)

Active plugins (`dns-brute`, `dns-zone-transfer`) also require no auth but must be enabled with `--mode active`.

### What is the difference between RDAP and RPSL plugins?

RDAP plugins (arin, ripe, lacnic) make live HTTP queries to each registry's RDAP API — one request per handle. RPSL plugins (apnic, afrinic) download the full registry database as a gzip file once per day and parse it locally. RPSL offers lower latency after the initial download; RDAP offers fresher data.

## Troubleshooting

### No CIDR results

**Cause**: Phase 1 plugins found no RIR handles, or handles returned no CIDRs.

**Solutions**:
1. Try alternate spellings of the organization name: `--org "Acme Corporation"` vs `--org "Acme Corp"`
2. Check if `whois` or `edgar` ran: run with `--plugins whois` to isolate
3. Verify the organization has RIR allocations (some orgs use cloud provider space)

### No domain results

**Cause**: Missing domain hint, or API keys not set.

**Solutions**:
1. Add `--domain` to unlock crt-sh and DNS plugins
2. Set `APOLLO_API_KEY`, `SECURITYTRAILS_API_KEY`, or `VIEWDNS_API_KEY` for those plugins
3. Run `pius list` to confirm which plugins are registered

### APNIC/AFRINIC results are stale

**Cause**: RPSL database cache is within its 24-hour TTL.

**Solution**:
```bash
rm ~/.pius/cache/*.rpsl
pius run --org "Acme Corp"
```

### Rate limiting from GitHub

**Cause**: `GITHUB_TOKEN` not set; unauthenticated requests limited to 60/hr.

**Solution**:
```bash
export GITHUB_TOKEN="ghp_..."
pius run --org "Acme Corp"
```

### Slow CIDR discovery

**Cause**: Multiple RDAP requests per handle across multiple registries.

**Solution**: Reduce concurrency or restrict to specific registries:
```bash
# Only query ARIN (faster if org is US-based)
pius run --org "Acme Corp" --plugins whois,arin
```

## Contributing

We welcome contributions. To add a new plugin:

1. Create the plugin file in the appropriate package (`domains/` or `cidrs/`)
2. Implement the `Plugin` interface — 7 methods required
3. Register via `init()` and add a blank import to `pkg/plugins/all/all.go`
4. Write unit tests covering `Accepts()`, `Run()`, error paths, and caching (if applicable)
5. Follow existing error handling conventions:
   - Transient failures → return `(nil, nil)` (graceful degradation)
   - Parse errors → return wrapped error with context
   - Log warnings with `slog.Warn()` for partial failures

### Development

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./pkg/plugins/domains/... -v

# Build binary
go build -o pius ./cmd/pius

# Install to $GOPATH/bin
go install ./cmd/pius
```

## Security

Pius is designed for **authorized security testing and asset discovery only**.

- Pius sends DNS queries and API requests for the organization you specify — always ensure you have authorization
- Active plugins (`dns-brute`, `dns-zone-transfer`) generate network traffic to target nameservers
- Never run against organizations you don't own or have explicit permission to assess

Report security issues via [GitHub Issues](https://github.com/praetorian-inc/pius/issues).

## License

[Apache 2.0](LICENSE) - Praetorian Security, Inc.

---

**Built by [Praetorian](https://www.praetorian.com/)** - Offensive Security Solutions
