# Pius Batch 5: CLI Entry Point & Runner - Implementation Summary

## Implementation Date
March 1, 2026

## Files Created

### 1. cmd/pius/main.go (152 bytes)
**Purpose:** Minimal CLI entry point

**Key Features:**
- Calls `runner.Execute()` to start Cobra command chain
- Returns exit code 1 on any error
- No CLI parsing logic (delegated to runner package)

### 2. pkg/runner/root.go (489 bytes)
**Purpose:** Cobra root command setup with plugin initialization

**Key Features:**
- Imports `_ "github.com/praetorian-inc/pius/pkg/plugins/all"` to trigger plugin registration
- Defines root command metadata (Use, Short, Long descriptions)
- Registers `run` and `list` subcommands via `AddCommand()`
- `Execute()` function as public entry point

### 3. pkg/runner/run.go (6.5K)
**Purpose:** Two-phase pipeline orchestration with concurrent plugin execution

**Key Features:**
- **Flags:**
  - `--org` (required): Organization name to search
  - `--domain` (optional): Known domain hint
  - `--asn` (optional): Known ASN hint (e.g., AS12345)
  - `--plugins` (optional): Comma-separated whitelist
  - `--disable` (optional): Comma-separated blacklist
  - `--concurrency` (default 5): Max concurrent plugins
  - `--output` (default "terminal"): Format (terminal|json|ndjson)

- **Two-Phase Pipeline:**
  - Phase 0 (independent): Runs concurrently with all phases (e.g., crt-sh, asn-bgp)
  - Phase 1: Discovers RIR org handles (whois, edgar)
  - Phase 2: Resolves handles to CIDRs (arin, ripe, apnic, afrinic)

- **Concurrency Control:**
  - Uses `golang.org/x/sync/errgroup` for bounded concurrency
  - `SetLimit(concurrency)` prevents goroutine explosion
  - Independent plugins run in parallel with phase pipeline

- **Error Handling:**
  - Plugin errors are logged, not returned (graceful degradation)
  - Partial success: return what was found with nil error
  - Empty results: `(nil, nil)` not an error condition

- **Meta Enrichment:**
  - `enrichWithHandles()` groups Phase 1 findings by registry
  - Populates `Input.Meta["arin_handles"]`, `Input.Meta["ripe_handles"]`, etc.
  - Phase 2 plugins read from Meta to know which handles to resolve

- **Output Filtering:**
  - `filterOutput()` removes internal `FindingCIDRHandle` findings
  - Only `FindingCIDR` and `FindingDomain` findings shown to users

- **Output Formats:**
  - `terminal`: `[type] value (source)` format
  - `json`: Pretty-printed JSON array
  - `ndjson`: Newline-delimited JSON (one finding per line)

### 4. pkg/runner/list.go (945 bytes)
**Purpose:** List available plugins with metadata

**Key Features:**
- Displays table: NAME, CATEGORY, PHASE, DESCRIPTION
- Phase labels: "phase-1", "phase-2", "independent"
- Alphabetically sorted by plugin name (via `plugins.List()`)
- Shows all 10 registered plugins

### 5. pkg/plugins/all/all.go (320 bytes)
**Purpose:** Blank imports to trigger plugin registration

**Key Features:**
- Imports `_ "github.com/praetorian-inc/pius/pkg/plugins/cidrs"`
- Imports `_ "github.com/praetorian-inc/pius/pkg/plugins/domains"`
- All plugin `init()` functions execute automatically
- Single package import per category (not per plugin file)

## Registered Plugins (10 Total)

### CIDR Plugins (7):
1. **whois** (phase-1): ARIN/RIPE WHOIS discovers org handles
2. **edgar** (phase-1): SEC EDGAR discovers org handles from filings
3. **arin** (phase-2): ARIN RDAP resolves handles to CIDRs
4. **ripe** (phase-2): RIPE RDAP resolves handles to CIDRs
5. **apnic** (phase-2): APNIC RPSL resolves handles to CIDRs
6. **afrinic** (phase-2): AFRINIC RPSL resolves handles to CIDRs
7. **asn-bgp** (independent): BGP routing tables for ASN→CIDR

### Domain Plugins (3):
1. **crt-sh** (independent): Certificate Transparency logs
2. **passive-dns** (independent): SecurityTrails Passive DNS (requires API key)
3. **reverse-whois** (independent): ViewDNS Reverse WHOIS (requires API key)

## Compilation Status

✅ All files compile successfully:
```bash
go build ./...
go vet ./...
go build -o pius ./cmd/pius/
```

No errors or warnings.

## Dependencies Added

- `github.com/spf13/cobra` v1.10.2: CLI framework
- `github.com/spf13/pflag` v1.0.9: Cobra dependency
- `golang.org/x/sync` v0.19.0: errgroup for concurrency
- `github.com/inconshreveable/mousetrap` v1.1.0: Cobra Windows support

## Key Design Decisions

### 1. Two-Phase Pipeline Architecture
- Phase 1 plugins discover org handles (FindingCIDRHandle)
- Phase 2 plugins resolve handles to CIDRs (FindingCIDR)
- Independent plugins run concurrently with all phases
- Meta enrichment passes data between phases

### 2. Graceful Degradation
- Plugin errors logged but don't stop pipeline
- Partial success returns what was found
- Empty results are not errors

### 3. Concurrency Model
- Bounded concurrency via errgroup.SetLimit()
- Three parallel execution groups:
  - Independent plugins (Phase 0)
  - Phase 1 discovery
  - Phase 2 resolution
- Phase 1 completes before Phase 2 starts
- Independent plugins run throughout

### 4. Plugin Selection
- Default: all plugins
- `--plugins`: whitelist (comma-separated)
- `--disable`: blacklist (comma-separated)
- Whitelist takes precedence over blacklist

### 5. Output Format Design
- `terminal`: Human-readable, one line per finding
- `json`: Machine-readable, single JSON array
- `ndjson`: Streaming format, one JSON object per line

## Usage Examples

### Basic Discovery
```bash
./pius run --org "Acme Corp"
```

### With Known Domain
```bash
./pius run --org "Acme Corp" --domain "acme.com"
```

### Whitelist Specific Plugins
```bash
./pius run --org "Acme Corp" --plugins whois,arin,ripe
```

### Disable Noisy Plugins
```bash
./pius run --org "Acme Corp" --disable crt-sh,passive-dns
```

### JSON Output
```bash
./pius run --org "Acme Corp" --output json > findings.json
```

### ASN Discovery
```bash
./pius run --org "Acme Corp" --asn AS12345
```

## Exit Criteria Verification

- ✅ 5 files created: main.go, root.go, run.go, list.go, all.go
- ✅ All files compile: `go build ./...` passes
- ✅ `go vet ./...` passes with no warnings
- ✅ `./pius --help` shows usage
- ✅ `./pius list` shows all 10 plugins
- ✅ `./pius run --help` shows all flags (--org, --domain, --asn, --plugins, --disable, --concurrency, --output)
- ✅ Binary executes without crashing

## Testing Recommendations

1. **Unit tests for runner package:**
   - Test `selectPlugins()` whitelist/blacklist logic
   - Test `enrichWithHandles()` Meta population
   - Test `filterOutput()` removes internal findings
   - Test `printFindings()` output formats

2. **Integration tests:**
   - Test complete two-phase pipeline with mock plugins
   - Test Phase 1 → Phase 2 data flow
   - Test independent plugins run concurrently
   - Test concurrency limits are respected

3. **CLI tests:**
   - Test flag validation (--org required)
   - Test plugin selection (--plugins, --disable)
   - Test output formats (terminal, json, ndjson)
   - Test error handling (invalid plugins, network errors)

4. **End-to-end tests:**
   - Test against real RIR APIs (rate-limited)
   - Test with real organization names
   - Test with real ASNs
   - Verify findings are accurate

## Notes

- Cobra provides built-in `completion` and `help` commands automatically
- The blank import pattern in `all.go` ensures all plugins register on startup
- The two-phase pipeline prevents circular dependencies between plugins
- Graceful error handling ensures partial results are useful
- Bounded concurrency prevents overwhelming RIR APIs or causing OOM
