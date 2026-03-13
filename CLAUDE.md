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

## Adding a New Plugin

1. Create file in `pkg/plugins/cidrs/` or `pkg/plugins/domains/`
2. Implement the `Plugin` interface
3. Register via `init()` with `plugins.Register()`
4. For HTTP operations, use `httpDoer` interface pattern for testability
5. Write tests using `httptest.Server` for mocking
