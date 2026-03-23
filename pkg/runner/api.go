package runner

import (
	"context"
	"strings"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

// Config holds the pipeline execution configuration.
type Config struct {
	// Org is the organization name to search for. Required.
	Org string

	// Domain is an optional known domain hint.
	Domain string

	// ASN is an optional known ASN hint (e.g., "AS12345").
	ASN string

	// Plugins is a whitelist of plugin names. Empty means all.
	Plugins []string

	// Disable is a blacklist of plugin names.
	Disable []string

	// Mode controls which plugins run: "passive", "active", or "all". Default: "passive".
	Mode string

	// Concurrency is the max concurrent plugins. Default: 5.
	Concurrency int

	// Meta holds per-plugin configuration parameters (e.g., doh_servers,
	// dns_brute_concurrency). Entries are copied into plugins.Input.Meta
	// so individual plugins can read them.
	Meta map[string]string
}

// Run executes the discovery pipeline and returns the filtered findings.
// Internal cidr-handle findings are automatically removed from the output.
func Run(ctx context.Context, cfg Config) ([]plugins.Finding, error) {
	input := plugins.Input{
		OrgName: cfg.Org,
		Domain:  cfg.Domain,
		ASN:     cfg.ASN,
		Meta:    make(map[string]string),
	}

	// Copy caller-provided meta into input for plugin consumption.
	for k, v := range cfg.Meta {
		input.Meta[k] = v
	}

	mode := cfg.Mode
	if mode == "" {
		mode = "passive"
	}

	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	whitelist := strings.Join(cfg.Plugins, ",")
	blacklist := strings.Join(cfg.Disable, ",")
	selected := selectPlugins(whitelist, blacklist, mode)

	if len(selected) == 0 {
		return nil, nil
	}

	return runPipeline(ctx, input, selected, concurrency)
}
