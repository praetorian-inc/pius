package cidrs

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/cidr"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

// rpslConfig holds per-registry configuration for RPSL plugins.
type rpslConfig struct {
	name        string // "apnic" or "afrinic"
	description string
	cacheURL    string // cache.APNICInetURL or cache.AFRINICAllURL
	metaKey     string // "apnic_handles" or "afrinic_handles"
	registry    string // "apnic" or "afrinic"
	mode        string // plugins.ModePassive or plugins.ModeActive
}

// rpslPlugin is a Phase 2 CIDR plugin that resolves RIR org handles
// to CIDR blocks by downloading and parsing RPSL inetnum databases.
type rpslPlugin struct {
	cfg    rpslConfig
	cache  *cache.Cache
	dbPath string // set by NewRPSLPlugin; reads this file instead of downloading
}

// RPSLConfigs are the RPSL registries this package can query, keyed by registry
// name. Exposed so embedders can enumerate what NewRPSLPlugin accepts.
var RPSLConfigs = map[string]rpslConfig{
	"apnic": {
		name:        "apnic",
		description: "APNIC RPSL: resolves org handles to CIDR blocks",
		cacheURL:    cache.APNICInetURL,
		metaKey:     "apnic_handles",
		registry:    "apnic",
		mode:        plugins.ModePassive,
	},
	"afrinic": {
		name:        "afrinic",
		description: "AFRINIC RPSL: resolves org handles to CIDR blocks",
		cacheURL:    cache.AFRINICAllURL,
		metaKey:     "afrinic_handles",
		registry:    "afrinic",
		mode:        plugins.ModePassive,
	},
}

// RPSLMetaKey is the Input.Meta key a registry's plugin reads its handles from.
func RPSLMetaKey(registry string) (string, bool) {
	cfg, ok := RPSLConfigs[registry]
	if !ok {
		return "", false
	}
	return cfg.metaKey, true
}

// NewRPSLPlugin builds an RPSL plugin that parses an already-present database
// file rather than downloading one into a cache directory. Embedders that ship
// the RIR dumps in their runtime image can point at them directly, which avoids
// a multi-hundred-megabyte download per run and needs no writable HOME.
//
// dbPath must be the decompressed RPSL text, matching what the cache would have
// produced after gunzipping.
func NewRPSLPlugin(registry, dbPath string) (plugins.Plugin, error) {
	cfg, ok := RPSLConfigs[registry]
	if !ok {
		return nil, fmt.Errorf("unknown RPSL registry %q", registry)
	}
	if dbPath == "" {
		return nil, fmt.Errorf("%s: database path is required", registry)
	}
	return &rpslPlugin{cfg: cfg, dbPath: dbPath}, nil
}

// newRPSLPlugin creates an rpslPlugin with the given config and cache.
// If cache is nil (init failed), the plugin self-disables via Accepts().
func newRPSLPlugin(cfg rpslConfig, c *cache.Cache) *rpslPlugin {
	return &rpslPlugin{cfg: cfg, cache: c}
}

func (p *rpslPlugin) Name() string        { return p.cfg.name }
func (p *rpslPlugin) Description() string { return p.cfg.description }
func (p *rpslPlugin) Category() string    { return "cidr" }
func (p *rpslPlugin) Phase() int          { return 2 }
func (p *rpslPlugin) Mode() string        { return p.cfg.mode }

func (p *rpslPlugin) Accepts(input plugins.Input) bool {
	if input.Meta == nil || input.Meta[p.cfg.metaKey] == "" {
		return false
	}
	return p.cache != nil || p.dbPath != ""
}

// database returns the RPSL file to parse, preferring an injected local path
// over the download cache.
func (p *rpslPlugin) database(ctx context.Context) (string, error) {
	if p.dbPath != "" {
		return p.dbPath, nil
	}
	return p.cache.GetOrDownload(ctx, p.cfg.cacheURL)
}

func (p *rpslPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	handles := splitHandles(input.Meta[p.cfg.metaKey])

	dbFile, err := p.database(ctx)
	if err != nil {
		return nil, err
	}

	// Parse RPSL file for inetnum records matching our handles
	ranges, err := parseRPSLInetnums(dbFile, handles)
	if err != nil {
		return nil, err
	}

	// Convert IP ranges to CIDRs and create findings
	var findings []plugins.Finding
	for handle, ipRanges := range ranges {
		for _, r := range ipRanges {
			cidrs, err := cidr.ConvertIPv4RangeToCIDR(r.start, r.end)
			if err != nil {
				continue
			}
			for _, c := range cidrs {
				findings = append(findings, plugins.Finding{
					Type:   plugins.FindingCIDR,
					Value:  c,
					Source: p.Name(),
					Data: map[string]any{
						"handle":   handle,
						"org":      input.OrgName,
						"registry": p.cfg.registry,
						"netname":  r.netname,
					},
				})
			}
		}
	}

	return findings, nil
}
