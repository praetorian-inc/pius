package cidrs

import (
	"context"

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
}

// rpslPlugin is a Phase 2 CIDR plugin that resolves RIR org handles
// to CIDR blocks by downloading and parsing RPSL inetnum databases.
type rpslPlugin struct {
	cfg   rpslConfig
	cache *cache.Cache
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
func (p *rpslPlugin) Mode() string        { return plugins.ModePassive }

func (p *rpslPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta[p.cfg.metaKey] != "" && p.cache != nil
}

func (p *rpslPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	handles := splitHandles(input.Meta[p.cfg.metaKey])

	// Download RPSL database
	dbFile, err := p.cache.GetOrDownload(ctx, p.cfg.cacheURL)
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
