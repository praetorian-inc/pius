package cidrs

import (
	"context"
	"log"
	"strings"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/cidr"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("afrinic", func() plugins.Plugin {
		c, err := cache.New()
		if err != nil {
			log.Printf("[afrinic] cache init failed: %v (plugin will be disabled)", err)
		}
		return &AFRINICPlugin{cache: c}
	})
}

type AFRINICPlugin struct {
	cache *cache.Cache
}

func (p *AFRINICPlugin) Name() string        { return "afrinic" }
func (p *AFRINICPlugin) Description() string { return "AFRINIC RPSL: resolves org handles to CIDR blocks" }
func (p *AFRINICPlugin) Category() string    { return "cidr" }
func (p *AFRINICPlugin) Phase() int          { return 2 }

func (p *AFRINICPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta["afrinic_handles"] != "" && p.cache != nil
}

func (p *AFRINICPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	handles := strings.Split(input.Meta["afrinic_handles"], ",")
	
	// Download AFRINIC complete database
	dbFile, err := p.cache.GetOrDownload(ctx, cache.AFRINICAllURL)
	if err != nil {
		return nil, err
	}

	// Parse RPSL file for inetnum records matching our handles
	ranges, err := p.parseInetnums(dbFile, handles)
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
						"registry": "afrinic",
						"netname":  r.netname,
					},
				})
			}
		}
	}

	return findings, nil
}

func (p *AFRINICPlugin) parseInetnums(filePath string, handles []string) (map[string][]ipRange, error) {
	return parseRPSLInetnums(filePath, handles)
}
