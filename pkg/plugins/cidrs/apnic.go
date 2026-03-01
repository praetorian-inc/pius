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
	plugins.Register("apnic", func() plugins.Plugin {
		c, err := cache.New()
		if err != nil {
			log.Printf("[apnic] cache init failed: %v (plugin will be disabled)", err)
		}
		return &APNICPlugin{cache: c}
	})
}

type APNICPlugin struct {
	cache *cache.Cache
}

func (p *APNICPlugin) Name() string        { return "apnic" }
func (p *APNICPlugin) Description() string { return "APNIC RPSL: resolves org handles to CIDR blocks" }
func (p *APNICPlugin) Category() string    { return "cidr" }
func (p *APNICPlugin) Phase() int          { return 2 }

func (p *APNICPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta["apnic_handles"] != "" && p.cache != nil
}

func (p *APNICPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	handles := strings.Split(input.Meta["apnic_handles"], ",")
	
	// Download APNIC inetnum database
	inetnumFile, err := p.cache.GetOrDownload(ctx, cache.APNICInetURL)
	if err != nil {
		return nil, err
	}

	// Parse RPSL file for inetnum records matching our handles
	ranges, err := p.parseInetnums(inetnumFile, handles)
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
						"registry": "apnic",
						"netname":  r.netname,
					},
				})
			}
		}
	}

	return findings, nil
}

type ipRange struct {
	start   string
	end     string
	netname string
}

func (p *APNICPlugin) parseInetnums(filePath string, handles []string) (map[string][]ipRange, error) {
	return parseRPSLInetnums(filePath, handles)
}
