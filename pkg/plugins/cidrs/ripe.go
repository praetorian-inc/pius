package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("ripe", func() plugins.Plugin { return &RIPEPlugin{client: client.New()} })
}

type RIPEPlugin struct {
	client *client.Client
}

func (p *RIPEPlugin) Name() string        { return "ripe" }
func (p *RIPEPlugin) Description() string { return "RIPE RDAP: resolves org handles to CIDR blocks" }
func (p *RIPEPlugin) Category() string    { return "cidr" }
func (p *RIPEPlugin) Phase() int          { return 2 }

func (p *RIPEPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta["ripe_handles"] != ""
}

func (p *RIPEPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	handles := strings.Split(input.Meta["ripe_handles"], ",")
	var findings []plugins.Finding
	for _, handle := range handles {
		handle = strings.TrimSpace(handle)
		if handle == "" {
			continue
		}
		cidrs, err := p.fetchCIDRs(ctx, handle)
		if err != nil {
			// Log but don't fail all handles
			continue
		}
		for _, cidr := range cidrs {
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingCIDR,
				Value:  cidr,
				Source: p.Name(),
				Data: map[string]any{
					"handle":   handle,
					"org":      input.OrgName,
					"registry": "ripe",
				},
			})
		}
	}
	return findings, nil
}

func (p *RIPEPlugin) fetchCIDRs(ctx context.Context, handle string) ([]string, error) {
	url := fmt.Sprintf("https://rdap.db.ripe.net/entity/%s", handle)
	body, err := p.client.GetWithHeaders(ctx, url, map[string]string{
		"Accept": "application/rdap+json",
	})
	if err != nil {
		return nil, err
	}

	var resp rdapEntityResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse RDAP response: %w", err)
	}

	var cidrs []string
	for _, network := range resp.Networks {
		for _, cidr0 := range network.Cidr0Cidrs {
			// IPv4
			if cidr0.V4Prefix != "" && cidr0.Length > 0 {
				cidrs = append(cidrs, fmt.Sprintf("%s/%d", cidr0.V4Prefix, cidr0.Length))
			}
			// IPv6
			if cidr0.V6Prefix != "" && cidr0.Length > 0 {
				cidrs = append(cidrs, fmt.Sprintf("%s/%d", cidr0.V6Prefix, cidr0.Length))
			}
		}
	}

	return cidrs, nil
}
