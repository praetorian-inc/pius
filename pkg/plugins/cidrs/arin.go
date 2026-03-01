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
	plugins.Register("arin", func() plugins.Plugin { return &ARINPlugin{client: client.New()} })
}

type ARINPlugin struct {
	client *client.Client
}

func (p *ARINPlugin) Name() string        { return "arin" }
func (p *ARINPlugin) Description() string { return "ARIN RDAP: resolves org handles to CIDR blocks" }
func (p *ARINPlugin) Category() string    { return "cidr" }
func (p *ARINPlugin) Phase() int          { return 2 }

func (p *ARINPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta["arin_handles"] != ""
}

func (p *ARINPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	handles := strings.Split(input.Meta["arin_handles"], ",")
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
					"registry": "arin",
				},
			})
		}
	}
	return findings, nil
}

func (p *ARINPlugin) fetchCIDRs(ctx context.Context, handle string) ([]string, error) {
	url := fmt.Sprintf("https://rdap.arin.net/registry/entity/%s", handle)
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

// rdapEntityResponse represents ARIN RDAP entity response structure.
// Ported from chariot RDAP parsing logic.
type rdapEntityResponse struct {
	Handle   string        `json:"handle"`
	Networks []rdapNetwork `json:"networks"`
}

type rdapNetwork struct {
	Handle     string     `json:"handle"`
	Cidr0Cidrs []rdapCidr `json:"cidr0_cidrs"`
}

type rdapCidr struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}
