package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("asn-bgp", func() plugins.Plugin {
		return &ASNBGPPlugin{client: client.New()}
	})
}

// ASNBGPPlugin discovers CIDR blocks from BGP routing tables given an ASN.
// Independent plugin (Phase 0): emits FindingCIDR findings directly.
type ASNBGPPlugin struct {
	client *client.Client
}

func (p *ASNBGPPlugin) Name() string        { return "asn-bgp" }
func (p *ASNBGPPlugin) Description() string { return "BGP routing tables: discovers CIDRs announced by an ASN" }
func (p *ASNBGPPlugin) Category() string    { return "cidr" }
func (p *ASNBGPPlugin) Phase() int          { return 0 } // Independent

func (p *ASNBGPPlugin) Accepts(input plugins.Input) bool {
	// Can run if ASN is provided
	return input.ASN != ""
}

func (p *ASNBGPPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	if input.ASN == "" {
		return nil, nil
	}

	// Try bgp.tools first
	cidrs, err := p.fetchFromBGPTools(ctx, input.ASN)
	if err != nil || len(cidrs) == 0 {
		// Fall back to RIPE RIS
		cidrs, err = p.fetchFromRIPERIS(ctx, input.ASN)
	}
	if err != nil {
		return nil, nil // Graceful degradation
	}

	// Convert to findings
	var findings []plugins.Finding
	for _, cidr := range cidrs {
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingCIDR,
			Value:  cidr,
			Source: "asn-bgp",
			Data: map[string]any{
				"asn": input.ASN,
				"org": input.OrgName,
			},
		})
	}

	return findings, nil
}

// fetchFromBGPTools queries bgp.tools prefix API
func (p *ASNBGPPlugin) fetchFromBGPTools(ctx context.Context, asn string) ([]string, error) {
	// Strip "AS" prefix if present
	asnNumber := strings.TrimPrefix(asn, "AS")
	apiURL := fmt.Sprintf("https://bgp.tools/prefix/%s.json", url.PathEscape(asnNumber))

	body, err := p.client.Get(ctx, apiURL)
	if err != nil {
		return nil, err
	}

	var resp BGPToolsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var cidrs []string
	for _, prefix := range resp.Prefixes {
		if prefix.Prefix != "" {
			cidrs = append(cidrs, prefix.Prefix)
		}
	}

	return cidrs, nil
}

// fetchFromRIPERIS queries RIPE RIS announced-prefixes API
func (p *ASNBGPPlugin) fetchFromRIPERIS(ctx context.Context, asn string) ([]string, error) {
	apiURL := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=%s", url.PathEscape(asn))

	body, err := p.client.Get(ctx, apiURL)
	if err != nil {
		return nil, err
	}

	var resp RIPERISResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var cidrs []string
	for _, prefix := range resp.Data.Prefixes {
		if prefix.Prefix != "" {
			cidrs = append(cidrs, prefix.Prefix)
		}
	}

	return cidrs, nil
}

// BGPToolsResponse represents bgp.tools prefix API response
type BGPToolsResponse struct {
	Prefixes []struct {
		Prefix string `json:"prefix"`
	} `json:"prefixes"`
}

// RIPERISResponse represents RIPE RIS announced-prefixes API response
type RIPERISResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}
