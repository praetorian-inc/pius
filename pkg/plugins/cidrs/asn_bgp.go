package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

const confASNBGPAnnouncedPrefix = 85

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

func (p *ASNBGPPlugin) Name() string { return "asn-bgp" }
func (p *ASNBGPPlugin) Description() string {
	return "BGP routing tables: discovers CIDRs announced by an ASN"
}
func (p *ASNBGPPlugin) Category() string { return "cidr" }
func (p *ASNBGPPlugin) Phase() int       { return 0 } // Independent
func (p *ASNBGPPlugin) Mode() string     { return plugins.ModePassive }

func (p *ASNBGPPlugin) Accepts(input plugins.Input) bool {
	// Can run if ASN is provided
	return input.ASN != ""
}

func (p *ASNBGPPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	if input.ASN == "" {
		return nil, nil
	}

	apiURL := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=%s",
		url.PathEscape(input.ASN))
	prefixes, response, err := p.fetchFromRIPERIS(ctx, apiURL)
	if err != nil {
		return nil, nil // Graceful degradation
	}

	var findings []plugins.Finding
	for _, prefix := range prefixes {
		finding := plugins.Finding{
			Type:   plugins.FindingCIDR,
			Value:  prefix,
			Source: "asn-bgp",
			Data: map[string]any{
				"asn": input.ASN,
				"org": input.OrgName,
			},
		}
		plugins.AddConfidence(&finding, confASNBGPAnnouncedPrefix, fmt.Sprintf(
			"RIPE RIS returned CIDR %q for queried ASN %q", prefix, input.ASN),
			plugins.NewHTTPExchangeReference("RIPE RIS announced-prefixes response", "GET", apiURL, nil, response))
		findings = append(findings, finding)
	}

	return findings, nil
}

// fetchFromRIPERIS queries RIPE RIS announced-prefixes API.
func (p *ASNBGPPlugin) fetchFromRIPERIS(ctx context.Context, apiURL string) ([]string, json.RawMessage, error) {
	body, err := p.client.Get(ctx, apiURL)
	if err != nil {
		return nil, nil, err
	}

	var resp RIPERISResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, err
	}

	var prefixes []string
	for _, prefix := range resp.Data.Prefixes {
		if prefix.Prefix != "" {
			prefixes = append(prefixes, prefix.Prefix)
		}
	}

	return prefixes, json.RawMessage(body), nil
}

// RIPERISResponse represents RIPE RIS announced-prefixes API response
type RIPERISResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}
