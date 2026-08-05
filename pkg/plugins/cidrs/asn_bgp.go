package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

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
func (p *ASNBGPPlugin) Mode() string        { return plugins.ModePassive }

func (p *ASNBGPPlugin) Accepts(input plugins.Input) bool {
	// Can run if ASN is provided
	return input.ASN != ""
}

func (p *ASNBGPPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	if input.ASN == "" {
		return nil, nil
	}

	cidrs, err := p.fetchFromRIPERIS(ctx, input.ASN)
	if err != nil {
		return nil, nil // Graceful degradation
	}

	var findings []plugins.Finding
	for _, cidr := range cidrs {
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingCIDR,
			Value:  cidr,
			Source: "asn-bgp",
			Confidences: []plugins.Confidence{{
				Score: confASNAnnouncedPrefix,
				Justification: fmt.Sprintf("RIPE RIS reports that ASN %s announces prefix %q",
					input.ASN, cidr),
			}},
			Data: map[string]any{
				"asn": input.ASN,
				"org": input.OrgName,
			},
		})
	}

	return findings, nil
}

// confASNAnnouncedPrefix is the evidence weight of a prefix observed in BGP
// under the target's ASN.
//
// It needs no upstream provenance: the ASN is a caller-supplied input, not
// something this pipeline inferred, so there is no name-matching guess in the
// chain to bound it. What is left is an observation of the global routing table
// — the operator of the ASN is announcing the prefix — which is about as direct
// as network ownership evidence gets. Short of certainty only because
// announcing a prefix and owning it are not identical: transit providers and
// DDoS scrubbers announce prefixes on a customer's behalf.
const confASNAnnouncedPrefix = 0.85

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

// RIPERISResponse represents RIPE RIS announced-prefixes API response
type RIPERISResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}
