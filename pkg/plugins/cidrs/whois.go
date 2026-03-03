package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("whois", func() plugins.Plugin {
		return &WhoisPlugin{client: client.New()}
	})
}

// WhoisPlugin discovers RIR org handles from company names via ARIN, RIPE, and LACNIC WHOIS.
// Phase 1 plugin: emits FindingCIDRHandle findings consumed by Phase 2.
type WhoisPlugin struct {
	client *client.Client
}

func (p *WhoisPlugin) Name() string        { return "whois" }
func (p *WhoisPlugin) Description() string { return "ARIN/RIPE/LACNIC WHOIS: discovers org handles from company name" }
func (p *WhoisPlugin) Category() string    { return "cidr" }
func (p *WhoisPlugin) Phase() int          { return 1 }

func (p *WhoisPlugin) Accepts(input plugins.Input) bool {
	return input.OrgName != ""
}

func (p *WhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	var findings []plugins.Finding

	// Query ARIN WHOIS for all entity types
	arinFindings, err := p.queryARIN(ctx, input.OrgName)
	if err != nil {
		slog.Warn("ARIN query failed", "plugin", "whois", "org", input.OrgName, "error", err)
	}
	findings = append(findings, arinFindings...)

	// Query RIPE search
	ripeFindings, err := p.queryRIPE(ctx, input.OrgName)
	if err != nil {
		slog.Warn("RIPE query failed", "plugin", "whois", "org", input.OrgName, "error", err)
	}
	findings = append(findings, ripeFindings...)

	// Query LACNIC RDAP entity search (Latin America & Caribbean)
	lacnicFindings, err := p.queryLACNIC(ctx, input.OrgName)
	if err != nil {
		slog.Warn("LACNIC query failed", "plugin", "whois", "org", input.OrgName, "error", err)
	}
	findings = append(findings, lacnicFindings...)

	return findings, nil
}

// queryARIN queries multiple ARIN entity types with handle deduplication
func (p *WhoisPlugin) queryARIN(ctx context.Context, org string) ([]plugins.Finding, error) {
	seen := make(map[string]bool)
	var findings []plugins.Finding

	// Query all entity types, deduplicating by handle value
	for _, entity := range []string{"orgs", "customers", "nets", "asns"} {
		for _, f := range p.queryArinEntity(ctx, entity, org) {
			if !seen[f.Value] {
				seen[f.Value] = true
				findings = append(findings, f)
			}
		}
	}

	return findings, nil
}

// queryArinEntity queries a specific ARIN entity type
func (p *WhoisPlugin) queryArinEntity(ctx context.Context, entity, org string) []plugins.Finding {
	apiURL := fmt.Sprintf("https://whois.arin.net/rest/%s;name=*%s*", entity, url.PathEscape(org))

	body, err := p.client.GetWithHeaders(ctx, apiURL, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		return nil
	}

	// Parse response based on entity type
	var handles []string
	switch entity {
	case "orgs":
		var resp ArinOrgsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil
		}
		for _, ref := range resp.Orgs.OrgRef {
			if ref.Handle != "" {
				handles = append(handles, ref.Handle)
			}
		}
	case "customers":
		var resp ArinCustomersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil
		}
		for _, ref := range resp.Customers.CustomerRef {
			if ref.Handle != "" {
				handles = append(handles, ref.Handle)
			}
		}
	case "nets":
		var resp ArinNetsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil
		}
		for _, ref := range resp.Nets.NetRef {
			if ref.Handle != "" {
				handles = append(handles, ref.Handle)
			}
		}
	case "asns":
		var resp ArinAsnsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil
		}
		for _, ref := range resp.Asns.AsnRef {
			if ref.Handle != "" {
				handles = append(handles, ref.Handle)
			}
		}
	}

	// Convert to findings
	var findings []plugins.Finding
	for _, handle := range handles {
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingCIDRHandle,
			Value:  handle,
			Source: "whois",
			Data: map[string]any{
				"registry": "arin",
				"org":      org,
			},
		})
	}

	return findings
}

// queryRIPE queries RIPE search API
func (p *WhoisPlugin) queryRIPE(ctx context.Context, org string) ([]plugins.Finding, error) {
	apiURL := fmt.Sprintf("https://rest.db.ripe.net/search?query-string=%s", url.QueryEscape(org))

	body, err := p.client.GetWithHeaders(ctx, apiURL, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		return nil, nil // Graceful degradation
	}

	var resp RipeWhoisResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}

	var findings []plugins.Finding
	for _, obj := range resp.Objects.Object {
		if len(obj.PrimaryKey.Attribute) == 0 {
			continue
		}

		name := obj.PrimaryKey.Attribute[0].Name
		value := obj.PrimaryKey.Attribute[0].Value

		if name == "organisation" {
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingCIDRHandle,
				Value:  value,
				Source: "whois",
				Data: map[string]any{
					"registry": "ripe",
					"org":      org,
				},
			})
		}
	}

	return findings, nil
}

// queryLACNIC queries LACNIC RDAP entity search API.
// LACNIC covers Latin America and the Caribbean.
// Search URL: https://rdap.lacnic.net/rdap/entities?fn={org}
// Response key: "entities" (LACNIC uses non-standard key vs RDAP spec's "entitySearchResults")
// Handle format: "BR-MERC-LACNIC", "MX-USCV4-LACNIC" (country-code prefix)
func (p *WhoisPlugin) queryLACNIC(ctx context.Context, org string) ([]plugins.Finding, error) {
	apiURL := fmt.Sprintf("https://rdap.lacnic.net/rdap/entities?fn=%s", url.QueryEscape(org))

	body, err := p.client.GetWithHeaders(ctx, apiURL, map[string]string{
		"Accept": "application/rdap+json",
	})
	if err != nil {
		return nil, nil // Graceful degradation
	}

	var resp LacnicSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}

	var findings []plugins.Finding
	for _, entity := range resp.Entities {
		if entity.Handle == "" {
			continue
		}
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingCIDRHandle,
			Value:  entity.Handle,
			Source: "whois",
			Data: map[string]any{
				"registry": "lacnic",
				"org":      org,
			},
		})
	}

	return findings, nil
}

// ARIN response types (ported from collect_cidr/collect-cidr.go lines 40-90)

type ArinRef struct {
	Handle string `json:"@handle"`
	Name   string `json:"@name"`
}

type ArinOrgsResponse struct {
	Orgs struct {
		OrgRef []ArinRef `json:"orgRef"`
	} `json:"orgs"`
}

type ArinCustomersResponse struct {
	Customers struct {
		CustomerRef []ArinRef `json:"customerRef"`
	} `json:"customers"`
}

type ArinNetsResponse struct {
	Nets struct {
		NetRef []ArinRef `json:"netRef"`
	} `json:"nets"`
}

type ArinAsnsResponse struct {
	Asns struct {
		AsnRef []ArinRef `json:"asnRef"`
	} `json:"asns"`
}

// RIPE response types (ported from collect_cidr/collect-cidr.go lines 25-37)

type RipeWhoisResponse struct {
	Objects struct {
		Object []struct {
			Type       string `json:"type,omitempty"`
			PrimaryKey struct {
				Attribute []struct {
					Name  string `json:"name,omitempty"`
					Value string `json:"value,omitempty"`
				} `json:"attribute,omitempty"`
			} `json:"primary-key,omitempty"`
		} `json:"object,omitempty"`
	} `json:"objects,omitempty"`
}

// LACNIC response types
// Note: LACNIC uses "entities" as the search results key (non-standard RDAP).

type LacnicSearchResponse struct {
	Entities []struct {
		Handle string `json:"handle"`
	} `json:"entities"`
}
