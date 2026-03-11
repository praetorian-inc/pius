package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("shodan", func() plugins.Plugin {
		return &ShodanPlugin{client: client.New()}
	})
}

// ShodanPlugin queries Shodan's pre-indexed internet scan data to discover
// hosts, IPs, and services associated with a target organization.
type ShodanPlugin struct {
	client  *client.Client
	baseURL string // override for testing
}

func (p *ShodanPlugin) Name() string { return "shodan" }
func (p *ShodanPlugin) Description() string {
	return "Shodan: discovers hosts and services from pre-indexed internet scan data (requires SHODAN_API_KEY)"
}
func (p *ShodanPlugin) Category() string { return "cidr" }
func (p *ShodanPlugin) Phase() int       { return 0 }
func (p *ShodanPlugin) Mode() string     { return plugins.ModePassive }

func (p *ShodanPlugin) shodanBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.shodan.io"
}

// Accepts if SHODAN_API_KEY is set and we have something to search
func (p *ShodanPlugin) Accepts(input plugins.Input) bool {
	if os.Getenv("SHODAN_API_KEY") == "" {
		return false
	}
	return input.OrgName != "" || input.Domain != "" || input.ASN != ""
}

func (p *ShodanPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		return nil, nil
	}

	// Build individual queries for each filter
	queries := p.buildQueries(input)
	if len(queries) == 0 {
		return nil, nil
	}

	// Run separate queries and merge results (Shodan uses AND for combined filters)
	var allMatches []ShodanMatch
	for _, query := range queries {
		results, err := p.search(ctx, apiKey, query)
		if err != nil {
			continue // Graceful degradation on API errors
		}
		allMatches = append(allMatches, results.Matches...)
	}

	return p.processResults(&ShodanSearchResponse{Matches: allMatches}, input), nil
}

// buildQueries constructs individual Shodan search queries from input
// Each filter is run as a separate query since Shodan uses AND for combined filters
func (p *ShodanPlugin) buildQueries(input plugins.Input) []string {
	var queries []string

	// Org name query for broadest results
	if input.OrgName != "" {
		queries = append(queries, fmt.Sprintf("org:\"%s\"", input.OrgName))
	}

	// ASN query
	if input.ASN != "" {
		asn := input.ASN
		if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
			asn = "AS" + asn
		}
		queries = append(queries, fmt.Sprintf("asn:%s", asn))
	}

	// Hostname query for domain
	if input.Domain != "" {
		queries = append(queries, fmt.Sprintf("hostname:%s", input.Domain))
	}

	return queries
}

// search performs the Shodan API search
func (p *ShodanPlugin) search(ctx context.Context, apiKey, query string) (*ShodanSearchResponse, error) {
	searchURL := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s",
		p.shodanBase(), apiKey, url.QueryEscape(query))

	body, err := p.client.Get(ctx, searchURL)
	if err != nil {
		return nil, err
	}

	var resp ShodanSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// processResults converts Shodan results to findings
func (p *ShodanPlugin) processResults(resp *ShodanSearchResponse, input plugins.Input) []plugins.Finding {
	var findings []plugins.Finding
	seenIPs := make(map[string]bool)
	seenDomains := make(map[string]bool)

	for _, match := range resp.Matches {
		// Emit IP as CIDR /32
		if match.IPStr != "" && !seenIPs[match.IPStr] {
			seenIPs[match.IPStr] = true
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingCIDR,
				Value:  match.IPStr + "/32",
				Source: p.Name(),
				Data: map[string]any{
					"org":   input.OrgName,
					"port":  match.Port,
					"asn":   match.ASN,
					"isp":   match.ISP,
					"os":    match.OS,
					"cloud": match.Cloud,
				},
			})
		}

		// Emit hostnames as domains
		for _, hostname := range match.Hostnames {
			hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
			if hostname != "" && !seenDomains[hostname] {
				seenDomains[hostname] = true
				findings = append(findings, plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  hostname,
					Source: p.Name(),
					Data: map[string]any{
						"org":    input.OrgName,
						"ip":     match.IPStr,
						"port":   match.Port,
						"source": "shodan_hostname",
					},
				})
			}
		}
	}

	return findings
}

// ShodanSearchResponse represents the Shodan search API response
type ShodanSearchResponse struct {
	Matches []ShodanMatch `json:"matches"`
	Total   int           `json:"total"`
}

// ShodanMatch represents a single result from Shodan search
type ShodanMatch struct {
	IPStr     string   `json:"ip_str"`
	Port      int      `json:"port"`
	Hostnames []string `json:"hostnames"`
	ASN       string   `json:"asn"`
	ISP       string   `json:"isp"`
	OS        string   `json:"os"`
	Cloud     *struct {
		Provider string `json:"provider"`
		Region   string `json:"region"`
	} `json:"cloud,omitempty"`
}
