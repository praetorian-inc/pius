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

const confShodanSearchResult = 85

type shodanQueryResult struct {
	queryURL string
	matches  []ShodanMatch
}

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
	apiKey  string // set by NewShodanPlugin; falls back to SHODAN_API_KEY when empty
}

// NewShodanPlugin builds the plugin around a caller-supplied client and API key,
// so embedders can route its egress through their own transport and resolve the
// key from their own secret store instead of the environment.
func NewShodanPlugin(c *client.Client, apiKey string) *ShodanPlugin {
	return &ShodanPlugin{client: c, apiKey: apiKey}
}

// key prefers an injected key so embedders never depend on process environment.
func (p *ShodanPlugin) key() string {
	if p.apiKey != "" {
		return p.apiKey
	}
	return os.Getenv("SHODAN_API_KEY")
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
	if p.key() == "" {
		return false
	}
	return input.OrgName != "" || input.Domain != "" || input.ASN != "" || input.CIDR != ""
}

func (p *ShodanPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := p.key()
	if apiKey == "" {
		return nil, nil
	}

	// Build individual queries for each filter
	queries := p.buildQueries(input)
	if len(queries) == 0 {
		return nil, nil
	}

	// Run separate queries since Shodan combines filters with AND.
	var queryResults []shodanQueryResult
	for _, query := range queries {
		results, displayURL, err := p.search(ctx, apiKey, query)
		if err != nil {
			continue // Graceful degradation on API errors
		}
		queryResults = append(queryResults, shodanQueryResult{queryURL: displayURL, matches: results.Matches})
	}

	return p.processResults(queryResults, input), nil
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

	// CIDR/net query for IP range
	if input.CIDR != "" {
		queries = append(queries, fmt.Sprintf("net:%s", input.CIDR))
	}

	// Hostname query for domain
	if input.Domain != "" {
		queries = append(queries, fmt.Sprintf("hostname:%s", input.Domain))
	}

	return queries
}

// search performs the Shodan API search
func (p *ShodanPlugin) search(ctx context.Context, apiKey, query string) (*ShodanSearchResponse, string, error) {
	searchURL := p.shodanSearchURL(apiKey, query)
	body, err := p.client.Get(ctx, searchURL)
	if err != nil {
		return nil, "", err
	}

	var resp ShodanSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, "", err
	}

	return &resp, p.shodanSearchURL("REDACTED", query), nil
}

func (p *ShodanPlugin) shodanSearchURL(apiKey, query string) string {
	parameters := url.Values{"key": {apiKey}, "query": {query}}
	return fmt.Sprintf("%s/shodan/host/search?%s", p.shodanBase(), parameters.Encode())
}

// processResults converts Shodan results to findings while retaining query provenance.
func (p *ShodanPlugin) processResults(results []shodanQueryResult, input plugins.Input) []plugins.Finding {
	var findings []plugins.Finding
	findingIndexes := make(map[string]int)
	evidenceURLs := make(map[string]map[string]bool)

	for _, result := range results {
		for _, match := range result.matches {
			if match.IPStr != "" {
				cidr := match.IPStr + "/32"
				p.addResultEvidence(&findings, findingIndexes, evidenceURLs, plugins.Finding{
					Type:   plugins.FindingCIDR,
					Value:  cidr,
					Source: p.Name(),
					Data: map[string]any{
						"org":   input.OrgName,
						"port":  match.Port,
						"asn":   match.ASN,
						"isp":   match.ISP,
						"os":    match.OS,
						"cloud": match.Cloud,
					},
				}, result.queryURL, "CIDR")
			}

			for _, hostname := range match.Hostnames {
				hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
				if hostname == "" {
					continue
				}
				p.addResultEvidence(&findings, findingIndexes, evidenceURLs, plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  hostname,
					Source: p.Name(),
					Data: map[string]any{
						"org":    input.OrgName,
						"ip":     match.IPStr,
						"port":   match.Port,
						"source": "shodan_hostname",
					},
				}, result.queryURL, "domain")
			}
		}
	}

	return findings
}

func (p *ShodanPlugin) addResultEvidence(findings *[]plugins.Finding, indexes map[string]int, evidenceURLs map[string]map[string]bool, finding plugins.Finding, queryURL, itemType string) {
	key := string(finding.Type) + ":" + finding.Value
	index, exists := indexes[key]
	if !exists {
		index = len(*findings)
		indexes[key] = index
		evidenceURLs[key] = make(map[string]bool)
		*findings = append(*findings, finding)
	}
	if evidenceURLs[key][queryURL] {
		return
	}

	evidenceURLs[key][queryURL] = true
	plugins.AddConfidence(&(*findings)[index], confShodanSearchResult, fmt.Sprintf(
		"Shodan returned %s %q from query %s", itemType, finding.Value, queryURL))
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
