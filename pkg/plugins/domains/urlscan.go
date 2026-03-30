package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("urlscan", func() plugins.Plugin { return &URLScanPlugin{client: client.New()} })
}

// URLScanPlugin queries the URLScan.io public search API to discover subdomains.
type URLScanPlugin struct {
	client  *client.Client
	baseURL string // override for testing
}

func (p *URLScanPlugin) urlscanBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://urlscan.io"
}

func (p *URLScanPlugin) Name() string        { return "urlscan" }
func (p *URLScanPlugin) Description() string { return "URLScan.io: discovers subdomains via public scan history" }
func (p *URLScanPlugin) Category() string    { return "domain" }
func (p *URLScanPlugin) Phase() int          { return 0 }
func (p *URLScanPlugin) Mode() string        { return plugins.ModePassive }

// Accepts returns true when an input domain is provided.
func (p *URLScanPlugin) Accepts(input plugins.Input) bool {
	return input.Domain != ""
}

// urlscanResponse is the top-level JSON response from the URLScan search API.
type urlscanResponse struct {
	Results []urlscanResult `json:"results"`
	Total   int             `json:"total"`
	Took    int             `json:"took"`
	HasMore bool            `json:"has_more"`
}

// urlscanResult is a single scan result entry.
type urlscanResult struct {
	Page urlscanPage `json:"page"`
	Task urlscanTask `json:"task"`
}

// urlscanPage holds the page-level domain information.
type urlscanPage struct {
	Domain     string `json:"domain"`
	ApexDomain string `json:"apexDomain"`
}

// urlscanTask holds the task-level domain information.
type urlscanTask struct {
	Domain     string `json:"domain"`
	ApexDomain string `json:"apexDomain"`
}

// Run queries URLScan.io and returns subdomain findings for the input domain.
func (p *URLScanPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	reqURL := fmt.Sprintf(
		"%s/api/v1/search/?q=page.apexDomain:%s&size=100",
		p.urlscanBase(),
		url.QueryEscape(input.Domain),
	)

	headers := map[string]string{
		"Accept": "application/json",
	}
	if apiKey := os.Getenv("URLSCAN_API_KEY"); apiKey != "" {
		headers["API-Key"] = apiKey
	}

	body, err := p.client.GetWithHeaders(ctx, reqURL, headers)
	if err != nil {
		return nil, nil // Network or rate-limit error — not critical
	}

	var response urlscanResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, nil
	}

	seen := make(map[string]bool)
	var findings []plugins.Finding

	for _, result := range response.Results {
		for _, raw := range []string{result.Page.Domain, result.Task.Domain} {
			host := normalizeDomain(raw)
			if host == "" {
				continue
			}
			if !matchesDomain(host, input.Domain) {
				continue
			}
			if seen[host] {
				continue
			}
			seen[host] = true
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingDomain,
				Value:  host,
				Source: p.Name(),
				Data: map[string]any{
					"base_domain": input.Domain,
				},
			})
		}
	}

	return findings, nil
}
