package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

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
	apiKey  string // set by NewURLScanPlugin; falls back to URLSCAN_API_KEY
}

// NewURLScanPlugin builds the plugin around a caller-supplied client and API key.
// The key is optional — urlscan serves unauthenticated requests at a lower rate
// limit — so an empty key is not an error here.
func NewURLScanPlugin(c *client.Client, apiKey string) *URLScanPlugin {
	return &URLScanPlugin{client: c, apiKey: apiKey}
}

// key prefers an injected key so embedders never depend on process environment.
func (p *URLScanPlugin) key() string {
	if p.apiKey != "" {
		return p.apiKey
	}
	return os.Getenv("URLSCAN_API_KEY")
}

func (p *URLScanPlugin) urlscanBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://urlscan.io"
}

func (p *URLScanPlugin) Name() string { return "urlscan" }
func (p *URLScanPlugin) Description() string {
	return "URLScan.io: discovers subdomains via public scan history"
}
func (p *URLScanPlugin) Category() string { return "domain" }
func (p *URLScanPlugin) Phase() int       { return 0 }
func (p *URLScanPlugin) Mode() string     { return plugins.ModePassive }

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
	if apiKey := p.key(); apiKey != "" {
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

	// Aggregate by host, recording which fields carried it.
	//
	// Neither axis of repetition is corroboration. The same domain in both
	// page.domain and task.domain of one scan is one scan: urlscan submitted a
	// URL and recorded where it landed. And a hundred scans of the same host are
	// a hundred people pasting the same link — popularity, not ownership. Which
	// fields saw it does go in the justification, because "we submitted this
	// URL" and "the page we landed on served this domain" are different
	// observations to a reader.
	base := normalizeDomain(input.Domain)

	var order []string
	fields := make(map[string][]string)

	for _, result := range response.Results {
		for _, observed := range []struct {
			field string
			value string
		}{
			{"page", result.Page.Domain},
			{"task", result.Task.Domain},
		} {
			host := normalizeDomain(observed.value)
			if host == "" || !matchesDomain(host, base) {
				continue
			}

			seenIn, seen := fields[host]
			if !seen {
				order = append(order, host)
			}
			if slices.Contains(seenIn, observed.field) {
				continue
			}
			fields[host] = append(seenIn, observed.field)
		}
	}

	findings := make([]plugins.Finding, 0, len(order))
	for _, host := range order {
		observedIn := fields[host]
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  host,
			Source: p.Name(),
			Confidences: []plugins.Confidence{{
				Score:         confURLScanObservation,
				Justification: describeURLScanObservation(host, base, observedIn),
			}},
			Data: map[string]any{
				"base_domain": input.Domain,
				"fields":      strings.Join(observedIn, ","),
			},
		})
	}

	return findings, nil
}

// confURLScanObservation is the evidence weight of a host in urlscan's public
// scan history beneath a known domain.
//
// The zone membership is what carries it: the name sits under a domain already
// tied to the target. What holds it below the clean threshold is that urlscan
// records what somebody submitted, whenever they submitted it — the scan may be
// years old, and the submitter may have been a stranger scanning a link, so the
// host is not established to be live or to be the target's to operate.
const confURLScanObservation = 0.60

// describeURLScanObservation explains one host, naming the fields it was seen in.
func describeURLScanObservation(host, base string, fields []string) string {
	described := make([]string, 0, len(fields))
	for _, field := range fields {
		described = append(described, "a "+field+" domain")
	}

	return fmt.Sprintf("URLScan public scan history observed %q as %s beneath %q",
		host, plugins.JoinPhrase(described), base)
}
