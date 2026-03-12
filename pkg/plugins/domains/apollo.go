package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("apollo", func() plugins.Plugin {
		return &ApolloPlugin{client: client.New()}
	})
}

// ApolloPlugin discovers domains associated with an organization via the
// Apollo.io organization enrichment API. It returns the primary domain,
// personnel email domains (most valuable: reveal subsidiaries/acquisitions),
// website, and blog domains.
//
// Phase 0 (independent): runs concurrently, requires only OrgName.
// Requires APOLLO_API_KEY environment variable.
// Results are cached in ~/.pius/cache/ with a 24-hour TTL to conserve API credits.
type ApolloPlugin struct {
	client  *client.Client
	baseURL string       // override for testing; empty means use real Apollo API
	apiCache *cache.APICache // injected in tests; nil = lazy init on first Run
}

func (p *ApolloPlugin) apolloBaseURL() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.apollo.io/api/v1/organizations/enrich"
}

// getCache returns the APICache, initializing it lazily on first use.
// Returns nil if the cache directory cannot be created (non-fatal).
func (p *ApolloPlugin) getCache() *cache.APICache {
	if p.apiCache != nil {
		return p.apiCache
	}
	c, err := cache.NewAPI("", "apollo")
	if err != nil {
		log.Printf("[apollo] cache init failed: %v", err)
		return nil
	}
	p.apiCache = c
	return c
}

func (p *ApolloPlugin) Name() string { return "apollo" }
func (p *ApolloPlugin) Description() string {
	return "Apollo.io: discovers org domains via organization enrichment API (requires APOLLO_API_KEY)"
}
func (p *ApolloPlugin) Category() string { return "domain" }
func (p *ApolloPlugin) Phase() int       { return 0 }
func (p *ApolloPlugin) Mode() string     { return plugins.ModePassive }

func (p *ApolloPlugin) Accepts(input plugins.Input) bool {
	return input.OrgName != "" && os.Getenv("APOLLO_API_KEY") != ""
}

// apolloResponse mirrors the subset of Apollo.io /organizations/enrich we use.
type apolloResponse struct {
	Organization apolloOrg `json:"organization"`
}

type apolloOrg struct {
	PrimaryDomain    *string  `json:"primary_domain,omitempty"`
	PersonnelDomains []string `json:"personnel_domains,omitempty"`
	WebsiteURL       *string  `json:"website_url,omitempty"`
	BlogURL          *string  `json:"blog_url,omitempty"`
}

func (p *ApolloPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("APOLLO_API_KEY")
	cacheKey := strings.ToLower(input.OrgName + "|" + input.Domain)

	// Check cache first — Apollo charges per request
	c := p.getCache()
	if c != nil {
		var cached []plugins.Finding
		if c.Get(cacheKey, &cached) {
			return cached, nil
		}
	}

	// Build query — domain is more precise than org name
	base := p.apolloBaseURL()
	var apiURL string
	if input.Domain != "" {
		apiURL = fmt.Sprintf("%s?domain=%s", base, url.QueryEscape(input.Domain))
	} else {
		apiURL = fmt.Sprintf("%s?organization_name=%s", base, url.QueryEscape(input.OrgName))
	}

	body, err := p.client.GetWithHeaders(ctx, apiURL, map[string]string{
		"X-Api-Key":     apiKey,
		"Accept":        "application/json",
		"Content-Type":  "application/json",
		"Cache-Control": "no-cache",
	})
	if err != nil {
		log.Printf("[apollo] API request failed for %q: %v", input.OrgName, err)
		return nil, nil // graceful degradation
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "Invalid access credentials") {
		log.Printf("[apollo] invalid API key")
		return nil, nil
	}
	if strings.Contains(bodyStr, "insufficient credits") {
		log.Printf("[apollo] insufficient credits — upgrade Apollo.io plan")
		return nil, nil
	}

	var resp apolloResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Printf("[apollo] failed to parse response for %q: %v", input.OrgName, err)
		return nil, nil
	}

	findings := p.extractFindings(input.OrgName, &resp.Organization)

	// Score confidence: domain-based queries are precise; org-name queries
	// may return data for a similarly-named company.
	confidence := 0.85 // ?domain= query
	if input.Domain == "" {
		confidence = 0.70 // ?organization_name= query — org name is ambiguous
	}
	for i := range findings {
		plugins.SetConfidence(&findings[i], confidence)
	}

	if c != nil {
		c.Set(cacheKey, findings)
	}

	return findings, nil
}

func (p *ApolloPlugin) extractFindings(orgName string, org *apolloOrg) []plugins.Finding {
	seen := make(map[string]bool)
	var findings []plugins.Finding

	emit := func(raw, field string) {
		domain := stripScheme(raw)
		if domain == "" || seen[domain] {
			return
		}
		seen[domain] = true
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: "apollo",
			Data: map[string]any{
				"org":   orgName,
				"field": field,
			},
		})
	}

	if org.PrimaryDomain != nil && *org.PrimaryDomain != "" {
		emit(*org.PrimaryDomain, "primary_domain")
	}
	for _, d := range org.PersonnelDomains {
		emit(d, "personnel_domain")
	}
	if org.WebsiteURL != nil && *org.WebsiteURL != "" {
		emit(*org.WebsiteURL, "website_url")
	}
	if org.BlogURL != nil && *org.BlogURL != "" {
		emit(*org.BlogURL, "blog_url")
	}

	return findings
}

// stripScheme removes URL scheme and path, returning just the host.
// "https://blog.example.com/path" → "blog.example.com"
func stripScheme(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := strings.ToLower(u.Hostname())
	return strings.TrimSuffix(host, ".")
}
