package domains

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

const apolloCacheTTL = 24 * time.Hour

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
	baseURL string // override for testing; empty means use real Apollo API
}

func (p *ApolloPlugin) apolloBaseURL() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.apollo.io/api/v1/organizations/enrich"
}

func (p *ApolloPlugin) Name() string        { return "apollo" }
func (p *ApolloPlugin) Description() string {
	return "Apollo.io: discovers org domains via organization enrichment API (requires APOLLO_API_KEY)"
}
func (p *ApolloPlugin) Category() string { return "domain" }
func (p *ApolloPlugin) Phase() int       { return 0 }

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

	// Check cache first
	cacheKey := strings.ToLower(input.OrgName + "|" + input.Domain)
	if cached, ok := p.readCache(cacheKey); ok {
		return cached, nil
	}

	// Build query — domain is more precise than org name
	var apiURL string
	base := p.apolloBaseURL()
	if input.Domain != "" {
		apiURL = fmt.Sprintf("%s?domain=%s", base, url.QueryEscape(input.Domain))
	} else {
		apiURL = fmt.Sprintf("%s?organization_name=%s", base, url.QueryEscape(input.OrgName))
	}

	body, err := p.client.GetWithHeaders(ctx, apiURL, map[string]string{
		"X-Api-Key":    apiKey,
		"Accept":       "application/json",
		"Content-Type": "application/json",
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

	// Cache for next run
	p.writeCache(cacheKey, findings)

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
	// Add scheme if missing so url.Parse works correctly
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

// ── JSON file cache ───────────────────────────────────────────────────────────

// apolloCacheEntry is what we persist to disk.
type apolloCacheEntry struct {
	Findings []plugins.Finding `json:"findings"`
}

func apolloCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".pius", "cache")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}

func apolloCachePath(key string) (string, error) {
	dir, err := apolloCacheDir()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(key))
	return filepath.Join(dir, fmt.Sprintf("apollo-%x.json", h[:8])), nil
}

func (p *ApolloPlugin) readCache(key string) ([]plugins.Finding, bool) {
	path, err := apolloCachePath(key)
	if err != nil {
		return nil, false
	}
	info, err := os.Stat(path)
	if err != nil || time.Since(info.ModTime()) > apolloCacheTTL {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var entry apolloCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}
	return entry.Findings, true
}

func (p *ApolloPlugin) writeCache(key string, findings []plugins.Finding) {
	path, err := apolloCachePath(key)
	if err != nil {
		log.Printf("[apollo] cache path error: %v", err)
		return
	}
	data, err := json.Marshal(apolloCacheEntry{Findings: findings})
	if err != nil {
		return
	}
	// Atomic write via temp file + rename
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Printf("[apollo] cache write error: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[apollo] cache rename error: %v", err)
		os.Remove(tmp)
	}
}
