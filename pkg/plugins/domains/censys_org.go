package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("censys-org", func() plugins.Plugin {
		return &CensysOrgPlugin{client: client.New()}
	})
}

// CensysOrgPlugin discovers domains associated with an organization by querying
// the Censys Platform API v3 search endpoint. It searches host data indexed by
// Censys to find domains in TLS certificate SANs and DNS records tied to the org.
//
// Phase 0 (independent): runs concurrently, requires OrgName.
// Requires CENSYS_API_TOKEN environment variable (Personal Access Token).
// Requires a Starter or Enterprise Censys plan (search is not available on Free).
// Results are cached in ~/.pius/cache/ with a 24-hour TTL to conserve API credits.
type CensysOrgPlugin struct {
	client   *client.Client
	baseURL  string          // override for testing; empty means use real Censys API
	apiCache *cache.APICache // injected in tests; nil = lazy init on first Run
}

const censysDefaultBaseURL = "https://api.platform.censys.io"

func (p *CensysOrgPlugin) censysBaseURL() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return censysDefaultBaseURL
}

// getCache returns the APICache, initializing it lazily on first use.
func (p *CensysOrgPlugin) getCache() *cache.APICache {
	if p.apiCache != nil {
		return p.apiCache
	}
	c, err := cache.NewAPI("", "censys-org")
	if err != nil {
		slog.Warn("censys-org: cache init failed", "error", err)
		return nil
	}
	p.apiCache = c
	return c
}

func (p *CensysOrgPlugin) Name() string { return "censys-org" }
func (p *CensysOrgPlugin) Description() string {
	return "Censys: discovers domains from host/certificate data via organization search (requires CENSYS_API_TOKEN, Starter+ plan)"
}
func (p *CensysOrgPlugin) Category() string { return "domain" }
func (p *CensysOrgPlugin) Phase() int       { return 0 }
func (p *CensysOrgPlugin) Mode() string     { return plugins.ModeActive }

func (p *CensysOrgPlugin) Accepts(input plugins.Input) bool {
	return input.OrgName != "" && os.Getenv("CENSYS_API_TOKEN") != ""
}

// ── Censys Platform API v3 request/response types ─────────────────────────────

// censysSearchRequest is the POST body for /v3/global/search/query.
type censysSearchRequest struct {
	Query    string   `json:"query"`
	PageSize int      `json:"page_size"`
	Fields   []string `json:"fields,omitempty"`
}

// censysSearchResponse is the top-level envelope.
type censysSearchResponse struct {
	Result *censysSearchResult `json:"result,omitempty"`
	Status int                 `json:"status,omitempty"` // non-zero on error
	Title  string              `json:"title,omitempty"`  // error title
}

type censysSearchResult struct {
	Hits      []censysSearchHit `json:"hits"`
	TotalHits float64           `json:"total_hits"`
}

type censysSearchHit struct {
	Host *censysHostHit `json:"host_v1,omitempty"`
}

type censysHostHit struct {
	Resource *censysHostResource `json:"resource,omitempty"`
}

type censysHostResource struct {
	IP               string                  `json:"ip"`
	Services         []censysHostService     `json:"services,omitempty"`
	DNS              *censysHostDNS          `json:"dns,omitempty"`
	AutonomousSystem *censysAutonomousSystem `json:"autonomous_system,omitempty"`
	Whois            *censysWhois            `json:"whois,omitempty"`
}

type censysAutonomousSystem struct {
	ASN       int    `json:"asn,omitempty"`
	BGPPrefix string `json:"bgp_prefix,omitempty"`
	Name      string `json:"name,omitempty"`
}

type censysWhois struct {
	Network      *censysWhoisNetwork `json:"network,omitempty"`
	Organization *censysWhoisOrg     `json:"organization,omitempty"`
}

type censysWhoisNetwork struct {
	CIDRs []string `json:"cidrs,omitempty"`
	Name  string   `json:"name,omitempty"`
}

type censysWhoisOrg struct {
	Name   string `json:"name,omitempty"`
	Handle string `json:"handle,omitempty"`
}

type censysHostService struct {
	Cert *censysServiceCert `json:"cert,omitempty"`
}

type censysServiceCert struct {
	Names  []string             `json:"names,omitempty"`
	Parsed *censysCertParsed    `json:"parsed,omitempty"`
}

type censysCertParsed struct {
	Subject *censysCertSubject `json:"subject,omitempty"`
}

type censysCertSubject struct {
	CommonName   []string `json:"common_name,omitempty"`
	Organization []string `json:"organization,omitempty"`
}

type censysHostDNS struct {
	ReverseDNS *censysReverseDNS `json:"reverse_dns,omitempty"`
}

type censysReverseDNS struct {
	Names []string `json:"names,omitempty"`
}

func (p *CensysOrgPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	token := os.Getenv("CENSYS_API_TOKEN")
	cacheKey := strings.ToLower("censys-org|" + input.OrgName + "|" + input.Domain)

	// Check cache first
	c := p.getCache()
	if c != nil {
		var cached []plugins.Finding
		if c.Get(cacheKey, &cached) {
			return cached, nil
		}
	}

	query := buildCensysQuery(input.OrgName, input.Domain)
	searchURL := p.censysBaseURL() + "/v3/global/search/query"

	reqBody := censysSearchRequest{
		Query:    query,
		PageSize: 100,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("censys-org: marshal request: %w", err)
	}

	respBody, err := p.client.PostWithHeaders(ctx, searchURL, bodyBytes, map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
		"Accept":        "application/json",
	})
	if err != nil {
		slog.Warn("censys-org: API request failed", "org", input.OrgName, "error", err)
		return nil, nil // graceful degradation
	}

	var resp censysSearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		slog.Warn("censys-org: failed to parse response", "org", input.OrgName, "error", err)
		return nil, nil
	}

	if resp.Status == 403 || resp.Status == 401 {
		slog.Warn("censys-org: auth error", "status", resp.Status, "detail", resp.Title)
		return nil, nil
	}
	if resp.Result == nil {
		slog.Warn("censys-org: empty result envelope", "status", resp.Status, "title", resp.Title)
		return nil, nil
	}

	findings := p.extractFindings(input.OrgName, resp.Result.Hits)

	if c != nil {
		c.Set(cacheKey, findings)
	}

	return findings, nil
}

// buildCensysQuery constructs a CenQL query searching for hosts whose TLS
// certificates contain the organization name in the subject field.
func buildCensysQuery(orgName, domain string) string {
	query := fmt.Sprintf("host.services.tls.certificates.leaf.parsed.subject.organization:%q", orgName)
	if domain != "" {
		query = fmt.Sprintf("(%s) or host.services.tls.certificates.leaf.names:%s", query, domain)
	}
	return query
}

// extractFindings collects unique domains and CIDR blocks from search hits.
func (p *CensysOrgPlugin) extractFindings(orgName string, hits []censysSearchHit) []plugins.Finding {
	seenDomains := make(map[string]bool)
	seenCIDRs := make(map[string]bool)
	var findings []plugins.Finding

	for _, hit := range hits {
		if hit.Host == nil || hit.Host.Resource == nil {
			continue
		}
		res := hit.Host.Resource

		// Domains from TLS certificate SANs and subject CN
		for _, svc := range res.Services {
			if svc.Cert == nil {
				continue
			}
			for _, name := range svc.Cert.Names {
				p.emitDomain(&findings, seenDomains, orgName, name, "certificate_names")
			}
			if svc.Cert.Parsed != nil && svc.Cert.Parsed.Subject != nil {
				for _, cn := range svc.Cert.Parsed.Subject.CommonName {
					p.emitDomain(&findings, seenDomains, orgName, cn, "subject_cn")
				}
			}
		}

		// Domains from reverse DNS
		if res.DNS != nil && res.DNS.ReverseDNS != nil {
			for _, name := range res.DNS.ReverseDNS.Names {
				p.emitDomain(&findings, seenDomains, orgName, name, "reverse_dns")
			}
		}

		// CIDRs from WHOIS network allocations
		if res.Whois != nil && res.Whois.Network != nil {
			for _, cidr := range res.Whois.Network.CIDRs {
				p.emitCIDR(&findings, seenCIDRs, orgName, cidr, "whois_network")
			}
		}

		// CIDRs from BGP prefix announcements
		if res.AutonomousSystem != nil && res.AutonomousSystem.BGPPrefix != "" {
			p.emitCIDR(&findings, seenCIDRs, orgName, res.AutonomousSystem.BGPPrefix, "bgp_prefix")
		}
	}

	return findings
}

// emitDomain normalizes and deduplicates a domain before appending to findings.
func (p *CensysOrgPlugin) emitDomain(findings *[]plugins.Finding, seen map[string]bool, orgName, raw, field string) {
	domain := normalizeCensysDomain(raw)
	if domain == "" || seen[domain] {
		return
	}
	seen[domain] = true
	*findings = append(*findings, plugins.Finding{
		Type:   plugins.FindingDomain,
		Value:  domain,
		Source: "censys-org",
		Data: map[string]any{
			"org":   orgName,
			"field": field,
		},
	})
}

// emitCIDR deduplicates a CIDR before appending to findings.
func (p *CensysOrgPlugin) emitCIDR(findings *[]plugins.Finding, seen map[string]bool, orgName, cidr, field string) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" || seen[cidr] {
		return
	}
	seen[cidr] = true
	*findings = append(*findings, plugins.Finding{
		Type:   plugins.FindingCIDR,
		Value:  cidr,
		Source: "censys-org",
		Data: map[string]any{
			"org":   orgName,
			"field": field,
		},
	})
}

// normalizeCensysDomain extends normalizeDomain with Censys-specific cleanup:
// strips whitespace and wildcard prefixes before canonical normalization.
func normalizeCensysDomain(raw string) string {
	d := strings.TrimSpace(raw)
	// Strip wildcard prefix (e.g., "*.example.com" → "example.com")
	d = strings.TrimPrefix(d, "*.")
	if d == "" || d == "*" {
		return ""
	}
	return normalizeDomain(d)
}
