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

// infraOrgDenyList contains organization names that appear in TLS certificate
// Subject Organization fields but represent infrastructure providers, not the
// actual operator. Keyed by lowercase for case-insensitive matching.
var infraOrgDenyList = map[string]bool{
	// CDN / Edge / WAF — terminate TLS on behalf of customers
	"cloudflare, inc.":                     true,
	"cloudflare":                           true,
	"akamai technologies, inc.":            true,
	"akamai international b.v.":            true,
	"fastly, inc.":                         true,
	"imperva, inc.":                        true,
	"incapsula inc":                        true,
	"sucuri":                               true,
	"stackpath, llc":                       true,
	"f5 networks, inc.":                    true,
	"f5, inc.":                             true,
	"verizon digital media services, inc.": true,

	// Cloud / PaaS — shared certs carry provider's org name
	"amazon.com, inc.":             true,
	"amazon technologies, inc.":    true,
	"amazon web services, inc.":    true,
	"amazon":                       true,
	"microsoft corporation":        true,
	"microsoft":                    true,
	"google llc":                   true,
	"google inc":                   true,
	"google trust services llc":    true,
	"google trust services":        true,
	"oracle corporation":           true,
	"ibm":                          true,
	"alibaba cloud computing ltd.": true,
	"digitalocean, llc":            true,
	"linode, llc":                  true,
	"hetzner online gmbh":          true,
	"ovhcloud":                     true,
	"ovh sas":                      true,
	"rackspace us, inc.":           true,

	// Hosting platforms — serve certs with platform org name
	"automattic, inc.":               true,
	"shopify inc.":                   true,
	"squarespace, inc.":              true,
	"github, inc.":                   true,
	"netlify":                        true,
	"vercel inc.":                    true,
	"heroku, inc.":                   true,
	"wix.com ltd.":                   true,
	"wp engine, inc.":                true,
	"godaddy operating company, llc": true,
	"godaddy.com, inc.":              true,
	"newfold digital, inc.":          true,
	"unified layer":                  true,
	"siteground hosting ltd.":        true,
	"dreamhost, llc":                 true,
	"hostinger international ltd.":   true,
	"pantheon systems, inc.":         true,

	// Hosting control panels — auto-provision certs with panel vendor org
	"cpanel, inc.":               true,
	"cpanel, l.l.c.":             true,
	"plesk":                      true,
	"parallels international gmbh": true,

	// CAs that appear as Subject O on shared/managed certs
	"let's encrypt":                    true,
	"internet security research group": true,
	"digicert inc":                     true,
	"sectigo limited":                  true,
	"comodo ca limited":                true,
	"globalsign nv-sa":                 true,
	"zerossl":                          true,
	"trustasia technologies, inc.":     true,
	"starfield technologies, inc.":     true,
	"entrust, inc.":                    true,
	"ssl.com":                          true,
	"certainly":                        true,
	"plex, inc.":                       true,
}

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
	Names  []string          `json:"names,omitempty"`
	Parsed *censysCertParsed `json:"parsed,omitempty"`
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

	// Censys Platform API requires organization_id for programmatic access.
	if orgID := os.Getenv("CENSYS_ORG_ID"); orgID != "" {
		searchURL += "?organization_id=" + orgID
	}

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
// certificates contain the organization name in the subject DN field.
// Uses v3 Platform API field paths (host.services.cert.*).
func buildCensysQuery(orgName, domain string) string {
	query := fmt.Sprintf("host.services.cert.parsed.subject_dn:%q", orgName)
	if domain != "" {
		query = fmt.Sprintf("(%s) or host.services.cert.names:%s", query, domain)
	}
	return query
}

// extractFindings collects unique domains, CIDR blocks, and org-name preseeds
// from search hits. A preseed is emitted for any TLS cert Subject Organization
// name (other than the searched orgName itself) that appears across 2+ distinct
// host IPs.
func (p *CensysOrgPlugin) extractFindings(orgName string, hits []censysSearchHit) []plugins.Finding {
	seenDomains := make(map[string]bool)
	seenCIDRs := make(map[string]bool)
	var findings []plugins.Finding

	// orgHosts tracks how many distinct host IPs carry each cert Organization name.
	orgHosts := make(map[string]map[string]bool)

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

				// Collect org names from TLS cert Subject Organization fields.
				for _, org := range svc.Cert.Parsed.Subject.Organization {
					org = strings.TrimSpace(org)
					if org == "" || strings.EqualFold(org, orgName) {
						continue // skip empty and self-match
					}
					if infraOrgDenyList[strings.ToLower(org)] {
						continue // skip infrastructure providers
					}
					if orgHosts[org] == nil {
						orgHosts[org] = make(map[string]bool)
					}
					orgHosts[org][res.IP] = true
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

	// Emit preseed for any org name that appears across 5+ distinct hosts.
	for org, hosts := range orgHosts {
		if len(hosts) < 5 {
			continue
		}
		f := plugins.Finding{
			Type:   plugins.FindingPreseed,
			Value:  org,
			Source: "censys-org",
			Data: map[string]any{
				"preseed_type":  "whois+company",
				"preseed_title": org,
				"org":           orgName,
				"field":         "subject_organization",
				"host_count":    len(hosts),
			},
		}
		plugins.SetConfidence(&f, plugins.ConfidenceHigh)
		findings = append(findings, f)
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
