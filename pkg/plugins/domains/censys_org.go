package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

// censysMinHosts is the number of distinct hosts a certificate Subject
// Organization must appear on before it is emitted as a preseed.
//
// Crossing it is a binary judgement, scored plugins.ConfidenceHigh: the
// threshold is what the evidence rests on, and appearing on more hosts past it
// does not make the organization more likely to belong to the target. Scoring
// per host instead would push any organization on eight or more hosts to the
// 1.0 cap purely on breadth of scanning.
const censysMinHosts = 5

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
	apiToken string          // set by NewCensysOrgPlugin; falls back to CENSYS_API_TOKEN
	orgID    string          // set by NewCensysOrgPlugin; falls back to CENSYS_ORG_ID
	noCache  bool            // set by NewCensysOrgPlugin; skips the on-disk cache entirely
}

// NewCensysOrgPlugin builds the plugin around a caller-supplied client and
// credentials, so embedders can route its egress through their own transport and
// resolve both values from their own secret store instead of the environment.
// The on-disk cache is disabled: embedders run in ephemeral containers where it
// never warms, and a stale entry would silently bypass the caller's transport.
func NewCensysOrgPlugin(c *client.Client, apiToken, orgID string) *CensysOrgPlugin {
	return &CensysOrgPlugin{client: c, apiToken: apiToken, orgID: orgID, noCache: true}
}

// token and org prefer injected values so embedders never depend on process
// environment.
func (p *CensysOrgPlugin) token() string {
	if p.apiToken != "" {
		return p.apiToken
	}
	return os.Getenv("CENSYS_API_TOKEN")
}

func (p *CensysOrgPlugin) org() string {
	if p.orgID != "" {
		return p.orgID
	}
	return os.Getenv("CENSYS_ORG_ID")
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
	"cpanel, inc.":                 true,
	"cpanel, l.l.c.":               true,
	"plesk":                        true,
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
	if p.noCache {
		return nil
	}
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
	return input.OrgName != "" && p.token() != ""
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
	token := p.token()
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
	if orgID := p.org(); orgID != "" {
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
// name (other than the searched orgName itself) that appears across 5+ distinct
// host IPs.
func (p *CensysOrgPlugin) extractFindings(orgName string, hits []censysSearchHit) []plugins.Finding {
	values := newCensysAggregator()

	// orgHosts tracks distinct host IPs per org name (lowercased key for
	// case-insensitive deduplication). orgDisplay maps the lowercased key to
	// the first-seen original casing so the preseed Value preserves it.
	orgHosts := make(map[string]map[string]bool)
	orgDisplay := make(map[string]string)

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
				p.emitDomain(values, orgName, name, censysFieldCertificateNames)
			}
			if svc.Cert.Parsed != nil && svc.Cert.Parsed.Subject != nil {
				for _, cn := range svc.Cert.Parsed.Subject.CommonName {
					p.emitDomain(values, orgName, cn, censysFieldSubjectCN)
				}

				// Collect org names from TLS cert Subject Organization fields.
				// Use lowercase keys so casing variants ("Acme Corp" / "ACME CORP")
				// merge into the same bucket.
				for _, org := range svc.Cert.Parsed.Subject.Organization {
					org = strings.TrimSpace(org)
					if org == "" || strings.EqualFold(org, orgName) {
						continue // skip empty and self-match
					}
					orgKey := strings.ToLower(org)
					if infraOrgDenyList[orgKey] {
						continue // skip infrastructure providers
					}
					if orgHosts[orgKey] == nil {
						orgHosts[orgKey] = make(map[string]bool)
						orgDisplay[orgKey] = org // preserve first-seen original casing
					}
					orgHosts[orgKey][res.IP] = true
				}
			}
		}

		// Domains from reverse DNS
		if res.DNS != nil && res.DNS.ReverseDNS != nil {
			for _, name := range res.DNS.ReverseDNS.Names {
				p.emitDomain(values, orgName, name, censysFieldReverseDNS)
			}
		}

		// CIDRs from WHOIS network allocations
		if res.Whois != nil && res.Whois.Network != nil {
			for _, cidr := range res.Whois.Network.CIDRs {
				p.emitCIDR(values, orgName, cidr, censysFieldWhoisNetwork)
			}
		}

		// CIDRs from BGP prefix announcements
		if res.AutonomousSystem != nil && res.AutonomousSystem.BGPPrefix != "" {
			p.emitCIDR(values, orgName, res.AutonomousSystem.BGPPrefix, censysFieldBGPPrefix)
		}
	}

	findings := values.findings()

	// Emit preseed for any org name that appears across 5+ distinct hosts.
	// orgKey is the lowercase-normalized key; orgDisplay[orgKey] is the original casing.
	for orgKey, hosts := range orgHosts {
		if len(hosts) < censysMinHosts {
			continue
		}
		displayName := orgDisplay[orgKey]
		f := plugins.Finding{
			Type:   plugins.FindingPreseed,
			Value:  displayName,
			Source: "censys-org",
			Data: map[string]any{
				"preseed_type":  "whois+company",
				"preseed_title": displayName,
				"org":           orgName,
				"field":         "subject_organization",
				"host_count":    len(hosts),
			},
		}
		// The host count is the only detail in the justification — no certificate
		// contents, and no host addresses.
		plugins.AddConfidence(&f, plugins.ConfidenceHigh,
			fmt.Sprintf("Certificate Subject Organization %q was observed on %d distinct hosts, at or above the %d-host threshold",
				displayName, len(hosts), censysMinHosts))
		findings = append(findings, f)
	}

	return findings
}

// Censys host fields this plugin reads values out of. The field is retained per
// value because it is what the evidence is worth: a name on a certificate the
// host actually serves and a PTR record its provider set are different claims.
const (
	censysFieldCertificateNames = "certificate_names"
	censysFieldSubjectCN        = "subject_cn"
	censysFieldReverseDNS       = "reverse_dns"
	censysFieldWhoisNetwork     = "whois_network"
	censysFieldBGPPrefix        = "bgp_prefix"
)

// Evidence weights per Censys field.
//
// Every one of these is review-level, and that is structural rather than
// timid: the hosts came back from a search on the organization NAME in
// certificate subjects, so each finding inherits a name match as its weakest
// link no matter how solid the field itself is. infraOrgDenyList removes the
// providers it knows; a certificate naming an unlisted hosting company still
// gets through.
//
// Within that band the fields still differ. A certificate name and a subject CN
// are things the host presented as itself. A PTR record is set by whoever
// controls the reverse zone — very often the hosting provider, not the tenant.
// The two CIDR fields are the broadest claims of all: a WHOIS network can be a
// provider's whole allocation and a BGP prefix broader still, so one matched
// host inside them says the least about the range as a whole.
const (
	confCensysCertificateName = 0.50
	confCensysSubjectCN       = 0.50
	confCensysReverseDNS      = 0.40
	confCensysWhoisNetwork    = 0.45
	confCensysBGPPrefix       = 0.40
)

// censysFieldWeight is one field's score and the clause that describes it. The
// clause carries its own preposition and ends where the shared tail begins.
type censysFieldWeight struct {
	score  float64
	phrase string
}

// censysFieldWeights pairs each field with its weight. Every justification ends
// in the same clause — the host came back from the organization query — because
// that shared weakest link is why they all sit in the review band.
var censysFieldWeights = map[string]censysFieldWeight{
	censysFieldCertificateNames: {confCensysCertificateName, "observed %q in a certificate name on"},
	censysFieldSubjectCN:        {confCensysSubjectCN, "observed %q as a certificate subject common name on"},
	censysFieldReverseDNS:       {confCensysReverseDNS, "reported %q as the reverse DNS name of"},
	censysFieldWhoisNetwork:     {confCensysWhoisNetwork, "reported %q as the WHOIS network of"},
	censysFieldBGPPrefix:        {confCensysBGPPrefix, "reported %q as the announced BGP prefix of"},
}

// censysFieldEvidence scores one value by the field that carried it.
//
// An unknown field is scored at the weakest weight rather than silently
// inheriting another field's: a new field added to the extractor without a
// weight should read as the least it could be worth, not as a certificate name.
func censysFieldEvidence(orgName, value, field string) plugins.Confidence {
	weight, ok := censysFieldWeights[field]
	if !ok {
		weight = censysFieldWeight{confCensysBGPPrefix, "associated %q with"}
	}

	return plugins.Confidence{
		Score: weight.score,
		Justification: fmt.Sprintf("Censys "+weight.phrase+" a host returned by the organization query for %q",
			value, orgName),
	}
}

// censysKey identifies one aggregated value.
type censysKey struct {
	typ   plugins.FindingType
	value string
}

// censysAggregator collects findings by value, keeping ONE evidence entry per
// distinct field that carried it.
//
// The boolean seen-set it replaces conflated two different repetitions. A domain
// appearing in the certificate names of forty hosts is one field saying one
// thing forty times — no more evidence than the first. But a domain that is both
// a certificate name and the host's reverse DNS was established two ways, and
// keeping only whichever came first threw the second away silently.
type censysAggregator struct {
	order []censysKey
	byKey map[censysKey]*censysValue
}

// censysValue is one aggregated value and the fields that carried it. The field
// list is both the dedup set and what Data reports — there are at most five, so
// a scan beats a second map keyed by the value all over again.
type censysValue struct {
	finding plugins.Finding
	fields  []string
}

func newCensysAggregator() *censysAggregator {
	return &censysAggregator{byKey: make(map[censysKey]*censysValue)}
}

// observe records that field carried value, adding evidence the first time each
// distinct field does.
func (a *censysAggregator) observe(typ plugins.FindingType, value, orgName, field string) {
	key := censysKey{typ, value}

	entry, ok := a.byKey[key]
	if !ok {
		entry = &censysValue{finding: plugins.Finding{
			Type:   typ,
			Value:  value,
			Source: "censys-org",
			Data: map[string]any{
				"org":   orgName,
				"field": field,
			},
		}}
		a.byKey[key] = entry
		a.order = append(a.order, key)
	}

	if slices.Contains(entry.fields, field) {
		return
	}
	entry.fields = append(entry.fields, field)

	evidence := censysFieldEvidence(orgName, value, field)
	plugins.AddConfidence(&entry.finding, evidence.Score, evidence.Justification)
}

// findings returns the aggregated findings in first-seen order.
func (a *censysAggregator) findings() []plugins.Finding {
	result := make([]plugins.Finding, 0, len(a.order))
	for _, key := range a.order {
		entry := a.byKey[key]
		entry.finding.Data["fields"] = strings.Join(entry.fields, ",")
		result = append(result, entry.finding)
	}
	return result
}

// emitDomain normalizes a domain and records the field that carried it.
func (p *CensysOrgPlugin) emitDomain(values *censysAggregator, orgName, raw, field string) {
	domain := normalizeCensysDomain(raw)
	if domain == "" {
		return
	}
	values.observe(plugins.FindingDomain, domain, orgName, field)
}

// emitCIDR records a CIDR and the field that carried it.
func (p *CensysOrgPlugin) emitCIDR(values *censysAggregator, orgName, cidr, field string) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return
	}
	values.observe(plugins.FindingCIDR, cidr, orgName, field)
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
