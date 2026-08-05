package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("crt-sh", func() plugins.Plugin { return NewCRTShPlugin(client.New()) })
}

type CRTShPlugin struct {
	client  *client.Client
	baseURL string // override for testing
}

func NewCRTShPlugin(c *client.Client) *CRTShPlugin {
	return &CRTShPlugin{client: c}
}

func (p *CRTShPlugin) crtshBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://crt.sh"
}

func (p *CRTShPlugin) Name() string { return "crt-sh" }
func (p *CRTShPlugin) Description() string {
	return "crt.sh: discovers domains via Certificate Transparency logs"
}
func (p *CRTShPlugin) Category() string { return "domain" }
func (p *CRTShPlugin) Phase() int       { return 0 }
func (p *CRTShPlugin) Mode() string     { return plugins.ModePassive }

// Accepts if we have a domain or org name to search
func (p *CRTShPlugin) Accepts(input plugins.Input) bool {
	return isDomainName(input.Domain) || input.OrgName != ""
}

// Evidence weights for Certificate Transparency results, by what the query
// establishes about the names it returns.
//
// A domain query returns names on certificates issued for that domain, so a
// result beneath the queried domain is a strong signal: somebody who controlled
// the zone proved that control to a CA. It is not certainty — CDN and SaaS
// providers hold certificates for customer subdomains they operate rather than
// own.
//
// A name OUTSIDE the queried domain is a different claim. It shares a
// certificate with the target's name, which happens for genuine sibling brands
// and equally for unrelated tenants on shared hosting whose SANs a provider
// bundled together.
//
// An organization-name query is the weakest: it matches the certificate's
// subject organization string, and that is a free-text field a CA validated at
// issuance against a company name hundreds of unrelated entities can resemble.
const (
	confCTBeneathKnownDomain = 0.70
	confCTSharedCertificate  = 0.50
	confCTOrganizationQuery  = 0.45
)

func (p *CRTShPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	// Search by domain if available, otherwise by org name
	query := input.Domain
	byDomain := query != ""
	if !byDomain {
		query = input.OrgName
	}

	urlStr := fmt.Sprintf("%s/?q=%s&output=json", p.crtshBase(), url.QueryEscape(query))
	body, err := p.client.Get(ctx, urlStr)
	if err != nil {
		return nil, nil // Rate limit or network error — not critical
	}

	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, nil
	}

	// Deduplicate domains
	seen := make(map[string]bool)
	var findings []plugins.Finding
	for _, entry := range entries {
		// name_value can contain multiple domains separated by newlines
		for _, domain := range strings.Split(entry.NameValue, "\n") {
			domain = normalizeDomain(domain)
			// Skip wildcards and empty
			if domain == "" || strings.HasPrefix(domain, "*") {
				continue
			}
			if seen[domain] {
				continue
			}
			seen[domain] = true

			data := map[string]any{
				"org":   input.OrgName,
				"query": query,
				"field": "name_value",
			}
			if entry.ID != 0 {
				data["crtsh_id"] = entry.ID
			}

			findings = append(findings, plugins.Finding{
				Type:        plugins.FindingDomain,
				Value:       domain,
				Source:      p.Name(),
				Confidences: []plugins.Confidence{crtShEvidence(domain, query, byDomain)},
				Data:        data,
			})
		}
	}
	return findings, nil
}

// crtShEvidence scores one CT result by which query returned it and, for a
// domain query, whether the name actually sits beneath the domain asked about.
func crtShEvidence(domain, query string, byDomain bool) plugins.Confidence {
	if !byDomain {
		return plugins.Confidence{
			Score: confCTOrganizationQuery,
			Justification: fmt.Sprintf("Certificate Transparency logs contain %q in results for organization query %q",
				domain, query),
		}
	}

	if matchesDomain(domain, query) {
		return plugins.Confidence{
			Score: confCTBeneathKnownDomain,
			Justification: fmt.Sprintf("Certificate Transparency logs contain %q in results for known domain %q",
				domain, query),
		}
	}

	return plugins.Confidence{
		Score: confCTSharedCertificate,
		Justification: fmt.Sprintf("Certificate Transparency logs list %q on a certificate returned for known domain %q",
			domain, query),
	}
}

// crtShEntry is one crt.sh result. The plugin reads names out of name_value and
// keeps the log entry id so a reviewer can pull the same certificate back up.
type crtShEntry struct {
	NameValue string `json:"name_value"`
	ID        int64  `json:"id"`
}
