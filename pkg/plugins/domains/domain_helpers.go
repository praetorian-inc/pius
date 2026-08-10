package domains

import (
	"strings"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

// domainFindings normalizes, deduplicates, and filters a raw list of domain
// strings into plausible FindingDomain entries with the pivot org attached.
// Shared by the reverse-whois plugins.
func domainFindings(source, pivotOrg string, rawDomains []string) []plugins.Finding {
	normalized := make([]string, 0, len(rawDomains))
	for _, raw := range rawDomains {
		domain := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(raw)), ".")
		if domain != "" && whois.IsPlausibleDomain(domain) {
			normalized = append(normalized, domain)
		}
	}

	var findings []plugins.Finding
	for _, domain := range strutil.Unique(normalized) {
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: source,
			Data:   map[string]any{"pivot_org": pivotOrg},
		})
	}
	return findings
}
