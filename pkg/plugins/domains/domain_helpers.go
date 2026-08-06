package domains

import (
	"strings"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

// domainFindings normalizes, deduplicates, and filters a raw list of domain
// strings into plausible FindingDomain entries with the pivot org attached.
// Shared by the reverse-whois plugins.
func domainFindings(source, pivotOrg string, rawDomains []string) []plugins.Finding {
	seen := make(map[string]struct{}, len(rawDomains))
	var findings []plugins.Finding

	for _, raw := range rawDomains {
		domain := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(raw)), ".")
		if domain == "" || !whois.IsPlausibleDomain(domain) {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}

		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: source,
			Data:   map[string]any{"pivot_org": pivotOrg},
		})
	}
	return findings
}
