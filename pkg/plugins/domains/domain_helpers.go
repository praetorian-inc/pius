package domains

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

const (
	confReverseWhoisResult       = 50
	confReverseWhoisFullMatch    = 50
	confReverseWhoisPartialMatch = 15
	minReverseWhoisPartialMatch  = 0.5
)

type domainWhoisLookup func(context.Context, string) (whois.Result, error)

// domainFindings normalizes, deduplicates, and filters a raw list of domain
// strings into plausible FindingDomain entries with the pivot attached.
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

func addReverseWhoisConfidences(
	ctx context.Context,
	input plugins.Input,
	findings []plugins.Finding,
	lookup domainWhoisLookup,
) {
	if lookup == nil {
		lookup = lookupDomainWhois
	}

	queryField, queryValue := reverseWhoisQuery(input)
	for i := range findings {
		finding := &findings[i]
		plugins.AddConfidence(finding, confReverseWhoisResult,
			fmt.Sprintf("%s returned %q for reverse WHOIS %s query %q",
				finding.Source, finding.Value, queryField, queryValue))

		result, err := lookup(ctx, finding.Value)
		if err != nil || result.Unregistered {
			continue
		}

		whoisValue := queriedWhoisValue(result, queryField, finding.Value)
		similarity := strutil.TokenSimilarity(queryValue, whoisValue)
		switch {
		case similarity == 1:
			plugins.AddConfidence(finding, confReverseWhoisFullMatch,
				fmt.Sprintf("fresh WHOIS %s %q fully matches the queried value %q", queryField, whoisValue, queryValue))
		case similarity >= minReverseWhoisPartialMatch:
			plugins.AddConfidence(finding, confReverseWhoisPartialMatch,
				fmt.Sprintf("fresh WHOIS %s %q partially matches the queried value %q with %.0f%% token similarity",
					queryField, whoisValue, queryValue, similarity*100))
		}
	}
}

func reverseWhoisQuery(input plugins.Input) (field, value string) {
	switch {
	case input.OrgName != "":
		return "company", input.OrgName
	case input.PersonName != "":
		return "name", input.PersonName
	default:
		return "email", input.Email
	}
}

func lookupDomainWhois(ctx context.Context, domain string) (whois.Result, error) {
	return whois.Lookup(ctx, domain)
}

func queriedWhoisValue(result whois.Result, queryField, domain string) string {
	switch queryField {
	case "company":
		return whois.RegistrantOrg(result.Registrant, domain)
	case "name":
		return result.Registrant.Name
	default:
		email, _ := whois.ContactEmail(result)
		return email
	}
}
