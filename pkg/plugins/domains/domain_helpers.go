package domains

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

const WhoisParametersKey = "whois_parameters"
const reverseWhoisBaselineConfidence = 50

// WhoisParameter records the typed pivot that produced a reverse-WHOIS result.
type WhoisParameter struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

type WhoisDomain struct {
	value      string
	parameters []WhoisParameter
}

// reverseWhoisFindings normalizes, filters, and deduplicates reverse-WHOIS results.
// A domain returned by multiple pivots is emitted once with their union.
func reverseWhoisFindings(source string, rawDomains []WhoisDomain) []plugins.Finding {
	parametersByDomain := map[string][]WhoisParameter{}
	var domains []string
	for _, rawDomain := range rawDomains {
		domain := normalizeWhoisDomain(rawDomain.value)
		if domain == "" || !whois.IsPlausibleDomain(domain) {
			continue
		}
		if _, exists := parametersByDomain[domain]; !exists {
			domains = append(domains, domain)
		}
		parametersByDomain[domain] = uniqueWhoisParameters(
			parametersByDomain[domain],
			rawDomain.parameters,
		)
	}

	findings := []plugins.Finding{}
	for _, domain := range domains {
		params := parametersByDomain[domain]
		finding := plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: source,
			Data: map[string]any{
				WhoisParametersKey: params,
			},
		}

		firstParam := params[0]
		plugins.AddConfidence(&finding, reverseWhoisBaselineConfidence,
			fmt.Sprintf("Queried %s and discovered domain %q was previously registered with registrant %q of %q",
				source, domain, firstParam.Field, firstParam.Value),
		)
		findings = append(findings, finding)
	}

	return findings
}

func normalizeWhoisDomain(domain string) string {
	return strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
}

func whoisParameters(input plugins.Input) []WhoisParameter {
	return []WhoisParameter{
		{Field: "company", Value: input.OrgName},
		{Field: "name", Value: input.PersonName},
		{Field: "email", Value: input.Email},
	}
}

func uniqueWhoisParameters(existing, incoming []WhoisParameter) []WhoisParameter {
	for _, candidate := range incoming {
		candidate.Field = strings.ToLower(strings.TrimSpace(candidate.Field))
		candidate.Value = strings.TrimSpace(candidate.Value)
		if candidate.Field == "" || candidate.Value == "" || whois.IsPrivacy(candidate.Value) {
			continue
		}
		duplicate := false
		for _, parameter := range existing {
			if parameter.Field == candidate.Field && strings.EqualFold(parameter.Value, candidate.Value) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			existing = append(existing, candidate)
		}
	}
	return existing
}
