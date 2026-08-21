package domains

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

const reverseWhoisParametersKey = "reverse_whois_parameters"
const reverseWhoisBaselineConfidence = 50

// ReverseWhoisParameter records the typed pivot that produced a reverse-WHOIS result.
type ReverseWhoisParameter struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

type reverseWhoisDomain struct {
	value      string
	parameters []ReverseWhoisParameter
}

// domainFindings normalizes, filters, and deduplicates reverse-WHOIS results.
// A domain returned by multiple pivots is emitted once with their union.
func domainFindings(source string, rawDomains []reverseWhoisDomain) []plugins.Finding {
	var findings []plugins.Finding
	findingByDomain := make(map[string]int, len(rawDomains))

	for _, rawDomain := range rawDomains {
		domain := normalizeReverseWhoisDomain(rawDomain.value)
		if domain == "" || !whois.IsPlausibleDomain(domain) {
			continue
		}

		parameters := validReverseWhoisParameters(rawDomain.parameters)
		if index, exists := findingByDomain[domain]; exists {
			findings[index].Data[reverseWhoisParametersKey] = mergeReverseWhoisParameters(
				findings[index].Data[reverseWhoisParametersKey].([]ReverseWhoisParameter),
				parameters,
			)
			continue
		}

		finding := plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: source,
			Data: map[string]any{
				reverseWhoisParametersKey: parameters,
			},
		}
		plugins.AddConfidence(&finding, reverseWhoisBaselineConfidence,
			fmt.Sprintf("%s reverse-WHOIS API returned domain %q", source, domain))

		findingByDomain[domain] = len(findings)
		findings = append(findings, finding)
	}

	return findings
}

func normalizeReverseWhoisDomain(domain string) string {
	return strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
}

func reverseWhoisParameters(input plugins.Input) []ReverseWhoisParameter {
	return validReverseWhoisParameters([]ReverseWhoisParameter{
		{Field: "company", Value: input.OrgName},
		{Field: "name", Value: input.PersonName},
		{Field: "email", Value: input.Email},
	})
}

func validReverseWhoisParameters(parameters []ReverseWhoisParameter) []ReverseWhoisParameter {
	valid := make([]ReverseWhoisParameter, 0, len(parameters))
	for _, parameter := range parameters {
		parameter.Field = strings.ToLower(strings.TrimSpace(parameter.Field))
		parameter.Value = strings.TrimSpace(parameter.Value)
		if !isReverseWhoisField(parameter.Field) || parameter.Value == "" || whois.IsPrivacy(parameter.Value) {
			continue
		}
		valid = mergeReverseWhoisParameters(valid, []ReverseWhoisParameter{parameter})
	}
	return valid
}

func isReverseWhoisField(field string) bool {
	switch field {
	case "company", "name", "email":
		return true
	default:
		return false
	}
}

func mergeReverseWhoisParameters(existing, incoming []ReverseWhoisParameter) []ReverseWhoisParameter {
	for _, candidate := range incoming {
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
