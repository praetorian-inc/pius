package domains

import (
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
	"github.com/praetorian-inc/pius/pkg/whois/data"
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
	for _, rawDomain := range rawDomains {
		domain := normalizeWhoisDomain(rawDomain.value)
		if domain == "" || !whois.IsPlausibleDomain(domain) {
			continue
		}

		parametersByDomain[domain] = uniqueWhoisParameters(
			parametersByDomain[domain],
			rawDomain.parameters,
		)
	}

	findings := []plugins.Finding{}
	for domain, params := range parametersByDomain {
		if len(params) == 0 { // skip findings with no legit params
			continue
		}

		finding := plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: source,
			Data: map[string]any{
				WhoisParametersKey: params,
			},
		}

		firstParam := params[0]
		fieldName := firstParam.Field
		if fieldName == "company" {
			fieldName = "organization"
		}

		plugins.AddConfidence(&finding, reverseWhoisBaselineConfidence,
			fmt.Sprintf("Queried %s and discovered domain %q was previously registered with registrant %v of %q",
				source, domain, fieldName, firstParam.Value),
		)
		findings = append(findings, finding)
	}

	return findings
}

func normalizeWhoisDomain(domain string) string {
	return strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
}

func whoisParametersFromInput(input plugins.Input) []WhoisParameter {
	var parameters []WhoisParameter
	for _, value := range reverseWhoisQueryValues(input.OrgName) {
		parameters = append(parameters, WhoisParameter{Field: "company", Value: value})
	}
	parameters = append(parameters,
		WhoisParameter{Field: "name", Value: input.PersonName},
		WhoisParameter{Field: "email", Value: input.Email},
	)
	return uniqueWhoisParameters(nil, parameters)
}

// reverseWhoisQueryValues returns the original value plus a legal-suffix
// punctuation alias. Reverse-WHOIS indexes match exact strings, so
// "Example Pharmacy, L.P." misses records stored as "Example Pharmacy, LP".
func reverseWhoisQueryValues(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || whois.IsPrivacy(value) {
		return nil
	}
	values := []string{value}
	if stripped := stripLegalSuffixPunctuation(value); stripped != "" && stripped != value {
		values = append(values, stripped)
	}
	return values
}

func stripLegalSuffixPunctuation(name string) string {
	words := strings.Fields(name)
	changed := false
	for i := len(words) - 1; i >= 0; i-- {
		withoutPeriods := strings.ReplaceAll(words[i], ".", "")
		suffix := strings.ToLower(strings.TrimSuffix(withoutPeriods, ","))
		if !data.LegalSuffixes[suffix] {
			break
		}
		if withoutPeriods != words[i] {
			words[i] = withoutPeriods
			changed = true
		}
	}
	if !changed {
		return name
	}
	return strings.Join(words, " ")
}

func reverseWhoisRecordStale(queryTime string) bool {
	t, err := time.Parse(time.DateTime, queryTime)
	if err != nil {
		return true
	}
	return t.Before(time.Now().AddDate(-10, 0, 0))
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
