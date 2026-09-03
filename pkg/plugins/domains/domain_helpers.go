package domains

import (
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
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

func whoisParametersFromInput(input plugins.Input, aliases ...func(string) string) []WhoisParameter {
	var parameters []WhoisParameter
	for _, value := range reverseWhoisCompanyValues(input.OrgName, aliases...) {
		parameters = append(parameters, WhoisParameter{Field: "company", Value: value})
	}
	parameters = append(parameters,
		WhoisParameter{Field: "name", Value: input.PersonName},
		WhoisParameter{Field: "email", Value: input.Email},
	)
	return uniqueWhoisParameters(nil, parameters)
}

// reverseWhoisCompanyValues returns value plus each alias applied to every
// variant so far. WhoisFreaks only needs suffix-period aliases; Whoxy also
// needs comma aliases because it treats "Acme, Inc" and "Acme Inc" as
// different queries. Periods in the name body stay ("123.Net" is not "123Net").
func reverseWhoisCompanyValues(value string, aliases ...func(string) string) []string {
	value = strings.TrimSpace(value)
	if value == "" || whois.IsPrivacy(value) {
		return nil
	}
	values := []string{value}
	for _, alias := range aliases {
		n := len(values)
		for i := range n {
			values = append(values, alias(values[i]))
		}
	}
	return strutil.Unique(values)
}

func stripCommas(name string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(name, ",", "")), " ")
}

func stripLegalSuffixPeriods(name string) string {
	words := strings.Fields(name)
	changed := false
	for i := len(words) - 1; i >= 0; i-- {
		stripped := strings.ReplaceAll(words[i], ".", "")
		if !data.LegalSuffixes[strings.ToLower(stripped)] {
			break
		}
		if stripped != words[i] {
			words[i] = stripped
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
