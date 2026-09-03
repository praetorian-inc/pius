package domains

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func findingReverseWhoisParameters(t *testing.T, finding plugins.Finding) []WhoisParameter {
	t.Helper()
	parameters, ok := finding.Data[WhoisParametersKey].([]WhoisParameter)
	require.True(t, ok, "finding should carry typed reverse-WHOIS parameters")
	return parameters
}

func TestReverseWhoisPlugins_AcceptTheSameInputFields(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	viewDNS := &ViewDNSReverseWhoisPlugin{}
	whoxy := &WhoxyReverseWhoisPlugin{apiKey: "test-key"}
	freaks := &WhoisFreaksReverseWhoisPlugin{apiKey: "test-key"}

	inputs := []plugins.Input{
		{OrgName: "Acme Corp"},
		{PersonName: "Alice Smith"},
		{Email: "admin@acme.com"},
		{OrgName: "Privacy Redaction"},
		{OrgName: " "},
	}
	for _, input := range inputs {
		assert.True(t, viewDNS.Accepts(input))
		assert.True(t, whoxy.Accepts(input))
		assert.True(t, freaks.Accepts(input))
	}
	assert.False(t, viewDNS.Accepts(plugins.Input{}))
	assert.False(t, whoxy.Accepts(plugins.Input{}))
	assert.False(t, freaks.Accepts(plugins.Input{}))
}

func TestDomainFindings_NormalizesDeduplicatesAndUnionsParameters(t *testing.T) {
	findings := reverseWhoisFindings("test-reverse-whois", []WhoisDomain{
		{value: " Example.COM. ", parameters: []WhoisParameter{{Field: "company", Value: "Acme Corp"}}},
		{value: "example.com", parameters: []WhoisParameter{{Field: "email", Value: "admin@acme.com"}}},
		{value: "not-a-domain", parameters: []WhoisParameter{{Field: "name", Value: "Alice Smith"}}},
	})

	require.Len(t, findings, 1)
	assert.Equal(t, "example.com", findings[0].Value)
	assert.Equal(t, []WhoisParameter{
		{Field: "company", Value: "Acme Corp"},
		{Field: "email", Value: "admin@acme.com"},
	}, findingReverseWhoisParameters(t, findings[0]))
	require.Len(t, findings[0].Confidences, 1)
	assert.Equal(t, 50, findings[0].Confidences[0].Score)
	assert.Equal(t, 50, plugins.TotalConfidence(findings[0]))
}

func TestWhoisParametersFromInput_OrgNameLegalSuffixAliases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []WhoisParameter
	}{
		{
			name:  "LP",
			input: "Example Pharmacy, L.P.",
			want: []WhoisParameter{
				{Field: "company", Value: "Example Pharmacy, L.P."},
				{Field: "company", Value: "Example Pharmacy, LP"},
				{Field: "company", Value: "Example Pharmacy L.P."},
				{Field: "company", Value: "Example Pharmacy LP"},
			},
		},
		{
			name:  "comma before suffix",
			input: "Acme, Inc",
			want: []WhoisParameter{
				{Field: "company", Value: "Acme, Inc"},
				{Field: "company", Value: "Acme Inc"},
			},
		},
		{
			name:  "multiple suffix words",
			input: "Acme Pty. Ltd.",
			want: []WhoisParameter{
				{Field: "company", Value: "Acme Pty. Ltd."},
				{Field: "company", Value: "Acme Pty Ltd"},
			},
		},
		{
			name:  "additional observed suffixes",
			input: "Acme Sdn. Bhd.",
			want: []WhoisParameter{
				{Field: "company", Value: "Acme Sdn. Bhd."},
				{Field: "company", Value: "Acme Sdn Bhd"},
			},
		},
		{
			name:  "already unpunctuated",
			input: "Acme Inc",
			want:  []WhoisParameter{{Field: "company", Value: "Acme Inc"}},
		},
		{
			name:  "period outside suffix",
			input: "Foo.Bar Inc.",
			want: []WhoisParameter{
				{Field: "company", Value: "Foo.Bar Inc."},
				{Field: "company", Value: "Foo.Bar Inc"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, whoisParametersFromInput(
				plugins.Input{OrgName: test.input},
				stripLegalSuffixPeriods,
				stripCommas,
			))
		})
	}
}

func TestWhoisParametersFromInput_SkipsPrivacyAndEmpty(t *testing.T) {
	assert.Empty(t, whoisParametersFromInput(plugins.Input{OrgName: "Privacy Redaction"}))
	assert.Empty(t, whoisParametersFromInput(plugins.Input{OrgName: " "}))
	assert.Equal(t, []WhoisParameter{
		{Field: "email", Value: "admin@acme.com"},
	}, whoisParametersFromInput(plugins.Input{Email: "admin@acme.com"}))
}

func TestDomainFindings_OmitsEmptyAndPrivacyParameters(t *testing.T) {
	findings := reverseWhoisFindings("test-reverse-whois", []WhoisDomain{{
		value: "example.com",
		parameters: []WhoisParameter{
			{Field: "company", Value: " "},
			{Field: "name", Value: "Privacy Redaction"},
			{Field: "email", Value: "admin@acme.com"},
		},
	}})

	require.Len(t, findings, 1)
	assert.Equal(t, []WhoisParameter{{Field: "email", Value: "admin@acme.com"}},
		findingReverseWhoisParameters(t, findings[0]))
	require.Len(t, findings[0].Confidences, 1, "privacy pivots must not create confidence entries")
}
