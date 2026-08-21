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

func TestWhoisParameters_ConvertsValidInputFieldsInOrder(t *testing.T) {
	parameters := whoisParameters(plugins.Input{
		OrgName:    " Acme Corp ",
		PersonName: "Privacy Redaction",
		Email:      "admin@acme.com",
	})

	assert.Equal(t, []WhoisParameter{
		{Field: "company", Value: "Acme Corp"},
		{Field: "email", Value: "admin@acme.com"},
	}, parameters)
}

func TestReverseWhoisPlugins_AcceptTheSameInputFields(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	viewDNS := &ViewDNSReverseWhoisPlugin{}
	whoxy := &WhoxyReverseWhoisPlugin{apiKey: "test-key"}

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
	}
	assert.False(t, viewDNS.Accepts(plugins.Input{}))
	assert.False(t, whoxy.Accepts(plugins.Input{}))
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
