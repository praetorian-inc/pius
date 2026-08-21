package domains

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func findingReverseWhoisParameters(t *testing.T, finding plugins.Finding) []ReverseWhoisParameter {
	t.Helper()
	parameters, ok := finding.Data[reverseWhoisParametersKey].([]ReverseWhoisParameter)
	require.True(t, ok, "finding should carry typed reverse-WHOIS parameters")
	return parameters
}

func TestDomainFindings_NormalizesDeduplicatesAndUnionsParameters(t *testing.T) {
	findings := domainFindings("test-reverse-whois", []reverseWhoisDomain{
		{value: " Example.COM. ", parameters: []ReverseWhoisParameter{{Field: "company", Value: "Acme Corp"}}},
		{value: "example.com", parameters: []ReverseWhoisParameter{{Field: "email", Value: "admin@acme.com"}}},
		{value: "not-a-domain", parameters: []ReverseWhoisParameter{{Field: "name", Value: "Alice Smith"}}},
	})

	require.Len(t, findings, 1)
	assert.Equal(t, "example.com", findings[0].Value)
	assert.Equal(t, []ReverseWhoisParameter{
		{Field: "company", Value: "Acme Corp"},
		{Field: "email", Value: "admin@acme.com"},
	}, findingReverseWhoisParameters(t, findings[0]))
	require.Len(t, findings[0].Confidences, 1)
	assert.Equal(t, 50, findings[0].Confidences[0].Score)
	assert.Equal(t, 50, plugins.TotalConfidence(findings[0]))
}

func TestDomainFindings_OmitsEmptyAndPrivacyParameters(t *testing.T) {
	findings := domainFindings("test-reverse-whois", []reverseWhoisDomain{{
		value: "example.com",
		parameters: []ReverseWhoisParameter{
			{Field: "company", Value: " "},
			{Field: "name", Value: "Privacy Redaction"},
			{Field: "email", Value: "admin@acme.com"},
		},
	}})

	require.Len(t, findings, 1)
	assert.Equal(t, []ReverseWhoisParameter{{Field: "email", Value: "admin@acme.com"}},
		findingReverseWhoisParameters(t, findings[0]))
	require.Len(t, findings[0].Confidences, 1, "privacy pivots must not create confidence entries")
}
