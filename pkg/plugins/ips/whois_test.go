package ips

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhoisPlugin_Accepts(t *testing.T) {
	plugin := NewWhoisPlugin(nil)
	tests := []struct {
		name  string
		input plugins.Input
		want  bool
	}{
		{name: "IP", input: plugins.Input{IP: "8.8.8.8"}, want: true},
		{name: "CIDR", input: plugins.Input{CIDR: "8.8.8.0/24"}, want: true},
		{name: "private", input: plugins.Input{IP: "10.0.0.1"}, want: true},
		{name: "both", input: plugins.Input{IP: "8.8.8.8", CIDR: "8.8.8.0/24"}, want: true},
		{name: "neither", input: plugins.Input{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, plugin.Accepts(test.input))
		})
	}
}

func TestNetworkFindings_EmitResultAndPreseeds(t *testing.T) {
	result := whois.NetworkResult{
		Query:        "8.8.8.8",
		StartAddress: "8.8.8.0",
		EndAddress:   "8.8.8.255",
		Handle:       "NET-8-8-8-0-1",
		Registry:     "arin",
		Server:       "whois.example.test",
		Status:       []string{"active"},
		Sources:      []string{"whois"},
		Contacts: []whois.NetworkContact{
			{
				Roles: []string{"registrant"}, Status: []string{"validated"}, Kind: "org", Direct: true,
				Contact: whois.Contact{Name: "Example Networks", Email: "jane@example.com"},
			},
			{
				Handle: "EXAMPLE-MNT", Roles: []string{"registrant"}, Kind: "individual", Direct: true,
				Contact: whois.Contact{Name: "EXAMPLE-MNT"},
			},
			{Roles: []string{"registrant"}, Kind: "org", Contact: whois.Contact{Name: "Upstream ISP"}},
			{
				Roles: []string{"technical"}, Kind: "group", Direct: true,
				Contact: whois.Contact{Organization: "Carrier NOC", Email: "noc@carrier.example"},
			},
		},
	}

	findings := []plugins.Finding{networkResultFinding(result)}
	findings = append(findings, networkPreseeds(result)...)
	require.Len(t, findings, 3)
	assert.Equal(t, plugins.FindingIPWhoisResult, findings[0].Type)
	assert.Equal(t, "8.8.8.8", findings[0].Value)

	assert.Equal(t, "whois+company", findings[1].Data["preseed_type"])
	assert.Equal(t, "Example Networks", findings[1].Value)
	assert.Equal(t, "whois+email", findings[2].Data["preseed_type"])
	assert.Equal(t, "jane@example.com", findings[2].Value)
	for _, finding := range findings[1:] {
		require.Len(t, finding.Confidences, 1)
		assert.Equal(t, confIPWhoisContact, finding.Confidences[0].Score)
		assert.Equal(t, []string{"validated"}, finding.Data["status"])
		assert.Equal(t, []string{"active"}, finding.Data["allocation_status"])
		assert.Contains(t, finding.Confidences[0].Justification, `IP WHOIS server "whois.example.test"`)
		assert.Contains(t, finding.Confidences[0].Justification, `with entity status "validated"`)
		assert.Contains(t, finding.Confidences[0].Justification, `allocation "NET-8-8-8-0-1" spanning 8.8.8.0-8.8.8.255`)
		assert.Contains(t, finding.Confidences[0].Justification, `returned for query "8.8.8.8"`)
	}
}

func TestNetworkPreseedJustification_AttributesMergedSources(t *testing.T) {
	result := whois.NetworkResult{
		Query:        "80.156.86.78",
		StartAddress: "80.156.84.0",
		EndAddress:   "80.156.87.255",
		Handle:       "80.156.84.0 - 80.156.87.255",
		RDAPServer:   "rdap.db.ripe.net",
		WhoisServer:  "whois.ripe.net",
		Sources:      []string{"rdap", "whois"},
	}

	justification := networkPreseedJustification(result, networkPreseedCandidate{
		field: "company", role: "registrant", value: "Example Networks",
	})

	assert.Contains(t, justification, `IP RDAP server "rdap.db.ripe.net"`)
	assert.Contains(t, justification, `IP WHOIS server "whois.ripe.net"`)
}

func TestNetworkPreseeds_PrefersCustomerOverRegistrant(t *testing.T) {
	findings := networkPreseeds(whois.NetworkResult{Contacts: []whois.NetworkContact{
		{Roles: []string{"registrant"}, Kind: "org", Direct: true, Contact: whois.Contact{Name: "Upstream ISP"}},
		{Roles: []string{"customer"}, Kind: "org", Direct: true, Contact: whois.Contact{Name: "Example Customer"}},
	}})

	require.Len(t, findings, 1)
	assert.Equal(t, "Example Customer", findings[0].Value)
}

func TestNetworkPreseeds_OmitsPrivacyProtectedContacts(t *testing.T) {
	for _, status := range []string{"private", "removed", "obscured"} {
		t.Run(status, func(t *testing.T) {
			findings := networkPreseeds(whois.NetworkResult{Contacts: []whois.NetworkContact{{
				Roles: []string{"registrant"}, Status: []string{status}, Kind: "org", Direct: true,
				Contact: whois.Contact{Name: "Private Customer"},
			}}})

			assert.Empty(t, findings)
		})
	}
}

func TestNetworkTarget_PrefersIP(t *testing.T) {
	target, ok := networkTarget(plugins.Input{IP: "8.8.8.8", CIDR: "8.8.8.0/24"})

	assert.True(t, ok)
	assert.Equal(t, "8.8.8.8", target)
}
