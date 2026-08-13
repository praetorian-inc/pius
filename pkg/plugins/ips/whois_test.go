package ips

import (
	"context"
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
		{name: "both", input: plugins.Input{IP: "8.8.8.8", CIDR: "8.8.8.0/24"}},
		{name: "neither", input: plugins.Input{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, plugin.Accepts(test.input))
		})
	}
}

func TestWhoisPlugin_RunEmitsResultAndPreseeds(t *testing.T) {
	plugin := NewWhoisPlugin(nil)
	plugin.lookup = func(context.Context, string, ...whois.Option) (whois.NetworkResult, error) {
		return whois.NetworkResult{
			Query:        "8.8.8.8",
			StartAddress: "8.8.8.0",
			EndAddress:   "8.8.8.255",
			Handle:       "NET-8-8-8-0-1",
			Registry:     "arin",
			Server:       "whois.example.test",
			Sources:      []string{"whois"},
			Contacts: []whois.NetworkContact{
				{Roles: []string{"registrant"}, Kind: "org", Direct: true, Name: "Example Networks", Email: "jane@example.com"},
				{Handle: "EXAMPLE-MNT", Roles: []string{"registrant"}, Kind: "individual", Direct: true, Name: "EXAMPLE-MNT"},
				{Roles: []string{"registrant"}, Kind: "org", Name: "Upstream ISP"},
				{Roles: []string{"technical"}, Kind: "group", Direct: true, Organization: "Carrier NOC", Email: "noc@carrier.example"},
			},
		}, nil
	}

	findings, err := plugin.Run(context.Background(), plugins.Input{IP: "8.8.8.8"})
	require.NoError(t, err)
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
		assert.Contains(t, finding.Confidences[0].Justification, `IP WHOIS server "whois.example.test"`)
		assert.Contains(t, finding.Confidences[0].Justification, `allocation "NET-8-8-8-0-1" spanning 8.8.8.0-8.8.8.255`)
		assert.Contains(t, finding.Confidences[0].Justification, `returned for query "8.8.8.8"`)
	}
}

func TestNetworkPreseeds_PrefersCustomerOverRegistrant(t *testing.T) {
	findings := networkPreseeds(whois.NetworkResult{Contacts: []whois.NetworkContact{
		{Roles: []string{"registrant"}, Kind: "org", Direct: true, Name: "Upstream ISP"},
		{Roles: []string{"customer"}, Kind: "org", Direct: true, Name: "Example Customer"},
	}})

	require.Len(t, findings, 1)
	assert.Equal(t, "Example Customer", findings[0].Value)
}

func TestWhoisPlugin_RunRejectsAmbiguousInput(t *testing.T) {
	plugin := NewWhoisPlugin(nil)
	_, err := plugin.Run(context.Background(), plugins.Input{IP: "8.8.8.8", CIDR: "8.8.8.0/24"})
	assert.Error(t, err)
}
