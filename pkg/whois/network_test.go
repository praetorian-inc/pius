package whois

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/openrdap/rdap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateNetworkTarget(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{name: "IPv4", query: "8.8.8.8"},
		{name: "IPv6", query: "2606:4700:4700::1111"},
		{name: "canonical CIDR", query: "8.8.8.7/24"},
		{name: "private IPv4", query: "10.0.0.1"},
		{name: "private IPv6", query: "fd00::1"},
		{name: "documentation IPv4", query: "192.0.2.1"},
		{name: "documentation IPv6", query: "2001:db8::1"},
		{name: "invalid", query: "not-an-ip", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateNetworkTarget(test.query)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestRequireContainingAllocation(t *testing.T) {
	target, err := parseNetworkTarget("8.8.8.0/23")
	require.NoError(t, err)

	tests := []struct {
		name    string
		start   string
		end     string
		wantErr bool
	}{
		{name: "exact", start: "8.8.8.0", end: "8.8.9.255"},
		{name: "parent", start: "8.8.0.0", end: "8.8.255.255"},
		{name: "only first half", start: "8.8.8.0", end: "8.8.8.255", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := requireContainingAllocation(NetworkResult{
				StartAddress: test.start,
				EndAddress:   test.end,
			}, target)
			if test.wantErr {
				assert.ErrorIs(t, err, ErrAllocationDoesNotContainTarget)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestLastAddress(t *testing.T) {
	tests := []struct {
		prefix string
		want   string
	}{
		{prefix: "8.8.8.0/24", want: "8.8.8.255"},
		{prefix: "2001:db8::/126", want: "2001:db8::3"},
	}
	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			prefix := netip.MustParsePrefix(test.prefix)
			assert.Equal(t, test.want, lastAddress(prefix).String())
		})
	}
}

func TestLookupNetwork_FallsBackToTCP43(t *testing.T) {
	original := tcp43RawFn
	tcp43RawFn = func(_ context.Context, query, server string) (string, error) {
		switch server {
		case defaultServer:
			return "refer: whois.example.test\n", nil
		case "whois.example.test":
			return "NetRange: 8.8.8.0 - 8.8.8.255\nOrgName: Example Networks\nOrganization: Example Networks (EXAMPLE-1)\nOrgAbuseEmail: abuse@example.com\n", nil
		default:
			return "", errors.New("unexpected server")
		}
	}
	t.Cleanup(func() { tcp43RawFn = original })

	result, err := LookupNetwork(context.Background(), "8.8.8.8", WithHTTPClient(failingHTTPClient()))
	require.NoError(t, err)
	assert.Equal(t, []string{"whois"}, result.Sources)
	assert.Equal(t, "whois.example.test", result.Server)
	assert.Equal(t, "8.8.8.0", result.StartAddress)
	assert.Equal(t, "8.8.8.255", result.EndAddress)
	require.Len(t, result.Contacts, 2)
	assert.Equal(t, "Example Networks", result.Contacts[0].Organization)
	assert.Equal(t, "abuse@example.com", result.Contacts[1].Email)
}

type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("RDAP unavailable")
}

func failingHTTPClient() *http.Client {
	return &http.Client{Transport: failingRoundTripper{}}
}

func TestRDAPResponseServer(t *testing.T) {
	response := &rdap.Response{HTTP: []*rdap.HTTPResponse{{
		URL: "https://rdap.example.test/ip/8.8.8.8",
	}}}

	assert.Equal(t, "rdap.example.test", rdapResponseServer(response))
}

func TestMapRDAPToNetworkResult_RecursesEntities(t *testing.T) {
	vcard, err := rdap.NewVCard([]byte(`["vcard",[["version",{},"text","4.0"],["kind",{},"text","org"],["fn",{},"text","Jane Doe"],["org",{},"text","Example Networks"],["email",{},"text","jane@example.com"]]]`))
	require.NoError(t, err)

	result := mapRDAPToNetworkResult("8.8.8.8", &rdap.IPNetwork{
		Handle:       "NET-8-8-8-0-1",
		StartAddress: "8.8.8.0",
		EndAddress:   "8.8.8.255",
		Entities: []rdap.Entity{{
			Entities: []rdap.Entity{{Handle: "EXAMPLE-TECH", Roles: []string{"technical"}, VCard: vcard}},
		}},
	})

	require.Len(t, result.Contacts, 1)
	assert.Equal(t, "EXAMPLE-TECH", result.Contacts[0].Handle)
	assert.Equal(t, []string{"technical"}, result.Contacts[0].Roles)
	assert.Equal(t, "org", result.Contacts[0].Kind)
	assert.False(t, result.Contacts[0].Direct)
	assert.Equal(t, "Example Networks", result.Contacts[0].Organization)
	assert.Equal(t, "jane@example.com", result.Contacts[0].Email)
}
