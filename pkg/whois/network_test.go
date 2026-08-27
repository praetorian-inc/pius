package whois

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
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

func TestPreferredNetworkRole_IgnoresPrivacyProtectedCustomer(t *testing.T) {
	contacts := []NetworkContact{
		{Roles: []string{"customer"}, Status: []string{"private"}, Direct: true, Contact: Contact{Name: "Private Customer"}},
		{Roles: []string{"registrant"}, Direct: true, Contact: Contact{Name: "Public Registrant"}},
	}

	assert.Equal(t, "registrant", PreferredNetworkRole(contacts))
}

func TestPreferredNetworkRole_IgnoresRedactedCustomer(t *testing.T) {
	contacts := []NetworkContact{
		{Roles: []string{"customer"}, Kind: "org", Direct: true, Contact: Contact{Organization: PrivacyRedaction}},
		{Roles: []string{"registrant"}, Kind: "org", Direct: true, Contact: Contact{Organization: "Public Registrant"}},
	}

	assert.Equal(t, "registrant", PreferredNetworkRole(contacts))
}

func TestHasUsefulNetworkIdentity_IgnoresPrivacyProtectedContact(t *testing.T) {
	contacts := []NetworkContact{{
		Roles: []string{"registrant"}, Status: []string{"private"}, Kind: "org", Direct: true,
		Contact: Contact{Name: "Private Customer"},
	}}

	assert.False(t, hasUsefulNetworkIdentity(contacts))
}

func TestHasUsefulNetworkIdentity_IgnoresRedactedContact(t *testing.T) {
	contacts := []NetworkContact{{
		Roles: []string{"registrant"}, Kind: "org", Direct: true,
		Contact: Contact{Organization: PrivacyRedaction, Email: PrivacyRedaction},
	}}

	assert.False(t, hasUsefulNetworkIdentity(contacts))
}

func TestMergeTCP43NetworkResult_PreservesServerAttribution(t *testing.T) {
	rdapResult := NetworkResult{
		Registry:   "whois.ripe.net",
		Server:     "rdap.db.ripe.net",
		RDAPServer: "rdap.db.ripe.net",
		Sources:    []string{"rdap"},
		Contacts: []NetworkContact{{
			Roles: []string{"technical"}, Kind: "group", Direct: true,
			Contact: Contact{Name: "Network Operations"},
		}},
	}
	tcpResult := NetworkResult{
		Server:      "whois.ripe.net",
		WhoisServer: "whois.ripe.net",
		Sources:     []string{"whois"},
		Raw:         "raw response",
		Contacts: []NetworkContact{{
			Roles: []string{"registrant"}, Kind: "org", Direct: true,
			Contact: Contact{Organization: "Example Networks"},
		}},
	}

	mergeTCP43NetworkResult(&rdapResult, tcpResult)

	assert.Equal(t, "rdap.db.ripe.net", rdapResult.Server)
	assert.Equal(t, "rdap.db.ripe.net", rdapResult.RDAPServer)
	assert.Equal(t, "whois.ripe.net", rdapResult.WhoisServer)
	assert.Equal(t, []string{"rdap", "whois"}, rdapResult.Sources)
	assert.Equal(t, "raw response", rdapResult.Raw)
	require.Len(t, rdapResult.Contacts, 2)
}

func TestLookupNetwork_SuccessfulRDAPWithoutUsefulIdentityFallsBackToTCP43(t *testing.T) {
	original := tcp43RawFn
	tcp43RawFn = func(_ context.Context, query, server string) (string, error) {
		switch {
		case query == "8.8.8.8" && server == defaultServer:
			return "refer: whois.example.test\n", nil
		case query == "8.8.8.8" && server == "whois.example.test":
			return "NetRange: 8.8.8.0 - 8.8.8.255\nOrgName: Example Networks\n", nil
		default:
			return "", errors.New("unexpected query")
		}
	}
	t.Cleanup(func() { tcp43RawFn = original })

	result, err := LookupNetwork(context.Background(), "8.8.8.8", WithHTTPClient(&http.Client{
		Transport: rdapResponseRoundTripper{},
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"rdap", "whois"}, result.Sources)
	assert.Equal(t, "rdap.arin.net", result.RDAPServer)
	assert.Equal(t, "whois.example.test", result.WhoisServer)
	assert.Equal(t, "NET-8-8-8-0-1", result.Handle)
	assert.Equal(t, []string{"active"}, result.Status)
	require.Len(t, result.Contacts, 3)
	assert.Equal(t, "ABUSE-1", result.Contacts[0].Handle)
	assert.Equal(t, []string{"abuse"}, result.Contacts[0].Roles)
	assert.Equal(t, []string{"validated"}, result.Contacts[0].Status)
	assert.Equal(t, "group", result.Contacts[0].Kind)
	assert.Equal(t, "Abuse Desk", result.Contacts[0].Name)
	assert.Equal(t, "abuse@example.com", result.Contacts[0].Email)
	assert.Equal(t, PrivacyRedaction, result.Contacts[1].Organization)
	assert.Equal(t, PrivacyRedaction, result.Contacts[1].Email)
	assert.Equal(t, "Example Networks", result.Contacts[2].Organization)
}

type rdapResponseRoundTripper struct{}

func (rdapResponseRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	const response = `{
		"rdapConformance":["rdap_level_0"],
		"objectClassName":"ip network",
		"handle":" NET-8-8-8-0-1 ",
		"port43":" whois.example.test ",
		"startAddress":" 8.8.8.0 ",
		"endAddress":" 8.8.8.255 ",
		"ipVersion":"v4",
		"status":[" active "," "],
		"entities":[{
			"objectClassName":"entity",
			"handle":" ABUSE-1 ",
			"roles":[" abuse "," "],
			"status":[" validated "," "],
			"vcardArray":["vcard",[
				["version",{},"text","4.0"],
				["kind",{},"text"," group "],
				["fn",{},"text"," Abuse Desk "],
				["email",{},"text"," abuse@example.com "]
			]]
		},{
			"objectClassName":"entity",
			"handle":" CUSTOMER-1 ",
			"roles":[" customer "],
			"vcardArray":["vcard",[
				["version",{},"text","4.0"],
				["kind",{},"text"," org "],
				["fn",{},"text"," REDACTED FOR PRIVACY "],
				["org",{},"text"," REDACTED FOR PRIVACY "],
				["email",{},"text"," domains@markmonitor.com "]
			]]
		}]
	}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/rdap+json"}},
		Body:       io.NopCloser(strings.NewReader(response)),
		Request:    request,
	}, nil
}

func TestParseTCP43NetworkResult_AcceptsCIDRFormInetnum(t *testing.T) {
	target, err := parseNetworkTarget("200.0.0.1")
	require.NoError(t, err)

	result, err := parseTCP43NetworkResult(target, "inetnum: 200.0.0.0/21\nowner: HOCOL S.A.\n", " whois.lacnic.net ")
	require.NoError(t, err)
	assert.Equal(t, "200.0.0.0", result.StartAddress)
	assert.Equal(t, "200.0.7.255", result.EndAddress)
	assert.Equal(t, "whois.lacnic.net", result.Registry)
	assert.Equal(t, "whois.lacnic.net", result.WhoisServer)
}

func TestTCP43NetworkContacts_NormalizesPrivacyEmail(t *testing.T) {
	result := NetworkResult{Contacts: tcp43NetworkContacts(map[string][]string{
		"email": {"zzzz03.com@shieldwhois.com"},
	})}

	result.Normalize()

	require.Len(t, result.Contacts, 1)
	assert.Equal(t, PrivacyRedaction, result.Contacts[0].Email)
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
	assert.Equal(t, "whois.example.test", result.WhoisServer)
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

func TestNetworkContactFromVCard_UsesAddressLabelFallback(t *testing.T) {
	tests := []struct {
		name  string
		label string
		want  string
	}{
		{
			name:  "Watertown",
			label: "404 BERNARD\nWatertown\nWI\n53094\nUnited States",
			want:  "404 BERNARD, Watertown, WI, 53094, United States",
		},
		{
			name:  "Sun Prairie",
			label: "6000 AMERICAN PKWY\nSUN PRAIRIE\nWI\n53783\nUnited States",
			want:  "6000 AMERICAN PKWY, SUN PRAIRIE, WI, 53783, United States",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vcard, err := rdap.NewVCard([]byte(fmt.Sprintf(
				`["vcard",[["version",{},"text","4.0"],["kind",{},"text","org"],["fn",{},"text","Example"],["adr",{"label":%q},"text",["","","","","","",""]]]]`,
				test.label,
			)))
			require.NoError(t, err)

			contact := networkContactFromEntity(&rdap.Entity{
				Handle: "EXAMPLE", Roles: []string{"registrant"}, VCard: vcard,
			}, true)

			assert.Equal(t, test.want, contact.Street)
		})
	}
}

func TestMapRDAPToNetworkResult_PreservesPrivateEntityWithoutVCard(t *testing.T) {
	result := mapRDAPToNetworkResult("8.8.8.8", &rdap.IPNetwork{
		Status: []string{"active"},
		Entities: []rdap.Entity{{
			Handle: "PRIVATE-1", Roles: []string{"registrant"}, Status: []string{"private"},
		}},
	})

	assert.Equal(t, []string{"active"}, result.Status)
	require.Len(t, result.Contacts, 1)
	assert.Equal(t, "PRIVATE-1", result.Contacts[0].Handle)
	assert.True(t, result.Contacts[0].IsPrivacyProtected())
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
