package whois

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrdap/rdap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapRDAPToResult_PreservesDNSSEC(t *testing.T) {
	signed, unsigned := true, false
	tests := []struct {
		name      string
		secureDNS *rdap.SecureDNS
		expected  string
	}{
		{name: "delegation signed", secureDNS: &rdap.SecureDNS{DelegationSigned: &signed}, expected: "signed"},
		{name: "delegation unsigned", secureDNS: &rdap.SecureDNS{DelegationSigned: &unsigned}, expected: "unsigned"},
		{name: "zone signed fallback", secureDNS: &rdap.SecureDNS{ZoneSigned: &signed}, expected: "signed"},
		{name: "zone unsigned fallback", secureDNS: &rdap.SecureDNS{ZoneSigned: &unsigned}, expected: "unsigned"},
		{name: "unknown", secureDNS: &rdap.SecureDNS{}},
		{name: "missing"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := mapRDAPToResult("example.com", &rdap.Domain{SecureDNS: test.secureDNS})

			assert.Equal(t, test.expected, result.DNSSEC)
		})
	}
}

func TestEnrichFromRegistrar_PreservesPartialContact(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{
			"rdapConformance":["rdap_level_0"],
			"objectClassName":"domain",
			"ldhName":"example.com",
			"entities":[{
				"objectClassName":"entity",
				"roles":["registrant"],
				"vcardArray":["vcard",[
					["version",{},"text","4.0"],
					["tel",{"type":"voice"},"uri","tel:+1.4155550100"]
				]]
			}]
		}`))
	}))
	t.Cleanup(server.Close)

	result := DomainResult{Registrant: Contact{Country: "US"}}
	enrichFromRegistrar(context.Background(), &rdap.Client{HTTP: server.Client()}, &result, &rdap.Domain{
		Links: []rdap.Link{{Rel: "related", Type: "application/rdap+json", Href: server.URL}},
	})

	assert.Equal(t, "US", result.Registrant.Country)
	assert.Equal(t, "+1.4155550100", result.Registrant.Phone)
}

func TestEnrichFromRegistrar_MergesFullRecord(t *testing.T) {
	fixture := readDomainFixture(t, "rdap_contacts.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(fixture))
	}))
	t.Cleanup(server.Close)

	result := DomainResult{
		Domain: "example.com", Registrar: "Registry Registrar",
		Registrant: Contact{Organization: PrivacyRedaction},
		Admin:      Contact{Name: "Existing Admin"},
	}
	enrichFromRegistrar(t.Context(), &rdap.Client{HTTP: server.Client()}, &result, &rdap.Domain{
		Links: []rdap.Link{{Rel: "related", Type: "application/rdap+json", Href: server.URL}},
	})

	assert.Equal(t, "Registry Registrar", result.Registrar)
	assert.Equal(t, PrivacyRedaction, result.Registrant.Organization)
	assert.Equal(t, "Existing Admin", result.Admin.Name)
	assert.Equal(t, "admin@example.com", result.Admin.Email)
	assert.Equal(t, "tech@example.com", result.Tech.Email)
	assert.Equal(t, "billing@example.com", result.Billing.Email)
	assert.Equal(t, "2026-09-19T12:45:42Z", result.Expiration)
	assert.Equal(t, []string{"ns1.example.com"}, result.NameServers)
}

func TestEnrichFromRegistrar_TriesNextRelatedLinkAfterFailure(t *testing.T) {
	fixture := readDomainFixture(t, "rdap_contacts.json")
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path != "/registrar" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(fixture))
	}))
	t.Cleanup(server.Close)

	result := DomainResult{Domain: "example.com"}
	enrichFromRegistrar(t.Context(), &rdap.Client{HTTP: server.Client()}, &result, &rdap.Domain{
		Links: []rdap.Link{
			{Rel: "self", Type: "application/rdap+json", Href: server.URL + "/self"},
			{Rel: "related", Type: "text/html", Href: server.URL + "/html"},
			{Rel: "related", Type: "application/rdap+json", Href: server.URL + "/broken"},
			{Rel: "related", Type: "application/rdap+json", Href: server.URL + "/registrar"},
			{Rel: "related", Type: "application/rdap+json", Href: server.URL + "/unused"},
		},
	})

	assert.Equal(t, []string{"/broken", "/registrar"}, paths)
	assert.Equal(t, "Example Registrar", result.Registrar)
	assert.Equal(t, "tech@example.com", result.Tech.Email)
}

func TestContactFromVCard_CleansIdentity(t *testing.T) {
	tests := []struct {
		name         string
		contactName  string
		organization string
		expected     Contact
	}{
		{
			name:         "trims identity",
			contactName:  " Jane Doe ",
			organization: " Example Inc. ",
			expected: Contact{
				Name:         "Jane Doe",
				Organization: "Example Inc.",
			},
		},
		{
			name:         "clears whitespace-only identity",
			contactName:  " ",
			organization: "\t",
			expected:     Contact{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vcard := &rdap.VCard{Properties: []*rdap.VCardProperty{
				{Name: "fn", Type: "text", Value: test.contactName},
				{Name: "org", Type: "text", Value: test.organization},
			}}

			assert.Equal(t, test.expected, contactFromVCard(vcard))
		})
	}
}

func TestContactFromVCard_PreservesContactFields(t *testing.T) {
	vcard, err := rdap.NewVCard([]byte(`[
		"vcard",
		[
			["version", {}, "text", "4.0"],
			["fn", {}, "text", "Jane Doe"],
			["org", {}, "text", "Example Inc."],
			["email", {}, "text", "jane@example.com"],
			["tel", {"type": "voice"}, "uri", "tel:+1.4155550100"],
			["adr", {"cc": "US"}, "text", ["", "", "1 Main St", "San Francisco", "CA", "94105", "US"]]
		]
	]`))
	require.NoError(t, err)

	contact := contactFromVCard(vcard)

	assert.Equal(t, Contact{
		Name:         "Jane Doe",
		Organization: "Example Inc.",
		Email:        "jane@example.com",
		Phone:        "+1.4155550100",
		Country:      "US",
		Province:     "CA",
		City:         "San Francisco",
		Street:       "1 Main St",
		PostalCode:   "94105",
	}, contact)
}

func TestContactFromVCard_PreservesPrivacyEvidence(t *testing.T) {
	vcard, err := rdap.NewVCard([]byte(`[
		"vcard",
		[
			["version", {}, "text", "4.0"],
			["fn", {}, "text", "REDACTED REGISTRANT"],
			["org", {}, "text", "Example Inc."],
			["email", {}, "text", "REDACTED FOR PRIVACY"],
			["tel", {"type": "voice"}, "text", "REDACTED FOR PRIVACY"]
		]
	]`))
	require.NoError(t, err)

	contact := contactFromVCard(vcard)

	assert.Equal(t, "Example Inc.", contact.Organization)
	assert.Equal(t, PrivacyRedaction, contact.Name)
	assert.Equal(t, PrivacyRedaction, contact.Email)
	assert.Equal(t, PrivacyRedaction, contact.Phone)
}
