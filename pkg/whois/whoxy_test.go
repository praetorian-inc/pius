package whois

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const whoxyRawRecord = `Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.example-registrar.com
Registrar URL: http://www.example-registrar.com
Updated Date: 2024-08-14T07:01:44Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Registrar: Example Registrar, Inc.
Registrant Organization: Example Corp
Registrant Name: Jane Doe
Registrant Email: jane@example.com
Registrant Phone: +1.4155550100
Registrant Street: 1 Example Street
Registrant Postal Code: 94105
Registrant Country: US
Registrant State/Province: CA
Registrant City: San Francisco
Admin Organization: Example Corp
Admin Email: admin@example.com
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
DNSSEC: unsigned
`

// newWhoxyTestResolver points a resolver at a stub server so no real request is
// ever made.
func newWhoxyTestResolver(t *testing.T, handler http.HandlerFunc) *WhoxyClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	r := NewWhoxyClient(srv.Client(), "test-key")
	r.baseURL = srv.URL
	return r
}

func TestWhoxyResolver_Name(t *testing.T) {
	assert.Equal(t, ProviderWhoxy, NewWhoxyClient(nil, "k").Name())
}

func TestWhoxyClient_ReverseLookup(t *testing.T) {
	client := newWhoxyTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		query := req.URL.Query()
		assert.Equal(t, "test-key", query.Get("key"))
		assert.Equal(t, "whois", query.Get("reverse"))
		assert.Equal(t, "Acme Corp", query.Get("company"))
		assert.Equal(t, "micro", query.Get("mode"))
		assert.Equal(t, "2", query.Get("page"))

		_ = json.NewEncoder(w).Encode(WhoxyReverseResponse{
			TotalPages: 3,
			SearchResult: []WhoxyReverseResult{
				{DomainName: "example.com", QueryTime: "2025-01-01 00:00:00"},
			},
		})
	})

	response, err := client.ReverseLookup(context.Background(), "company", "Acme Corp", 2)

	require.NoError(t, err)
	assert.Equal(t, 3, response.TotalPages)
	require.Len(t, response.SearchResult, 1)
	assert.Equal(t, "example.com", response.SearchResult[0].DomainName)
}

func TestWhoxyClient_ReverseLookupValidatesInput(t *testing.T) {
	client := NewWhoxyClient(nil, "test-key")

	_, err := client.ReverseLookup(context.Background(), "domain", "example.com", 1)
	assert.ErrorContains(t, err, "unsupported reverse-WHOIS field")

	_, err = client.ReverseLookup(context.Background(), "company", "Acme", 0)
	assert.ErrorContains(t, err, "page must be positive")
}

func TestWhoxyClient_ReverseLookupRequiresCredential(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")

	_, err := NewWhoxyClient(nil, "").ReverseLookup(context.Background(), "company", "Acme", 1)

	assert.ErrorIs(t, err, ErrNoCredential)
}

func TestWhoxyResolver_Success(t *testing.T) {
	var gotQuery string
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		gotQuery = req.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":1,"raw_whois":` + jsonQuote(t, whoxyRawRecord) + `}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.com")
	require.NoError(t, err)

	assert.Contains(t, gotQuery, "key=test-key")
	assert.Contains(t, gotQuery, "whois=example.com")

	assert.Equal(t, "example.com", result.Domain)
	assert.Equal(t, "Example Registrar, Inc.", result.Registrar)
	assert.Equal(t, "Example Corp", result.Registrant.Organization)
	assert.Equal(t, "Jane Doe", result.Registrant.Name)
	assert.Equal(t, "jane@example.com", result.Registrant.Email)
	assert.Equal(t, "+1.4155550100", result.Registrant.Phone)
	assert.Equal(t, "1 Example Street", result.Registrant.Street)
	assert.Equal(t, "94105", result.Registrant.PostalCode)
	assert.Equal(t, "whois.example-registrar.com", result.WhoisServer)
	assert.Equal(t, "unsigned", result.DNSSEC)
	assert.Equal(t, []string{ProviderWhoxy}, result.Sources)
	assert.Len(t, result.NameServers, 2)
}

func TestWhoxyResolver_AppliesDNSPTFallback(t *testing.T) {
	raw := "Generator: test\nRegistry WHOIS: whois.dns.pt\n\n" + readDomainFixture(t, "dns_pt.raw")
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":1,"raw_whois":` + jsonQuote(t, raw) + `}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.pt")

	require.NoError(t, err)
	assert.Equal(t, "Example Networks", result.RegistrantIdentity)
	assert.Equal(t, "1 Example Street", result.Registrant.Street)
	assert.Equal(t, "1000-001", result.Registrant.PostalCode)
	assert.Equal(t, "Example Registrar", result.Admin.Name)
	assert.Equal(t, "whois.dns.pt", result.WhoisServer)
	assert.Equal(t, []string{"ns1.example.net", "ns2.example.net"}, result.NameServers)
}

func TestWhoxyResolver_PreservesRegistryCOFields(t *testing.T) {
	raw := "Generator: test\nRegistry WHOIS: whois.registry.co\n\n" + readDomainFixture(t, "registry_co.raw")
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":1,"raw_whois":` + jsonQuote(t, raw) + `}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.co")

	require.NoError(t, err)
	assert.Equal(t, "Example Registrar, LLC", result.Registrar)
	assert.Equal(t, "unsigned", result.DNSSEC)
	assert.Equal(t, "whois.registry.co", result.WhoisServer)
	assert.NotEmpty(t, result.Registrant.Email)
	assert.Empty(t, result.ContactEmail)
}

func TestWhoxyResolver_RecoversNICChileRecord(t *testing.T) {
	raw := "Generator: test\nRegistry WHOIS: whois.nic.cl\n\n" + readDomainFixture(t, "nic_cl.raw")
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":1,"raw_whois":` + jsonQuote(t, raw) + `}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.cl")

	require.NoError(t, err)
	assert.Equal(t, "Example Media LLC", result.RegistrantIdentity)
	assert.Equal(t, "Example Registrar", result.Registrar)
	assert.Equal(t, "whois.nic.cl", result.WhoisServer)
	assert.Equal(t, []string{ProviderWhoxy}, result.Sources)
}

func TestWhoxyResolver_RejectsRegistryDenial(t *testing.T) {
	raw := readDomainFixture(t, "nic_ch_denied.raw")
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":1,"raw_whois":` + jsonQuote(t, raw) + `}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.ch")

	assert.ErrorIs(t, err, errRegistryAccessDenied)
	assert.Equal(t, DomainResult{}, result)
}

// TestWhoxyResolver_ZeroBalanceIsAFailure is the case that matters
// operationally: Whoxy reports an exhausted credit pool with HTTP 200 and
// status != 1. Treating that as data would record an empty record as fact.
func TestWhoxyResolver_ZeroBalanceIsAFailure(t *testing.T) {
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":0,"status_reason":"Zero Account Balance"}`))
	})

	_, err := r.LookupDomain(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Zero Account Balance")
}

func TestWhoxyResolver_NoCredential(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")

	_, err := NewWhoxyClient(nil, "").LookupDomain(context.Background(), "example.com")

	assert.ErrorIs(t, err, ErrNoCredential)
}

func TestWhoxyResolver_EnvFallback(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "from-env")

	r := NewWhoxyClient(nil, "")
	assert.True(t, r.hasCredential())
	assert.Equal(t, "from-env", r.getAPIKey())

	assert.Equal(t, "explicit", NewWhoxyClient(nil, "explicit").getAPIKey(),
		"an explicit key should win over the environment")
}

func TestWhoxyResolver_EmptyRecordIsNotAnAnswer(t *testing.T) {
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":1,"raw_whois":""}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Empty(t, result.Domain, "an empty record must not end the fallback route")
}

func TestWhoxyResolver_HTTPError(t *testing.T) {
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})

	_, err := r.LookupDomain(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "429")
}

// TestWhoxyResolver_ErrorsDoNotLeakAPIKey: Whoxy authenticates with a query
// parameter, so a naively wrapped transport error renders the whole URL — key
// included — into logs.
func TestWhoxyResolver_ErrorsDoNotLeakAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // force a connection failure

	r := NewWhoxyClient(nil, "super-secret-key")
	r.baseURL = url

	_, err := r.LookupDomain(context.Background(), "example.com")

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "super-secret-key")
}

func TestWhoxyClient_LookupDomainHistory(t *testing.T) {
	client := newWhoxyTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "test-key", req.URL.Query().Get("key"))
		assert.Equal(t, "example.com", req.URL.Query().Get("history"))
		assert.Empty(t, req.URL.Query().Get("whois"))
		_, _ = w.Write([]byte(`{
			"status": 1,
			"whois_records": [
				{
					"query_time": "2024-01-01 00:00:00",
					"domain_name": "example.com",
					"domain_registrar": {"registrar_name": "Old Registrar"}
				},
				{
					"query_time": "2025-01-01 00:00:00",
					"domain_name": "example.com",
					"create_date": "1995-08-14",
					"domain_registrar": {
						"registrar_name": "Current Registrar",
						"whois_server": "whois.current.example"
					},
					"registrant_contact": {
						"full_name": "Jane Doe",
						"company_name": "Example Corp",
						"email_address": "jane@example.com",
						"mailing_address": "1 Example Way",
						"city_name": "San Francisco",
						"state_name": "CA",
						"zip_code": "94105",
						"country_code": "US",
						"phone_number": "+1.5555550100"
					},
					"name_servers": ["ns1.example.com"],
					"domain_status": ["clientTransferProhibited"]
				}
			]
		}`))
	})

	records, err := client.LookupDomainHistory(context.Background(), "example.com")

	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, "2025-01-01 00:00:00", records[0].QueryTime)
	assert.Equal(t, "Current Registrar", records[0].Registrar)
	assert.Equal(t, "whois.current.example", records[0].WhoisServer)
	assert.Equal(t, "Example Corp", records[0].Registrant.Organization)
	assert.Equal(t, "Jane Doe", records[0].Registrant.Name)
	assert.Equal(t, "jane@example.com", records[0].Registrant.Email)
	assert.Equal(t, "US", records[0].Registrant.Country)
	assert.Equal(t, "1 Example Way", records[0].Registrant.Street)
	assert.Equal(t, []string{ProviderWhoxy}, records[0].Sources)
	assert.Equal(t, "Old Registrar", records[1].Registrar)
}

func TestWhoxyClient_LookupDomainHistoryRequiresCredential(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")

	_, err := NewWhoxyClient(nil, "").LookupDomainHistory(context.Background(), "example.com")

	assert.ErrorIs(t, err, ErrNoCredential)
}

func TestWhoxyClient_LookupDomainHistoryRejectsProviderError(t *testing.T) {
	client := newWhoxyTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":0,"status_reason":"Zero Account Balance"}`))
	})

	_, err := client.LookupDomainHistory(context.Background(), "example.com")

	require.Error(t, err)
	assert.ErrorContains(t, err, "Zero Account Balance")
}

// jsonQuote renders s as a JSON string literal.
func jsonQuote(t *testing.T, s string) string {
	t.Helper()
	quoted, err := json.Marshal(s)
	require.NoError(t, err)
	return string(quoted)
}
