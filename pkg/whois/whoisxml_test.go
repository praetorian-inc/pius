package whois

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const whoisXMLRecordJSON = `{
  "WhoisRecord": {
    "domainName": "example.com",
    "createdDate": "1995-08-14T04:00:00.000+00:00",
    "updatedDate": "2024-08-14T07:01:44.000+00:00",
    "expiresDate": "2027-08-13T04:00:00.000+00:00",
    "registrarName": "Example Registrar, Inc.",
    "whoisServer": "whois.example-registrar.com",
    "status": "clientTransferProhibited https://icann.org/epp#clientTransferProhibited clientDeleteProhibited",
    "nameServers": {"hostNames": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]},
    "registrant": {
      "name": "Jane Doe",
      "organization": "Example Corp",
      "email": "jane@example.com",
      "street1": "1 Example Way",
      "city": "San Francisco",
      "state": "CA",
      "postalCode": "94105",
      "country": "UNITED STATES",
      "countryCode": "US",
      "telephone": "+1.5555550100"
    },
    "administrativeContact": {"organization": "Example Corp", "email": "admin@example.com"}
  }
}`

func newWhoisXMLTestResolver(t *testing.T, handler http.HandlerFunc) *WhoisXMLResolver {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	r := NewWhoisXMLResolver(srv.Client(), "test-key")
	r.baseURL = srv.URL
	return r
}

func TestWhoisXMLResolver_Name(t *testing.T) {
	assert.Equal(t, ProviderWhoisXML, NewWhoisXMLResolver(nil, "k").Name())
}

func TestWhoisXMLResolver_Success(t *testing.T) {
	var gotQuery string
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		gotQuery = req.URL.RawQuery
		_, _ = w.Write([]byte(whoisXMLRecordJSON))
	})

	result, err := r.Lookup(context.Background(), "example.com")
	require.NoError(t, err)

	assert.Contains(t, gotQuery, "apiKey=test-key")
	assert.Contains(t, gotQuery, "domainName=example.com")
	assert.Contains(t, gotQuery, "outputFormat=JSON")

	assert.Equal(t, "example.com", result.Domain)
	assert.Equal(t, "Example Registrar, Inc.", result.Registrar)
	assert.Equal(t, "1995-08-14T04:00:00.000+00:00", result.Created)
	assert.Equal(t, "2027-08-13T04:00:00.000+00:00", result.Expiration)
	assert.Equal(t, []string{"NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"}, result.NameServers)
	assert.Equal(t, []string{ProviderWhoisXML}, result.Sources)

	assert.Equal(t, "Example Corp", result.Registrant.Organization)
	assert.Equal(t, "Jane Doe", result.Registrant.Name)
	assert.Equal(t, "US", result.Registrant.Country, "the ISO code should win over the country name")
	assert.Equal(t, "1 Example Way", result.Registrant.Street)
	assert.Equal(t, "+1.5555550100", result.Registrant.Phone)
	assert.Equal(t, "admin@example.com", result.Admin.Email)
}

// TestWhoisXMLResolver_HardRefreshOffByDefault guards a 5x cost multiplier: a
// hard refresh costs 5 credits against 1, so it must never be sent implicitly.
func TestWhoisXMLResolver_HardRefreshOffByDefault(t *testing.T) {
	var gotQuery string
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		gotQuery = req.URL.RawQuery
		_, _ = w.Write([]byte(whoisXMLRecordJSON))
	})

	_, err := r.Lookup(context.Background(), "example.com")
	require.NoError(t, err)

	assert.NotContains(t, gotQuery, "_hardRefresh",
		"hard refresh costs 5 credits per query and must be opt-in")
}

func TestWhoisXMLResolver_HardRefreshWhenEnabled(t *testing.T) {
	var gotQuery string
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		gotQuery = req.URL.RawQuery
		_, _ = w.Write([]byte(whoisXMLRecordJSON))
	})

	_, err := r.WithHardRefresh(true).Lookup(context.Background(), "example.com")
	require.NoError(t, err)

	assert.Contains(t, gotQuery, "_hardRefresh=1")
}

// TestWhoisXMLResolver_CreditExhaustionOnHTTP200: WhoisXML reports an exhausted
// or unauthorized account as AUTHENTICATE_06 inside a 200 response, so the
// status code alone cannot be trusted to mean success.
func TestWhoisXMLResolver_CreditExhaustionOnHTTP200(t *testing.T) {
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ErrorMessage":{"errorCode":"AUTHENTICATE_06","msg":"Access restricted"}}`))
	})

	_, err := r.Lookup(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
}

// TestWhoisXMLResolver_MissingDataIsNotUnregistered: absent data is weaker
// evidence than a registry saying the domain does not exist. Reporting it as
// unregistered would mark a live domain dead.
func TestWhoisXMLResolver_MissingDataIsNotUnregistered(t *testing.T) {
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"WhoisRecord":{"domainName":"example.com","dataError":"MISSING_WHOIS_DATA"}}`))
	})

	result, err := r.Lookup(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Empty(t, result.Domain, "no usable record, so the route should continue")
	assert.False(t, result.Unregistered)
}

// TestWhoisXMLResolver_FillsFromRegistryData: reserved and thin-registry
// domains populate the registry-level record while the registrar-level one is
// sparse.
func TestWhoisXMLResolver_FillsFromRegistryData(t *testing.T) {
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "WhoisRecord": {
		    "domainName": "example.com",
		    "registrarName": "RESERVED-Internet Assigned Numbers Authority",
		    "dataError": "RESERVED_DOMAIN_NAME",
		    "registryData": {
		      "createdDate": "1995-08-14T04:00:00Z",
		      "expiresDate": "2027-08-13T04:00:00Z",
		      "nameServers": {"hostNames": ["A.IANA-SERVERS.NET"]}
		    }
		  }
		}`))
	})

	result, err := r.Lookup(context.Background(), "example.com")
	require.NoError(t, err)

	assert.Equal(t, "RESERVED-Internet Assigned Numbers Authority", result.Registrar,
		"the registrar-level value must not be overwritten")
	assert.Equal(t, "1995-08-14T04:00:00Z", result.Created, "gaps should be filled from registryData")
	assert.Equal(t, []string{"A.IANA-SERVERS.NET"}, result.NameServers)
}

func TestWhoisXMLResolver_NoCredential(t *testing.T) {
	t.Setenv("WHOISXML_API_KEY", "")

	_, err := NewWhoisXMLResolver(nil, "").Lookup(context.Background(), "example.com")

	assert.ErrorIs(t, err, ErrNoCredential)
}

func TestWhoisXMLResolver_EnvFallback(t *testing.T) {
	t.Setenv("WHOISXML_API_KEY", "from-env")

	assert.True(t, NewWhoisXMLResolver(nil, "").hasCredential())
	assert.Equal(t, "from-env", NewWhoisXMLResolver(nil, "").resolveAPIKey())
	assert.Equal(t, "explicit", NewWhoisXMLResolver(nil, "explicit").resolveAPIKey())
}

func TestWhoisXMLResolver_ErrorsDoNotLeakAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	r := NewWhoisXMLResolver(nil, "super-secret-key")
	r.baseURL = url

	_, err := r.Lookup(context.Background(), "example.com")

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "super-secret-key")
}

// TestSplitWhoisXMLStatus: WhoisXML returns EPP statuses as one space-separated
// string, each routinely followed by the ICANN URL documenting it. The URLs are
// noise, not status.
func TestSplitWhoisXMLStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"only urls", "https://icann.org/epp#x", nil},
		{
			"strips documentation urls",
			"clientTransferProhibited https://icann.org/epp#clientTransferProhibited clientDeleteProhibited",
			[]string{"clientTransferProhibited", "clientDeleteProhibited"},
		},
		{"single status", "ok", []string{"ok"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, splitWhoisXMLStatus(tc.in))
		})
	}
}
