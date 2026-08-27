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

func newWhoisXMLTestResolver(t *testing.T, handler http.HandlerFunc) *WhoisXMLClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	r := NewWhoisXMLClient(srv.Client(), "test-key")
	r.baseURL = srv.URL
	return r
}

func TestWhoisXMLResolver_Name(t *testing.T) {
	assert.Equal(t, ProviderWhoisXML, NewWhoisXMLClient(nil, "k").Name())
}

func TestWhoisXMLResolver_Success(t *testing.T) {
	var gotQuery string
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		gotQuery = req.URL.RawQuery
		_, _ = w.Write([]byte(whoisXMLRecordJSON))
	})

	result, err := r.LookupDomain(context.Background(), "example.com")
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

	_, err := r.LookupDomain(context.Background(), "example.com")
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

	_, err := r.WithHardRefresh(true).LookupDomain(context.Background(), "example.com")
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

	_, err := r.LookupDomain(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "AUTHENTICATE_06")
	assert.Contains(t, err.Error(), "Access restricted")
}

// TestWhoisXMLResolver_RecordMentioningErrorCodeIsNotAFailure: the exhaustion
// check reads the decoded error envelope, not the raw payload. A registry that
// happens to echo the marker inside a legitimate record must still parse — the
// same class of false positive that once produced a fabricated throttle verdict
// in the GATE 1 harness.
func TestWhoisXMLResolver_RecordMentioningErrorCodeIsNotAFailure(t *testing.T) {
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"WhoisRecord":{
		  "domainName":"example.com",
		  "registrarName":"Example Registrar, Inc.",
		  "registrant":{"organization":"AUTHENTICATE_06 Holdings"}
		}}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, "example.com", result.Domain)
	assert.Equal(t, "AUTHENTICATE_06 Holdings", result.Registrant.Organization)
}

// TestWhoisXMLResolver_MissingDataMeansUnregistered: WhoisXML documents
// MISSING_WHOIS_DATA as "domain is not registered; no need to retry fetching the
// data", so it is a verdict rather than a gap.
//
// Safe to believe despite coming from a fallback, because Lookup discards an
// Unregistered result from the route whenever RDAP or TCP-43 already returned a
// record — see TestFallbackUnregisteredNeverOverwritesAResolvedRecord.
func TestWhoisXMLResolver_MissingDataMeansUnregistered(t *testing.T) {
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"WhoisRecord":{"domainName":"example.com","dataError":"MISSING_WHOIS_DATA"}}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.True(t, result.Unregistered)
	assert.Equal(t, "example.com", result.Domain)
}

// TestWhoisXMLResolver_EmptyRecordIsNotAnAnswer: no domain name anywhere and no
// verdict either. That is a gap, not a verdict, so the route must continue.
func TestWhoisXMLResolver_EmptyRecordIsNotAnAnswer(t *testing.T) {
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"WhoisRecord":{}}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Empty(t, result.Domain)
	assert.False(t, result.Unregistered)
}

// TestWhoisXMLResolver_TakesContactsFromRegistryData is the ccTLD case, and the
// one that matters most for this fallback: WhoisXML documents that "most
// country-code TLDs contain only registryData", and ccTLDs are the bulk of the
// coverage gap the route exists to close. Since the route is entered precisely
// because registrant identity is missing, dropping contacts held only in
// registryData would mean paying a provider and still failing at the one job it
// was called for.
func TestWhoisXMLResolver_TakesContactsFromRegistryData(t *testing.T) {
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "WhoisRecord": {
		    "registryData": {
		      "domainName": "example.co.kr",
		      "createdDate": "2003-04-17T00:00:00Z",
		      "registrarName": "Registry Registrar",
		      "nameServers": {"hostNames": ["NS1.EXAMPLE.CO.KR"]},
		      "registrant": {
		        "name": "Registry Registrant",
		        "organization": "Registry Org",
		        "email": "reg@example.co.kr",
		        "countryCode": "KR"
		      },
		      "administrativeContact": {"organization": "Registry Admin Org"}
		    }
		  }
		}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.co.kr")
	require.NoError(t, err)

	assert.Equal(t, "Registry Org", result.Registrant.Organization,
		"the registrant must be taken from registryData when the top-level record has none")
	assert.Equal(t, "Registry Registrant", result.Registrant.Name)
	assert.Equal(t, "reg@example.co.kr", result.Registrant.Email)
	assert.Equal(t, "KR", result.Registrant.Country)
	assert.Equal(t, "Registry Admin Org", result.Admin.Organization)
	assert.True(t, result.HasRegistrant(),
		"a record satisfying the trigger condition is the point of the fallback")

	assert.Equal(t, "Registry Registrar", result.Registrar)
	assert.Equal(t, "2003-04-17T00:00:00Z", result.Created)
	assert.Equal(t, []string{"NS1.EXAMPLE.CO.KR"}, result.NameServers)
	assert.Equal(t, []string{ProviderWhoisXML}, result.Sources,
		"both halves came from one provider, so Sources must not double up")
}

// TestWhoisXMLResolver_TopLevelContactsWinOverRegistryData: registrar-level data
// is the more specific record, so registryData only fills gaps.
func TestWhoisXMLResolver_TopLevelContactsWinOverRegistryData(t *testing.T) {
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "WhoisRecord": {
		    "domainName": "example.com",
		    "registrant": {"organization": "Registrar Level Org"},
		    "registryData": {
		      "domainName": "example.com",
		      "registrant": {"organization": "Registry Level Org", "email": "fill@example.com"}
		    }
		  }
		}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.com")
	require.NoError(t, err)

	assert.Equal(t, "Registrar Level Org", result.Registrant.Organization)
	assert.Equal(t, "fill@example.com", result.Registrant.Email, "gaps are still filled")
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

	result, err := r.LookupDomain(context.Background(), "example.com")
	require.NoError(t, err)

	assert.Equal(t, "RESERVED-Internet Assigned Numbers Authority", result.Registrar,
		"the registrar-level value must not be overwritten")
	assert.Equal(t, "1995-08-14T04:00:00Z", result.Created, "gaps should be filled from registryData")
	assert.Equal(t, []string{"A.IANA-SERVERS.NET"}, result.NameServers)
}

func TestWhoisXMLResolver_NoCredential(t *testing.T) {
	t.Setenv("WHOISXML_API_KEY", "")

	_, err := NewWhoisXMLClient(nil, "").LookupDomain(context.Background(), "example.com")

	assert.ErrorIs(t, err, ErrNoCredential)
}

func TestWhoisXMLResolver_EnvFallback(t *testing.T) {
	t.Setenv("WHOISXML_API_KEY", "from-env")

	assert.True(t, NewWhoisXMLClient(nil, "").hasCredential())
	assert.Equal(t, "from-env", NewWhoisXMLClient(nil, "").resolveAPIKey())
	assert.Equal(t, "explicit", NewWhoisXMLClient(nil, "explicit").resolveAPIKey())
}

func TestWhoisXMLResolver_ErrorsDoNotLeakAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	r := NewWhoisXMLClient(nil, "super-secret-key")
	r.baseURL = url

	_, err := r.LookupDomain(context.Background(), "example.com")

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

// TestWhoisXMLResolver_OtherErrorCodesAreReported: WhoisXML reports every API
// error the same way — an ErrorMessage envelope with HTTP 200. Checking the
// decoded envelope rather than one known code means an invalid key surfaces as a
// failure instead of unmarshalling into an empty record and being silently
// skipped as "this provider has nothing".
func TestWhoisXMLResolver_OtherErrorCodesAreReported(t *testing.T) {
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ErrorMessage":{"errorCode":"AUTHENTICATE_01","msg":"Invalid API key"}}`))
	})

	_, err := r.LookupDomain(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "AUTHENTICATE_01")
	assert.Contains(t, err.Error(), "Invalid API key")
}

// TestWhoisXMLResolver_RegistryDataSurvivesRegistrarLevelMissingData is the thin-
// registry case: the registrar-level record carries dataError MISSING_WHOIS_DATA
// while registryData holds the actual record.
//
// Judging the marker before the merged record would discard a usable answer and,
// worse, report a live domain as unregistered — a verdict Guard persists as a
// cacheable success, so it would stick.
func TestWhoisXMLResolver_RegistryDataSurvivesRegistrarLevelMissingData(t *testing.T) {
	r := newWhoisXMLTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "WhoisRecord": {
		    "domainName": "example.co.kr",
		    "dataError": "MISSING_WHOIS_DATA",
		    "registryData": {
		      "domainName": "example.co.kr",
		      "createdDate": "2003-04-17T00:00:00Z",
		      "registrarName": "Registry Registrar",
		      "registrant": {"organization": "Registry Org"}
		    }
		  }
		}`))
	})

	result, err := r.LookupDomain(context.Background(), "example.co.kr")
	require.NoError(t, err)

	assert.False(t, result.Unregistered,
		"a usable registry record must not be discarded for a registrar-level marker")
	assert.Equal(t, "Registry Org", result.Registrant.Organization)
	assert.Equal(t, "Registry Registrar", result.Registrar)
	assert.Equal(t, "2003-04-17T00:00:00Z", result.Created)
}
