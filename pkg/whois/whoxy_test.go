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
func newWhoxyTestResolver(t *testing.T, handler http.HandlerFunc) *WhoxyResolver {
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

func TestWhoxyResolver_Success(t *testing.T) {
	var gotQuery string
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		gotQuery = req.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":1,"raw_whois":` + jsonQuote(t, whoxyRawRecord) + `}`))
	})

	result, err := r.Lookup(context.Background(), "example.com")
	require.NoError(t, err)

	assert.Contains(t, gotQuery, "key=test-key")
	assert.Contains(t, gotQuery, "whois=example.com")

	assert.Equal(t, "example.com", result.Domain)
	assert.Equal(t, "Example Registrar, Inc.", result.Registrar)
	assert.Equal(t, "Example Corp", result.Registrant.Organization)
	assert.Equal(t, "Jane Doe", result.Registrant.Name)
	assert.Equal(t, []string{ProviderWhoxy}, result.Sources)
	assert.Len(t, result.NameServers, 2)
}

// TestWhoxyResolver_ZeroBalanceIsAFailure is the case that matters
// operationally: Whoxy reports an exhausted credit pool with HTTP 200 and
// status != 1. Treating that as data would record an empty record as fact.
func TestWhoxyResolver_ZeroBalanceIsAFailure(t *testing.T) {
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":0,"status_reason":"Zero Account Balance"}`))
	})

	_, err := r.Lookup(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Zero Account Balance")
}

func TestWhoxyResolver_NoCredential(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")

	_, err := NewWhoxyClient(nil, "").Lookup(context.Background(), "example.com")

	assert.ErrorIs(t, err, ErrNoCredential)
}

func TestWhoxyResolver_EnvFallback(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "from-env")

	r := NewWhoxyClient(nil, "")
	assert.True(t, r.hasCredential())
	assert.Equal(t, "from-env", r.resolveAPIKey())

	assert.Equal(t, "explicit", NewWhoxyClient(nil, "explicit").resolveAPIKey(),
		"an explicit key should win over the environment")
}

func TestWhoxyResolver_EmptyRecordIsNotAnAnswer(t *testing.T) {
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":1,"raw_whois":""}`))
	})

	result, err := r.Lookup(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Empty(t, result.Domain, "an empty record must not end the fallback route")
}

func TestWhoxyResolver_HTTPError(t *testing.T) {
	r := newWhoxyTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})

	_, err := r.Lookup(context.Background(), "example.com")

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

	_, err := r.Lookup(context.Background(), "example.com")

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "super-secret-key")
}

// jsonQuote renders s as a JSON string literal.
func jsonQuote(t *testing.T, s string) string {
	t.Helper()
	quoted, err := json.Marshal(s)
	require.NoError(t, err)
	return string(quoted)
}
