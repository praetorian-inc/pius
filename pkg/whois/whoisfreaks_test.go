package whois

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fullWhoisFreaksResponse builds a complete whoisFreaksResponse with realistic
// data for reuse across tests. Every field is populated so callers can assert
// the full mapping surface.
func fullWhoisFreaksResponse() whoisFreaksResponse {
	return whoisFreaksResponse{
		Status:           true,
		DomainName:       "example.com",
		DomainRegistered: "yes",
		CreateDate:       "2000-01-15",
		UpdateDate:       "2024-06-10",
		ExpiryDate:       "2030-01-15",
		WhoisServer:      "whois.example-registrar.com",
		DomainRegistrar: whoisFreaksRegistrar{
			RegistrarName: "Example Registrar Inc.",
		},
		NameServers:  []string{"ns1.example.com", "ns2.example.com"},
		DomainStatus: []string{"clientTransferProhibited", "clientDeleteProhibited"},
		Registrant: whoisFreaksContact{
			Name:         "John Doe",
			Company:      "Example Corp",
			EmailAddress: "admin@example.com",
			Street:       "123 Main St",
			City:         "San Francisco",
			State:        "CA",
			ZipCode:      "94105",
			CountryName:  "United States",
			CountryCode:  "US",
			Phone:        "+1.4155551234",
		},
		Admin: whoisFreaksContact{
			Name:         "Jane Admin",
			Company:      "Example Corp",
			EmailAddress: "admin-contact@example.com",
			Street:       "456 Admin Ave",
			City:         "New York",
			State:        "NY",
			ZipCode:      "10001",
			CountryName:  "United States",
			CountryCode:  "US",
			Phone:        "+1.2125559876",
		},
		Tech: whoisFreaksContact{
			Name:         "Tech Support",
			Company:      "Example Tech LLC",
			EmailAddress: "tech@example.com",
			Street:       "789 Tech Blvd",
			City:         "Austin",
			State:        "TX",
			ZipCode:      "73301",
			CountryName:  "United States",
			CountryCode:  "US",
			Phone:        "+1.5125554321",
		},
		Billing: whoisFreaksContact{
			Name:         "Billing Dept",
			Company:      "Example Billing Inc",
			EmailAddress: "billing@example.com",
			Street:       "321 Billing Rd",
			City:         "Chicago",
			State:        "IL",
			ZipCode:      "60601",
			CountryName:  "United States",
			CountryCode:  "US",
			Phone:        "+1.3125557890",
		},
	}
}

// overrideWhoisFreaksBaseURL points whoisFreaksBaseURL at the given httptest
// server and restores the original value when the test completes.
func overrideWhoisFreaksBaseURL(t *testing.T, url string) {
	t.Helper()
	orig := whoisFreaksBaseURL
	whoisFreaksBaseURL = url
	t.Cleanup(func() { whoisFreaksBaseURL = orig })
}

// TestWhoisFreaksLookup_Success verifies that a full WhoisFreaks API response
// is correctly mapped to every field on Result, including all four contact
// roles, dates, registrar, nameservers, status, and sources.
func TestWhoisFreaksLookup_Success(t *testing.T) {
	wfResp := fullWhoisFreaksResponse()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "test-key", r.URL.Query().Get("apiKey"))
		assert.Equal(t, "example.com", r.URL.Query().Get("domainName"))

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(wfResp))
	}))
	defer srv.Close()

	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	overrideWhoisFreaksBaseURL(t, srv.URL)

	result, err := NewWhoisFreaksClient(srv.Client(), "").Lookup(context.Background(), "example.com")

	require.NoError(t, err)

	// Domain and registrar.
	assert.Equal(t, "example.com", result.Domain)
	assert.Equal(t, "Example Registrar Inc.", result.Registrar)

	// Dates.
	assert.Equal(t, "2000-01-15", result.Created)
	assert.Equal(t, "2024-06-10", result.Updated)
	assert.Equal(t, "2030-01-15", result.Expiration)

	// WHOIS server.
	assert.Equal(t, "whois.example-registrar.com", result.WhoisServer)

	// Name servers.
	assert.Equal(t, []string{"ns1.example.com", "ns2.example.com"}, result.NameServers)

	// Status.
	assert.Equal(t, []string{"clientTransferProhibited", "clientDeleteProhibited"}, result.Status)

	// Sources.
	assert.Equal(t, []string{"whoisfreaks"}, result.Sources)

	// Not unregistered.
	assert.False(t, result.Unregistered)

	// Registrant contact.
	assert.Equal(t, "Example Corp", result.Registrant.Organization)
	assert.Equal(t, "John Doe", result.Registrant.Name)
	assert.Equal(t, "admin@example.com", result.Registrant.Email)
	assert.Equal(t, "US", result.Registrant.Country)
	assert.Equal(t, "CA", result.Registrant.Province)
	assert.Equal(t, "San Francisco", result.Registrant.City)
	assert.Equal(t, "123 Main St", result.Registrant.Street)
	assert.Equal(t, "94105", result.Registrant.PostalCode)
	assert.Equal(t, "+1.4155551234", result.Registrant.Phone)

	// Admin contact.
	assert.Equal(t, "Example Corp", result.Admin.Organization)
	assert.Equal(t, "Jane Admin", result.Admin.Name)
	assert.Equal(t, "admin-contact@example.com", result.Admin.Email)
	assert.Equal(t, "US", result.Admin.Country)
	assert.Equal(t, "NY", result.Admin.Province)
	assert.Equal(t, "New York", result.Admin.City)
	assert.Equal(t, "456 Admin Ave", result.Admin.Street)
	assert.Equal(t, "10001", result.Admin.PostalCode)
	assert.Equal(t, "+1.2125559876", result.Admin.Phone)

	// Tech contact.
	assert.Equal(t, "Example Tech LLC", result.Tech.Organization)
	assert.Equal(t, "Tech Support", result.Tech.Name)
	assert.Equal(t, "tech@example.com", result.Tech.Email)
	assert.Equal(t, "US", result.Tech.Country)
	assert.Equal(t, "TX", result.Tech.Province)
	assert.Equal(t, "Austin", result.Tech.City)
	assert.Equal(t, "789 Tech Blvd", result.Tech.Street)
	assert.Equal(t, "73301", result.Tech.PostalCode)
	assert.Equal(t, "+1.5125554321", result.Tech.Phone)

	// Billing contact.
	assert.Equal(t, "Example Billing Inc", result.Billing.Organization)
	assert.Equal(t, "Billing Dept", result.Billing.Name)
	assert.Equal(t, "billing@example.com", result.Billing.Email)
	assert.Equal(t, "US", result.Billing.Country)
	assert.Equal(t, "IL", result.Billing.Province)
	assert.Equal(t, "Chicago", result.Billing.City)
	assert.Equal(t, "321 Billing Rd", result.Billing.Street)
	assert.Equal(t, "60601", result.Billing.PostalCode)
	assert.Equal(t, "+1.3125557890", result.Billing.Phone)
}

// TestWhoisFreaksLookup_UnregisteredDomain verifies that a response with
// domain_registered:"no" produces a Result with Unregistered=true, the domain
// set, and all other fields at zero values.
func TestWhoisFreaksLookup_UnregisteredDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"status":            true,
			"domain_name":       "not-registered-xyz.com",
			"domain_registered": "no",
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer srv.Close()

	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	overrideWhoisFreaksBaseURL(t, srv.URL)

	result, err := NewWhoisFreaksClient(srv.Client(), "").Lookup(context.Background(), "not-registered-xyz.com")

	require.NoError(t, err)
	assert.True(t, result.Unregistered)
	assert.Equal(t, "not-registered-xyz.com", result.Domain)

	// All other fields should be zero-valued.
	assert.Empty(t, result.Registrar)
	assert.Empty(t, result.Created)
	assert.Empty(t, result.Updated)
	assert.Empty(t, result.Expiration)
	assert.Empty(t, result.NameServers)
	assert.Empty(t, result.Status)
	assert.Empty(t, result.Sources)
	assert.True(t, result.Registrant.IsEmpty())
}

// TestWhoisFreaksLookup_PrivacyRedacted verifies that contact fields filled
// with WHOIS privacy placeholders are cleared by ScrubContacts, while
// non-contact fields (registrar, dates, nameservers) remain populated.
func TestWhoisFreaksLookup_PrivacyRedacted(t *testing.T) {
	redactedContact := whoisFreaksContact{
		Name:         "REDACTED FOR PRIVACY",
		Company:      "REDACTED FOR PRIVACY",
		EmailAddress: "REDACTED FOR PRIVACY",
		Street:       "REDACTED FOR PRIVACY",
		City:         "REDACTED FOR PRIVACY",
		State:        "REDACTED FOR PRIVACY",
		ZipCode:      "REDACTED FOR PRIVACY",
		CountryCode:  "REDACTED FOR PRIVACY",
		Phone:        "REDACTED FOR PRIVACY",
	}

	wfResp := whoisFreaksResponse{
		Status:           true,
		DomainName:       "private-domain.com",
		DomainRegistered: "yes",
		CreateDate:       "2020-03-01",
		UpdateDate:       "2024-01-15",
		ExpiryDate:       "2025-03-01",
		WhoisServer:      "whois.example.com",
		DomainRegistrar: whoisFreaksRegistrar{
			RegistrarName: "Privacy Registrar LLC",
		},
		NameServers:  []string{"ns1.private.com"},
		DomainStatus: []string{"clientTransferProhibited"},
		Registrant:   redactedContact,
		Admin:        redactedContact,
		Tech:         redactedContact,
		Billing:      redactedContact,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(wfResp))
	}))
	defer srv.Close()

	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	overrideWhoisFreaksBaseURL(t, srv.URL)

	result, err := NewWhoisFreaksClient(srv.Client(), "").Lookup(context.Background(), "private-domain.com")

	require.NoError(t, err)

	// Before scrub: contact fields are populated with privacy placeholders.
	assert.Equal(t, "REDACTED FOR PRIVACY", result.Registrant.Organization)
	assert.Equal(t, "REDACTED FOR PRIVACY", result.Registrant.Name)

	// Scrub the contacts.
	result.ScrubContacts()

	// After scrub: all contact fields should be cleared.
	for _, c := range result.AllContacts() {
		assert.Empty(t, c.Organization, "Organization should be empty after scrub")
		assert.Empty(t, c.Name, "Name should be empty after scrub")
		assert.Empty(t, c.Email, "Email should be empty after scrub")
		assert.Empty(t, c.Country, "Country should be empty after scrub")
		assert.Empty(t, c.Province, "Province should be empty after scrub")
		assert.Empty(t, c.City, "City should be empty after scrub")
		assert.Empty(t, c.Street, "Street should be empty after scrub")
		assert.Empty(t, c.PostalCode, "PostalCode should be empty after scrub")
		assert.Empty(t, c.Phone, "Phone should be empty after scrub")
	}

	// Non-contact fields remain populated.
	assert.Equal(t, "Privacy Registrar LLC", result.Registrar)
	assert.Equal(t, "2020-03-01", result.Created)
	assert.Equal(t, "2024-01-15", result.Updated)
	assert.Equal(t, "2025-03-01", result.Expiration)
	assert.Equal(t, []string{"ns1.private.com"}, result.NameServers)
	assert.Equal(t, []string{"clientTransferProhibited"}, result.Status)
	assert.Equal(t, []string{"whoisfreaks"}, result.Sources)
}

// TestWhoisFreaksLookup_APIError401 verifies that an HTTP 401 response
// produces an error mentioning the status code.
func TestWhoisFreaksLookup_APIError401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	t.Setenv("WHOISFREAKS_API_KEY", "bad-key")
	overrideWhoisFreaksBaseURL(t, srv.URL)

	result, err := NewWhoisFreaksClient(srv.Client(), "").Lookup(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.Equal(t, Result{}, result)
}

// TestWhoisFreaksLookup_RateLimit429 verifies that an HTTP 429 response
// produces an error mentioning the status code.
func TestWhoisFreaksLookup_RateLimit429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	overrideWhoisFreaksBaseURL(t, srv.URL)

	result, err := NewWhoisFreaksClient(srv.Client(), "").Lookup(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "429")
	assert.Equal(t, Result{}, result)
}

// TestWhoisFreaksLookup_StatusFalse verifies that an HTTP 200 response with
// status:false (e.g. invalid key, quota exceeded) produces an error.
func TestWhoisFreaksLookup_StatusFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"status":  false,
			"message": "Invalid API Key",
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer srv.Close()

	t.Setenv("WHOISFREAKS_API_KEY", "bad-key")
	overrideWhoisFreaksBaseURL(t, srv.URL)

	result, err := NewWhoisFreaksClient(srv.Client(), "").Lookup(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsuccessful status")
	assert.Equal(t, Result{}, result)
}

// TestWhoisFreaksLookup_NoAPIKey verifies that an unkeyed resolver declines
// loudly.
//
// This replaces the previous no-op contract, where an unset key produced a zero
// Result and a nil error. That reads identically to "this provider has no
// record", so a cascade could never tell an operator that a configured provider
// was doing nothing — and it also billed nothing while looking like a normal
// empty answer in the metrics.
func TestWhoisFreaksLookup_NoAPIKey(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "")

	result, err := NewWhoisFreaksClient(http.DefaultClient, "").Lookup(context.Background(), "example.com")

	assert.ErrorIs(t, err, ErrNoCredential)
	assert.Equal(t, Result{}, result)
}

// TestWhoisFreaksLookup_ExplicitKeyBeatsEnv covers the Guard requirement: the
// credential is injected as a constructor parameter, and the environment is
// only a fallback for local use.
func TestWhoisFreaksLookup_ExplicitKeyBeatsEnv(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "from-env")

	assert.Equal(t, "from-env", NewWhoisFreaksClient(nil, "").resolveAPIKey())
	assert.Equal(t, "injected", NewWhoisFreaksClient(nil, "injected").resolveAPIKey())
	assert.True(t, NewWhoisFreaksClient(nil, "").hasCredential())

	t.Setenv("WHOISFREAKS_API_KEY", "")
	assert.False(t, NewWhoisFreaksClient(nil, "").hasCredential())
	assert.True(t, NewWhoisFreaksClient(nil, "injected").hasCredential(),
		"an injected key works with no environment at all")
}

func TestWhoisFreaksResolver_Name(t *testing.T) {
	assert.Equal(t, ProviderWhoisFreaks, NewWhoisFreaksClient(nil, "k").Name())
}

// TestWhoisFreaksLookup_Integration is a gated integration test that queries
// the real WhoisFreaks API. It is skipped unless WHOISFREAKS_API_KEY is set
// in the environment.
func TestWhoisFreaksLookup_Integration(t *testing.T) {
	apiKey := os.Getenv("WHOISFREAKS_API_KEY")
	if apiKey == "" {
		t.Skip("WHOISFREAKS_API_KEY not set; skipping integration test")
	}

	result, err := NewWhoisFreaksClient(http.DefaultClient, "").Lookup(context.Background(), "google.com")

	require.NoError(t, err)
	assert.Equal(t, "google.com", result.Domain)
	assert.NotEmpty(t, result.Registrar, "expected non-empty registrar for google.com")
	assert.NotEmpty(t, result.Registrant.Organization, "expected non-empty registrant org for google.com")
	assert.NotEmpty(t, result.Created, "expected non-empty created date for google.com")
	assert.NotEmpty(t, result.Updated, "expected non-empty updated date for google.com")
	assert.NotEmpty(t, result.Expiration, "expected non-empty expiration date for google.com")
	assert.NotEmpty(t, result.NameServers, "expected non-empty nameservers for google.com")
	assert.Equal(t, []string{"whoisfreaks"}, result.Sources)
	assert.False(t, result.Unregistered)
}
