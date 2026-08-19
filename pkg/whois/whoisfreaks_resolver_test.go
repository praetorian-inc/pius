package whois

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhoisFreaksResolver_Name(t *testing.T) {
	assert.Equal(t, ProviderWhoisFreaks, NewWhoisFreaksResolver(nil, "k").Name())
}

// TestWhoisFreaksResolver_NoCredentialIsDistinguishable is the behavioural
// difference between the resolver and the bare lookup it wraps. The bare
// function returns an empty result and a nil error when the key is missing,
// which reads identically to "this provider has no record" — so a route could
// never tell an operator that a configured provider was doing nothing.
func TestWhoisFreaksResolver_NoCredentialIsDistinguishable(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "")

	bare, bareErr := whoisFreaksLookup(context.Background(), http.DefaultClient, "example.com")
	require.NoError(t, bareErr, "the bare lookup keeps its no-op contract")
	assert.Equal(t, Result{}, bare)

	_, resolverErr := NewWhoisFreaksResolver(nil, "").Lookup(context.Background(), "example.com")
	assert.ErrorIs(t, resolverErr, ErrNoCredential, "the resolver reports it instead")
}

func TestWhoisFreaksResolver_EnvFallback(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "from-env")

	assert.True(t, NewWhoisFreaksResolver(nil, "").hasCredential())
	assert.Equal(t, "from-env", NewWhoisFreaksResolver(nil, "").resolveAPIKey())
	assert.Equal(t, "explicit", NewWhoisFreaksResolver(nil, "explicit").resolveAPIKey())
}

// TestWhoxyResolver_Integration queries the real Whoxy API. Skipped unless
// WHOXY_API_KEY is set.
//
// Note this leg is billed per query against a credit pool that is shared
// fleet-wide, so it deliberately looks up a single well-known domain.
func TestWhoxyResolver_Integration(t *testing.T) {
	if os.Getenv("WHOXY_API_KEY") == "" {
		t.Skip("WHOXY_API_KEY not set; skipping integration test")
	}

	result, err := NewWhoxyResolver(http.DefaultClient, "").
		Lookup(context.Background(), "google.com")

	require.NoError(t, err)
	assert.Equal(t, "google.com", result.Domain)
	assert.NotEmpty(t, result.Registrar, "expected a registrar for google.com")
	assert.NotEmpty(t, result.NameServers, "expected nameservers for google.com")
	assert.Equal(t, []string{ProviderWhoxy}, result.Sources)
}

// TestWhoisXMLResolver_Integration queries the real WhoisXML API. Skipped
// unless WHOISXML_API_KEY is set. Hard refresh stays off, so this costs a
// single credit.
func TestWhoisXMLResolver_Integration(t *testing.T) {
	if os.Getenv("WHOISXML_API_KEY") == "" {
		t.Skip("WHOISXML_API_KEY not set; skipping integration test")
	}

	result, err := NewWhoisXMLResolver(http.DefaultClient, "").
		Lookup(context.Background(), "google.com")

	require.NoError(t, err)
	assert.Equal(t, "google.com", result.Domain)
	assert.NotEmpty(t, result.Registrar, "expected a registrar for google.com")
	assert.NotEmpty(t, result.Created, "expected a creation date for google.com")
	assert.NotEmpty(t, result.NameServers, "expected nameservers for google.com")
	assert.Equal(t, []string{ProviderWhoisXML}, result.Sources)
}

// TestWhoisXMLResolver_Integration_CcTLDRegistryData is the regression test for
// the highest-impact bug in this work: WhoisXML returns ccTLD registrant data
// only under registryData, so a resolver that reads the registrar-level record
// alone gets billed and returns no registrant.
//
// That matters because ccTLDs are 95.4% of the measured Whoxy-miss set (516 of
// 541), and the route is entered precisely because registrant identity is
// missing — so this is the case the fallback exists for.
//
// Confirmed live on 2026-08-19 across samsung.co.kr, baidu.com.cn, gov.us,
// infosys.in, orange.fr, dbs.com.sg and pchome.com.tw: every one had an empty
// top-level registrant and a populated registryData registrant.
//
// Skipped unless WHOISXML_API_KEY is set. Costs 1 credit per domain.
func TestWhoisXMLResolver_Integration_CcTLDRegistryData(t *testing.T) {
	if os.Getenv("WHOISXML_API_KEY") == "" {
		t.Skip("WHOISXML_API_KEY not set; skipping integration test")
	}

	for _, domain := range []string{"samsung.co.kr", "orange.fr", "dbs.com.sg"} {
		t.Run(domain, func(t *testing.T) {
			result, err := NewWhoisXMLResolver(http.DefaultClient, "").
				Lookup(context.Background(), domain)

			require.NoError(t, err)
			assert.Equal(t, domain, result.Domain)
			assert.False(t, result.Unregistered, "these are live registered domains")

			// The assertion that would fail without the registryData merge.
			assert.True(t, result.HasRegistrant(),
				"registrant is carried only in registryData for this ccTLD")
			assert.NotEmpty(t, result.Created,
				"createdDate is also registryData-only for these TLDs")
		})
	}
}
