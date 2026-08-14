package whois

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/openrdap/rdap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENG-5174: the hardened transport wired into safeRDAPHTTPClient must refuse
// connections to non-public addresses. Hermetic: the httptest server binds to
// 127.0.0.1, a loopback address the SSRF guard rejects.
func TestRDAPClientTransport_SSRFGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("SSRF guard must prevent the request from reaching the server")
	}))
	defer srv.Close()

	safe := safeRDAPHTTPClient()
	client := &rdap.Client{HTTP: safe}
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	req := rdap.NewDomainRequest("example.com").WithServer(u)
	_, doErr := client.Do(req)
	require.Error(t, doErr, "RDAP request to loopback must fail")
}

// ENG-5174: bodyCappedTransport truncates a response body exceeding
// maxRDAPResponseBytes. Hermetic: httptest server returns an oversized payload
// through the capped transport (without the SSRF dialer, so it can reach
// loopback).
func TestRDAPClientTransport_BodyCap(t *testing.T) {
	oversized := make([]byte, maxRDAPResponseBytes+4096)
	for i := range oversized {
		oversized[i] = 'x'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write(oversized)
	}))
	defer srv.Close()

	capped := &http.Client{
		Transport: &bodyCappedTransport{
			base: http.DefaultTransport,
			cap:  maxRDAPResponseBytes,
		},
	}
	resp, err := capped.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Len(t, body, int(maxRDAPResponseBytes),
		"response must be capped at maxRDAPResponseBytes")
}
