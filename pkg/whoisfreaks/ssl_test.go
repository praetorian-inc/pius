package whoisfreaks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise SSLLive against an in-process httptest.Server. They are
// fully offline: no real network, no real WhoisFreaks endpoint, and no real API
// key — the ~/.whoisfreaks.key on disk is never read or referenced. The key the
// client sends is the obvious sentinel WF_SSL_SENTINEL, never a credential.
//
// Fixtures are synthetic provider JSON built from the package's own DTO types;
// every certificate field is obviously fake and no real certificate, PEM, or
// private key appears. Response bodies are marshalled from sslLiveResponse so the
// wire tags stay in lockstep with the DTOs the client actually decodes.
//
// Assertions target observable behavior: the metered credit spend (T7 — derived
// from the request plus a capped cert count), the chain self-consistency flag and
// anomalies propagated from validateChain, verbatim RawPEM gating, and the
// free-outcome / no-panic guarantees for 4xx, empty, and malformed responses (T6).

// certDTO builds a synthetic provider certificate entry. Only the fields the
// mapper and chain validator read are populated; every value is obviously fake.
func certDTO(subjectCN, issuerCN, serial, order string) sslCertDTO {
	return sslCertDTO{
		Subject:      dnDTO{CommonName: subjectCN},
		Issuer:       dnDTO{CommonName: issuerCN},
		SerialNumber: serial,
		ChainOrder:   order,
	}
}

// sslBody marshals a synthetic ssl/live response body from the package's own DTO,
// so the served JSON always matches the tags the client decodes.
func sslBody(t *testing.T, certs []sslCertDTO, raw string) []byte {
	t.Helper()
	b, err := json.Marshal(sslLiveResponse{SSLCertificates: certs, SSLRaw: raw})
	require.NoError(t, err)
	return b
}

// serveSSL stands up an offline httptest.Server returning (status, body) and a
// Client wired to it with a fresh injected CreditMeter, returned so a test can
// assert exact metered spend. The apiKey is an obvious sentinel, never a real key.
func serveSSL(t *testing.T, status int, body []byte) (*Client, *CreditMeter) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	meter := NewCreditMeter()
	c, err := New(WithAPIKey("WF_SSL_SENTINEL"), WithBaseURL(srv.URL), WithCreditMeter(meter))
	require.NoError(t, err)
	return c, meter
}

// wellLinkedChain is a clean end-user->intermediate->intermediate->self-signed-root
// chain (4 entries) with all-hex serials: validateChain classifies it valid with
// no anomalies. The leaf's chainOrder is the vendor's real "end-user" label.
func wellLinkedChain() []sslCertDTO {
	return []sslCertDTO{
		certDTO("leaf.example", "Intermediate CA 1", "1a2b", "end-user"),
		certDTO("Intermediate CA 1", "Intermediate CA 2", "0af9", "intermediate"),
		certDTO("Intermediate CA 2", "Example Root CA", "0bde", "intermediate"),
		certDTO("Example Root CA", "Example Root CA", "deadBEEF", "root"),
	}
}

// TestSSLLive_LeafOnly: a single-cert body with Chain unset returns the leaf, no
// chain, no raw PEM, and costs exactly 1 credit.
func TestSSLLive_LeafOnly(t *testing.T) {
	t.Parallel()

	leaf := certDTO("leaf.example", "Intermediate CA 1", "1a2b", "end-user")
	c, meter := serveSSL(t, http.StatusOK, sslBody(t, []sslCertDTO{leaf}, ""))

	res, err := c.SSLLive(context.Background(), "example.com", SSLOptions{})
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.Equal(t, "leaf.example", res.Leaf.Subject.CommonName, "the leaf must be populated")
	assert.Equal(t, 1, res.CreditsCharged, "a leaf-only lookup costs exactly 1 credit")
	assert.Equal(t, creditsFor(SSLOptions{}, 1, true), res.CreditsCharged,
		"charged credits must match creditsFor for the fixture")
	assert.Empty(t, res.Chain, "no chain is returned when Chain is not requested")
	assert.Empty(t, res.RawPEM, "no raw PEM is returned when Raw is not requested")
	assert.Equal(t, 1, meter.Total(), "the meter records exactly the charged credit")
}

// TestSSLLive_ChainValid: a well-linked, self-signed-root 4-cert chain with
// Chain=true is classified valid with no anomalies, returns every processed cert,
// and costs 1+ceil(4/2)==3 credits. It also locks the wire format: apiKey and
// domain ride as query parameters, chain=true is set, sslRaw is absent, and the
// apiKey never appears in a request header.
func TestSSLLive_ChainValid(t *testing.T) {
	t.Parallel()

	const sentinel = "WF_SSL_SENTINEL"
	certs := wellLinkedChain()

	type captured struct {
		apiKeyQuery     string
		domainQuery     string
		chainQuery      string
		rawQuery        string
		anyHeaderHasKey bool
	}
	reqCh := make(chan captured, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anyHeaderHasKey := false
		for _, vals := range r.Header {
			for _, v := range vals {
				if strings.Contains(v, sentinel) {
					anyHeaderHasKey = true
				}
			}
		}
		reqCh <- captured{
			apiKeyQuery:     r.URL.Query().Get("apiKey"),
			domainQuery:     r.URL.Query().Get("domainName"),
			chainQuery:      r.URL.Query().Get("chain"),
			rawQuery:        r.URL.Query().Get("sslRaw"),
			anyHeaderHasKey: anyHeaderHasKey,
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sslBody(t, certs, ""))
	}))
	t.Cleanup(srv.Close)

	meter := NewCreditMeter()
	c, err := New(WithAPIKey(sentinel), WithBaseURL(srv.URL), WithCreditMeter(meter))
	require.NoError(t, err)

	res, err := c.SSLLive(context.Background(), "example.com", SSLOptions{Chain: true})
	require.NoError(t, err)
	require.NotNil(t, res)

	// Credit: 1 + ceil(4/2) == 3, derived from creditsFor for the exact fixture.
	want := creditsFor(SSLOptions{Chain: true}, len(certs), true)
	assert.Equal(t, 3, want, "sanity: a 4-cert chain costs 3 credits")
	assert.Equal(t, want, res.CreditsCharged, "charged credits must match creditsFor")
	assert.Equal(t, want, meter.Total(), "the meter records exactly the charged credits")

	assert.True(t, res.ChainValid, "a well-linked self-signed-root chain is self-consistent")
	assert.Empty(t, res.ChainAnomalies, "the golden chain raises no anomalies")
	assert.Len(t, res.Chain, len(certs), "every processed chain cert is returned")
	assert.Equal(t, "leaf.example", res.Leaf.Subject.CommonName)

	got := <-reqCh
	assert.Equal(t, sentinel, got.apiKeyQuery, "apiKey rides as a query parameter")
	assert.Equal(t, "example.com", got.domainQuery, "the domain rides as domainName")
	assert.Equal(t, "true", got.chainQuery, "chain=true is set when Chain is requested")
	assert.Empty(t, got.rawQuery, "sslRaw is absent when Raw is not requested")
	assert.False(t, got.anyHeaderHasKey, "the apiKey must not appear in any request header")
}

// TestSSLLive_RawPEM: RawPEM carries the provider's sslRaw bytes verbatim when
// Raw=true, and is empty when Raw=false even though the server sends the field.
func TestSSLLive_RawPEM(t *testing.T) {
	t.Parallel()

	// Synthetic, obviously-fake CERTIFICATE block — never a private key and never a
	// real captured cert (fixture hygiene T4).
	const rawPEM = "-----BEGIN CERTIFICATE-----\nU1lOVEhFVElDX0ZBS0VfQ0VSVA==\n-----END CERTIFICATE-----\n"
	leaf := certDTO("leaf.example", "Intermediate CA 1", "1a2b", "end-user")

	t.Run("Raw:true returns the raw PEM verbatim", func(t *testing.T) {
		t.Parallel()
		c, _ := serveSSL(t, http.StatusOK, sslBody(t, []sslCertDTO{leaf}, rawPEM))
		res, err := c.SSLLive(context.Background(), "example.com", SSLOptions{Raw: true})
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Equal(t, rawPEM, res.RawPEM, "RawPEM must equal the served bytes verbatim")
	})

	t.Run("Raw:false omits the raw PEM", func(t *testing.T) {
		t.Parallel()
		c, _ := serveSSL(t, http.StatusOK, sslBody(t, []sslCertDTO{leaf}, rawPEM))
		res, err := c.SSLLive(context.Background(), "example.com", SSLOptions{})
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Empty(t, res.RawPEM, "RawPEM must be empty when Raw is not requested")
	})
}

// TestSSLLive_ChainBroken: a mid-chain link break makes the chain inconsistent —
// ChainValid=false with anomalies — but the leaf is still returned and, because
// the lookup succeeded and was non-empty, it is still metered.
func TestSSLLive_ChainBroken(t *testing.T) {
	t.Parallel()

	// cert[1].Issuer ("Mismatched Issuer") != cert[2].Subject ("Intermediate B").
	certs := []sslCertDTO{
		certDTO("leaf.example", "Intermediate A", "1a", "end-user"),
		certDTO("Intermediate A", "Mismatched Issuer", "2b", "intermediate"),
		certDTO("Intermediate B", "Example Root CA", "3c", "intermediate"),
		certDTO("Example Root CA", "Example Root CA", "4d", "root"),
	}
	c, meter := serveSSL(t, http.StatusOK, sslBody(t, certs, ""))

	res, err := c.SSLLive(context.Background(), "example.com", SSLOptions{Chain: true})
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.False(t, res.ChainValid, "a broken chain must be classified invalid")
	assert.NotEmpty(t, res.ChainAnomalies, "a broken chain must report anomalies")
	assert.Equal(t, "leaf.example", res.Leaf.Subject.CommonName,
		"the leaf is returned even when the chain is broken")

	// A successful, non-empty lookup is metered regardless of chain validity.
	want := creditsFor(SSLOptions{Chain: true}, len(certs), true)
	assert.Equal(t, want, res.CreditsCharged, "a broken but non-empty chain is still charged")
	assert.Equal(t, want, meter.Total())
}

// TestSSLLive_FreeOutcomesChargeNothing: a 4xx status and an empty certificate
// array both error and leave the credit meter untouched (T6 — those outcomes are
// free; the leaf is never assumed).
func TestSSLLive_FreeOutcomesChargeNothing(t *testing.T) {
	t.Parallel()

	t.Run("a 4xx status errors and charges nothing", func(t *testing.T) {
		t.Parallel()
		c, meter := serveSSL(t, http.StatusNotFound, []byte(`{"error":"not found"}`))
		res, err := c.SSLLive(context.Background(), "example.com", SSLOptions{Chain: true})
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, 0, meter.Total(), "a 4xx outcome is free")
	})

	t.Run("an empty certificate array errors and charges nothing", func(t *testing.T) {
		t.Parallel()
		c, meter := serveSSL(t, http.StatusOK, sslBody(t, []sslCertDTO{}, ""))
		res, err := c.SSLLive(context.Background(), "example.com", SSLOptions{Chain: true})
		assert.ErrorIs(t, err, errNoCertificates, "an empty result is errNoCertificates")
		assert.Nil(t, res)
		assert.Equal(t, 0, meter.Total(), "an empty result is free")
	})
}

// TestSSLLive_MalformedBodyNeverPanics is the T6 no-panic guard: an empty, null,
// truncated, or garbage 200 body surfaces an error gracefully — never a panic —
// and charges nothing. The test not panicking is itself the primary assertion.
func TestSSLLive_MalformedBodyNeverPanics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"json null", "null"},
		{"truncated object", "{"},
		{"array not object", "[]"},
		{"null certificate array", `{"sslCertificates":null}`},
		{"garbage", "not json at all"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, meter := serveSSL(t, http.StatusOK, []byte(tt.body))
			res, err := c.SSLLive(context.Background(), "example.com", SSLOptions{Chain: true})
			require.Error(t, err, "a malformed body must surface an error, never a panic")
			assert.Nil(t, res)
			assert.Equal(t, 0, meter.Total(), "a malformed/empty body charges nothing")
		})
	}
}

// pinnedSSLResponse is a LITERAL ssl/live response body in the exact wire shape
// pinned from the vendor's rendered docs (OFFSEC-2444 wire-format comment): a
// leaf→root sslCertificates[] with nested publicKey (unit-suffixed keySize) and
// nested extensions (keyUsages, extendedKeyUsages, authorityInfoAccess.ocsp,
// subjectAlternativeNames.dnsNames), authenticationType "domain", chainOrder
// "end-user", and an UNPADDED validityStartDate. It is a hand-written string on
// purpose — NOT json.Marshal(sslLiveResponse{...}) — so it exercises the real
// json tags rather than round-tripping through whatever tags happen to exist.
const pinnedSSLResponse = `{
  "domainName": "example.com",
  "queryTime": "2024-09-8 00:00:00 UTC",
  "sslCertificates": [
    {
      "chainOrder": "end-user",
      "authenticationType": "domain",
      "validityStartDate": "2024-09-7 23:03:18 UTC",
      "validityEndDate": "2025-09-7 23:03:18 UTC",
      "serialNumber": "01:AF:9C:DE",
      "signatureAlgorithm": "SHA256-RSA",
      "subject": { "commonName": "leaf.example.com", "organization": ["Example Inc"], "country": ["US"] },
      "issuer": { "commonName": "Example Intermediate CA", "organization": ["Example CA"], "country": ["US"] },
      "publicKey": { "keySize": "256 bit", "keyAlgorithm": "ECDSA" },
      "extensions": {
        "authorityKeyIdentifier": "AK:ID:00",
        "subjectKeyIdentifier": "SK:ID:00",
        "keyUsages": ["digitalSignature", "keyEncipherment"],
        "extendedKeyUsages": ["serverAuth", "clientAuth"],
        "authorityInfoAccess": {
          "issuers": ["http://ca.example/issuer.crt"],
          "ocsp": ["http://ocsp.example", "http://ocsp2.example"]
        },
        "subjectAlternativeNames": { "dnsNames": ["leaf.example.com", "www.example.com"] },
        "certificatePolicies": [ { "policyId": "2.23.140.1.2.1" } ]
      }
    }
  ]
}`

// TestMapCertificate_PinnedWireFormat is the teeth of the wire-format fix. It
// unmarshals the LITERAL pinnedSSLResponse (a Go string constant, never built by
// marshalling the DTO) into sslLiveResponse, maps cert[0], and asserts the nested
// vendor shape flattened correctly: the unit-suffixed keySize parsed to bits, the
// key algorithm carried, SANs read from extensions.subjectAlternativeNames.dnsNames,
// OCSP from extensions.authorityInfoAccess.ocsp, key usages populated,
// authenticationType carried, and the UNPADDED validity date parsed to the exact
// instant. Against the previous FLAT DTO these tags do not match the nested JSON,
// so every one of these assertions fails; it passes only when the DTO nesting and
// mapCertificate flattening are both correct. Routing the fixture through
// json.Marshal(sslLiveResponse{...}) would have hidden the bug — hence the literal.
func TestMapCertificate_PinnedWireFormat(t *testing.T) {
	t.Parallel()

	var resp sslLiveResponse
	require.NoError(t, json.Unmarshal([]byte(pinnedSSLResponse), &resp),
		"the pinned wire-format body must unmarshal into sslLiveResponse")
	require.Len(t, resp.SSLCertificates, 1, "the pinned body carries exactly one certificate")

	got := mapCertificate(resp.SSLCertificates[0])

	// publicKey is a nested object whose keySize is a unit-suffixed STRING.
	assert.Equal(t, 256, got.PublicKeyBits, `keySize "256 bit" must parse to 256 bits`)
	assert.Equal(t, "ECDSA", got.PublicKeyAlgorithm, "publicKey.keyAlgorithm must carry")

	// SANs live under extensions.subjectAlternativeNames.dnsNames.
	assert.Equal(t, []string{"leaf.example.com", "www.example.com"}, got.SubjectAltNames,
		"SubjectAltNames must read from extensions.subjectAlternativeNames.dnsNames")

	// OCSP responders live under extensions.authorityInfoAccess.ocsp.
	assert.Equal(t, []string{"http://ocsp.example", "http://ocsp2.example"}, got.OCSPServers,
		"OCSPServers must read from extensions.authorityInfoAccess.ocsp")

	// Key usages live under extensions.keyUsages / extensions.extendedKeyUsages.
	assert.Equal(t, []string{"digitalSignature", "keyEncipherment"}, got.KeyUsage,
		"KeyUsage must read from extensions.keyUsages")
	assert.Equal(t, []string{"serverAuth", "clientAuth"}, got.ExtKeyUsage,
		"ExtKeyUsage must read from extensions.extendedKeyUsages")

	// Top-level scalars.
	assert.Equal(t, "domain", got.AuthenticationType, `authenticationType "domain" must carry`)
	assert.Equal(t, "end-user", got.ChainOrder, `chainOrder "end-user" must carry`)
	assert.Equal(t, "01:AF:9C:DE", got.SerialNumber, "serialNumber must carry verbatim")
	assert.Equal(t, "SHA256-RSA", got.SignatureAlgorithm, "signatureAlgorithm must carry")
	assert.Equal(t, "leaf.example.com", got.Subject.CommonName, "subject.commonName must carry")
	assert.Equal(t, "Example Intermediate CA", got.Issuer.CommonName, "issuer.commonName must carry")

	// The UNPADDED validity date must parse to the exact instant.
	wantNotBefore := time.Date(2024, 9, 7, 23, 3, 18, 0, time.UTC)
	require.False(t, got.NotBefore.IsZero(), "an unpadded validityStartDate must parse to a non-zero time")
	assert.True(t, wantNotBefore.Equal(got.NotBefore),
		"NotBefore must parse to 2024-09-07T23:03:18Z, got %s", got.NotBefore)
}

// TestMapCertificate_FieldFidelity is the T8 faithful-carry test. It builds a
// FULLY populated provider DTO in the nested wire shape — distinct sentinels in
// every leaf field, including nested publicKey and extensions — calls
// mapCertificate DIRECTLY (no SSLLive / httptest), and asserts every output field
// carries its exact input, unswapped and unmodified.
//
// The certDTO helper populates only 4 fields, so it cannot express this full
// fixture; the DTO is built inline on purpose. Distinct-per-field sentinels mean
// a mis-wire (Subject<->Issuer, KeyUsage<->ExtKeyUsage, NotBefore<->NotAfter) is
// caught rather than masked by identical values. SubjectAltNames (now under
// extensions.subjectAlternativeNames.dnsNames) carries a wildcard AND an
// injection-shaped element with an embedded newline; the mapper must carry those
// bytes verbatim — never sanitized, escaped, or reordered (T8).
func TestMapCertificate_FieldFidelity(t *testing.T) {
	t.Parallel()

	// NotBefore/NotAfter route through parseCertTime; distinct instants guard
	// against the two timestamp fields being swapped.
	const notBeforeStr = "2024-01-02T15:04:05Z"
	const notAfterStr = "2035-06-07T08:09:10Z"
	wantNotBefore := time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)
	wantNotAfter := time.Date(2035, 6, 7, 8, 9, 10, 0, time.UTC)

	// An SAN slice mixing a plain name, a wildcard, and an injection-shaped
	// element (embedded newline + fake header) — all opaque, obviously-fake bytes
	// that must be carried through untouched (T8).
	const sanInjection = "*.evil\nInjected: x"
	sans := []string{
		"leaf.example.com",
		"*.wildcard.example",
		sanInjection,
		"second-san.example",
	}

	subjectDTO := dnDTO{
		CommonName:   "subject.cn.sentinel",
		Organization: []string{"Subject Org A", "Subject Org B"},
		Country:      []string{"US"},
		Raw:          "CN=subject.raw.sentinel",
	}
	issuerDTO := dnDTO{
		CommonName:   "issuer.cn.sentinel",
		Organization: []string{"Issuer Org"},
		Country:      []string{"CA"},
		Raw:          "CN=issuer.raw.sentinel",
	}

	keyUsages := []string{"KU_digitalSignature", "KU_keyEncipherment"}
	extKeyUsages := []string{"EKU_serverAuth"}
	crl := []string{"http://crl.example/sentinel.crl"}
	ocsp := []string{"http://ocsp.example/sentinel"}

	d := sslCertDTO{
		Subject:            subjectDTO,
		Issuer:             issuerDTO,
		SerialNumber:       "SERIAL_1a2b3c",
		SignatureAlgorithm: "SIG_ALGO_SENTINEL",
		AuthenticationType: "organization",
		ValidityStartDate:  notBeforeStr,
		ValidityEndDate:    notAfterStr,
		PublicKey: publicKeyDTO{
			KeySize:      "4096 bit",
			KeyAlgorithm: "PUBKEY_ALGO_SENTINEL",
		},
		Extensions: extensionsDTO{
			KeyUsages:               keyUsages,
			ExtendedKeyUsages:       extKeyUsages,
			AuthorityInfoAccess:     authorityInfoAccessDTO{OCSP: ocsp},
			SubjectAlternativeNames: subjectAltNamesDTO{DNSNames: sans},
			CRLDistributionPoints:   crl,
		},
		ChainOrder: "intermediate",
	}

	got := mapCertificate(d)

	// DNs route through mapDN (a verbatim dnDTO->DN conversion): every field of
	// the distinguished name is carried, and Subject is never confused with Issuer.
	assert.Equal(t, DN(subjectDTO), got.Subject, "Subject must carry every dnDTO field verbatim")
	assert.Equal(t, DN(issuerDTO), got.Issuer, "Issuer must carry every dnDTO field verbatim")
	assert.NotEqual(t, got.Subject, got.Issuer, "Subject and Issuer must not be conflated")

	assert.Equal(t, d.SerialNumber, got.SerialNumber, "serial carried verbatim (mapCertificate never sanitizes)")

	require.False(t, got.NotBefore.IsZero(), "a valid NotBefore must parse to a non-zero time")
	require.False(t, got.NotAfter.IsZero(), "a valid NotAfter must parse to a non-zero time")
	assert.True(t, wantNotBefore.Equal(got.NotBefore), "NotBefore must parse to the exact input instant")
	assert.True(t, wantNotAfter.Equal(got.NotAfter), "NotAfter must parse to the exact input instant")
	assert.False(t, got.NotBefore.Equal(got.NotAfter), "the two timestamp fields must not be swapped")

	assert.Equal(t, d.SignatureAlgorithm, got.SignatureAlgorithm)
	assert.Equal(t, d.AuthenticationType, got.AuthenticationType, "authenticationType must carry")

	// publicKey is nested; keyAlgorithm carries verbatim and keySize is parsed.
	assert.Equal(t, d.PublicKey.KeyAlgorithm, got.PublicKeyAlgorithm)
	assert.Equal(t, 4096, got.PublicKeyBits, `keySize "4096 bit" must parse to 4096`)

	// extensions is nested; each list is read from its nested home.
	assert.Equal(t, d.Extensions.KeyUsages, got.KeyUsage)
	assert.Equal(t, d.Extensions.ExtendedKeyUsages, got.ExtKeyUsage)
	assert.NotEqual(t, got.KeyUsage, got.ExtKeyUsage, "KeyUsage and ExtKeyUsage must not be conflated")
	assert.Equal(t, d.Extensions.CRLDistributionPoints, got.CRLDistributionPoints)
	assert.Equal(t, d.Extensions.AuthorityInfoAccess.OCSP, got.OCSPServers)
	assert.Equal(t, d.ChainOrder, got.ChainOrder)

	// SubjectAltNames must be byte-identical: same length, same order, every
	// element unmodified — including the wildcard and the injection-shaped string.
	require.Len(t, got.SubjectAltNames, len(sans), "no SAN may be dropped or added")
	assert.Equal(t, sans, got.SubjectAltNames, "SubjectAltNames must be carried byte-identical (T8)")
	assert.Equal(t, d.Extensions.SubjectAlternativeNames.DNSNames, got.SubjectAltNames,
		"SubjectAltNames must read from extensions.subjectAlternativeNames.dnsNames")
	assert.Equal(t, sanInjection, got.SubjectAltNames[2], "the injection-shaped SAN is carried verbatim")
	assert.Contains(t, got.SubjectAltNames[2], "\n", "the embedded newline must survive — no sanitization")
}

// TestParseCertTime_TolerantContract locks parseCertTime's deliberately
// non-fatal contract (supports T6): every accepted layout parses to a non-zero
// time; empty / whitespace-only input yields the zero time; an unrecognized
// string yields the zero time WITHOUT panicking; and a valid value wrapped in
// whitespace still parses. Assertions are on IsZero()/instant equality, never a
// golden formatted string. The first ten valid inputs are one representative per
// entry in certTimeLayouts (ssl.go), in the same source order — including the
// vendor's UNPADDED-day, trailing-zone wire format.
func TestParseCertTime_TolerantContract(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		in       string
		wantZero bool
		want     time.Time // meaningful only when wantZero is false
	}{
		// One sample per certTimeLayouts entry, in source order.
		{"RFC3339", "2024-01-02T15:04:05Z", false, time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)},
		{"RFC3339Nano", "2024-01-02T15:04:05.123456789Z", false, time.Date(2024, 1, 2, 15, 4, 5, 123456789, time.UTC)},
		{"no-zone T-separated", "2024-01-02T15:04:05", false, time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)},
		{"space-separated datetime", "2024-01-02 15:04:05", false, time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)},
		{"space datetime with zone (padded day)", "2024-01-02 15:04:05 UTC", false, time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)},
		{"unpadded day with zone (vendor wire format)", "2024-09-7 23:03:18 UTC", false, time.Date(2024, 9, 7, 23, 3, 18, 0, time.UTC)},
		{"unpadded month and day with zone", "2015-6-4 11:04:38 UTC", false, time.Date(2015, 6, 4, 11, 4, 38, 0, time.UTC)},
		{"unpadded day, no zone", "2024-09-7 23:03:18", false, time.Date(2024, 9, 7, 23, 3, 18, 0, time.UTC)},
		{"unix date style", "Jan  2 15:04:05 2024 UTC", false, time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)},
		{"date only", "2024-01-02", false, time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)},

		// The two vendor samples the wire-format comment pins must both parse
		// (padded month + unpadded day + trailing UTC).
		{"vendor validity start", "2024-09-7 23:03:18 UTC", false, time.Date(2024, 9, 7, 23, 3, 18, 0, time.UTC)},
		{"vendor validity (padded month, unpadded day)", "2015-06-4 11:04:38 UTC", false, time.Date(2015, 6, 4, 11, 4, 38, 0, time.UTC)},

		// (d) a valid value wrapped in whitespace still parses (TrimSpace).
		{"valid value wrapped in whitespace", "  2024-01-02T15:04:05Z  ", false, time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)},

		// (b) empty / whitespace-only -> zero time.
		{"empty string", "", true, time.Time{}},
		{"spaces only", "   ", true, time.Time{}},
		{"tabs and newline only", "\t\n ", true, time.Time{}},

		// (c) unrecognized -> zero time, never a panic.
		{"unrecognized garbage", "not-a-timestamp", true, time.Time{}},
		{"wrong separators and out-of-range", "2024/13/45 99:99:99", true, time.Time{}},
		{"partial date", "2024-13", true, time.Time{}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got time.Time
			// (c) the no-panic guarantee holds for EVERY input, valid or not.
			require.NotPanics(t, func() { got = parseCertTime(tc.in) },
				"parseCertTime must never panic on any input")

			if tc.wantZero {
				assert.True(t, got.IsZero(),
					"empty/whitespace/unrecognized input must yield the zero time.Time")
			} else {
				require.False(t, got.IsZero(),
					"a recognized layout must parse to a non-zero time")
				assert.True(t, tc.want.Equal(got),
					"parsed instant must equal the expected time: want %s, got %s", tc.want, got)
			}
		})
	}
}
