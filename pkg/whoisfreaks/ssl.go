package whoisfreaks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// errNoCertificates is returned when ssl/live succeeds (HTTP 200) but the
// provider's sslCertificates array is empty or absent. It is charged 0 credits
// (T6): an empty result is free and must not be indexed.
var errNoCertificates = errors.New("whoisfreaks: response contained no certificates")

// certTimeLayouts are the timestamp formats accepted for a certificate's
// notBefore/notAfter, tried in order. The exact provider format is [VERIFY]
// pending a captured fixture, so parsing is tolerant and non-fatal: an
// unrecognized value yields the zero time rather than an error (see
// parseCertTime).
var certTimeLayouts = []string{
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05 MST",
	"Jan _2 15:04:05 2006 MST",
	"2006-01-02",
}

// SSLLive performs a single ssl/live lookup for domain and assembles an
// SSLResult. It is the security-critical entry point:
//
//   - Transport / non-200 / decode failures return early with a key-free error
//     (T1/T3) and leave the credit meter untouched — 4xx/429/transport outcomes
//     are charged 0 credits (T6).
//   - An empty certificate array is guarded before any indexing and returns
//     errNoCertificates with 0 credits charged (T6); the leaf is never assumed.
//   - When o.Chain is set the provider chain is classified for self-consistency
//     (validateChain); a broken chain still returns the leaf with
//     ChainValid=false — the leaf is never dropped.
//   - A successful, non-empty lookup is metered exactly once and the charged
//     amount is reported in SSLResult.CreditsCharged.
func (c *Client) SSLLive(ctx context.Context, domain string, o SSLOptions) (*SSLResult, error) {
	body, err := c.do(ctx, CatLive, c.sslLiveURL(domain, o))
	if err != nil {
		// Key-free per do (T1/T3); meter deliberately untouched so 4xx/429/
		// transport failures cost 0 credits (T6).
		return nil, err
	}

	var dto sslLiveResponse
	if err := json.Unmarshal(body, &dto); err != nil {
		// The decode error describes the JSON body, not the request URL — safe to
		// wrap. The meter stays untouched (0 credits).
		return nil, fmt.Errorf("whoisfreaks: decode ssl/live response: %w", err)
	}

	// T6: guard the empty/missing certificate array BEFORE indexing. Never panic,
	// and charge nothing for an empty result.
	if len(dto.SSLCertificates) == 0 {
		return nil, errNoCertificates
	}

	certs := make([]Certificate, len(dto.SSLCertificates))
	for i := range dto.SSLCertificates {
		certs[i] = mapCertificate(dto.SSLCertificates[i])
	}

	result := &SSLResult{Leaf: certs[0]}

	if o.Chain {
		// validateChain retains index 0 (the leaf) in every case — a broken chain
		// is reported via ChainValid=false and ChainAnomalies, never by dropping
		// the leaf.
		valid, anomalies, sanitized := validateChain(certs)
		result.Chain = sanitized
		result.ChainValid = valid
		result.ChainAnomalies = anomalies
	}

	if o.Raw {
		result.RawPEM = dto.SSLRaw
	}

	// Meter only a successful, non-empty lookup. chainCerts is the full provider
	// array length (leaf included); creditsFor bounds it by maxChainCertsForCredit
	// so a provider-inflated array cannot inflate the charge (T7).
	n := creditsFor(o, len(certs), true)
	c.meter.charge(n)
	result.CreditsCharged = n

	return result, nil
}

// sslLiveURL builds the ssl/live request URL. The apiKey and domain travel as
// escaped query parameters (url.Values.Encode); chain and sslRaw are added only
// when requested. The apiKey is never placed in a header, the path, or a log
// line (security T1/T3).
func (c *Client) sslLiveURL(domain string, o SSLOptions) string {
	v := url.Values{}
	v.Set(paramAPIKey, c.apiKey)
	v.Set(paramDomainName, domain)
	if o.Chain {
		v.Set(paramChain, "true")
	}
	if o.Raw {
		v.Set(paramSSLRaw, "true")
	}
	return c.baseURL + pathSSLLive + "?" + v.Encode()
}

// mapCertificate maps a provider certificate DTO to the exported Certificate.
// Every field is carried verbatim as opaque, untrusted data; only the timestamps
// are parsed (tolerantly, never fatally). No DER/PEM is decoded here.
func mapCertificate(d sslCertDTO) Certificate {
	return Certificate{
		Subject:               mapDN(d.Subject),
		Issuer:                mapDN(d.Issuer),
		SerialNumber:          d.SerialNumber,
		NotBefore:             parseCertTime(d.NotBefore),
		NotAfter:              parseCertTime(d.NotAfter),
		SignatureAlgorithm:    d.SignatureAlgorithm,
		PublicKeyAlgorithm:    d.PublicKeyAlgorithm,
		PublicKeyBits:         d.PublicKeyBits,
		KeyUsage:              d.KeyUsage,
		ExtKeyUsage:           d.ExtKeyUsage,
		CRLDistributionPoints: d.CRLDistributionPoints,
		OCSPServers:           d.OCSPServers,
		SubjectAltNames:       d.SubjectAltNames,
		ChainOrder:            d.ChainOrder,
	}
}

// mapDN maps a provider distinguished-name DTO to the exported DN, carrying each
// field verbatim.
func mapDN(d dnDTO) DN {
	return DN(d)
}

// parseCertTime parses a certificate timestamp using certTimeLayouts. It is
// deliberately non-fatal: an empty or unrecognized value returns the zero
// time.Time rather than an error, so a single odd timestamp never fails an
// otherwise good lookup and never panics. [VERIFY] the exact provider format
// against a captured fixture and tighten the layout list if warranted.
func parseCertTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range certTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
