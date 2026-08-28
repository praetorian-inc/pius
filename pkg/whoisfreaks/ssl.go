package whoisfreaks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// errNoCertificates is returned when ssl/live succeeds (HTTP 200) but the
// provider's sslCertificates array is empty or absent. It is charged 0 credits
// (T6): an empty result is free and must not be indexed.
var errNoCertificates = errors.New("whoisfreaks: response contained no certificates")

// certTimeLayouts are the timestamp formats accepted for a certificate's
// validityStartDate/validityEndDate, tried in order. The vendor's rendered docs
// pin the wire format to a non-RFC3339 datetime with an UNPADDED day and a
// trailing zone literal — e.g. "2024-09-7 23:03:18 UTC" — so the padded
// "2006-01-02 ..." layouts alone do not parse it (verified). The list therefore
// carries both padded and unpadded day/month variants. Parsing stays tolerant
// and non-fatal: an unrecognized value yields the zero time rather than an
// error (see parseCertTime).
var certTimeLayouts = []string{
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05 MST",
	"2006-01-2 15:04:05 MST", // vendor wire format: padded month, UNPADDED day, zone
	"2006-1-2 15:04:05 MST",  // fully unpadded month + day, zone
	"2006-01-2 15:04:05",     // unpadded day, no zone
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

// mapCertificate maps a provider certificate DTO to the exported Certificate,
// flattening the vendor's nested publicKey/extensions objects into the flat
// Certificate shape. Every field is carried verbatim as opaque, untrusted data;
// only the validity timestamps and the unit-suffixed key size are parsed (both
// tolerantly, never fatally). No DER/PEM is decoded here.
func mapCertificate(d sslCertDTO) Certificate {
	return Certificate{
		Subject:               mapDN(d.Subject),
		Issuer:                mapDN(d.Issuer),
		SerialNumber:          d.SerialNumber,
		NotBefore:             parseCertTime(d.ValidityStartDate),
		NotAfter:              parseCertTime(d.ValidityEndDate),
		SignatureAlgorithm:    d.SignatureAlgorithm,
		AuthenticationType:    d.AuthenticationType,
		PublicKeyAlgorithm:    d.PublicKey.KeyAlgorithm,
		PublicKeyBits:         parseKeyBits(d.PublicKey.KeySize),
		KeyUsage:              d.Extensions.KeyUsages,
		ExtKeyUsage:           d.Extensions.ExtendedKeyUsages,
		CRLDistributionPoints: d.Extensions.CRLDistributionPoints,
		OCSPServers:           d.Extensions.AuthorityInfoAccess.OCSP,
		SubjectAltNames:       d.Extensions.SubjectAlternativeNames.DNSNames,
		ChainOrder:            d.ChainOrder,
	}
}

// mapDN maps a provider distinguished-name DTO to the exported DN, carrying each
// field verbatim.
func mapDN(d dnDTO) DN {
	return DN(d)
}

// parseKeyBits extracts the integer key size from the vendor's unit-suffixed
// keySize string (e.g. "256 bit" -> 256, "4096 bit" -> 4096). It trims, then
// takes the leading run of ASCII digits and Atoi's it; empty input or input with
// no leading digit (e.g. "" or "unknown") yields 0.
//
// Parsing on read is deliberate: keySize is a STRING with a unit on the wire, so
// a naive `int` json field would raise a fatal UnmarshalTypeError that discards
// the ENTIRE response. Extracting the number here keeps the whole lookup alive
// and treats a missing/odd size as a non-fatal 0.
func parseKeyBits(s string) int {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0
	}
	return n
}

// parseCertTime parses a certificate timestamp using certTimeLayouts. It is
// deliberately non-fatal: an empty or unrecognized value returns the zero
// time.Time rather than an error, so a single odd timestamp never fails an
// otherwise good lookup and never panics. The accepted layouts are pinned to the
// vendor's rendered-docs wire format (non-RFC3339, unpadded day, trailing zone);
// the tolerant fallbacks remain in case the provider drifts.
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
