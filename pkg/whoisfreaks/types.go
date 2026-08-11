// Package whoisfreaks is a shared client for the WhoisFreaks SSL-certificate
// API. It performs single-domain SSL certificate lookups (leaf + chain, parsed
// fields plus raw PEM), classifies the provider's chain for internal
// self-consistency, and accounts for billed credits.
//
// Security note: this package parses no real certificates. It imports none of
// the standard-library X.509 or PEM decoding packages; the provider already
// returns parsed certificate fields, which are mapped as opaque, untrusted
// strings and never decoded as DER/PEM. Chain "validation" here is
// data-integrity classification of provider bytes, NOT trust-store path
// validation (see SSLResult.ChainValid).
package whoisfreaks

import (
	"strings"
	"time"
)

// DN is a certificate distinguished name (subject or issuer). Its String and
// Equal methods are the linkage primitive that chain validation (§3.7) uses to
// test whether issuer[n] resolves to subject[n+1].
//
// All fields are opaque, untrusted strings taken verbatim from the provider
// response; they are carried faithfully and never interpreted as trusted data.
type DN struct {
	CommonName   string
	Organization []string
	Country      []string
	Raw          string // full DN as the provider returned it (authoritative form)
}

// String returns a stable, deterministic textual form of the DN. When Raw is
// non-empty it is used verbatim (trimmed); otherwise the structured attributes
// are assembled in the fixed order CN, O, C joined by ", ". The result is a
// display form and preserves case; use Equal for normalized comparison.
func (d DN) String() string {
	if raw := strings.TrimSpace(d.Raw); raw != "" {
		return raw
	}
	return strings.Join(d.attributes(), ", ")
}

// Equal reports whether two DNs are equivalent under normalized comparison:
// whitespace runs collapsed to a single space and ASCII case folded. It is the
// linkage primitive for chain validation (§3.7): Chain[n].Issuer.Equal(
// Chain[n+1].Subject).
func (d DN) Equal(o DN) bool {
	return normalizeDN(d.String()) == normalizeDN(o.String())
}

// attributes assembles the structured DN attributes in a fixed, deterministic
// order, skipping empty values.
func (d DN) attributes() []string {
	var parts []string
	if cn := strings.TrimSpace(d.CommonName); cn != "" {
		parts = append(parts, "CN="+cn)
	}
	for _, o := range d.Organization {
		if o = strings.TrimSpace(o); o != "" {
			parts = append(parts, "O="+o)
		}
	}
	for _, c := range d.Country {
		if c = strings.TrimSpace(c); c != "" {
			parts = append(parts, "C="+c)
		}
	}
	return parts
}

// normalizeDN collapses internal whitespace and folds ASCII case so that
// cosmetically different but semantically identical DNs compare equal.
func normalizeDN(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// Certificate is a parsed certificate as returned by the provider. Every field
// is opaque, untrusted provider data; nothing here is parsed from real DER/PEM.
type Certificate struct {
	Subject               DN
	Issuer                DN
	SerialNumber          string // hex; blanked by chain validation if non-hex
	NotBefore             time.Time
	NotAfter              time.Time
	SignatureAlgorithm    string
	PublicKeyAlgorithm    string
	PublicKeyBits         int
	KeyUsage              []string
	ExtKeyUsage           []string
	CRLDistributionPoints []string
	OCSPServers           []string
	// SubjectAltNames are opaque, untrusted strings carried faithfully; never
	// logged raw and never auto-promoted to trusted hostnames (security T8).
	SubjectAltNames []string
	ChainOrder      string // "leaf"|"intermediate"|"root" — drives the §3.7 root check
}

// SSLOptions selects what an ssl/live lookup returns.
type SSLOptions struct {
	Chain bool // include the full certificate chain
	Raw   bool // include the raw PEM bytes verbatim
}

// SSLResult is the outcome of a single ssl/live lookup.
type SSLResult struct {
	Leaf           Certificate
	Chain          []Certificate // populated only when Chain=true; sanitized (bad root dropped)
	RawPEM         string        // populated only when Raw=true; carried verbatim
	CreditsCharged int           // credits the meter recorded for THIS call (AC#3)
	// ChainValid is self-consistency of the provider's chain bytes; NOT
	// trust-store path validation. A true value means the provider's chain is
	// well-linked and terminates in a self-signed cert it claims is the root; it
	// says nothing about real-world trust, expiry, revocation, or hostname.
	// Never gate a security/authorization decision on this field (security T9).
	ChainValid     bool
	ChainAnomalies []string // e.g. "link break [2]→[3]: issuer≠subject", "non-hex serial [3]", "root not self-signed"
}

// Usage maps the account usage endpoint (GET /v1.0/whoisapi/usage). Exact field
// mapping is verified against the Batch-3 fixture.
type Usage struct {
	Remaining int
	Used      int
	Total     int
}

// --- Unexported provider DTOs -------------------------------------------------
//
// These mirror the raw WhoisFreaks JSON. The exact shapes and tags are VERIFIED
// against the 2026-08-06 captured fixture in Batch 3 (ssl.go owns DTO→Certificate
// mapping); they are defined here so the data model lives in one file.

// dnDTO is the provider's representation of a distinguished name.
type dnDTO struct {
	CommonName   string   `json:"commonName"`
	Organization []string `json:"organization"`
	Country      []string `json:"country"`
	Raw          string   `json:"raw"`
}

// sslCertDTO is a single certificate entry in the provider response.
type sslCertDTO struct {
	Subject               dnDTO    `json:"subject"`
	Issuer                dnDTO    `json:"issuer"`
	SerialNumber          string   `json:"serialNumber"`
	NotBefore             string   `json:"notBefore"`
	NotAfter              string   `json:"notAfter"`
	SignatureAlgorithm    string   `json:"signatureAlgorithm"`
	PublicKeyAlgorithm    string   `json:"publicKeyAlgorithm"`
	PublicKeyBits         int      `json:"publicKeyBits"`
	KeyUsage              []string `json:"keyUsage"`
	ExtKeyUsage           []string `json:"extendedKeyUsage"`
	CRLDistributionPoints []string `json:"crlDistributionPoints"`
	OCSPServers           []string `json:"ocspServers"`
	SubjectAltNames       []string `json:"subjectAltNames"`
	ChainOrder            string   `json:"chainOrder"`
}

// sslLiveResponse is the top-level ssl/live response body.
type sslLiveResponse struct {
	SSLCertificates []sslCertDTO `json:"sslCertificates"`
	SSLRaw          string       `json:"sslRaw"`
}

// usageResponse is the raw account-usage response body.
type usageResponse struct {
	Remaining int `json:"remaining"`
	Used      int `json:"used"`
	Total     int `json:"total"`
}
