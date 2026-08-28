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
	Subject            DN
	Issuer             DN
	SerialNumber       string // hex; blanked by chain validation if non-hex
	NotBefore          time.Time
	NotAfter           time.Time
	SignatureAlgorithm string
	// AuthenticationType is the provider's DV/OV/self-signed-CA classification of
	// the certificate — one of "domain" | "organization" | "self-signed-ca". It is
	// opaque, untrusted provider data (never derived from a real certificate) and
	// is exposed for issuer-anomaly / DV-vs-OV heuristics; never gate a trust or
	// authorization decision on it.
	AuthenticationType    string
	PublicKeyAlgorithm    string
	PublicKeyBits         int
	KeyUsage              []string
	ExtKeyUsage           []string
	CRLDistributionPoints []string
	OCSPServers           []string
	// SubjectAltNames are opaque, untrusted strings carried faithfully; never
	// logged raw and never auto-promoted to trusted hostnames (security T8).
	SubjectAltNames []string
	ChainOrder      string // "end-user"|"intermediate"|"root" — drives the §3.7 root check
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
	// trust-store path validation. A true value means the provider's chain bytes
	// are well-linked and internally self-consistent, AND — only if the chain
	// terminates in a cert claiming to be the root (ChainOrder == "root") — that
	// terminal cert is self-signed; a chain ending in a leaf or intermediate is
	// held to no self-signed-root clause. It says nothing about real-world trust,
	// expiry, revocation, or hostname. Never gate a security/authorization
	// decision on this field (security T9).
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
// These mirror the raw WhoisFreaks JSON. The shapes and json tags below are
// pinned to the vendor's rendered-docs SSL Certificate API wire format recorded
// in the OFFSEC-2444 wire-format comment (a leaf→root sslCertificates[] array
// where each cert nests publicKey and extensions objects). ssl.go owns the
// DTO→Certificate mapping; the DTOs live here so the data model stays in one
// file.
//
// Exactly TWO tags still require confirmation against a LIVE response and are
// marked [VERIFY] at their fields: the raw-cert key (sslRaw) — the docs' raw
// sample carried no raw field — and the CRL key (crlDistributionPoints) — the
// docs' extensions sample showed only authorityInfoAccess, no CRL key.

// dnDTO is the provider's representation of a distinguished name.
type dnDTO struct {
	CommonName   string   `json:"commonName"`
	Organization []string `json:"organization"`
	Country      []string `json:"country"`
	Raw          string   `json:"raw"`
}

// publicKeyDTO is the provider's nested publicKey object. keySize is a
// unit-suffixed STRING (e.g. "256 bit"), NOT an integer — parseKeyBits (ssl.go)
// extracts the leading digits on read so a naive int json field cannot fail the
// whole unmarshal with an UnmarshalTypeError.
type publicKeyDTO struct {
	KeySize      string `json:"keySize"`
	KeyAlgorithm string `json:"keyAlgorithm"`
}

// authorityInfoAccessDTO is the provider's extensions.authorityInfoAccess object:
// CA-issuer URLs and OCSP responder URLs.
type authorityInfoAccessDTO struct {
	Issuers []string `json:"issuers"`
	OCSP    []string `json:"ocsp"`
}

// subjectAltNamesDTO is the provider's extensions.subjectAlternativeNames object.
// Only dnsNames is mapped today; other SAN kinds are unmapped (YAGNI).
type subjectAltNamesDTO struct {
	DNSNames []string `json:"dnsNames"`
}

// extensionsDTO is the provider's nested extensions object.
type extensionsDTO struct {
	AuthorityKeyIdentifier  string                 `json:"authorityKeyIdentifier"`
	SubjectKeyIdentifier    string                 `json:"subjectKeyIdentifier"`
	KeyUsages               []string               `json:"keyUsages"`
	ExtendedKeyUsages       []string               `json:"extendedKeyUsages"`
	AuthorityInfoAccess     authorityInfoAccessDTO `json:"authorityInfoAccess"`
	SubjectAlternativeNames subjectAltNamesDTO     `json:"subjectAlternativeNames"`
	CertificatePolicies     []struct {
		PolicyID string `json:"policyId"`
	} `json:"certificatePolicies"`
	// CRLDistributionPoints: [VERIFY] live. The rendered docs did NOT confirm this
	// key — their extensions sample showed only authorityInfoAccess, no CRL field.
	// "crlDistributionPoints" is a best-guess tag; confirm against a live response.
	CRLDistributionPoints []string `json:"crlDistributionPoints"`
}

// sslCertDTO is a single certificate entry in the provider response. Its shape
// mirrors the vendor's rendered-docs wire format: nested subject/issuer,
// publicKey, and extensions objects, with a unit-suffixed keySize and
// non-RFC3339 validity dates that ssl.go parses on read.
type sslCertDTO struct {
	Subject            dnDTO         `json:"subject"`
	Issuer             dnDTO         `json:"issuer"`
	SerialNumber       string        `json:"serialNumber"`
	SignatureAlgorithm string        `json:"signatureAlgorithm"`
	AuthenticationType string        `json:"authenticationType"`
	ValidityStartDate  string        `json:"validityStartDate"`
	ValidityEndDate    string        `json:"validityEndDate"`
	PublicKey          publicKeyDTO  `json:"publicKey"`
	Extensions         extensionsDTO `json:"extensions"`
	ChainOrder         string        `json:"chainOrder"`
}

// sslLiveResponse is the top-level ssl/live response body.
type sslLiveResponse struct {
	SSLCertificates []sslCertDTO `json:"sslCertificates"`
	// SSLRaw: [VERIFY] live. The docs did NOT reveal which field carries the raw
	// OpenSSL output — a sslRaw=true sample showed no raw field — so "sslRaw" is a
	// best-guess tag; confirm against a live response before relying on it.
	SSLRaw string `json:"sslRaw"`
}

// usageResponse is the raw account-usage response body.
type usageResponse struct {
	Remaining int `json:"remaining"`
	Used      int `json:"used"`
	Total     int `json:"total"`
}
