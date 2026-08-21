// This file implements §3.7 chain self-consistency classification.
//
// SECURITY (T9): validateChain performs DATA-INTEGRITY CLASSIFICATION of
// untrusted provider bytes only — adjacent issuer→subject linkage, a self-signed
// terminal root, and hex-shaped serials. It is NOT X.509 trust-store path
// validation: it decodes no DER/PEM, verifies no signatures, and checks no
// expiry, revocation, hostname, or real-world trust. Its result (surfaced as
// SSLResult.ChainValid) must NEVER be used as a trust or authorization gate.

package whoisfreaks

import "fmt"

// maxProcessedChainCerts bounds how many chain certificates validateChain will
// process, so a provider-inflated sslCertificates[] cannot drive unbounded work
// on hostile input (security T6/§3.7). It MUST stay equal to
// maxChainCertsForCredit in credits.go so the credit meter and the chain
// validator agree on the same processing cap.
const maxProcessedChainCerts = 16

// validateChain classifies the self-consistency of an untrusted, leaf→root
// ordered certificate list (index 0 = leaf, last = the cert the provider claims
// is the root). certs may be nil, empty, or pathologically large; the function
// never panics and never mutates certs or its elements.
//
// It is integrity classification, NOT trust-store path validation, and its
// result must never gate a trust or authorization decision (see the file header,
// security T9).
//
// Returns:
//   - valid: true iff no anomaly was recorded, i.e. valid == (len(anomalies)==0).
//   - anomalies: deterministic, index-ordered defects (order described below).
//   - out: a fresh, sanitized copy of the processed certs — non-hex serials
//     blanked, a fabricated (non-self-signed or mislinked) terminal root
//     dropped. out is returned even when valid is false.
//
// Anomalies are emitted in this fixed order: an optional "chain truncated at N"
// first, then Rule 1 link breaks (ascending pair index), then Rule 3 non-hex
// serials (ascending index), then Rule 2 root defects. When the terminal cert is
// a root, the gap between it and the prior cert is reported once — as a Rule 2
// "root subject≠prior issuer", never also as a Rule 1 "link break".
func validateChain(certs []Certificate) (valid bool, anomalies []string, out []Certificate) {
	if len(certs) == 0 {
		return true, nil, nil // vacuously self-consistent; ssl.go decides meaning
	}

	// Cap the processed length; excess certs are dropped and the truncation is
	// itself an anomaly (security T6).
	n := len(certs)
	if n > maxProcessedChainCerts {
		n = maxProcessedChainCerts
		anomalies = append(anomalies, fmt.Sprintf("chain truncated at %d", maxProcessedChainCerts))
	}

	// Fresh copy of the processed prefix. Elements are value-copied, so blanking
	// a serial or dropping the root below never touches the caller's input.
	out = make([]Certificate, n)
	copy(out, certs[:n])

	last := n - 1
	terminalIsRoot := out[last].ChainOrder == "root"

	// Rule 1: adjacent issuer→subject linkage. When the terminal cert is a root,
	// the final (last-1 → last) pair is owned by Rule 2 and excluded here so that
	// gap is never double-reported.
	pairs := last
	if terminalIsRoot && last >= 1 {
		pairs = last - 1
	}
	for i := range pairs {
		if !out[i].Issuer.Equal(out[i+1].Subject) {
			anomalies = append(anomalies, fmt.Sprintf("link break [%d]→[%d]: issuer≠subject", i, i+1))
		}
	}

	// Rule 3: serial sanitization. Blank every non-hex serial in out and record
	// it. Runs before the Rule 2 root drop so each index still maps into out.
	for i := range n {
		if !isHexSerial(out[i].SerialNumber) {
			out[i].SerialNumber = ""
			anomalies = append(anomalies, fmt.Sprintf("non-hex serial [%d]", i))
		}
	}

	// Rule 2: root sanity. The terminal root must be self-signed and must link to
	// the prior cert; either failure drops it from out so it is never treated as
	// a trust anchor.
	if terminalIsRoot {
		root := out[last]
		bad := false
		if !root.Subject.Equal(root.Issuer) {
			anomalies = append(anomalies, "root not self-signed")
			bad = true
		}
		if last >= 1 && !root.Subject.Equal(out[last-1].Issuer) {
			anomalies = append(anomalies, "root subject≠prior issuer")
			bad = true
		}
		if bad && last >= 1 {
			out = out[:last] // drop the fabricated root; never a trust anchor
		}
	}

	return len(anomalies) == 0, anomalies, out
}

// isHexSerial reports whether s matches ^[0-9A-Fa-f:]+$ — a non-empty run of hex
// digits and colons. It is a linear byte scan (no regexp) so per-serial work is
// bounded on hostile input.
func isHexSerial(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		case c == ':':
		default:
			return false
		}
	}
	return true
}
