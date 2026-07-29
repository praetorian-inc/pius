package domains

import (
	"context"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"

	whoisparser "github.com/likexian/whois-parser"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("whois", func() plugins.Plugin { return &WhoisPlugin{} })
}

// WhoisPlugin performs domain WHOIS lookups to extract registration information
// (registrant organization, contact names, and emails) and emits them as preseed
// findings for downstream discovery.
type WhoisPlugin struct{}

func (p *WhoisPlugin) Name() string { return "whois" }
func (p *WhoisPlugin) Description() string {
	return "Domain WHOIS: extracts registrant organization, contacts, and emails from WHOIS records"
}
func (p *WhoisPlugin) Category() string { return "domain" }
func (p *WhoisPlugin) Phase() int       { return 0 }
func (p *WhoisPlugin) Mode() string     { return plugins.ModePassive }

func (p *WhoisPlugin) Accepts(input plugins.Input) bool {
	return input.Domain != ""
}

func (p *WhoisPlugin) Run(ctx context.Context, input plugins.Input) (findings []plugins.Finding, err error) {
	domain := rootDomain(input.Domain)
	if domain == "" {
		return nil, fmt.Errorf("whois: unable to determine root domain from %q", input.Domain)
	}

	// whoisparser.Parse runs over untrusted third-party WHOIS text. The
	// reverse-whois verifier already wraps its identical Parse call in a
	// worker-level recover (reverse_whois_verify.go) because plugins execute
	// inside an errgroup goroutine (runner/run.go) with no framework-level
	// recover — an unrecovered panic there crashes the whole pius run. Guard
	// this sibling call site the same way so a malformed record during primary
	// discovery de-grades to a logged error + no preseeds instead of a crash
	// (ENG-5123 review, Gemini).
	defer func() {
		if rec := recover(); rec != nil {
			slog.Warn("whois: recovered panic parsing WHOIS record; emitting no preseeds",
				"domain", domain, "panic", rec)
			findings = nil
			err = fmt.Errorf("whois: recovered panic parsing record for %q: %v", domain, rec)
		}
	}()

	raw, incomplete, err := whoisQuery(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("whois: lookup failed for %q: %w", domain, err)
	}

	// whoisQuery is shared with the reverse-whois verifier, where a caller
	// cancellation deliberately salvages the last post-referral record
	// (recall-safe). WhoisPlugin has no such recall contract: a cancelled run
	// must abort, not emit preseeds from a salvaged partial record. Re-check the
	// context before parsing/emitting (ENG-5123 review, Codex).
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// An incomplete chain reaches this point in one of two regimes, and the
	// re-check above is what separates them — do not read it as unreachable for
	// incomplete records:
	//
	//   - ctx-CAUSED partiality (the deadline/cancel expired mid-chain, which
	//     whoisQuery classifies as whoisIncompleteDeadline): ctx.Err() is non-nil,
	//     so the re-check fires and we already returned. Correct — a cancelled run
	//     must abort, not emit preseeds from a salvaged partial record.
	//   - a GENUINE transport failure on a referral hop after the registry
	//     answered: ctx stays clean, so control falls through to here and emitting
	//     is correct — the salvaged record is a real registry response, just less
	//     specific, and preseeds are additive discovery where a MISSING seed is the
	//     failure mode.
	//
	// So this warn-and-emit path serves the second regime (plus a hop budget
	// exhausted with a referral pending). Report the partiality so a thin preseed
	// set is attributable, but never gate emission on it (ENG-5405). Only `domain`
	// (already root-normalized) and the closed whoisIncompleteness constant are
	// logged — never the raw record or the unbounded referral server string.
	if incomplete != whoisComplete {
		slog.Warn("whois: referral chain incomplete; preseeds may be partial",
			"domain", domain, "reason", incomplete)
	}

	parsed, perr := whoisParseFn(raw)
	if perr != nil {
		slog.Warn("whois: parse failed, skipping preseed extraction", "domain", domain, "error", perr)
		return nil, nil
	}

	return extractPreseeds(parsed), nil
}

// whoisParseFn is a seam over whoisparser.Parse so the panic-recover in
// WhoisPlugin.Run can be exercised by a test that injects a panicking parse.
var whoisParseFn = whoisparser.Parse

// whoisPrivacyNames contains name-field values used by WHOIS privacy
// services. These appear as registrant name but don't identify a real person.
// Keyed by lowercase for case-insensitive matching.
var whoisPrivacyNames = map[string]bool{
	"registration private":                  true,
	"domain admin":                          true,
	"domain administrator":                  true,
	"whois agent":                           true,
	"whois privacy":                         true,
	"data protected":                        true,
	"redacted for privacy":                  true,
	"withheld for privacy":                  true,
	"contact privacy inc. customer":         true,
	"identity protection service":           true,
	"domain privacy group":                  true,
	"private registration":                  true,
	"not disclosed":                         true,
	"statutory masking enabled":             true,
	"admin":                                 true,
	"hostmaster":                            true,
	"dns admin":                             true,
	"domain hostmaster":                     true,
	"abuse":                                 true,
	"postmaster":                            true,
	"super privacy service ltd c/o migadu": true,
}

// whoisPrivacyGuards contains organization names used by WHOIS privacy
// services. These appear as registrant org but don't represent the actual
// domain owner. Keyed by lowercase for case-insensitive matching.
var whoisPrivacyGuards = map[string]bool{
	"domains by proxy, llc":              true,
	"domains by proxy":                   true,
	"whoisguard, inc.":                   true,
	"whoisguard protected":               true,
	"whoisguard":                         true,
	"privacy protect, llc":               true,
	"contact privacy inc.":               true,
	"contact privacy inc. customer":      true,
	"privacyprotect.org":                 true,
	"whois privacy corp.":                true,
	"perfect privacy, llc":               true,
	"data protected":                     true,
	"identity protection service":        true,
	"withheld for privacy":               true,
	"redacted for privacy":               true,
	"statutory masking enabled":          true,
	"super privacy service ltd":          true,
	"privacy service provided by withheld for privacy ehf": true,
	"domain protection services, inc.":                     true,
	"contactprivacy.com":                                   true,
	"private by design, llc":                               true,
	"domain privacy group, inc.":                           true,
	"whoisprivacyprotect.com":                              true,
	"gandi sas":                                            true,
	"tucows domains inc.":                                  true,
	"privacy hero, inc.":                                   true,
	"proxy protection llc":                                 true,
	"id shield":                                            true,
}

// Redaction MARKER vocabulary (ENG-5404).
//
// The two tables above are exact-phrase allowlists, which makes privacy
// detection structurally fail-open: it fires only when the registrant string is
// an enumerated wording or a SUPERSTRING of one (the substring pass in
// isMaskedOrg). Any wording assembled from the same vocabulary in a different
// order therefore escapes entirely — it is neither enumerated nor a superstring
// of anything enumerated. "DATA REDACTED", the live cloudflare.com registrant
// org, is exactly that case: unmistakably a redaction placeholder, yet
// unreachable by both tiers. Enumerating registrar wordings one at a time loses
// that race by construction, so detection also keys on the MARKER vocabulary a
// placeholder carries, independent of word order.
//
// Markers are matched on WHOLE TOKENS, never as substrings. That token boundary
// is what keeps the class fix from becoming a false-positive machine: a genuine
// org such as "Redactron Systems" contains "redact" but tokenizes to
// ["redactron", "systems"], so no token equals a marker and it stays unmasked.
// It is the same false-positive concern maskedSubstringMinLen encodes for the
// substring pass, enforced structurally rather than by phrase length.
//
// SCOPE: these tables are consumed ONLY by isMaskedOrg in
// reverse_whois_verify.go — the reverse-WHOIS ranking predicate. They are
// deliberately NOT wired into extractPreseeds: the whoisPrivacyGuards lookup at
// the "company" branch below is an EXACT-match preseed suppressor, and widening
// it to marker matching would silently change which preseeds this plugin emits.
// That is a separate behavior change with its own recall risk, outside
// ENG-5404's scope.
//
// Every entry below names the redaction ACTION ("redacted", "withheld",
// "masked"). That is the membership rule, and it is what keeps the table from
// drifting back into wording enumeration: a token qualifies only if its presence
// as a whole token IS the evidence of redaction, in any word order.
//
// EXCLUDED marker — "privacy": the ticket floated a bare "privacy" token as a
// candidate marker; it was considered and rejected. Genuine organizations carry
// it as a whole token (e.g. "Privacy International", a real NGO), so it would
// mask real registrants — and it buys nothing, because the multi-word privacy
// wordings ("whois privacy", "privacy protect, llc", "redacted for privacy", …)
// are already covered by tiers 1 and 2.
//
// EXCLUDED marker — "gdpr": the ticket floated it too, and it was carried here
// in the first cut before review (Codex, PR #106) pushed back. It fails the
// membership rule above: GDPR is the legal REASON a registrant is hidden, not
// the hiding itself, so it is not evidence on its own. A registrant genuinely
// named for the statute ("GDPR Register B.V.", "The GDPR Institute") would be
// read as a placeholder, and because the query org is compared against every
// candidate, a GDPR-named CUSTOMER would lose corroboration on all of its own
// domains at once — 0.60 to 0.50 across the board, plus a wasted WHOIS lookup
// each. Against that it buys no reach: the real registrar wordings that carry
// the statute carry an action word beside it ("REDACTED FOR GDPR",
// "GDPR Masked", "Data Protected by GDPR"), so all three remain masked: the
// first two through the "redacted" and "masked" markers here, and the third
// through tier 2's "data protected" guard phrase, which the substring pass
// answers before tier 3 is reached. Asserted by
// TestIsMaskedOrg_PrivacyMarkers, which keeps those wordings in the masked set
// and a statute-named org in the genuine set.
var whoisPrivacyMarkerTokens = map[string]bool{
	"redacted":  true,
	"redaction": true,
	"redact":    true,
	"withheld":  true,
	"masked":    true,
	"masking":   true,
}

// whoisPrivacyMarkerPhrases are marker RUNS of CONSECUTIVE tokens whose
// individual words are too generic to mark alone — "data", "not", and
// "protected" all appear in real org names, so only the adjacent pair is
// evidence of redaction.
var whoisPrivacyMarkerPhrases = [][]string{
	{"data", "protected"},
	{"not", "disclosed"},
}

// extractPreseeds pulls registrant organization, name, and email from WHOIS contacts.
func extractPreseeds(info whoisparser.WhoisInfo) []plugins.Finding {
	type param struct {
		name  string
		value string
	}

	seen := make(map[param]bool)
	var findings []plugins.Finding

	contacts := []*whoisparser.Contact{
		info.Registrant, info.Administrative, info.Billing, info.Technical,
	}
	for _, c := range contacts {
		if c == nil {
			continue
		}

		candidates := []param{
			{"company", c.Organization},
			{"name", c.Name},
			{"email", c.Email},
		}

		for _, p := range candidates {
			if p.value == "" || seen[p] {
				continue
			}
			if p.name == "email" && !isEmail(p.value) {
				continue
			}
			if p.name == "company" && whoisPrivacyGuards[strings.ToLower(p.value)] {
				continue
			}
			if p.name == "name" && whoisPrivacyNames[strings.ToLower(p.value)] {
				continue
			}
			seen[p] = true

			preseedType := "whois+" + p.name
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingPreseed,
				Value:  p.value,
				Source: "whois",
				Data: map[string]any{
					"preseed_type":  preseedType,
					"preseed_title": p.value,
				},
			})
		}
	}

	return findings
}

// rootDomain extracts the registrable domain (e.g., "example.com" from "sub.example.com").
// Uses a simple heuristic: take the last two labels. This covers the common case;
// multi-level TLDs (e.g., ".co.uk") are not handled here — WHOIS servers typically
// resolve them correctly regardless.
func rootDomain(domain string) string {
	domain = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	if len(parts) == 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func isEmail(s string) bool {
	_, err := mail.ParseAddress(s)
	return err == nil
}
