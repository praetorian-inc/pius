package domains

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"
	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

// Reverse-WHOIS verify-after-retrieve scoring (ENG-5123).
//
// A reverse-WHOIS hit is a broad substring/token match over a full WHOIS
// record, so a match does NOT prove the candidate's registrant is the query
// org. To reduce that false-positive class we re-resolve each candidate's OWN
// registrant organization and compare it to the query org.
//
// Design constraint (human-approved): reverse-WHOIS is a lead signal, not
// ownership evidence. Re-reading the candidate's own WHOIS/RDAP samples the
// SAME noisy, frequently-masked namespace the lead came from, so token
// similarity between two registrant-org strings is nowhere near an auto-clean
// bar — and, by the same logic, nowhere near an auto-DROP bar either. A
// token-mismatched registrant routinely reflects legitimate cross-entity
// ownership (subsidiaries, parent/holding registrations, corporate registrars,
// DBAs, post-acquisition records), so removing it would silently destroy a real
// asset. Corroboration is therefore used ONLY to RANK within the needs_review
// band: a clear mismatch is de-ranked to the bottom of the band, never dropped.
// Reverse-WHOIS never removes a candidate from the graph. Every emitted finding
// is scored strictly below plugins.ConfidenceHigh, so plugins.NeedsReview always
// flags it. An auto-clean path, if ever wanted, must come from an
// INDEPENDENT corroboration channel calibrated against labeled data — out of
// scope, filed as follow-up.
const (
	// confReverseWhoisCorroborated is the top of the needs_review band: the
	// candidate's own registrant org corroborates the query org. Still < 0.65,
	// so it ranks above unverified matches without reading as clean.
	confReverseWhoisCorroborated = 0.60
	// confReverseWhoisUnverified is the mid-band score for every match that is
	// neither corroborated nor a clear mismatch. Several distinct routes land here
	// — a lookup that failed, was cut short, or was never attempted; a masked or
	// absent registrant; an org that reduces to no comparable tokens; an indecisive
	// partial-token overlap — and the list is deliberately NOT enumerated here: the
	// authoritative, exhaustive-by-construction enumeration is the set of
	// justifyReverseWhois* constants below, which is what a reviewer actually reads.
	// Each of those distinguishes its route in WORDING only; every one of them keeps
	// this score, so the band a candidate lands in is independent of which route it
	// took (ENG-5889).
	confReverseWhoisUnverified = 0.50
	// confReverseWhoisMismatch is the bottom-of-band score for a present,
	// unmasked registrant org that clearly disagrees with the query org. It sits
	// below confReverseWhoisUnverified so the likely false positive (walmart.com
	// from a Leica query) sinks to the bottom of the Pending queue, but stays
	// >= plugins.ConfidenceLow so it remains needs_review — de-ranked, NEVER
	// dropped, because a textual registrant mismatch is not proof of non-ownership.
	confReverseWhoisMismatch = 0.40

	// simCorroborate is the token-similarity threshold at/above which the
	// candidate's registrant org is treated as corroborating the query org.
	simCorroborate = 0.60
	// simMismatch is the token-similarity threshold below which a present,
	// unmasked registrant org is treated as a clear mismatch and de-ranked to the
	// bottom of the needs_review band (the walmart.com-from-a-Leica-query false
	// positive) — de-ranked, never dropped.
	simMismatch = 0.30

	// maxReverseWhoisCandidates caps how many candidates we verify per run.
	maxReverseWhoisCandidates = 500
	// reverseWhoisWorkers bounds concurrent registrant lookups.
	reverseWhoisWorkers = 6
	// reverseWhoisLookupTimeout bounds a single resolver STEP — the RDAP attempt,
	// and INDEPENDENTLY the WHOIS fallback. resolveWithFallback derives each step's
	// context fresh from the overall budget context, so an RDAP attempt that burns
	// its whole timeout does NOT starve the WHOIS fallback of time to recover from
	// precisely that RDAP-timeout case (ENG-5123 review, Codex). Both steps stay
	// bounded by reverseWhoisTotalBudget, so worst case per candidate is two step
	// timeouts, still capped by the pass-wide budget.
	reverseWhoisLookupTimeout = 10 * time.Second
)

// reverseWhoisTotalBudget bounds the ENTIRE verification pass, not just a single
// lookup. Even with RDAP now running in parallel (a per-worker client pool — see
// viaRDAP), a single candidate can cost up to two step timeouts (RDAP, then the
// WHOIS fallback), and the WHOIS fallback itself follows up to 5 referral hops.
// Against a large result set backed by slow or timing-out resolvers, that per-
// candidate cost would otherwise let the plugin — which holds a phase-0
// concurrency slot the whole time — run for many minutes (ENG-5123 review, Codex
// critical). This overall deadline caps that: any candidate still unresolved when
// the budget expires is scored unverified (recall-safe — still emitted, still
// needs_review, never dropped). It is a var, not a const, so tests can shorten it.
// The per-step read path now honors ctx (see whoisclient.go); a byte cap on the
// WHOIS response is tracked as ENG-5167. This budget is the backstop that holds
// regardless.
var reverseWhoisTotalBudget = 90 * time.Second

// errReverseWhoisBudgetExpired exists SOLELY as the context.Cause discriminator
// that lets verifyCandidates prove the pass-wide reverseWhoisTotalBudget — and
// not some ancestor deadline — is what cancelled the verification pass, which is
// the whole meaning of the budget_expired log field. It is never returned to a
// caller and never wrapped into a plugin error; the only thing that ever reads it
// is budgetFired, via context.Cause (ENG-5405).
var errReverseWhoisBudgetExpired = errors.New("reverse-whois: pass verification budget expired")

// registrantResult is the outcome of resolving a single candidate domain's own
// registrant organization.
type registrantResult struct {
	// Org is the resolved registrant organization (empty if none was found).
	Org string
	// Masked is true when Org is a known WHOIS privacy/proxy string.
	Masked bool
	// Found is true when a non-empty registrant org was resolved.
	Found bool

	// Incomplete records why the WHOIS leg that produced this result is known to
	// be partial; whoisComplete ("") when the chain ran to completion, when WHOIS
	// never ran (RDAP answered), or when the candidate was never looked up.
	//
	// PURELY OBSERVATIONAL: it must never be read by decideConfidence. A salvaged
	// partial record that DOES yield a registrant org is still scored on its
	// merits — that recall is what the salvage exists for (ENG-5405 AC4).
	Incomplete whoisIncompleteness
}

// registrantResolver resolves a domain's own registrant organization. The prod
// implementation is rdapWhoisResolver; tests inject a stub.
type registrantResolver interface {
	resolveRegistrant(ctx context.Context, domain string) (registrantResult, error)
}

// candidate pairs a discovered domain with its pre-built finding (whose
// Data["org"] provenance is the query org / active seed).
type candidate struct {
	domain  string
	finding plugins.Finding
}

// candidateOutcome is one worker's observability report for one candidate.
//
// Written index-disjointly — worker i writes only outcomes[i], exactly like the
// existing decisions[i] — so verifyCandidates stays lock-free and g.Wait() remains
// the single happens-before barrier that publishes every write (ENG-5123 review;
// ENG-5405). No mutex and no atomic: either would introduce the first shared
// mutable state into this fan-out and weaken a property the pass documents.
type candidateOutcome struct {
	incomplete whoisIncompleteness // whoisComplete when the WHOIS leg finished, or never ran
	failed     bool                // resolveRegistrant returned an error
	panicked   bool                // the worker recovered a panic before scoring
}

// orgLegalSuffixes are legal-form tokens stripped by normalizeOrg before
// comparison. Disambiguating tokens (group, holdings, international, systems)
// are deliberately NOT included — they carry signal.
var orgLegalSuffixes = map[string]bool{
	"inc": true, "llc": true, "ltd": true, "corp": true, "gmbh": true,
	"sas": true, "co": true, "plc": true, "bv": true, "nv": true,
	"pty": true, "oy": true, "ab": true, "as": true, "kk": true,
	"pte": true, "sa": true, "srl": true, "spa": true, "ag": true,
	"kg": true, "aps": true, "oyj": true,
	// Full-word spellings of forms already covered in abbreviated form above, so
	// "Walmart Incorporated" normalizes the same as "Walmart Inc." (ENG-5123
	// review, Gemini). These remain generic legal-form words — disambiguating
	// tokens (group, holdings, international, systems) are still excluded.
	"corporation": true, "incorporated": true, "company": true, "limited": true,
}

// normalizeOrg lowercases, tokenizes, and strips legal-suffix tokens so that
// "Walmart Inc." and "Walmart" compare equal while disambiguating tokens are
// preserved. Without suffix stripping, "Walmart Inc." vs a "…, Inc." query
// would share the "inc" token and wrongly clear the mismatch-drop test.
func normalizeOrg(s string) string {
	tokens := tokenize(s)
	kept := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if orgLegalSuffixes[t] {
			continue
		}
		kept = append(kept, t)
	}
	return strings.Join(kept, " ")
}

// maskedSubstringMinLen is the shortest privacy-guard phrase eligible for
// substring matching in isMaskedOrg. The whoisPrivacyGuards phrases are all
// distinctive multi-word org strings (>= 8 chars), so requiring this length
// avoids matching an incidental substring of a legitimate org name.
const maskedSubstringMinLen = 8

// isMaskedOrg reports whether v is a known WHOIS privacy/proxy org or name
// string. It first tries an exact lowercase lookup (parity with whois.go's
// registrant filter), then falls back to substring containment against the
// known privacy-GUARD phrases. Privacy/proxy orgs routinely append a
// per-customer suffix ("Domains By Proxy, LLC (customer 12345)"), which an
// exact lookup misses; because these are non-authoritative registrants, missing
// one would mis-rank (a masked domain scored as a mismatch) rather than clear
// it, but the substring pass keeps the masked → unverified ranking correct
// (ENG-5123). Only the org-name guard phrases are used for substring matching;
// the name-field generics ("admin", "abuse") are too short to match safely.
//
// Both of those tiers are keyed on ENUMERATED wordings, which makes them
// structurally fail-open: they fire only on a listed phrase or a superstring of
// one, so a placeholder built from the same vocabulary in a different word order
// is unreachable by either. "DATA REDACTED" — the live cloudflare.com registrant
// org — is exactly that miss, and it mis-ranks twice: decideConfidence reads the
// zero token overlap as a clear MISMATCH (0.40) rather than unverifiable (0.50),
// and resolveWithFallback treats the placeholder as an authoritative registrant
// and short-circuits the WHOIS leg that may carry the real one. A third tier
// therefore matches redaction MARKER vocabulary on whole tokens, catching the
// class instead of chasing registrar wordings one phrase at a time (ENG-5404).
// Two earlier versions of this comment tried to summarize the change as a
// DIRECTIONAL band move, and both were wrong (Codex, PR #106 rounds 2 and 3).
// Direction is not the thing to state. What the tier does is force the DIRECTLY
// SCORED value to unverifiable (0.50) — which may raise, preserve, or LOWER what
// that same string would otherwise have scored. Lowering is not exotic: for a
// query org "Data Inc.", normalizeOrg gives "data" against the placeholder's
// "data redacted", and tokenSimilarity divides by the SHORTER token set, so the
// placeholder used to score a spurious 1.0 and corroborate at 0.60. And in the
// integrated path, masking additionally routes through resolveWithFallback,
// whose WHOIS result is scored FRESH by decideConfidence and can land in any of
// the three bands, 0.40 included.
//
// The invariant that does hold unconditionally — and all ENG-5123 ever claimed —
// is "never DROPS", not "never demotes": every outcome stays inside the
// needs_review band [0.35, 0.65), below ConfidenceHigh, and no candidate is
// removed, so a human still sees it.
//
// The false-positive cost — a real org carrying marker vocabulary as a whole
// token, e.g. "Masking Technologies" — is accepted, and unlike the rejected
// "gdpr" token it is paid for: these tokens name the redaction ACTION and carry
// test-proven recall (AC1, isMaskedOrg("DATA REDACTED"), is unreachable without
// "redacted"). See whois.go for the membership rule that holds the table to that
// vocabulary.
func isMaskedOrg(v string) bool {
	key := strings.ToLower(strings.TrimSpace(v))
	if key == "" {
		return false
	}
	if whoisPrivacyGuards[key] || whoisPrivacyNames[key] {
		return true
	}
	for phrase := range whoisPrivacyGuards {
		if len(phrase) >= maskedSubstringMinLen && strings.Contains(key, phrase) {
			return true
		}
	}
	// Tier 3: token-boundary marker matching. tokenize (github_org.go) lowercases
	// and splits on non-alphanumerics, which is precisely the boundary needed here.
	// normalizeOrg is deliberately NOT used: it strips legal-suffix tokens, a
	// similarity-comparison concern that would silently drop tokens from a masking
	// decision.
	return hasPrivacyMarker(tokenize(key))
}

// hasPrivacyMarker reports whether tokens carry redaction-placeholder
// vocabulary. Matching is on whole tokens, never substrings: "Redactron
// Systems" contains "redact" but tokenizes to ["redactron","systems"] and stays
// unmasked, which is the false-positive class maskedSubstringMinLen guards
// against in the substring pass.
func hasPrivacyMarker(tokens []string) bool {
	for _, t := range tokens {
		if whoisPrivacyMarkerTokens[t] {
			return true
		}
	}
	for _, phrase := range whoisPrivacyMarkerPhrases {
		if containsTokenRun(tokens, phrase) {
			return true
		}
	}
	return false
}

// containsTokenRun reports whether run appears as consecutive tokens in tokens.
func containsTokenRun(tokens, run []string) bool {
	if len(run) == 0 || len(run) > len(tokens) {
		return false
	}
	for i := 0; i+len(run) <= len(tokens); i++ {
		if slices.Equal(tokens[i:i+len(run)], run) {
			return true
		}
	}
	return false
}

// isPlausibleDomain reports whether d is a syntactically plausible hostname:
// non-empty, within the DNS length limit, free of whitespace/control characters
// and URL/authority punctuation, and containing at least one dot. It is
// intentionally permissive about the label charset (IDN punycode already arrives
// ASCII); the goal is to reject malformed or injection-bearing values, not to
// fully validate DNS grammar. This is the ONLY gate between a source's raw
// "domain" field and a graph node, because reverse-whois never drops (ENG-5123),
// so a value like "example.com:443" or "http://example.com/path" must be rejected
// here or it becomes a bogus domain node (ENG-5123 review, Codex suggestion).
func isPlausibleDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	for _, r := range d {
		switch {
		case r <= ' ' || r == 0x7f:
			return false
		case r == '/' || r == ':' || r == '@' || r == '?' || r == '#':
			// URL / authority punctuation: a bare registrable hostname carries none
			// of these.
			return false
		}
	}
	// A registrable domain has at least one dot; a bare single label is not a
	// candidate a reverse-whois source should be returning.
	return strings.Contains(d, ".")
}

// confidenceDecision is one verification outcome: the score it earns and the
// explanation a reviewer sees.
//
// It is a SINGLE entry, deliberately — unlike the additive plugins, an outcome
// here is one mutually exclusive CLASSIFICATION of one verification operation,
// not an independent signal that could co-occur with another. What makes it
// exclusive is that a candidate is verified exactly once, so exactly one
// classification is true of it; it is NOT a count. Counting proves nothing here
// and an earlier version of this comment ("the three outcomes") invited the
// reader to check the wrong thing: the scores number three while the
// justifyReverseWhois* wordings number more, and both sets grow whenever a route
// earns its own explanation (ENG-5889).
//
// Emitting outcomes as separate additive entries would let a candidate
// accumulate contradictory evidence and climb out of the needs_review band,
// breaking the invariant that every reverse-WHOIS finding stays below
// ConfidenceHigh. That single-entry rule is load-bearing and holds however many
// wordings exist.
type confidenceDecision struct {
	Score         float64
	Justification string
}

// Justifications never name the resolved registrant. The registrant string is
// exactly the third-party WHOIS/RDAP PII this plugin is careful not to log, and
// a justification travels into Guard and onto an operator's screen — so these
// describe the RELATION to the queried organization ("corroborates", "differs")
// without reproducing the value itself.
const (
	justifyReverseWhoisCorroborated = "The candidate domain's own registrant organization corroborates the queried organization"
	justifyReverseWhoisUnverified   = "The candidate domain's registrant organization could not be verified (masked, absent, or unresolvable)"
	justifyReverseWhoisMismatch     = "The candidate domain's registrant organization differs from the queried organization; retained for review because a textual mismatch is not proof of non-ownership"

	// The three below split routes that all used to emit
	// justifyReverseWhoisUnverified — "could not be verified (masked, absent, or
	// unresolvable)" — even though none of them describes what actually happened
	// on that route. All three keep confReverseWhoisUnverified: ENG-5889 is a
	// wording defect, not a scoring change, so the band each candidate lands in
	// is byte-identical to before.
	justifyReverseWhoisAmbiguous   = "The candidate domain's registrant organization neither corroborates nor clearly differs from the queried organization; retained for review because a partial name overlap is evidence of neither ownership nor its absence"
	justifyReverseWhoisNoQueryOrg  = "The candidate domain's registrant organization was not compared: this pivot supplied no queried organization"
	justifyReverseWhoisNotLookedUp = "The candidate domain's registrant organization was not looked up: the per-pass resolver cap was reached before this candidate"

	// The two below split the LAST route still emitting the unverifiable wording
	// falsely: the no-comparable-tokens guard in decideConfidence. By the time it
	// runs, the lookup has already succeeded, the registrant is unmasked and
	// non-empty — so every clause of "masked, absent, or unresolvable" is false, the
	// same construction the AMBIGUOUS split below already rejected for reporting a
	// lookup problem that never occurred (ENG-5889).
	//
	// They are split by SIDE because the two sides are not the same fact and are not
	// even about the same organization. The queried org is pass-wide (input.OrgName),
	// so its wording must never blame the candidate's registrant: doing so
	// mis-attributes the failure to the wrong side AND repeats that mis-attribution
	// for every candidate in the pass, reading as a systemic WHOIS outage when the
	// real cause is one un-comparable seed. Neither is justifyReverseWhoisNoQueryOrg:
	// that reports NO queried organization at all (email-mode), whereas here one was
	// supplied but normalized away to nothing.
	// Both keep confReverseWhoisUnverified — wording, not scoring.
	//
	// Both name the normalization OUTCOME ("normalizes to no comparable tokens")
	// rather than a single cause, and give legal-form stripping as an EXAMPLE. There
	// are two routes to empty and stripping is only one of them: normalizeOrg
	// tokenizes first and drops legal suffixes second, and tokenize keeps only ASCII
	// letters and digits — so a name like "!!!" clears the TrimSpace fast path in
	// verifyCandidates, reaches here, and normalizes to "" with nothing stripped at
	// all. Blaming legal-form stripping there would report an event that never
	// occurred, which is the very defect class ENG-5889 exists to fix.
	justifyReverseWhoisQueryOrgNotComparable   = "The candidate domain's registrant organization was resolved but not compared: the queried organization normalizes to no comparable tokens (e.g. a name made up only of legal-form words, or one carrying no ASCII letters or digits), so no comparison was possible"
	justifyReverseWhoisRegistrantNotComparable = "The candidate domain's registrant organization was resolved but normalizes to no comparable tokens (e.g. a name made up only of legal-form words, or one carrying no ASCII letters or digits), so it could not be compared to the queried organization"
)

// decideConfidence maps a candidate's resolved registrant against the query org
// to a needs-review decision. THREE distinct classes share the mid-band score and
// must NOT share wording (ENG-5889), because each reports a different fact to the
// reviewer who reads it. Classes, not routes: NOT COMPARABLE splits by SIDE below,
// so the three classes are reached by four mid-band returns.
//
//   - UNVERIFIABLE — a lookup error, or a masked or absent registrant. The
//     registrant itself never arrived, so there was nothing to compare.
//   - NOT COMPARABLE — the registrant arrived clean (lookup succeeded, unmasked,
//     non-empty) but one side normalizes to no comparable tokens — an all-suffix org
//     like "Co., Ltd." whose tokens are all stripped, or a name like "!!!" that
//     carries no ASCII letters or digits to tokenize. Nothing failed and
//     nothing is hidden; there is simply no token to compare. This is its own class,
//     NOT a sub-case of UNVERIFIABLE: the behavior that shipped before ENG-5889
//     folded it in, and that is the ruling ENG-5889 overturns. It splits further by
//     SIDE, since the queried org and the candidate's registrant are different
//     organizations.
//   - AMBIGUOUS — the registrant WAS compared and the comparison was indecisive.
//
// None of the three classes is a "mismatch". Nothing here ever drops a
// candidate — a clear mismatch is de-ranked to the bottom of the band, and
// every return scores < ConfidenceHigh.
func decideConfidence(queryOrg string, res registrantResult, lookupErr error) confidenceDecision {
	unverified := confidenceDecision{Score: confReverseWhoisUnverified, Justification: justifyReverseWhoisUnverified}

	if lookupErr != nil || res.Masked || res.Org == "" {
		return unverified
	}
	nq, nc := normalizeOrg(queryOrg), normalizeOrg(res.Org)
	// Past the guard above, the lookup SUCCEEDED and the registrant is unmasked and
	// non-empty, so "masked, absent, or unresolvable" is false in all three clauses
	// and the unverifiable wording would report a lookup problem that never occurred
	// (ENG-5889) — the same defect the AMBIGUOUS default arm below already fixed, one
	// arm further up. Token similarity is undefined when either side has no
	// comparable tokens, so this stays mid-band and is never a mismatch; only the
	// wording changes.
	//
	// The queried side is tested FIRST, which also decides the both-empty case in its
	// favour. Either verdict would be defensible there, but the queried org is
	// pass-wide (input.OrgName), so it is the cause that explains every candidate in
	// the pass at once and the only one a reviewer can act on — re-seed the pivot.
	// Reporting the per-candidate side instead would bury that under one identical
	// line per candidate.
	if nq == "" {
		return confidenceDecision{Score: confReverseWhoisUnverified, Justification: justifyReverseWhoisQueryOrgNotComparable}
	}
	if nc == "" {
		return confidenceDecision{Score: confReverseWhoisUnverified, Justification: justifyReverseWhoisRegistrantNotComparable}
	}
	sim := tokenSimilarity(nq, nc)
	switch {
	case sim >= simCorroborate:
		return confidenceDecision{Score: confReverseWhoisCorroborated, Justification: justifyReverseWhoisCorroborated}
	case sim < simMismatch:
		// Present, unmasked, clear mismatch → de-rank to the bottom of the
		// needs_review band (walmart.com-from-a-Leica-query). A textual registrant
		// mismatch is not proof of non-ownership, so this is never dropped.
		return confidenceDecision{Score: confReverseWhoisMismatch, Justification: justifyReverseWhoisMismatch}
	default:
		// Partial overlap [simMismatch, simCorroborate). Same mid-band score as every
		// other return above bar the two banded ones, but deliberately NOT their
		// wording — and note "unverifiable" now names only the FIRST of those returns,
		// not the not-comparable pair (ENG-5889): here the
		// registrant WAS resolved, unmasked, non-empty and comparable — the
		// comparison simply came out indecisive. Saying "could not be verified"
		// would report a lookup problem that never occurred (ENG-5889).
		return confidenceDecision{Score: confReverseWhoisUnverified, Justification: justifyReverseWhoisAmbiguous}
	}
}

// verifyCandidates scores each candidate by resolving its own registrant and
// comparing to queryOrg, then emits findings in the original order. Lookups run
// under bounded concurrency with a per-lookup timeout; a timeout/error is
// treated as unverifiable. No candidate is ever dropped — every plausible
// candidate is emitted (in needs_review).
//
// At most maxReverseWhoisCandidates candidates are resolved, to bound lookup
// cost; any beyond that cap are still emitted at the same mid-band score
// (confReverseWhoisUnverified) WITHOUT a lookup, so a large result set is
// ranked-where-possible but never truncated (ENG-5123 #3 — the cap limits
// resolver calls, not recall). They read justifyReverseWhoisNotLookedUp, not
// the unverifiable wording: no lookup was attempted (ENG-5889).
//
// When queryOrg is empty (email-mode seed) there is nothing to corroborate
// against, so every candidate short-circuits to that same mid-band score with
// no resolver calls, reading justifyReverseWhoisNoQueryOrg — nothing failed,
// there was simply no org to compare against (ENG-5889).
func verifyCandidates(ctx context.Context, r registrantResolver, queryOrg string, cands []candidate) ([]plugins.Finding, error) {
	// A caller that already cancelled before we start must abort here, not emit a
	// result set. The post-g.Wait check below covers cancellation DURING parallel
	// resolution, but the email-mode fast path and the pre-resolution setup both
	// return before reaching it — so without this entry check a caller that
	// cancelled after the upstream API fetch (e.g. email-mode, which does no
	// lookups of its own) would still get a full findings slice with a nil error,
	// as though the aborted run completed (ENG-5123 review, Codex P2).
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Defensive: drop candidates that aren't syntactically plausible hostnames
	// (empty, over-length, or carrying interior whitespace/control chars) before
	// any lookup or emission, so a malformed API record can't reach the graph or
	// splice control characters into a resolver query (ENG-5123 F2).
	if n := len(cands); n > 0 {
		kept := make([]candidate, 0, n)
		for _, c := range cands {
			if isPlausibleDomain(c.domain) {
				kept = append(kept, c)
			}
		}
		cands = kept
	}

	if strings.TrimSpace(queryOrg) == "" {
		findings := make([]plugins.Finding, 0, len(cands))
		for _, c := range cands {
			f := c.finding
			// Mid-band score, but NOT the unverifiable wording: no lookup was
			// attempted and nothing failed — this pivot simply supplied no org to
			// compare against (ENG-5889).
			plugins.AddConfidence(&f, confReverseWhoisUnverified, justifyReverseWhoisNoQueryOrg)
			findings = append(findings, f)
		}
		// Re-check before returning: the plausibility filter and the scoring loop
		// above do no context-aware work, so a caller that cancelled after the
		// entry check would otherwise still get a full findings slice with a nil
		// error. Bracketing the email path with entry + pre-return checks keeps it
		// consistent with the resolve path's post-g.Wait check (ENG-5123 review,
		// Codex P2).
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return findings, nil
	}

	// Resolve at most maxReverseWhoisCandidates; overflow is emitted unverified
	// below without a lookup (recall-safe cap on resolver calls, not on output).
	resolveCount := len(cands)
	if resolveCount > maxReverseWhoisCandidates {
		resolveCount = maxReverseWhoisCandidates
	}

	// Pre-fill EVERY candidate with the unverified mid-band score up front, not
	// just the un-resolved overflow (indices >= resolveCount): a resolve worker
	// whose panic is recovered below must still leave a score inside
	// the needs_review band [0.35,0.65). The make() zero value 0.0 falls under the
	// discard floor and would silently drop the candidate — violating
	// de-rank-never-drop (Gemini review, ENG-5123). Successful workers overwrite
	// their index with the decided band.
	//
	// The SCORE is identical for both halves, for exactly that reason; only the
	// JUSTIFICATION splits at resolveCount, because the two halves are different
	// facts (ENG-5889).
	//
	// Below the cap this pre-fill is a fallback that only ever SURVIVES when the
	// worker's deferred recover fires: a recovered panic skips the
	// `decisions[i] = decideConfidence(...)` assignment, so the pre-filled entry is
	// what gets emitted. Every other outcome overwrites it, a cancelled gctx
	// included — that surfaces as a resolveRegistrant error and routes through
	// decideConfidence's lookupErr branch, which reaches the same score by its own
	// path rather than by inheriting this one. A recovered panic is the ONLY way the
	// pre-fill survives below the cap: errgroup runs every func handed to g.Go (only
	// TryGo may decline), so every submitted lookup starts and there is no never-run
	// worker to cover. And a recovered panic IS genuinely "could not be verified" —
	// the lookup started and its result was destroyed.
	//
	// At or above the cap the candidate was never looked up at all: the pass-wide
	// resolver cap ran out first, so reporting a failed verification would send a
	// reviewer hunting a WHOIS problem that never happened.
	decisions := make([]confidenceDecision, len(cands))
	for i := range decisions {
		justification := justifyReverseWhoisUnverified
		if i >= resolveCount {
			justification = justifyReverseWhoisNotLookedUp
		}
		decisions[i] = confidenceDecision{Score: confReverseWhoisUnverified, Justification: justification}
	}

	// Per-candidate observability, sized len(cands) — NOT resolveCount — so it
	// indexes identically to decisions and a stray index can never be out of range.
	// Unlike scores this needs no pre-fill loop: the zero candidateOutcome
	// (whoisComplete, not failed, not panicked) is already the correct reading for
	// the overflow indices >= resolveCount, which were never looked up (ENG-5405).
	outcomes := make([]candidateOutcome, len(cands))

	// Bound the whole pass, not just each lookup: a candidate can cost up to two
	// step timeouts plus WHOIS referral hops (see reverseWhoisTotalBudget), so
	// without a pass-wide cap a large result set against slow resolvers could hold
	// the phase-0 slot for minutes. Any lookup still in flight or queued when this
	// fires sees a cancelled context, returns an error, and is scored unverified —
	// capping worst-case runtime without dropping anything. Per-step timeouts are
	// owned by resolveWithFallback, derived from gctx, so this budget bounds them.
	bctx, cancelBudget := context.WithTimeoutCause(ctx, reverseWhoisTotalBudget, errReverseWhoisBudgetExpired)
	defer cancelBudget()

	g, gctx := errgroup.WithContext(bctx)
	g.SetLimit(reverseWhoisWorkers)
	for i := 0; i < resolveCount; i++ {
		i := i
		g.Go(func() error {
			// The RDAP path recovers its own panics (extractRDAPRegistrantOrg) so it
			// can drop a poisoned pooled client, but the WHOIS fallback runs
			// whoisparser.Parse over untrusted third-party WHOIS text with no such
			// guard. An unrecovered panic in ANY resolver would propagate out of this
			// errgroup goroutine and crash the whole pius run — losing every finding.
			// Recover here as the worker-level backstop: the candidate keeps its
			// pre-filled unverified score, so a single malformed record de-ranks that
			// one candidate instead of taking down the pass (Gemini review, ENG-5123).
			defer func() {
				if rec := recover(); rec != nil {
					// recover() fires BEFORE the outcomes[i] assignment below ever runs,
					// so without this line a panicking candidate would tally as
					// complete-and-not-failed — recreating ENG-5405's exact blindness
					// inside the mechanism built to end it. A panic gets its OWN bucket:
					// it is not a WHOIS incompleteness and must never be conflated with
					// one (ENG-5405 F4). Still index-disjoint (same worker, same i), so
					// g.Wait() publishes it like every other write.
					outcomes[i].panicked = true
					slog.Warn("reverse-whois: recovered panic resolving candidate registrant; scoring unverified",
						"domain", cands[i].domain, "panic", rec)
				}
			}()
			res, err := r.resolveRegistrant(gctx, cands[i].domain)
			decisions[i] = decideConfidence(queryOrg, res, err)
			// Record why this candidate is (or is not) fully verified. res.Incomplete is
			// PURELY OBSERVATIONAL — decideConfidence above never reads it, so scoring
			// stays byte-identical to ENG-5123 (ENG-5405 AC4). err is otherwise
			// discarded by design (see g.Wait's comment below), which is exactly why a
			// pass where every lookup failed outright would look healthy without this.
			outcomes[i] = candidateOutcome{incomplete: res.Incomplete, failed: err != nil}
			return nil
		})
	}
	// Workers deliberately absorb every lookup error (scoring the candidate
	// unverified rather than failing the pass), so g.Wait never actually returns
	// non-nil today. We keep the check as the happens-before barrier that
	// publishes all scores[] writes to this goroutine, and as defensive cover if
	// a future worker ever propagates an error (Gemini review, ENG-5123).
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// An INTERNAL budget expiry is recall-safe: bctx's own deadline cancels the
	// workers, their in-flight lookups score unverified, and every candidate is
	// still emitted. But that timeout is derived from ctx, so it never cancels the
	// PARENT — meaning a cancelled parent ctx here can ONLY be the caller aborting
	// (user interrupt / runner deadline). In that case the pass is incomplete, so
	// propagate ctx.Err() instead of returning a full set of half-verified findings
	// as though the run completed — matching every other plugin (ENG-5123 review,
	// Codex critical). Internal-budget expiry leaves ctx.Err() nil and still emits.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// The whoisIncompleteness enum cannot separate "this candidate's own
	// reverseWhoisLookupTimeout expired" from "the pass-wide
	// reverseWhoisTotalBudget expired": at the WHOIS layer both are just
	// ctx.Err() != nil on a derived context (whoisclient.go), and that layer has no
	// handle on which ancestor fired. This function DOES — it owns bctx.
	//
	// Discriminate on the CAUSE, not on bctx.Err(): matching the
	// context.DeadlineExceeded identity was NOT exact. It did correctly exclude a
	// late caller CANCEL, which yields context.Canceled — but it did NOT exclude a
	// late caller DEADLINE, and that is the case it got wrong. bctx is derived from
	// ctx, which carries a deadline in production (runner.DefaultPipelineTimeout),
	// and Go cancels a child with the PARENT's error, so a parent deadline sets
	// bctx.Err() to context.DeadlineExceeded even though bctx's own timer never
	// fired. In that shape there is in fact no 90s bound in play to report at all:
	// once the parent's remaining time is under the budget, WithDeadline caps the
	// child to the parent's deadline and arms no timer of its own. The ctx.Err()
	// re-check above only proves the caller was clean AT THAT INSTANT, so a caller
	// deadline landing between that check and this line reported budget_expired=true
	// for a pass the pass-wide budget never bounded — sending an operator to resize a
	// bound that was not the binding one (credit: Codex, PR #108). That window is two
	// adjacent statements with no blocking call between them, so this was a
	// low-probability race, not a routine misreport; it is worth fixing because
	// making exactly this distinction is the field's entire purpose.
	//
	// context.Cause against a private sentinel is exact in BOTH directions:
	// WithTimeoutCause installs errReverseWhoisBudgetExpired only when bctx's OWN
	// timer fires, and any parent-propagated cancellation — deadline or cancel alike
	// — leaves context.Cause(bctx) as the parent's cause, never the sentinel. The
	// deferred cancelBudget() likewise leaves context.Canceled. So neither a late
	// caller cancel nor a late caller deadline can masquerade as a budget expiry: the
	// field now means precisely "the pass-wide budget fired", and nothing outside
	// this function can forge it. budgetFired holds the predicate so it can be
	// exercised directly (ENG-5405).
	//
	// It is deliberately NOT a term in the degraded predicate, and must not become
	// one: bctx's deadline can fire after every worker has already finished, in
	// which case nothing was lost and the pass really was clean. Folding it into
	// the predicate would report a false degradation on a complete pass. It is
	// reported as its own field so an operator can tell a budget-bounded pass from
	// a timeout-bounded one without it changing the pass verdict.
	budgetExpired := budgetFired(bctx)

	// Placement is load-bearing in BOTH directions. After g.Wait() because that is
	// the only happens-before barrier that publishes the workers' outcomes[] writes
	// to this goroutine — reading the slice any earlier is a data race. After the
	// ctx.Err() re-check because a caller-aborted pass returns an error instead of
	// findings, and must not claim a pass completed (ENG-5405).
	summarizeVerifyPass(len(cands), resolveCount, budgetExpired, outcomes)

	findings := make([]plugins.Finding, 0, len(cands))
	for i, c := range cands {
		f := c.finding
		plugins.AddConfidence(&f, decisions[i].Score, decisions[i].Justification)
		findings = append(findings, f)
	}
	return findings, nil
}

// budgetFired reports whether bctx was cancelled by its OWN
// reverseWhoisTotalBudget timer rather than by anything the caller did. It is the
// sole reader of errReverseWhoisBudgetExpired: context.Cause returns that
// sentinel only for the timer WithTimeoutCause armed in verifyCandidates, so a
// caller cancel, a caller deadline, and the deferred cancelBudget() all report
// false. Split out of verifyCandidates so the discrimination can be exercised
// directly on constructed contexts instead of by racing a real pass (ENG-5405).
func budgetFired(bctx context.Context) bool {
	return errors.Is(context.Cause(bctx), errReverseWhoisBudgetExpired)
}

// summarizeVerifyPass emits the pass's single observability record.
//
// One record per pass, not per candidate: maxReverseWhoisCandidates is 500 and
// pius configures no slog handler (cmd/pius/main.go has no slog.New, no
// SetDefault, no --log-level flag), so the default handler runs at LevelInfo and
// slog.Debug is unreachable in production. A per-candidate line would therefore be
// up to 500 unconditional lines per run, per plugin (ENG-5405).
//
// Warn on a degraded pass matches this package's established
// degraded-but-handled level (the response-cap truncation in whoisclient.go, the
// recovered worker panic above, runner/run.go). Info on a clean pass is the
// positive control: it distinguishes "not degraded" from "this summary never ran",
// which is the only thing that proves the instrumentation is wired at all.
//
// NO untrusted content: counts and compile-time constants only — no raw WHOIS
// payload, no registrant org (PII), no referral hostname read from WHOIS text, and
// the message strings are compile-time constants so nothing can forge a log line
// (security-review.md §3).
//
// The counters are NOT a partition of candidates: a candidate whose salvaged
// record failed to parse counts in BOTH lookup_failed and its reason bucket (see
// viaWHOIS), so do not read the record as a disjoint breakdown.
// budgetExpired reports whether the pass-wide reverseWhoisTotalBudget fired (see
// its derivation in verifyCandidates). It is reported, never used to decide
// whether the pass was degraded: a budget that fires after the last worker
// finished lost nothing.
func summarizeVerifyPass(total, attempted int, budgetExpired bool, outcomes []candidateOutcome) {
	var deadline, referral, hops, failed, panicked int
	for _, o := range outcomes {
		switch o.incomplete {
		case whoisIncompleteDeadline:
			deadline++
		case whoisIncompleteReferral:
			referral++
		case whoisIncompleteHops:
			hops++
		}
		if o.failed {
			failed++
		}
		if o.panicked {
			panicked++
		}
	}
	// The cap is the FOURTH degradation arm, alongside the three per-candidate
	// buckets and the panic bucket. Candidates past maxReverseWhoisCandidates are
	// never looked up, so their zero-valued outcomes entries read as whoisComplete
	// — summing the buckets alone would call a pass over 5000 candidates that
	// attempted only 500 "complete" at Info level, which is exactly the
	// silent-degradation class ENG-5405 exists to remove, reappearing at the cap
	// boundary. attempted < total is truncation and must degrade the pass.
	//
	// budgetExpired is deliberately absent from this predicate — see its
	// derivation in verifyCandidates. The pass-wide budget can expire after the
	// last worker returned, so a true here proves nothing was lost; adding it as a
	// fifth arm would downgrade complete passes to Warn on the strength of a race.
	// It rides on both records as a field instead.
	if deadline+referral+hops+failed+panicked == 0 && attempted >= total {
		slog.Info("reverse-whois: verification pass complete",
			"candidates", total, "attempted", attempted,
			"budget_expired", budgetExpired)
		return
	}
	// attempted (NOT "resolved"): the count of candidates a lookup was started for,
	// capped at maxReverseWhoisCandidates. It says nothing about how many resolved
	// successfully — a pass can legitimately read candidates=14 attempted=14
	// lookup_failed=14, and naming this "resolved" would tell an operator that all
	// fourteen verified when none did.
	//
	// budget_ms is logged because reverseWhoisTotalBudget is a var that tests
	// shorten: recording the EFFECTIVE budget is what makes this line
	// self-diagnosing for the deferred sizing follow-up. Milliseconds, not seconds:
	// integer-dividing a sub-second budget by time.Second floors to 0, so the
	// self-diagnosing denominator reported "budget 0s" — i.e. misconfigured — for a
	// budget that was fine. The worker count is deliberately NOT logged — it is a
	// compile-time constant, so it is noise.
	//
	// lookup_timeout_ms is logged BESIDE budget_ms because a pass is bounded by
	// whichever of the two binds first, and budget_ms alone cannot tell a reader
	// which one did: incomplete_deadline=6 against a 90000ms budget reads as an
	// undersized budget until you know each lookup was independently capped at
	// 10000ms. Both bounds have to be on the record for it to be self-describing.
	// budget_expired then says which one actually fired for THIS pass.
	slog.Warn("reverse-whois: verification pass degraded; some candidates were not fully verified",
		"candidates", total,
		"attempted", attempted,
		"incomplete_deadline", deadline,
		"incomplete_referral", referral,
		"incomplete_referral_budget", hops,
		"lookup_failed", failed,
		"panicked", panicked,
		"budget_expired", budgetExpired,
		"budget_ms", int(reverseWhoisTotalBudget/time.Millisecond),
		"lookup_timeout_ms", int(reverseWhoisLookupTimeout/time.Millisecond),
	)
}

// rdapWhoisResolver resolves a domain's registrant org via RDAP (primary),
// falling back to raw WHOIS when RDAP is unavailable (transport error, or a
// TLD with no RDAP service, e.g. many ccTLDs).
type rdapWhoisResolver struct {
	initOnce   sync.Once
	clientPool chan *rdap.Client // fixed set of clients; each is used by one goroutine at a time
}

// newRDAPClient is the single construction point for the reverse-whois RDAP
// client. ENG-5174 must attach the SSRF-safe, body-capped *http.Client at BOTH
// attach points — HTTP and Bootstrap (e.g. Bootstrap: &bootstrap.Client{HTTP: safeClient}) —
// because Do otherwise lazily creates an unguarded bootstrap client with its own
// default *http.Client and an unbounded read of the IANA bootstrap response.
func newRDAPClient() *rdap.Client { return &rdap.Client{} }

// initClientPool lazily pre-fills the pool with exactly reverseWhoisWorkers
// clients. Lazy sync.Once init keeps the zero-value resolver usable — both
// call sites construct it as a bare &rdapWhoisResolver{} literal.
func (r *rdapWhoisResolver) initClientPool() {
	r.initOnce.Do(func() {
		pool := make(chan *rdap.Client, reverseWhoisWorkers)
		for i := 0; i < reverseWhoisWorkers; i++ {
			pool <- newRDAPClient()
		}
		r.clientPool = pool
	})
}

// acquireClient hands out a pooled client, or a fresh one if the pool is
// momentarily empty. The receive is deliberately non-blocking: under the
// g.SetLimit(reverseWhoisWorkers) invariant in verifyCandidates at most
// reverseWhoisWorkers lookups are in flight so the pool never runs dry, but if
// that invariant is ever violated the fallback degrades to a cold client (a
// slowdown) instead of a blocked worker (a hang until the pass budget cancels).
func (r *rdapWhoisResolver) acquireClient() *rdap.Client {
	r.initClientPool()
	select {
	case c := <-r.clientPool:
		return c
	default:
		return newRDAPClient()
	}
}

// releaseClient returns a client to the pool. A client that panicked
// mid-Lookup may hold a half-written registries map, so it is discarded — but
// its slot is refilled with a FRESH client, or the pool would leak one slot per
// panic and eventually sit permanently empty. initClientPool runs first (it is
// idempotent), so the clientPool field read in the select below is always
// ordered after the sync.Once — race-free even for a caller that releases
// without ever acquiring (such a call would pre-fill a full pool and simply
// drop c). The send is non-blocking so a full pool — that case, or the acquire
// fallback path — drops the extra client for GC, keeping total live clients
// bounded by in-flight (≤ SetLimit) + stored (≤ reverseWhoisWorkers).
func (r *rdapWhoisResolver) releaseClient(c *rdap.Client, panicked bool) {
	r.initClientPool()
	if panicked {
		c = newRDAPClient()
	}
	select {
	case r.clientPool <- c:
	default:
	}
}

func (r *rdapWhoisResolver) resolveRegistrant(ctx context.Context, domain string) (registrantResult, error) {
	return resolveWithFallback(ctx, domain, r.viaRDAP, r.viaWHOIS)
}

// resolveWithFallback implements the RDAP-primary / WHOIS-fallback policy. RDAP
// is authoritative ONLY when it resolved a real, usable registrant — Found AND
// not masked. Every other RDAP outcome falls through to WHOIS: a transport
// error, a successful response whose registrant org is absent/redacted
// (Found==false), OR a successful response carrying a literal privacy/proxy
// value such as "REDACTED FOR PRIVACY" or "Domains By Proxy, LLC" (Masked).
//
// The redacted/masked cases are the ones that matter in production: under GDPR
// most gTLD RDAP records either omit the registrant org or return a privacy
// placeholder, so treating either as "resolved" would skip WHOIS and collapse
// corroboration to the unverified mid-band for the common path — the
// corroborate/mismatch bands would almost never fire. Falling through to WHOIS
// gives the candidate a real second source before scoring; if WHOIS is also
// empty/masked/errored the candidate simply stays in the same unverified band,
// so the fallback never de-ranks (Codex+Claude+Gemini review, ENG-5123).
//
// Each step gets its OWN timeout derived from the incoming budget context, not a
// single shared per-lookup deadline: an RDAP attempt that consumes its entire
// timeout (a transport hang) must not leave the WHOIS fallback with an already-
// exhausted context, or the fallback would no-op in precisely the RDAP-timeout
// case it exists to cover (ENG-5123 review, Codex P2). Both step contexts remain
// bounded by ctx, so the pass-wide budget still caps total time.
func resolveWithFallback(
	ctx context.Context,
	domain string,
	rdapFn, whoisFn func(context.Context, string) (registrantResult, error),
) (registrantResult, error) {
	rctx, cancelRDAP := context.WithTimeout(ctx, reverseWhoisLookupTimeout)
	res, err := rdapFn(rctx, domain)
	cancelRDAP()
	if err == nil && res.Found && !res.Masked {
		return res, nil
	}

	wctx, cancelWHOIS := context.WithTimeout(ctx, reverseWhoisLookupTimeout)
	defer cancelWHOIS()
	return whoisFn(wctx, domain)
}

func (r *rdapWhoisResolver) viaRDAP(ctx context.Context, domain string) (registrantResult, error) {
	// openrdap's bootstrap Client is not safe for concurrent Do: Lookup writes an
	// unsynchronized registries map backed by a plain-map MemoryCache. Serializing
	// every RDAP call through one slot is the wrong fix in both directions — a
	// blocking slot starves queued workers of their 10s budget, and a non-blocking
	// slot bypasses RDAP for ~5 of every 6 concurrent lookups (reverseWhoisWorkers)
	// so WHOIS silently becomes the primary resolver and takes the rate-limit hit.
	// Instead give each in-flight lookup its OWN client from a fixed pre-filled
	// pool: a pooled client is only ever touched by one goroutine at a time, so its
	// maps stay race-free, and up to reverseWhoisWorkers clients run RDAP truly in
	// parallel. The pool is a buffered channel, NOT a sync.Pool: the runtime's
	// poolCleanup GC pre-hook evicts sync.Pool items within two GC cycles, and a
	// 500-candidate pass allocates enough to trigger GC mid-pass, so pooled clients
	// went cold and re-fetched the rate-limited IANA bootstrap. A channel is a
	// normal heap-reachable object the GC never evicts, so each persistent client
	// fetches the bootstrap at most once per pass (ENG-5376).
	client := r.acquireClient()
	var (
		org      string
		panicked bool
		err      error
	)
	// Release via defer so returning the client is structural rather than
	// dependent on control flow: no current path skips the release
	// (extractRDAPRegistrantOrg recovers its own panics and there is no early
	// return between acquire and release), but the defer also covers a future
	// early return or a runtime.Goexit. The closure reads panicked at defer
	// time, after the call below has set it (Gemini review suggestion,
	// ENG-5376).
	defer func() { r.releaseClient(client, panicked) }()
	org, panicked, err = extractRDAPRegistrantOrg(ctx, client, domain)
	if err != nil {
		return registrantResult{}, err
	}
	return newRegistrantResult(org), nil
}

// rdapDoer is the single method extractRDAPRegistrantOrg needs from an
// *rdap.Client. Narrowing to an interface gives tests a seam to drive the
// panic-recovery and malformed-response branches without real network I/O
// (ENG-5123 review, Claude — direct viaRDAP coverage).
type rdapDoer interface {
	Do(*rdap.Request) (*rdap.Response, error)
}

// extractRDAPRegistrantOrg runs the RDAP lookup and jCard extraction for one
// candidate. It recovers a panic anywhere in the extraction into an error so a
// single malformed response can't crash the whole pius run (which would lose
// every finding); the caller then falls through to WHOIS like any other RDAP
// failure. The recover must wrap the ENTIRE extraction, not just Do: parsing the
// jCard (registrantOrgFromDomain → openrdap's VCard.GetFirst/Property.Values)
// runs over attacker-influenced registry data and can itself panic on a
// malformed entry, and that panic would otherwise be unrecovered in the errgroup
// goroutine (Gemini review + ENG-5123 review, Claude critical). The returned
// panicked flag tells the caller to DISCARD rather than pool the client, since a
// client that panicked mid-Lookup may hold a half-written registries map.
func extractRDAPRegistrantOrg(ctx context.Context, doer rdapDoer, domain string) (org string, panicked bool, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			panicked = true
			org, err = "", fmt.Errorf("rdap: recovered panic resolving %q: %v", domain, rec)
		}
	}()
	req := rdap.NewDomainRequest(domain).WithContext(ctx)
	resp, err := doer.Do(req)
	if err != nil {
		return "", false, err
	}
	// Defensive: openrdap should never return (nil, nil), but guard it so a nil
	// response falls through to WHOIS like any other RDAP miss rather than
	// panicking on resp.Object.
	if resp == nil {
		return "", false, fmt.Errorf("rdap: nil response for %q", domain)
	}
	dom, ok := resp.Object.(*rdap.Domain)
	if !ok || dom == nil {
		return "", false, fmt.Errorf("rdap: unexpected response object for %q", domain)
	}
	return registrantOrgFromDomain(dom), false, nil
}

func (r *rdapWhoisResolver) viaWHOIS(ctx context.Context, domain string) (registrantResult, error) {
	raw, incomplete, err := whoisQuery(ctx, domain)
	if err != nil {
		// Nothing to preserve here: whoisQuery reports whoisComplete on EVERY path
		// that returns a non-nil error (whoisclient.go), so incomplete is the zero
		// value and registrantResult{} already carries it.
		return registrantResult{}, err
	}
	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		// Carry the reason out WITH the error. whoisQuery salvages a partial chain as
		// (lastRaw, <reason>, nil), and lastRaw is any post-referral response —
		// including a redirect stub or throttle banner that whoisparser.Parse rejects
		// (no `domain:`-shaped line → ErrDomainDataInvalid/ErrDomainLimitExceed). The
		// caller reads res.Incomplete unconditionally, alongside err, at
		// `outcomes[i] = candidateOutcome{incomplete: res.Incomplete, failed: err != nil}`
		// above, so returning the reason on this error path is what keeps a
		// salvaged-but-unparseable record's deadline/referral/hop-budget attribution
		// instead of collapsing it to a bare lookup_failed — the exact blindness
		// ENG-5405 exists to remove.
		//
		// This deliberately makes lookup_failed and the three reason buckets
		// NON-DISJOINT for this one case: a single candidate increments both, because
		// "the lookup failed AND we know the chain was partial" is the true statement
		// and dropping either half would be a lie. Safe because the only place the
		// buckets are ever summed is summarizeVerifyPass's clean-predicate
		// (deadline+referral+hops+failed+panicked == 0), which tests for zero and is
		// therefore unaffected by double-counting a non-zero candidate.
		return registrantResult{Incomplete: incomplete}, err
	}
	org := ""
	if parsed.Registrant != nil {
		org = parsed.Registrant.Organization
		if org == "" {
			org = parsed.Registrant.Name
		}
	}
	res := newRegistrantResult(org)
	res.Incomplete = incomplete
	return res, nil
}

// newRegistrantResult builds a registrantResult from a raw org string, marking
// it masked when it matches a known privacy/proxy string.
func newRegistrantResult(org string) registrantResult {
	org = strings.TrimSpace(org)
	if org == "" {
		return registrantResult{}
	}
	return registrantResult{Org: org, Masked: isMaskedOrg(org), Found: true}
}

// registrantOrgFromDomain returns the registrant entity's org (jCard "org",
// falling back to "fn"), or "" when there is no registrant entity/vCard/value.
func registrantOrgFromDomain(dom *rdap.Domain) string {
	for i := range dom.Entities {
		e := &dom.Entities[i]
		if !hasRole(e.Roles, "registrant") || e.VCard == nil {
			continue
		}
		if org := vcardValue(e.VCard, "org"); org != "" {
			return org
		}
		if fn := vcardValue(e.VCard, "fn"); fn != "" {
			return fn
		}
	}
	return ""
}

func vcardValue(vc *rdap.VCard, name string) string {
	p := vc.GetFirst(name)
	if p == nil {
		return ""
	}
	vals := p.Values()
	if len(vals) == 0 {
		return ""
	}
	return strings.TrimSpace(vals[0])
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}
