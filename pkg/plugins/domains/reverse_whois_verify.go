package domains

import (
	"context"
	"fmt"
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
// is scored strictly below plugins.ConfidenceHigh, so SetConfidence always
// flags needs_review. An auto-clean path, if ever wanted, must come from an
// INDEPENDENT corroboration channel calibrated against labeled data — out of
// scope, filed as follow-up.
const (
	// confReverseWhoisCorroborated is the top of the needs_review band: the
	// candidate's own registrant org corroborates the query org. Still < 0.65,
	// so it ranks above unverified matches without reading as clean.
	confReverseWhoisCorroborated = 0.60
	// confReverseWhoisUnverified is the mid-band score for matches we could not
	// corroborate (lookup failed/timed out, masked registrant, empty org, or an
	// ambiguous partial-token overlap).
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

// registrantResult is the outcome of resolving a single candidate domain's own
// registrant organization.
type registrantResult struct {
	// Org is the resolved registrant organization (empty if none was found).
	Org string
	// Masked is true when Org is a known WHOIS privacy/proxy string.
	Masked bool
	// Found is true when a non-empty registrant org was resolved.
	Found bool
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

// orgLegalSuffixes are legal-form tokens stripped by normalizeOrg before
// comparison. Disambiguating tokens (group, holdings, international, systems)
// are deliberately NOT included — they carry signal.
var orgLegalSuffixes = map[string]bool{
	"inc": true, "llc": true, "ltd": true, "corp": true, "gmbh": true,
	"sas": true, "co": true, "plc": true, "bv": true, "nv": true,
	"pty": true, "oy": true, "ab": true, "as": true, "kk": true,
	"pte": true, "sa": true, "srl": true, "spa": true, "ag": true,
	"kg": true, "aps": true, "oyj": true,
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

// decideConfidence maps a candidate's resolved registrant against the query org
// to a needs_review score. A lookup error means "unverifiable", NOT "mismatch":
// it is scored mid-band. Nothing here ever drops a candidate — a clear mismatch
// is de-ranked to the bottom of the band, and every return is < ConfidenceHigh.
func decideConfidence(queryOrg string, res registrantResult, lookupErr error) float64 {
	if lookupErr != nil || res.Masked || res.Org == "" {
		return confReverseWhoisUnverified
	}
	nq, nc := normalizeOrg(queryOrg), normalizeOrg(res.Org)
	if nq == "" || nc == "" {
		// One side has no comparable tokens after legal-suffix stripping (e.g. an
		// all-suffix org like "Co., Ltd."). Token similarity is undefined here, so
		// the candidate is UNVERIFIABLE, not a mismatch — score mid-band.
		return confReverseWhoisUnverified
	}
	sim := tokenSimilarity(nq, nc)
	switch {
	case sim >= simCorroborate:
		return confReverseWhoisCorroborated
	case sim < simMismatch:
		// Present, unmasked, clear mismatch → de-rank to the bottom of the
		// needs_review band (walmart.com-from-a-Leica-query). A textual registrant
		// mismatch is not proof of non-ownership, so this is never dropped.
		return confReverseWhoisMismatch
	default:
		// Ambiguous partial overlap [simMismatch, simCorroborate).
		return confReverseWhoisUnverified
	}
}

// verifyCandidates scores each candidate by resolving its own registrant and
// comparing to queryOrg, then emits findings in the original order. Lookups run
// under bounded concurrency with a per-lookup timeout; a timeout/error is
// treated as unverifiable. No candidate is ever dropped — every plausible
// candidate is emitted (in needs_review).
//
// At most maxReverseWhoisCandidates candidates are resolved, to bound lookup
// cost; any beyond that cap are still emitted at the unverified mid-band score
// WITHOUT a lookup, so a large result set is ranked-where-possible but never
// truncated (ENG-5123 #3 — the cap limits resolver calls, not recall).
//
// When queryOrg is empty (email-mode seed) there is nothing to corroborate
// against, so every candidate short-circuits to the unverified mid-band score
// with no resolver calls.
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
			plugins.SetConfidence(&f, confReverseWhoisUnverified)
			findings = append(findings, f)
		}
		return findings, nil
	}

	// Resolve at most maxReverseWhoisCandidates; overflow is emitted unverified
	// below without a lookup (recall-safe cap on resolver calls, not on output).
	resolveCount := len(cands)
	if resolveCount > maxReverseWhoisCandidates {
		resolveCount = maxReverseWhoisCandidates
	}

	scores := make([]float64, len(cands))
	for i := resolveCount; i < len(cands); i++ {
		scores[i] = confReverseWhoisUnverified
	}

	// Bound the whole pass, not just each lookup: a candidate can cost up to two
	// step timeouts plus WHOIS referral hops (see reverseWhoisTotalBudget), so
	// without a pass-wide cap a large result set against slow resolvers could hold
	// the phase-0 slot for minutes. Any lookup still in flight or queued when this
	// fires sees a cancelled context, returns an error, and is scored unverified —
	// capping worst-case runtime without dropping anything. Per-step timeouts are
	// owned by resolveWithFallback, derived from gctx, so this budget bounds them.
	bctx, cancelBudget := context.WithTimeout(ctx, reverseWhoisTotalBudget)
	defer cancelBudget()

	g, gctx := errgroup.WithContext(bctx)
	g.SetLimit(reverseWhoisWorkers)
	for i := 0; i < resolveCount; i++ {
		i := i
		g.Go(func() error {
			res, err := r.resolveRegistrant(gctx, cands[i].domain)
			scores[i] = decideConfidence(queryOrg, res, err)
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

	findings := make([]plugins.Finding, 0, len(cands))
	for i, c := range cands {
		f := c.finding
		plugins.SetConfidence(&f, scores[i])
		findings = append(findings, f)
	}
	return findings, nil
}

// rdapWhoisResolver resolves a domain's registrant org via RDAP (primary),
// falling back to raw WHOIS when RDAP is unavailable (transport error, or a
// TLD with no RDAP service, e.g. many ccTLDs).
type rdapWhoisResolver struct {
	initOnce   sync.Once
	clientPool *sync.Pool // pool of *rdap.Client; each is used by one goroutine at a time
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
	// Instead give each in-flight lookup its OWN client from a pool: a pooled client
	// is only ever touched by one goroutine at a time, so its maps stay race-free,
	// and up to reverseWhoisWorkers clients run RDAP truly in parallel. Each distinct
	// client warms the DNS bootstrap registry once (24h in-client cache), so the pool
	// amortizes bootstrap cost across the run (Gemini review, ENG-5123).
	r.initOnce.Do(func() {
		r.clientPool = &sync.Pool{New: func() any { return &rdap.Client{} }}
	})
	client := r.clientPool.Get().(*rdap.Client)
	// Recover a panic inside Do into an error so a single malformed response can't
	// crash the whole pius run (which would lose every finding); it then falls
	// through to WHOIS like any other RDAP failure. A client that panicked
	// mid-Lookup may have a half-written registries map, so it is NOT returned to
	// the pool — a fresh one is created on next Get (Gemini review, ENG-5123).
	returnToPool := true
	resp, err := func() (resp *rdap.Response, err error) {
		defer func() {
			if rec := recover(); rec != nil {
				returnToPool = false
				resp, err = nil, fmt.Errorf("rdap: recovered panic resolving %q: %v", domain, rec)
			}
		}()
		req := rdap.NewDomainRequest(domain).WithContext(ctx)
		return client.Do(req)
	}()
	if returnToPool {
		r.clientPool.Put(client)
	}
	if err != nil {
		return registrantResult{}, err
	}
	// Defensive: openrdap should never return (nil, nil), but the recover above
	// only guards the Do call — a nil resp here would panic on resp.Object in the
	// errgroup goroutine, an unrecovered panic that crashes the whole pius run and
	// loses every finding (exactly what the recover exists to prevent). Guard it so
	// a nil response falls through to WHOIS like any other RDAP miss (ENG-5123
	// review, Claude critical).
	if resp == nil {
		return registrantResult{}, fmt.Errorf("rdap: nil response for %q", domain)
	}
	dom, ok := resp.Object.(*rdap.Domain)
	if !ok || dom == nil {
		return registrantResult{}, fmt.Errorf("rdap: unexpected response object for %q", domain)
	}
	return newRegistrantResult(registrantOrgFromDomain(dom)), nil
}

func (r *rdapWhoisResolver) viaWHOIS(ctx context.Context, domain string) (registrantResult, error) {
	raw, err := whoisQuery(ctx, domain)
	if err != nil {
		return registrantResult{}, err
	}
	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return registrantResult{}, err
	}
	org := ""
	if parsed.Registrant != nil {
		org = parsed.Registrant.Organization
		if org == "" {
			org = parsed.Registrant.Name
		}
	}
	return newRegistrantResult(org), nil
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
