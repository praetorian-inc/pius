package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"os"
	"strings"

	whoisparser "github.com/likexian/whois-parser"
	"golang.org/x/net/publicsuffix"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

// Source names carried in Data["method"] of every emitted record finding.
const (
	whoisMethodRDAP  = "rdap"
	whoisMethodTCP43 = "whois43"
	whoisMethodWhoxy = "whoxy"
)

func init() {
	plugins.Register("whois", func() plugins.Plugin { return NewWhoisPlugin() })
}

type WhoisOption func(*WhoisPlugin)

func NewWhoisPlugin(opts ...WhoisOption) *WhoisPlugin {
	plugin := &WhoisPlugin{}
	for _, opt := range opts {
		opt(plugin)
	}
	return plugin
}

func WithWhoisRaw(raw func(context.Context, string, string) (string, error)) WhoisOption {
	return func(plugin *WhoisPlugin) {
		plugin.whoisRaw = raw
	}
}

func WithWhoxyClient(httpClient *client.Client, apiKey string) WhoisOption {
	return func(plugin *WhoisPlugin) {
		plugin.whoxy = &whoxyWhoisClient{client: httpClient, apiKey: apiKey}
	}
}

func WithRDAPLookup(lookup func(context.Context, string) (string, error)) WhoisOption {
	return func(plugin *WhoisPlugin) {
		plugin.rdap = rdapLookup(lookup)
	}
}

type rdapLookup func(context.Context, string) (string, error)

func (lookup rdapLookup) rdapRecord(ctx context.Context, domain string) (whoisRecord, error) {
	raw, err := lookup(ctx, domain)
	if err != nil {
		return whoisRecord{}, err
	}
	return textWhoisRecord(whoisMethodRDAP, raw)
}

// WhoisPlugin gathers a domain's WHOIS registration data by cascading over
// RDAP, TCP/43, and Whoxy, emitting one record finding per source that answered
// plus preseeds (registrant organization, contact names, emails) from the
// accepted record.
//
// It gathers and enriches; the consumer owns persistence and lifecycle.
// Every answering source is emitted in the order tried so the consumer can
// preserve its existing record-selection behavior during consolidation.
type WhoisPlugin struct {
	rdap     rdapRecordSource  // overridable for tests; defaults to rdapWhoisResolver
	whoxy    *whoxyWhoisClient // overridable for tests; nil takes a default client
	whoisRaw func(context.Context, string, string) (string, error)
}

func (p *WhoisPlugin) Name() string { return "whois" }
func (p *WhoisPlugin) Description() string {
	return "Domain WHOIS: cascades RDAP, WHOIS/43, and Whoxy to gather registration records, contacts, and emails"
}
func (p *WhoisPlugin) Category() string { return "domain" }
func (p *WhoisPlugin) Phase() int       { return 0 }
func (p *WhoisPlugin) Mode() string     { return plugins.ModePassive }

func (p *WhoisPlugin) Accepts(input plugins.Input) bool {
	return input.Domain != ""
}

// whoisRecord is one source's answer: the raw record text as that source
// rendered it, alongside the parse this plugin adjudicates on.
type whoisRecord struct {
	method string
	raw    string
	info   whoisparser.WhoisInfo
}

type whoisSource struct {
	method string
	fetch  func(ctx context.Context, domain string) (whoisRecord, error)
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

	whoxy := p.whoxyClient()

	var (
		accepted       *whoisRecord
		last           *whoisRecord
		lastErr        error
		notFoundMethod string
	)
	for _, src := range p.sources(whoxy) {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		rec, ferr := src.fetch(ctx, domain)
		// The TCP/43 leg is shared with the reverse-whois verifier, where a caller
		// cancellation deliberately salvages the last post-referral record
		// (recall-safe). WhoisPlugin has no such recall contract: a cancelled run
		// must abort, not emit from a salvaged partial record. Re-check the context
		// before emitting (ENG-5123 review, Codex).
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		if ferr != nil {
			if notFoundMethod == "" && isDomainNotFound(ferr) {
				notFoundMethod = src.method
			}
			lastErr = ferr
			slog.Warn("whois: source did not answer, falling through",
				"domain", domain, "method", src.method, "error", ferr)
			continue
		}

		accept := hasNamedContact(rec.info)
		enrichWhoisRecord(&rec, domain)
		finding, merr := recordFinding(domain, rec, p.Name())
		if merr != nil {
			return nil, merr
		}
		findings = append(findings, finding)
		last = &rec
		if accept {
			accepted = &rec
			break
		}
	}

	switch {
	case last != nil:
		// Preseeds come from the record that satisfied the predicate; with none
		// satisfied, the last one that parsed is still the richest available.
		src := accepted
		if src == nil {
			src = last
		}
		findings = append(findings, extractRichPreseeds(src.info, domain, p.Name())...)
	case notFoundMethod != "":
		// An unregistered domain is a result, not a failure: the consumer caches
		// the negative rather than re-querying every pass.
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingWhoisRecord,
			Value:  domain,
			Source: p.Name(),
			Data: map[string]any{
				"method":       notFoundMethod,
				"unregistered": true,
			},
		})
	case lastErr != nil:
		return nil, fmt.Errorf("whois: all sources failed for %q: %w", domain, lastErr)
	default:
		return nil, nil
	}

	if whoxy != nil {
		if hist, herr := whoxy.history(ctx, domain); herr != nil {
			slog.Warn("whois: history fetch failed", "domain", domain, "error", herr)
		} else if len(hist) > 0 {
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingWhoisHistory,
				Value:  domain,
				Source: p.Name(),
				Data: map[string]any{
					"method":  whoisMethodWhoxy,
					"history": string(hist),
				},
			})
		}
	}

	return findings, nil
}

// sources returns the cascade in call order: the two free sources first, the
// paid one last, so a Whoxy credit is only ever spent on a domain the free legs
// could not answer for (MAR-10241).
func (p *WhoisPlugin) sources(whoxy *whoxyWhoisClient) []whoisSource {
	// Resolve into a local rather than mutating p.rdap: writing shared plugin
	// state inside Run() would be a data race if an instance were ever reused or
	// run concurrently (Gemini review, ENG-5123).
	rdapSource := p.rdap
	if rdapSource == nil {
		rdapSource = &rdapWhoisResolver{}
	}

	sources := []whoisSource{
		{method: whoisMethodRDAP, fetch: rdapSource.rdapRecord},
		{method: whoisMethodTCP43, fetch: p.whois43Record},
	}
	if whoxy != nil {
		sources = append(sources, whoisSource{method: whoisMethodWhoxy, fetch: whoxy.record})
	}
	return sources
}

// whoxyClient gates the paid stage on the API key. Without it the cascade must
// behave exactly as the free plugin always has: a plain CLI or SDK run must not
// silently start spending Whoxy credits.
func (p *WhoisPlugin) whoxyClient() *whoxyWhoisClient {
	if p.whoxy != nil && p.whoxy.apiKey != "" {
		return p.whoxy
	}
	if os.Getenv("WHOXY_API_KEY") == "" {
		return nil
	}
	if p.whoxy != nil {
		return p.whoxy
	}
	return &whoxyWhoisClient{client: client.New()}
}

func (p *WhoisPlugin) whois43Record(ctx context.Context, domain string) (whoisRecord, error) {
	rawFn := whoisRawFn
	if p.whoisRaw != nil {
		rawFn = p.whoisRaw
	}
	raw, err := whoisQueryWithRaw(ctx, domain, rawFn)
	if err != nil {
		return whoisRecord{}, fmt.Errorf("whois43: lookup failed for %q: %w", domain, err)
	}
	return textWhoisRecord(whoisMethodTCP43, raw)
}

// textWhoisRecord parses a raw WHOIS record from a text-returning source. The
// parse error is wrapped rather than replaced so the cascade's not-found probe
// can still see whoisparser.ErrNotFoundDomain through it. whoisParseFn is called
// directly, not through parseWhoisRecordSafely, so a parser panic reaches the
// recover in Run.
func textWhoisRecord(method, raw string) (whoisRecord, error) {
	info, err := whoisParseFn(raw)
	if err != nil {
		return whoisRecord{}, fmt.Errorf("%s: parse record: %w", method, err)
	}
	return whoisRecord{method: method, raw: raw, info: info}, nil
}

func recordFinding(domain string, rec whoisRecord, source string) (plugins.Finding, error) {
	info, err := json.Marshal(rec.info)
	if err != nil {
		return plugins.Finding{}, fmt.Errorf("whois: marshal parsed record for %q: %w", domain, err)
	}
	return plugins.Finding{
		Type:   plugins.FindingWhoisRecord,
		Value:  domain,
		Source: source,
		Data: map[string]any{
			"method": rec.method,
			"raw":    rec.raw,
			"info":   string(info),
		},
	}, nil
}

// hasNamedContact is deliberately stricter than the persistence acceptance
// predicate, so an organization-only response falls through to the next source.
func hasNamedContact(info whoisparser.WhoisInfo) bool {
	for _, c := range whoisContacts(info) {
		if c == nil {
			continue
		}
		if c.Email != "" || c.Name != "" {
			return true
		}
	}
	return false
}

func whoisContacts(info whoisparser.WhoisInfo) []*whoisparser.Contact {
	return []*whoisparser.Contact{
		info.Registrant, info.Administrative, info.Billing, info.Technical,
	}
}

// whoisParseFn is a seam over whoisparser.Parse so the panic-recover in
// WhoisPlugin.Run can be exercised by a test that injects a panicking parse.
var whoisParseFn = whoisparser.Parse

// whoisPrivacyNames contains name-field values used by WHOIS privacy
// services. These appear as registrant name but don't identify a real person.
// Keyed by lowercase for case-insensitive matching.
var whoisPrivacyNames = map[string]bool{
	"registration private":                 true,
	"domain admin":                         true,
	"domain administrator":                 true,
	"whois agent":                          true,
	"whois privacy":                        true,
	"data protected":                       true,
	"redacted for privacy":                 true,
	"withheld for privacy":                 true,
	"contact privacy inc. customer":        true,
	"identity protection service":          true,
	"domain privacy group":                 true,
	"private registration":                 true,
	"not disclosed":                        true,
	"statutory masking enabled":            true,
	"admin":                                true,
	"hostmaster":                           true,
	"dns admin":                            true,
	"domain hostmaster":                    true,
	"abuse":                                true,
	"postmaster":                           true,
	"super privacy service ltd c/o migadu": true,
}

// whoisPrivacyGuards contains organization names used by WHOIS privacy
// services. These appear as registrant org but don't represent the actual
// domain owner. Keyed by lowercase for case-insensitive matching.
var whoisPrivacyGuards = map[string]bool{
	"domains by proxy, llc":         true,
	"domains by proxy":              true,
	"whoisguard, inc.":              true,
	"whoisguard protected":          true,
	"whoisguard":                    true,
	"privacy protect, llc":          true,
	"contact privacy inc.":          true,
	"contact privacy inc. customer": true,
	"privacyprotect.org":            true,
	"whois privacy corp.":           true,
	"perfect privacy, llc":          true,
	"data protected":                true,
	"identity protection service":   true,
	"withheld for privacy":          true,
	"redacted for privacy":          true,
	"statutory masking enabled":     true,
	"super privacy service ltd":     true,
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
func extractPreseeds(info whoisparser.WhoisInfo, source string) []plugins.Finding {
	type param struct {
		name  string
		value string
	}

	seen := make(map[param]bool)
	var findings []plugins.Finding

	for _, c := range whoisContacts(info) {
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
				Source: source,
				Data: map[string]any{
					"preseed_type":  preseedType,
					"preseed_title": p.value,
				},
			})
		}
	}

	return findings
}

// rootDomain returns the domain to look up WHOIS for.
//
// For ICANN-managed suffixes it is the eTLD+1:
//
//	"app.praetorian.com" → "praetorian.com"
//	"www.example.co.uk"  → "example.co.uk"
//
// For privately-managed suffixes (shared cloud infrastructure) it is the
// ICANN-level eTLD+1 of the suffix, since the sub-suffix has no registration of
// its own — the provider's domain is what WHOIS can answer for:
//
//	"d2anv8h5waxwp1.cloudfront.net"              → "cloudfront.net"
//	"myapp.herokuapp.com"                        → "herokuapp.com"
//	"mybucket.s3.amazonaws.com"                  → "amazonaws.com"
//	"abc123.execute-api.us-east-1.amazonaws.com" → "amazonaws.com"
//
// Returns "" for input with no registrable domain (a bare hostname, a bare
// suffix, or an IP address).
func rootDomain(hostname string) string {
	hostname = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(hostname)), ".")
	if hostname == "" {
		return ""
	}

	// IPs are not domains.
	if net.ParseIP(hostname) != nil {
		return ""
	}

	// Repeatedly compute eTLD+1 until the result sits under an ICANN-managed
	// suffix. Normal domains return on the first iteration; hosts under a private
	// PSL suffix walk up through the suffix until they reach the ICANN-level
	// registrable domain.
	domain := hostname
	for range strings.Count(hostname, ".") + 1 {
		etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			// domain IS a suffix, so it has no registrable part. When that suffix is
			// ICANN-managed there is nothing beneath it to look up — "co.uk" is a
			// public suffix, not a domain.
			if ps, icann := publicsuffix.PublicSuffix(domain); icann && ps == domain {
				return ""
			}
			// Step up one label; if what remains is exactly an ICANN suffix, the
			// label we just dropped made this the registrable domain.
			_, remainder, ok := strings.Cut(domain, ".")
			if !ok {
				return ""
			}
			if tld, icann := publicsuffix.PublicSuffix(remainder); icann && tld == remainder {
				return domain
			}
			domain = remainder
			continue
		}

		tld, icann := publicsuffix.PublicSuffix(etld1)
		if icann {
			return etld1
		}
		if tld == domain {
			return domain
		}
		domain = tld
	}
	return ""
}

func isEmail(s string) bool {
	_, err := mail.ParseAddress(s)
	return err == nil
}
