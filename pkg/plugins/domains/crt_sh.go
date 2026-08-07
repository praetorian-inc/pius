package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

// Confidence decomposition for a certificate-transparency name.
//
// crt.sh is a decade-deep archive of every certificate ever logged, so "this
// name was on a certificate" is a weak claim on its own — measured against
// three client datasets, 31-70% of the names it returns no longer resolve at
// all. Three things can be observed about a returned name, and each can be
// true while the others are false, so each is its own AddConfidence entry:
//
//   - confCRTShObservation — the name appeared on a logged certificate. Every
//     emitted name has this; it is the floor, not evidence of much.
//   - confCRTShOwnedZone — the name's registrable zone is one the caller owns.
//     Independent of the log: a name can be on the certificate and belong to an
//     unrelated tenant sharing a multi-tenant CDN certificate.
//   - confCRTShLiveDNS — the name has live DNS presence right now. Independent
//     of both: a decommissioned in-zone host is in scope but dead, and a live
//     host can sit in a zone the caller does not own.
//
// "Live DNS presence" deliberately means an address OR a CNAME, not an address
// alone — see dnsPresence for why a dangling CNAME must not read as dead.
//
// The arithmetic against pkg/plugins/confidence.go's ConfidenceHigh (0.65) and
// ConfidenceLow (0.35):
//
//	in-zone + live DNS     0.30+0.30+0.20 = 0.80  clean, above ConfidenceHigh
//	in-zone + dead         0.30+0.30      = 0.60  needs review — an in-scope
//	                                              name whose DNS is gone is a
//	                                              lead to chase, not an asset
//	out-of-zone + live DNS 0.30+0.20      = 0.50  needs review — the cross-brand
//	                                              discovery case, real but
//	                                              unattributed
//	out-of-zone + dead     0.30           = 0.30  below the ConfidenceLow noise
//	                                              floor
//
// The 0.30 case is de-ranked, not dropped: this plugin emits every surviving
// name scored and lets the framework's thresholds act on it.
const (
	confCRTShObservation = 0.30
	confCRTShOwnedZone   = 0.30
	confCRTShLiveDNS     = 0.20
)

// crtShResolveWorkers bounds the DNS fan-out. A single crt.sh response can
// carry hundreds of unique names (939 in the worst measured case) against a
// 5-minute upstream RunTimeout, so the resolution pass is concurrent — but
// unbounded goroutines would put a burst of that size on one resolver.
const crtShResolveWorkers = 50

func init() {
	plugins.Register("crt-sh", func() plugins.Plugin { return NewCRTShPlugin(client.New(), nil) })
}

type CRTShPlugin struct {
	client  *client.Client
	lookup  Resolver // caller-supplied; nil keeps the package default resolver
	baseURL string   // override for testing
}

// NewCRTShPlugin builds the plugin around a caller-supplied resolver, matching
// NewDNSBrutePlugin's contract: a nil lookup keeps the package's default DNS
// client, which is only appropriate when the caller does not need to route
// forward lookups through its own resolver or mocking layer.
func NewCRTShPlugin(c *client.Client, lookup Resolver) *CRTShPlugin {
	return &CRTShPlugin{client: c, lookup: lookup}
}

// crtShEntry is one record of the crt.sh JSON response. not_after is decoded
// for downstream use only — deliberately NOT used to filter, because measuring
// expiry-based filtering against real datasets cost real recall: an expired
// certificate is routine for a host that is still very much alive.
type crtShEntry struct {
	NameValue string `json:"name_value"`
	NotAfter  string `json:"not_after"`
}

func (p *CRTShPlugin) crtshBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://crt.sh"
}

func (p *CRTShPlugin) Name() string { return "crt-sh" }
func (p *CRTShPlugin) Description() string {
	return "crt.sh: discovers domains via Certificate Transparency logs"
}
func (p *CRTShPlugin) Category() string { return "domain" }
func (p *CRTShPlugin) Phase() int       { return 0 }
func (p *CRTShPlugin) Mode() string     { return plugins.ModePassive }

// Accepts if we have a domain or org name to search
func (p *CRTShPlugin) Accepts(input plugins.Input) bool {
	return isDomainName(input.Domain) || input.OrgName != ""
}

func (p *CRTShPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	// Search by domain if available, otherwise by org name
	query := input.Domain
	if query == "" {
		query = input.OrgName
	}

	urlStr := fmt.Sprintf("%s/?q=%s&output=json", p.crtshBase(), url.QueryEscape(query))
	body, err := p.client.Get(ctx, urlStr)
	if err != nil {
		// Graceful degradation is the shared contract with the other domain
		// plugins, but silence is not: crt.sh returns HTTP 502 often enough
		// that 2 of 3 measured attempts failed, and without this record an
		// outage is indistinguishable from "this domain has no subdomains".
		//
		// The URL is logged verbatim because for this endpoint that IS the
		// sanitized form: client.sanitizeURL redacts only key/apikey/api_key/
		// token/access_token, and crt.sh takes neither — its only parameters
		// are q (the query, already logged) and output. It is unexported, so
		// this package cannot call it to say so mechanically.
		slog.Warn("crt-sh: request failed, treating as no results",
			"error", err, "query", query, "url", urlStr)
		return nil, nil
	}

	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		slog.Warn("crt-sh: response was not the expected JSON, treating as no results",
			"error", err, "query", query, "url", urlStr)
		return nil, nil
	}

	names, notAfter := crtShNames(entries, query)

	// Junk removal straddles the DNS pass: OOB/canary names go before it, the
	// entropy heuristic after it. See dropOOBNames and dropDeadJunk.
	names, oobDropped := dropOOBNames(names)
	presence := p.resolveAll(ctx, names)
	names, junkDropped := dropDeadJunk(names, presence)

	addressed, danglingCNAME := 0, 0
	for _, name := range names {
		switch {
		case presence[name].Addressed:
			addressed++
		case presence[name].CNAME != "":
			danglingCNAME++
		}
	}
	slog.Info("crt-sh: junk filtering complete",
		"query", query, "oob_dropped", oobDropped, "entropy_dropped", junkDropped,
		"kept", len(names), "addressed", addressed, "cname_only", danglingCNAME)

	zones := OwnedZones(input.Meta, query)

	findings := make([]plugins.Finding, 0, len(names))
	for _, name := range names {
		finding := plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  name,
			Source: p.Name(),
			Data: map[string]any{
				"org":       input.OrgName,
				"query":     query,
				"not_after": notAfter[name],
			},
		}

		plugins.AddConfidence(&finding, confCRTShObservation,
			fmt.Sprintf("crt.sh returned %q on a logged certificate for query %q; query results: %s",
				name, query, urlStr))

		if InOwnedZone(name, zones) {
			plugins.AddConfidence(&finding, confCRTShOwnedZone,
				fmt.Sprintf("%q sits in registrable zone %q, which is covered by the caller's owned-domain set",
					name, registrableZone(name)))
		}

		// The two live-DNS cases score the same but read very differently to a
		// human, so the justification must not claim an address that does not
		// exist: a CNAME with no address is a takeover candidate, not a host.
		if d := presence[name]; d.Addressed {
			plugins.AddConfidence(&finding, confCRTShLiveDNS,
				fmt.Sprintf("%q currently resolves to an address in DNS, so the certificate name is a live host rather than certificate-log history",
					name))
		} else if d.CNAME != "" {
			plugins.AddConfidence(&finding, confCRTShLiveDNS,
				fmt.Sprintf("%q has no address but its CNAME to %q is still published, so the name has live DNS presence; a CNAME pointing at a resource that no longer answers is a subdomain-takeover candidate",
					name, d.CNAME))
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// crtShNames flattens the entries into a deduplicated, order-preserving list of
// candidate names, plus each name's latest not_after.
//
// Wildcard names are reduced to the zone they cover rather than discarded: the
// parent of "*.foo.example.com" is a real zone that had a certificate issued
// for it. The queried name itself is never re-emitted — doing so fed the caller
// its own seed back as a discovery (5,477 times for one measured tenant).
func crtShNames(entries []crtShEntry, query string) ([]string, map[string]string) {
	normalizedQuery := normalizeDomain(query)

	var names []string
	notAfter := make(map[string]string)
	seen := make(map[string]bool)

	for _, entry := range entries {
		// name_value can contain multiple domains separated by newlines
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name, ok := DropWildcard(name)
			if !ok || name == "" || name == normalizedQuery {
				continue
			}
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
			// A name appears on every certificate that ever covered it; the
			// latest expiry is the informative one. crt.sh formats not_after
			// as ISO-8601, which orders lexicographically.
			if entry.NotAfter > notAfter[name] {
				notAfter[name] = entry.NotAfter
			}
		}
	}

	return names, notAfter
}

// dropOOBNames removes out-of-band-interaction and canary names, and reports how
// many it removed.
//
// This arm drops unconditionally and runs BEFORE the DNS pass, unlike the
// entropy arm below. containsOOBPattern matches fixed literal substrings
// ("interactsh.", "burpcollaborator", "canarytokens", …), so it has no
// false-positive mode to protect against — and a live interaction server
// resolving perfectly well is not evidence it is a customer asset, so there is
// nothing DNS could add to the decision.
func dropOOBNames(names []string) ([]string, int) {
	kept := make([]string, 0, len(names))
	dropped := 0

	for _, name := range names {
		if containsOOBPattern(name) {
			slog.Info("crt-sh: dropped OOB/canary name", "domain", name)
			dropped++
			continue
		}
		kept = append(kept, name)
	}

	return kept, dropped
}

// dropDeadJunk removes names that BOTH look like random tokens AND have no DNS
// record, and reports how many it removed.
//
// The conjunction is the whole point: entropy alone is not evidence of junk.
// shannonEntropy only sees character diversity over a label, so a long lowercase
// compound scores like a random token. Running junkLabel as a pre-DNS filter over
// the whole set — which this plugin briefly did — therefore deleted
// dash-foxupfront.fox.com, which resolves today (Akamai, 23.36.20.219): a live
// asset thrown away by a heuristic that had no business ruling on it alone.
//
// DNS is what the heuristic was always proxying for. An ACME validation token is
// minted for one challenge and never given a record, so "high entropy" AND "no
// record" together are strong. Either alone is not: a name that resolves is a
// real host however random it looks, and a dead name that reads normally is
// still worth emitting as a lead.
//
// The gate discriminates rather than merely admitting more. In the same measured
// pass it kept dash-foxupfront.fox.com at 0.80 and still dropped
// liveanotherday.fox.com and lyncdiscoverinternal.fox.com — same entropy verdict,
// no DNS record, nothing left vouching for them.
//
// Do not "simplify" this back into a pre-filter. Doing so silently deletes
// resolving assets, and it breaks the de-rank-never-drop rule everywhere else in
// this plugin — the entropy arm is the one place a name is removed outright, and
// it is only justified because a name with no DNS record and a random-looking
// label has nothing left vouching for it.
// "Dead" here is dnsPresence.live(), the same notion scoring uses — so a
// high-entropy name whose CNAME still exists is kept, not dropped. Dangling
// CNAMEs are exactly the takeover candidates this plugin most wants to surface,
// and randomly-generated-looking hostnames are common among them.
func dropDeadJunk(names []string, presence map[string]dnsPresence) ([]string, int) {
	kept := make([]string, 0, len(names))
	dropped := 0

	for _, name := range names {
		if !presence[name].live() {
			if label, ok := junkLabel(name); ok {
				slog.Info("crt-sh: dropped high-entropy name with no DNS record",
					"domain", name, "label", label)
				dropped++
				continue
			}
		}
		kept = append(kept, name)
	}

	return kept, dropped
}

// dnsPresence is what DNS says about a name: it has an address, or it has only
// a CNAME, or it has nothing.
//
// The CNAME case exists because "no A/AAAA" is NOT the same as "dead". A CNAME
// pointing at a deprovisioned resource — an S3 bucket, an ELB, a CloudFront
// distribution that no longer exists — resolves to no address at all, yet it is
// the single highest-value thing this source produces: it is a subdomain-takeover
// candidate. Measured, 4 of 67 names on one domain were exactly this, all
// pointing at deprovisioned AWS resources.
//
// Scoring those as dead is not a cosmetic ranking error, it loses the finding
// outright. A dead name lands in the needs-review band, Guard routes
// needs-review findings to Preseeds, and Guard's correlator is asset-only — so
// the dangling-CNAME takeover rule never fires on them. The name gets reported;
// the vulnerability does not.
//
// That is why the second lookup exists and why it must not be "simplified" away.
// It runs ONLY for names that came back with no address, so it costs nothing on
// the common path, and it is the difference between surfacing a takeover and
// burying it.
type dnsPresence struct {
	// Addressed reports at least one A or AAAA record.
	Addressed bool

	// CNAME is the target of a CNAME record when the name has no address, and
	// "" otherwise. Non-empty here is the takeover-candidate signal.
	CNAME string
}

// live reports whether DNS has anything at all for this name. This is the single
// notion of "not dead": scoring and the entropy-junk gate both read it, so a
// high-entropy name with a live CNAME is both scored and kept.
func (d dnsPresence) live() bool {
	return d.Addressed || d.CNAME != ""
}

// resolveAll reports, per name, what DNS has for it. Concurrency is bounded and
// mirrors dns_brute's semaphore-plus-WaitGroup pass; the parallel writes are
// index-disjoint, so the pass needs no lock, and the results are keyed by name
// afterwards (names are unique by then, having been deduped).
//
// The CNAME lookup happens inside the same worker, guarded by the address
// result, so it stays within this same bounded pool and the same ctx-cancellation
// check instead of needing a second pass.
func (p *CRTShPlugin) resolveAll(ctx context.Context, names []string) map[string]dnsPresence {
	results := make([]dnsPresence, len(names))

	sem := make(chan struct{}, crtShResolveWorkers)
	var wg sync.WaitGroup

	for i, name := range names {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{} // acquire slot
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }() // release slot

			results[i] = p.resolve(ctx, name)
		}(i, name)
	}
	wg.Wait()

	presence := make(map[string]dnsPresence, len(names))
	for i, name := range names {
		presence[name] = results[i]
	}
	return presence
}

// resolve reports what DNS has for host. A lookup failure reads as "nothing":
// the name is still emitted, it just does not earn confCRTShLiveDNS.
//
// The CNAME query runs only when no address came back, so a name that already
// resolved never costs a second lookup.
func (p *CRTShPlugin) resolve(ctx context.Context, host string) dnsPresence {
	// An injected resolver answers both address families in one call and reports
	// failure as "no addresses", matching how dns-brute degrades.
	if p.lookup != nil {
		if len(p.lookup.Resolve(host)) > 0 {
			return dnsPresence{Addressed: true}
		}
		// CNAMEResolver is optional: a resolver without it yields no CNAME
		// evidence rather than an error.
		if cr, ok := p.lookup.(CNAMEResolver); ok {
			return dnsPresence{CNAME: normalizeDomain(cr.ResolveCNAME(host))}
		}
		return dnsPresence{}
	}

	ips, err := resolveIPs(ctx, host, dnsDefaultResolver)
	if err != nil {
		slog.Debug("crt-sh: DNS lookup failed", "host", host, "error", err)
	} else if len(ips) > 0 {
		return dnsPresence{Addressed: true}
	}

	return dnsPresence{CNAME: cnameTarget(ctx, host)}
}

// cnameTarget returns host's CNAME target, or "" when it has none or the lookup
// fails.
func cnameTarget(ctx context.Context, host string) string {
	r, err := queryDNS(ctx, host, dns.TypeCNAME, dnsDefaultResolver)
	if err != nil {
		slog.Debug("crt-sh: CNAME lookup failed", "host", host, "error", err)
		return ""
	}
	if r == nil || r.Rcode != dns.RcodeSuccess {
		return ""
	}
	for _, ans := range r.Answer {
		if c, ok := ans.(*dns.CNAME); ok {
			return normalizeDomain(c.Target)
		}
	}
	return ""
}
