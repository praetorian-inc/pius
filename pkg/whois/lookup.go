package whois

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"
)

// Option configures a Lookup call.
type Option func(*config)

type config struct {
	httpClient *http.Client
}

// WithHTTPClient sets the HTTP client used for RDAP requests.
func WithHTTPClient(c *http.Client) Option {
	return func(cfg *config) { cfg.httpClient = c }
}

// Lookup resolves domain registration data by trying RDAP first (structured,
// standardized dates) then TCP-43 (better email coverage, raw text), and
// merging the best fields from each source.
//
// Both sources are always attempted unless one definitively says the domain is
// unregistered. This is intentional: RDAP provides clean metadata but rarely
// has email (GDPR), while TCP-43 has email but fragile referral chains. The
// merge gives callers the best of both.
func Lookup(ctx context.Context, domain string, opts ...Option) (Result, error) {
	cfg := config{}
	for _, o := range opts {
		o(&cfg)
	}

	domain = RootDomain(domain)
	if domain == "" {
		return Result{}, fmt.Errorf("whois: no registrable domain")
	}

	// Try RDAP — structured data, standardized dates.
	rdapResult, rdapErr := rdapLookup(cfg.httpClient, domain)
	if rdapErr != nil && isDomainNotFound(rdapErr) {
		return Result{Domain: domain, Unregistered: true}, nil
	}
	if rdapErr != nil {
		slog.Debug("RDAP lookup failed, will rely on TCP-43", "domain", domain, "error", rdapErr)
	}

	// Try TCP-43 — broader email coverage, raw WHOIS text.
	tcp43Result, tcp43Err := tcp43Lookup(ctx, domain)
	if tcp43Err != nil && isDomainNotFound(tcp43Err) {
		return Result{Domain: domain, Unregistered: true}, nil
	}
	if tcp43Err != nil {
		slog.Debug("TCP-43 lookup failed", "domain", domain, "error", tcp43Err)
	}

	// Both failed entirely.
	if rdapErr != nil && tcp43Err != nil {
		return Result{}, fmt.Errorf("whois: all methods failed for %s", domain)
	}

	return merge(domain, rdapResult, rdapErr, tcp43Result, tcp43Err), nil
}

// merge combines the best fields from RDAP and TCP-43 results. Strategy:
//   - RDAP for structured metadata (dates, country, registrar) — more reliable
//   - TCP-43 for email and raw text — broader coverage
//   - Registrant org from whichever source has it
//   - If both have registrant org, prefer RDAP (more structured)
func merge(domain string, rdap Result, rdapErr error, tcp43 Result, tcp43Err error) Result {
	// Only one source available — return it.
	if rdapErr != nil {
		return tcp43
	}
	if tcp43Err != nil {
		return rdap
	}

	// Both available — merge.
	r := Result{Domain: domain}

	// Dates: prefer RDAP (RFC3339 format) over TCP-43 (variable formats).
	r.Created = coalesce(rdap.Created, tcp43.Created)
	r.Updated = coalesce(rdap.Updated, tcp43.Updated)
	r.Expiration = coalesce(rdap.Expiration, tcp43.Expiration)
	r.Registrar = coalesce(rdap.Registrar, tcp43.Registrar)
	r.NameServers = rdap.NameServers
	if len(r.NameServers) == 0 {
		r.NameServers = tcp43.NameServers
	}
	r.Status = rdap.Status
	if len(r.Status) == 0 {
		r.Status = tcp43.Status
	}

	// Raw text: prefer TCP-43 (traditional format users expect).
	r.Raw = coalesce(tcp43.Raw, rdap.Raw)

	// Contacts: merge per-role — prefer RDAP org/name (structured), supplement
	// email from TCP-43 (RDAP almost never has email due to GDPR).
	r.Registrant = mergeContact(rdap.Registrant, tcp43.Registrant)
	r.Admin = mergeContact(rdap.Admin, tcp43.Admin)
	r.Tech = mergeContact(rdap.Tech, tcp43.Tech)
	r.Billing = mergeContact(rdap.Billing, tcp43.Billing)

	return r
}

// mergeContact takes the best fields from two contacts. RDAP provides better
// org/name/country (structured VCard), TCP-43 provides email.
func mergeContact(rdap, tcp43 Contact) Contact {
	c := Contact{
		Organization: coalesce(rdap.Organization, tcp43.Organization),
		Name:         coalesce(rdap.Name, tcp43.Name),
		Email:        coalesce(rdap.Email, tcp43.Email),
		Country:      coalesce(rdap.Country, tcp43.Country),
		Province:     coalesce(rdap.Province, tcp43.Province),
		City:         coalesce(rdap.City, tcp43.City),
	}
	return c
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// isDomainNotFound reports whether err definitively means the domain is not
// registered (RDAP 404 or whoisparser "not found" sentinel).
func isDomainNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, whoisparser.ErrNotFoundDomain) {
		return true
	}
	var ce *rdap.ClientError
	if errors.As(err, &ce) {
		return ce.Type == rdap.ObjectDoesNotExist
	}
	return false
}

// ParseExpiration attempts to parse an expiration date string and returns
// how long until the domain expires.
func ParseExpiration(expirationDate string) (time.Duration, bool) {
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, expirationDate); err == nil {
			return time.Until(t), true
		}
	}
	return 0, false
}

// RedactionMarkers are high-precision substrings indicating a registry
// deliberately redacted contact data.
func containsRedactionMarkerInRaw(raw string) bool {
	return ContainsRedactionMarker(raw)
}

// --- ISOC-IL (.il) fallback ---

// applyISOCILFallback fills empty Registrant org/email for ISOC-IL (.il)
// domains from the raw RPSL descr/e-mail block, which likexian/whois-parser
// does not map onto Registrant. No-op for non-.il domains and for fields
// the parser already populated.
func applyISOCILFallback(r *Result) {
	dns := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Domain), "."))
	if !strings.HasSuffix(dns, ".il") {
		return
	}
	if r.Registrant.Organization != "" && r.Registrant.Email != "" {
		return
	}

	// Find first paragraph with a descr: line — that's the holder block.
	var holder map[string]string
	for _, p := range parseRPSLParagraphs(r.Raw) {
		if p["first_descr"] != "" {
			holder = p
			break
		}
	}
	if holder == nil {
		return
	}

	if r.Registrant.Organization == "" {
		org := strings.TrimSpace(holder["first_descr"])
		if runes := []rune(org); len(runes) > 255 {
			org = strings.TrimSpace(string(runes[:255]))
		}
		r.Registrant.Organization = org
	}

	if r.Registrant.Email == "" {
		deobfuscated := strings.ReplaceAll(holder["e-mail"], " AT ", "@")
		if classifyEmail(deobfuscated) != "" {
			r.Registrant.Email = deobfuscated
		}
	}
}

// parseRPSLParagraphs splits raw WHOIS text into key:value paragraph maps.
func parseRPSLParagraphs(raw string) []map[string]string {
	var paragraphs []map[string]string
	current := map[string]string{}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			if len(current) > 0 {
				paragraphs = append(paragraphs, current)
				current = map[string]string{}
			}
			continue
		}
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if key == "descr" {
			if _, seen := current["first_descr"]; !seen {
				current["first_descr"] = value
			}
		}
		current[key] = value
	}
	if len(current) > 0 {
		paragraphs = append(paragraphs, current)
	}
	return paragraphs
}
