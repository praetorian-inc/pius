package whois

import (
	"cmp"
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
// unregistered. RDAP provides clean metadata but rarely has email (GDPR),
// while TCP-43 has email but fragile referral chains. The merge gives callers
// the best of both.
func Lookup(ctx context.Context, domain string, opts ...Option) (Result, error) {
	cfg := config{}
	for _, o := range opts {
		o(&cfg)
	}

	domain = RootDomain(domain)
	if domain == "" {
		return Result{}, fmt.Errorf("whois: no registrable domain")
	}

	rdapResult, rdapErr := rdapLookup(cfg.httpClient, domain)
	if rdapErr != nil && isDomainNotFound(rdapErr) {
		return Result{Domain: domain, Unregistered: true}, nil
	}
	if rdapErr != nil {
		slog.Debug("RDAP lookup failed, will rely on TCP-43", "domain", domain, "error", rdapErr)
	}

	tcp43Result, tcp43Err := tcp43Lookup(ctx, domain)
	if tcp43Err != nil && isDomainNotFound(tcp43Err) {
		return Result{Domain: domain, Unregistered: true}, nil
	}
	if tcp43Err != nil {
		slog.Debug("TCP-43 lookup failed", "domain", domain, "error", tcp43Err)
	}

	if rdapErr != nil && tcp43Err != nil {
		return Result{}, fmt.Errorf("whois: all methods failed for %s", domain)
	}

	result := mergeResults(domain, rdapResult, rdapErr, tcp43Result, tcp43Err)
	applyISOCILFallback(&result)
	return result, nil
}

// mergeResults combines the best fields from RDAP and TCP-43 results.
// RDAP for structured metadata, TCP-43 for email and raw text.
func mergeResults(domain string, rdapR Result, rdapErr error, tcp43R Result, tcp43Err error) Result {
	if rdapErr != nil {
		return tcp43R
	}
	if tcp43Err != nil {
		return rdapR
	}

	r := Result{Domain: domain}

	// Dates: prefer RDAP (RFC3339) over TCP-43 (variable formats).
	r.Created = cmp.Or(rdapR.Created, tcp43R.Created)
	r.Updated = cmp.Or(rdapR.Updated, tcp43R.Updated)
	r.Expiration = cmp.Or(rdapR.Expiration, tcp43R.Expiration)
	r.Registrar = cmp.Or(rdapR.Registrar, tcp43R.Registrar)
	r.NameServers = rdapR.NameServers
	if len(r.NameServers) == 0 {
		r.NameServers = tcp43R.NameServers
	}
	r.Status = rdapR.Status
	if len(r.Status) == 0 {
		r.Status = tcp43R.Status
	}

	// Raw text: prefer TCP-43 (traditional format users expect).
	r.Raw = cmp.Or(tcp43R.Raw, rdapR.Raw)

	// Contacts: prefer RDAP org/name (structured), supplement email from TCP-43.
	r.Registrant = mergeContact(rdapR.Registrant, tcp43R.Registrant)
	r.Admin = mergeContact(rdapR.Admin, tcp43R.Admin)
	r.Tech = mergeContact(rdapR.Tech, tcp43R.Tech)
	r.Billing = mergeContact(rdapR.Billing, tcp43R.Billing)

	return r
}

func mergeContact(rdap, tcp43 Contact) Contact {
	return Contact{
		Organization: cmp.Or(rdap.Organization, tcp43.Organization),
		Name:         cmp.Or(rdap.Name, tcp43.Name),
		Email:        cmp.Or(rdap.Email, tcp43.Email),
		Country:      cmp.Or(rdap.Country, tcp43.Country),
		Province:     cmp.Or(rdap.Province, tcp43.Province),
		City:         cmp.Or(rdap.City, tcp43.City),
	}
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

// --- ISOC-IL (.il) fallback ---

// applyISOCILFallback fills empty Registrant org/email for .il domains from
// the raw RPSL descr/e-mail block, which likexian/whois-parser does not map
// onto Registrant.
func applyISOCILFallback(r *Result) {
	dns := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Domain), "."))
	if !strings.HasSuffix(dns, ".il") {
		return
	}
	if r.Registrant.Organization != "" && r.Registrant.Email != "" {
		return
	}

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

// parseRPSLParagraphs splits raw WHOIS/RPSL text into key:value paragraph
// maps. Used for ISOC-IL fallback and IP WHOIS (future). No third-party
// library exists for RPSL paragraph parsing — it's a niche wire format.
func parseRPSLParagraphs(raw string) []map[string]string {
	var paragraphs []map[string]string
	current := map[string]string{}

	for line := range strings.SplitSeq(raw, "\n") {
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
