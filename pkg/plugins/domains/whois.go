package domains

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	whoisparser "github.com/likexian/whois-parser"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("whois", func() plugins.Plugin { return &WhoisPlugin{} })
}

// WhoisResult is the structured output of an RDAP or WHOIS lookup.
type WhoisResult struct {
	Domain         *whoisparser.Domain
	Registrar      *whoisparser.Contact
	Registrant     *whoisparser.Contact
	Administrative *whoisparser.Contact
	Technical      *whoisparser.Contact
	Billing        *whoisparser.Contact
	Raw            string
	Unregistered   bool
}

// WhoisPlugin performs domain WHOIS lookups via RDAP (primary) with TCP 43
// fallback, extracting registration information and emitting preseeds and
// structured WHOIS result findings.
type WhoisPlugin struct {
	HTTPClient *http.Client // injectable for Guard's collector transport
}

// NewWhoisPlugin creates a WhoisPlugin with an injectable HTTP client.
func NewWhoisPlugin(httpClient *http.Client) *WhoisPlugin {
	return &WhoisPlugin{HTTPClient: httpClient}
}

func (p *WhoisPlugin) Name() string        { return "whois" }
func (p *WhoisPlugin) Description() string { return "Domain WHOIS via RDAP and TCP 43" }
func (p *WhoisPlugin) Category() string    { return "domain" }
func (p *WhoisPlugin) Phase() int          { return 0 }
func (p *WhoisPlugin) Mode() string        { return plugins.ModePassive }
func (p *WhoisPlugin) Accepts(input plugins.Input) bool { return input.Domain != "" }

func (p *WhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	domain := rootDomain(input.Domain)
	if domain == "" {
		return nil, fmt.Errorf("whois: unable to determine root domain from %q", input.Domain)
	}

	result, err := p.resolve(ctx, domain)
	if err != nil {
		return nil, err
	}

	if result.Unregistered {
		return []plugins.Finding{p.whoisResultFinding(domain, result, input.OrgName)}, nil
	}

	var findings []plugins.Finding

	// Emit structured WHOIS result (metadata, raw text, corroboration)
	findings = append(findings, p.whoisResultFinding(domain, result, input.OrgName))

	// Emit preseeds (company, email, name)
	findings = append(findings, p.extractPreseeds(domain, result)...)

	return findings, nil
}

// resolve tries RDAP first, falls back to TCP 43 WHOIS.
func (p *WhoisPlugin) resolve(ctx context.Context, domain string) (WhoisResult, error) {
	// 1. Try RDAP
	result, err := rdapLookup(p.HTTPClient, domain)
	if err == nil && hasContacts(result) {
		return result, nil
	}

	if err != nil && isDomainNotFound(err) {
		return WhoisResult{Unregistered: true}, nil
	}

	var best WhoisResult
	if err != nil {
		slog.Debug("RDAP lookup failed, falling back to TCP 43", "domain", domain, "error", err)
	} else {
		slog.Debug("RDAP returned no contacts, falling back to TCP 43", "domain", domain)
		best = result
	}

	// 2. Try TCP 43 WHOIS
	raw, _, whoisErr := whoisQuery(ctx, domain)
	if whoisErr != nil {
		if isDomainNotFound(whoisErr) {
			return WhoisResult{Unregistered: true}, nil
		}
		slog.Debug("TCP 43 WHOIS lookup failed", "domain", domain, "error", whoisErr)
		// Return best RDAP result if we have one
		if best.Domain != nil {
			return best, nil
		}
		return WhoisResult{}, fmt.Errorf("whois: all methods failed for %s", domain)
	}

	if err := ctx.Err(); err != nil {
		return WhoisResult{}, err
	}

	parsed, parseErr := whoisparser.Parse(raw)
	if parseErr != nil {
		slog.Debug("whois: parse failed", "domain", domain, "error", parseErr)
		if best.Domain != nil {
			return best, nil
		}
		return WhoisResult{}, nil
	}

	tcp43Result := extractWhoisResultFromParsed(parsed, raw)
	if hasContacts(tcp43Result) {
		return tcp43Result, nil
	}

	// Use whichever has more data
	if best.Domain != nil {
		return best, nil
	}
	return tcp43Result, nil
}

// whoisResultFinding builds a FindingWhoisResult from a resolved WhoisResult.
func (p *WhoisPlugin) whoisResultFinding(domain string, result WhoisResult, pivotOrg string) plugins.Finding {
	data := map[string]any{}

	if result.Unregistered {
		data["unregistered"] = true
	} else {
		if result.Registrant != nil {
			data["registrant"] = registrantOrg(result.Registrant, domain)
			data["country"] = normalizeRedacted(result.Registrant.Country)
			data["province"] = normalizeRedacted(result.Registrant.Province)
			data["city"] = normalizeRedacted(result.Registrant.City)
		}

		email, sawProxy := contactEmail(result)
		registrantRedacted := false
		if reg, ok := data["registrant"].(string); ok {
			data["registrant"] = normalizeRedacted(reg)
			registrantRedacted = data["registrant"] == PrivacyRedaction
		}
		switch {
		case email != "":
			data["email"] = email
		case sawProxy || registrantRedacted:
			data["email"] = PrivacyRedaction
		}

		if result.Registrar != nil {
			data["registrar"] = normalizeRegistrar(result.Registrar.Name)
		}

		if result.Domain != nil {
			data["purchased"] = result.Domain.CreatedDate
			data["updated"] = result.Domain.UpdatedDate
			data["expiration"] = result.Domain.ExpirationDate
		}

		data["raw"] = result.Raw

		// Corroboration: if pivotOrg is set, compare against resolved registrant
		if pivotOrg != "" {
			resolvedOrg := ""
			if result.Registrant != nil {
				resolvedOrg = registrantOrg(result.Registrant, domain)
			}
			data["corroboration"] = corroborate(pivotOrg, resolvedOrg)
		}
	}

	return plugins.Finding{
		Type:   plugins.FindingWhoisResult,
		Value:  domain,
		Source: p.Name(),
		Data:   data,
	}
}

// extractPreseeds pulls registrant organization, name, and email from WHOIS contacts.
func (p *WhoisPlugin) extractPreseeds(domain string, result WhoisResult) []plugins.Finding {
	type param struct {
		name  string
		value string
	}

	seen := make(map[param]bool)
	var findings []plugins.Finding

	contacts := []*whoisparser.Contact{
		result.Registrant, result.Administrative, result.Billing, result.Technical,
	}
	for _, c := range contacts {
		if c == nil {
			continue
		}

		// For registrant, use registrantOrg to handle ccTLD promotion and
		// registry artifact filtering.
		org := c.Organization
		if c == result.Registrant {
			org = registrantOrg(c, domain)
		} else if org != "" && isRegistryArtifact(org, domain) {
			org = ""
		}

		candidates := []param{
			{"company", org},
			{"name", c.Name},
			{"email", c.Email},
		}

		for _, p := range candidates {
			if p.value == "" || seen[p] {
				continue
			}
			if p.name == "email" && !isValidEmail(p.value) {
				continue
			}
			if p.name == "company" && isNoisyWhoisParam(p.value) {
				continue
			}
			if p.name == "name" && whoisPrivacyNames[strings.ToLower(p.value)] {
				continue
			}
			// Skip noisy email values
			if p.name == "email" && isNoisyWhoisParam(p.value) {
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

// rootDomain extracts the registrable domain (e.g., "example.com" from
// "sub.example.com"). Uses a simple heuristic: take the last two labels.
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

// parseExpirationDuration returns how long until the domain expires, if parseable.
func parseExpirationDuration(expirationDate string) (time.Duration, bool) {
	t, ok := parseExpirationTime(expirationDate)
	if !ok {
		return 0, false
	}
	return time.Until(t), true
}
