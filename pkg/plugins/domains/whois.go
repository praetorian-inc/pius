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

func (p *WhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	domain := rootDomain(input.Domain)
	if domain == "" {
		return nil, fmt.Errorf("whois: unable to determine root domain from %q", input.Domain)
	}

	raw, err := whoisQuery(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("whois: lookup failed for %q: %w", domain, err)
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		slog.Warn("whois: parse failed, skipping preseed extraction", "domain", domain, "error", err)
		return nil, nil
	}

	return extractPreseeds(parsed), nil
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
