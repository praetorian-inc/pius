package domains

import (
	"context"
	"strings"
	"time"

	certstream "github.com/CaliDog/certstream-go"
	"github.com/jmoiron/jsonq"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("certstream", func() plugins.Plugin { return &CertstreamPlugin{} })
}

// CertstreamPlugin monitors real-time Certificate Transparency logs via certstream.calidog.io
type CertstreamPlugin struct {
	// timeout controls how long to stream certificates (default: 30s)
	timeout time.Duration
	// maxResults limits the number of findings (default: 1000)
	maxResults int
}

func (p *CertstreamPlugin) Name() string { return "certstream" }
func (p *CertstreamPlugin) Description() string {
	return "CERTSTREAM: real-time Certificate Transparency log monitoring for domain discovery"
}
func (p *CertstreamPlugin) Category() string { return "domain" }
func (p *CertstreamPlugin) Phase() int       { return 0 }
func (p *CertstreamPlugin) Mode() string     { return plugins.ModePassive }

// Accepts if we have a domain to filter against
func (p *CertstreamPlugin) Accepts(input plugins.Input) bool {
	return input.Domain != ""
}

func (p *CertstreamPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	timeout := p.timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	maxResults := p.maxResults
	if maxResults == 0 {
		maxResults = 1000
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Start certstream
	stream, errStream := certstream.CertStreamEventStream(false)

	seen := make(map[string]bool)
	var findings []plugins.Finding
	baseDomain := strings.ToLower(input.Domain)

	for {
		select {
		case <-ctx.Done():
			return findings, nil
		case err := <-errStream:
			if err != nil {
				// Log but continue - transient errors are expected
				continue
			}
		case jq := <-stream:
			// Extract domains from certificate
			domains := extractDomainsFromCert(&jq)

			for _, domain := range domains {
				domain = cleanCertDomain(domain)
				if domain == "" {
					continue
				}

				// Filter: must match or be subdomain of target domain
				if !matchesDomain(domain, baseDomain) {
					continue
				}

				if seen[domain] {
					continue
				}
				seen[domain] = true

				findings = append(findings, plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  domain,
					Source: p.Name(),
					Data: map[string]any{
						"org":         input.OrgName,
						"base_domain": input.Domain,
						"source":      "certificate_transparency",
					},
				})

				if len(findings) >= maxResults {
					return findings, nil
				}
			}
		}
	}
}

// extractDomainsFromCert extracts domain names from a certificate transparency log entry
func extractDomainsFromCert(jq *jsonq.JsonQuery) []string {
	var domains []string

	// Extract leaf_cert.all_domains which contains CN and SANs
	if allDomains, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains"); err == nil {
		domains = append(domains, allDomains...)
	}

	return domains
}

// cleanCertDomain normalizes a domain from certificate data
func cleanCertDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "*.")
	return normalizeDomain(domain)
}

// matchesDomain returns true if domain equals or is a subdomain of base
func matchesDomain(domain, base string) bool {
	if domain == base {
		return true
	}
	return strings.HasSuffix(domain, "."+base)
}
