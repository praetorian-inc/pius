package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"golang.org/x/sync/errgroup"
)

const (
	crtShDNSConcurrency                         = 10
	confCRTShCertificateTransparencyObservation = 20
	confCRTShDNSPresenceObservation             = 50
)

var crtShDNSRecordTypes = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeCNAME,
	dns.TypeMX,
	dns.TypeSRV,
	dns.TypeSVCB,
	dns.TypeHTTPS,
	dns.TypeNS,
	dns.TypeSOA,
	dns.TypeNAPTR,
}

func init() {
	plugins.Register("crt-sh", func() plugins.Plugin { return NewCRTShPlugin(client.New()) })
}

type CRTShPlugin struct {
	client   *client.Client
	baseURL  string // override for testing
	resolver string // override for testing
}

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

type crtShCandidate struct {
	domain        string
	dnsRecordType uint16
}

func NewCRTShPlugin(c *client.Client) *CRTShPlugin {
	return &CRTShPlugin{client: c, resolver: dnsDefaultResolver}
}

func (p *CRTShPlugin) crtshBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://crt.sh"
}

func (p *CRTShPlugin) dnsResolver() string {
	if p.resolver != "" {
		return p.resolver
	}
	return dnsDefaultResolver
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
	query := input.Domain
	if query == "" {
		query = input.OrgName
	}

	fmt.Printf("running against %v\n", query)

	urlStr := fmt.Sprintf("%s/?q=%s&output=json", p.crtshBase(), url.QueryEscape(query))
	body, err := p.client.Get(ctx, urlStr)
	if err != nil {
		fmt.Printf("http error: %v", err)
		return nil, nil
	}

	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, nil
	}

	candidates := p.findDNSRecordTypes(ctx, crtShCandidates(entries))

	findings := make([]plugins.Finding, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.dnsRecordType == 0 {
			fmt.Printf("skipping domain %v due to invalid DNS record (%d)\n", candidate.domain, candidate.dnsRecordType)
			continue
		}

		finding := plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  candidate.domain,
			Source: p.Name(),
			Data: map[string]any{
				"org":   input.OrgName,
				"query": query,
			},
		}
		plugins.AddConfidence(&finding, confCRTShCertificateTransparencyObservation,
			fmt.Sprintf("crt.sh returned domain %q from Certificate Transparency data for query %q; query results: %s",
				candidate.domain, query, urlStr))
		plugins.AddConfidence(&finding, confCRTShDNSPresenceObservation,
			fmt.Sprintf("DNS presence for %q was confirmed by a qualifying %s record",
				candidate.domain, dns.TypeToString[candidate.dnsRecordType]))
		findings = append(findings, finding)
	}
	return findings, nil
}

func crtShCandidates(entries []crtShEntry) []crtShCandidate {
	seen := make(map[string]bool)
	var candidates []crtShCandidate
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			domain := normalizeDomain(name)
			domain = strings.TrimPrefix(domain, "*.")
			if domain == "" || domain == "*" || strings.HasPrefix(domain, "*") || seen[domain] {
				continue
			}
			seen[domain] = true
			candidates = append(candidates, crtShCandidate{domain: domain})
		}
	}
	return candidates
}

func (p *CRTShPlugin) findDNSRecordTypes(ctx context.Context, candidates []crtShCandidate) []crtShCandidate {
	var group errgroup.Group
	group.SetLimit(crtShDNSConcurrency)

	for index := range candidates {
		candidatePtr := &candidates[index]
		group.Go(func() error {
			candidatePtr.dnsRecordType = p.findDNSRecordType(ctx, candidatePtr.domain)
			return nil
		})
	}

	_ = group.Wait()
	return candidates
}

func (p *CRTShPlugin) findDNSRecordType(ctx context.Context, candidate string) uint16 {
	for _, queryType := range crtShDNSRecordTypes {
		if ctx.Err() != nil {
			fmt.Printf("encountered error: %v\n", ctx.Err())
			return 0
		}

		response, err := queryDNS(ctx, candidate, queryType, p.dnsResolver())
		if err != nil || response == nil {
			fmt.Printf("encountered query dns error: %v\n", err)
			continue
		}
		if response.Rcode == dns.RcodeNameError {
			fmt.Println("response had dns error code")
			return 0
		}
		if response.Rcode != dns.RcodeSuccess {
			fmt.Println("response was not a success")
			continue
		}
		if recordType := qualifyingDNSRecordType(response.Answer); recordType != 0 {
			return recordType
		}
	}

	fmt.Println("no response received")
	return 0
}

func qualifyingDNSRecordType(records []dns.RR) uint16 {
	for _, record := range records {
		recordType := record.Header().Rrtype
		for _, qualifyingType := range crtShDNSRecordTypes {
			if recordType == qualifyingType {
				return recordType
			}
		}
	}
	return 0
}
