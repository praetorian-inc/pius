package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("reverse-ip", func() plugins.Plugin {
		return &ReverseIPPlugin{client: client.New()}
	})
}

// ReverseIPPlugin discovers hostnames via reverse IP lookups (PTR records)
// and passive DNS services like HackerTarget and ViewDNS.
//
// Phase 3: Consumes CIDRs discovered by Phase 2 RDAP plugins (arin, ripe, apnic, afrinic, lacnic).
// Reads CIDRs from Input.Meta["cidrs"] and performs reverse lookups on each IP.
//
// For small CIDRs (/24 and smaller), iterates all IPs.
// For larger CIDRs, samples representative IPs to avoid excessive queries.
type ReverseIPPlugin struct {
	client     *client.Client
	baseURL    string // HackerTarget override for testing
	viewDNSURL string // ViewDNS override for testing
	resolver   string // DNS resolver override for testing
	maxResults int    // max hostnames to return (default 500)
	maxIPs     int    // max IPs to query per CIDR (default 256)

	ptr    PTRResolver // set by NewReverseIPPlugin; replaces the direct DNS client
	apiKey string      // set by NewReverseIPPlugin; falls back to VIEWDNS_API_KEY
}

// PTRResolver resolves an IP to its PTR hostnames. Embedders supply their own so
// reverse lookups route through their resolver — and their mocking layer —
// instead of this package's hardcoded public resolver.
type PTRResolver interface {
	ReverseLookup(ip string) []string
}

// NewReverseIPPlugin builds the plugin around caller-supplied dependencies, so
// every source it uses is interceptable: client covers the HackerTarget and
// ViewDNS HTTP legs, ptr covers the PTR leg. A nil ptr keeps the default DNS
// client, which is only appropriate when the caller does not need interception.
func NewReverseIPPlugin(c *client.Client, ptr PTRResolver, apiKey string) *ReverseIPPlugin {
	return &ReverseIPPlugin{client: c, ptr: ptr, apiKey: apiKey}
}

// key prefers an injected key so embedders never depend on process environment.
func (p *ReverseIPPlugin) key() string {
	if p.apiKey != "" {
		return p.apiKey
	}
	return os.Getenv("VIEWDNS_API_KEY")
}

// Independent evidence contributions for a reverse-IP hostname. They are
// additive, so the branch totals of the original decision tree fall out of the
// combinations: CDN + unrelated hostname = 25, CDN + known-domain = 55,
// non-CDN + unmatched = 55, non-CDN + org-name = 70, non-CDN +
// known-domain = 85.
const (
	// confReverseIPAssociated is the base signal: the hostname was observed
	// against an IP inside a netblock attributed to the target.
	confReverseIPAssociated = 25
	// confReverseIPNonCDN credits the IP not belonging to a known CDN — shared
	// CDN address space is where reverse-IP false positives come from.
	confReverseIPNonCDN = 30
	// confReverseIPKnownDomain credits the hostname sitting under the known
	// target domain.
	confReverseIPKnownDomain = 30
	// confReverseIPOrgName credits the weaker signal of the hostname carrying
	// the normalized organization name. It is only added when the stronger
	// known-domain evidence did not already fire.
	confReverseIPOrgName = 15

	// confReverseIPDiscardFloor is the aggregate below which a hostname is
	// dropped rather than emitted.
	confReverseIPDiscardFloor = 30
)

func (p *ReverseIPPlugin) Name() string { return "reverse-ip" }
func (p *ReverseIPPlugin) Description() string {
	return "Reverse IP: discovers hostnames via PTR records, HackerTarget, and ViewDNS (optional, requires VIEWDNS_API_KEY) from discovered CIDRs (Phase 3)"
}
func (p *ReverseIPPlugin) Category() string { return "domain" }
func (p *ReverseIPPlugin) Phase() int       { return 3 }
func (p *ReverseIPPlugin) Mode() string     { return plugins.ModePassive }

func (p *ReverseIPPlugin) hackerTargetBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.hackertarget.com"
}

func (p *ReverseIPPlugin) viewDNSBase() string {
	if p.viewDNSURL != "" {
		return p.viewDNSURL
	}
	return "https://api.viewdns.info"
}

func (p *ReverseIPPlugin) dnsResolver() string {
	if p.resolver != "" {
		return p.resolver
	}
	return "8.8.8.8:53"
}

// Accepts returns true if we have CIDRs to process from Phase 2.
func (p *ReverseIPPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta["cidrs"] != ""
}

func (p *ReverseIPPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	maxResults := p.maxResults
	if maxResults == 0 {
		maxResults = 500
	}
	maxIPs := p.maxIPs
	if maxIPs == 0 {
		maxIPs = 256
	}

	// Parse CIDRs from Meta
	cidrsStr := input.Meta["cidrs"]
	if cidrsStr == "" {
		return nil, nil
	}

	cidrList := strings.Split(cidrsStr, ",")
	var allIPs []string

	for _, cidrStr := range cidrList {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" {
			continue
		}
		ips := expandCIDR(cidrStr, maxIPs)
		allIPs = append(allIPs, ips...)
	}

	if len(allIPs) == 0 {
		return nil, nil
	}

	// Check for ViewDNS API key
	viewDNSKey := p.key()

	seen := make(map[string]bool)
	var findings []plugins.Finding

	for _, ip := range allIPs {
		if len(findings) >= maxResults {
			break
		}

		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		isCDN := isKnownCDN(ip)

		// PTR lookup
		ptrHosts := p.ptrLookup(ctx, ip)
		for _, host := range ptrHosts {
			host = normalizeDomain(host)
			if host == "" || seen[host] {
				continue
			}
			seen[host] = true

			// Skips very low confidence results, e.g. unrelated hostnames on CDN IPs.
			f, ok := scoredReverseIPFinding(p.Name(), host, ip, "ptr", input, isCDN)
			if !ok {
				continue
			}
			findings = append(findings, f)
		}

		// HackerTarget reverse IP lookup (skip for CDN IPs to avoid noise)
		if !isCDN {
			htHosts := p.hackerTargetLookup(ctx, ip)
			for _, host := range htHosts {
				host = normalizeDomain(host)
				if host == "" || seen[host] {
					continue
				}
				seen[host] = true

				f, ok := scoredReverseIPFinding(p.Name(), host, ip, "hackertarget", input, isCDN)
				if !ok {
					continue
				}
				findings = append(findings, f)
			}
		}

		// ViewDNS reverse IP lookup (optional, requires VIEWDNS_API_KEY, skip for CDN IPs)
		if viewDNSKey != "" && !isCDN {
			vdHosts := p.viewDNSLookup(ctx, ip, viewDNSKey)
			for _, host := range vdHosts {
				host = normalizeDomain(host)
				if host == "" || seen[host] {
					continue
				}
				seen[host] = true

				f, ok := scoredReverseIPFinding(p.Name(), host, ip, "viewdns", input, isCDN)
				if !ok {
					continue
				}
				findings = append(findings, f)
			}
		}
	}

	return findings, nil
}

// expandCIDR returns up to maxIPs IP addresses from a CIDR.
// For /32, returns the single IP.
// For /24 and smaller, returns all IPs.
// For larger ranges, samples evenly across the range.
func expandCIDR(cidrStr string, maxIPs int) []string {
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		// Try parsing as single IP
		ip, err := netip.ParseAddr(strings.TrimSuffix(cidrStr, "/32"))
		if err != nil {
			return nil
		}
		return []string{ip.String()}
	}

	// Calculate number of IPs in range
	bits := prefix.Bits()
	var numIPs int
	if prefix.Addr().Is4() {
		numIPs = 1 << (32 - bits)
	} else {
		// For IPv6, cap at maxIPs
		numIPs = maxIPs
	}

	if numIPs > maxIPs {
		numIPs = maxIPs
	}

	var ips []string
	addr := prefix.Addr()

	// For small ranges, iterate all
	if numIPs <= maxIPs {
		for i := 0; i < numIPs && prefix.Contains(addr); i++ {
			ips = append(ips, addr.String())
			addr = addr.Next()
		}
	}

	return ips
}

// ptrLookup performs reverse DNS lookup for an IP
func (p *ReverseIPPlugin) ptrLookup(ctx context.Context, ip string) []string {
	if p.ptr != nil {
		return p.ptr.ReverseLookup(ip)
	}

	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return nil
	}

	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(arpa, dns.TypePTR)
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, p.dnsResolver())
	if err != nil {
		return nil
	}

	var hosts []string
	for _, ans := range r.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			hosts = append(hosts, ptr.Ptr)
		}
	}
	return hosts
}

// hackerTargetLookup queries HackerTarget reverse IP API
func (p *ReverseIPPlugin) hackerTargetLookup(ctx context.Context, ip string) []string {
	// Validate IP
	if net.ParseIP(ip) == nil {
		return nil
	}

	url := p.hackerTargetBase() + "/reverseiplookup/?q=" + ip
	body, err := p.client.Get(ctx, url)
	if err != nil {
		return nil
	}

	// Response is newline-separated hostnames
	// May contain error messages like "API count exceeded"
	lines := strings.Split(string(body), "\n")
	var hosts []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and error messages
		if line == "" || strings.Contains(line, "error") || strings.Contains(line, "API") {
			continue
		}
		// Basic hostname validation
		if strings.Contains(line, ".") && !strings.Contains(line, " ") {
			hosts = append(hosts, line)
		}
	}
	return hosts
}

// viewDNSLookup queries ViewDNS reverse IP API (requires VIEWDNS_API_KEY)
func (p *ReverseIPPlugin) viewDNSLookup(ctx context.Context, ip string, apiKey string) []string {
	// Validate IP
	if net.ParseIP(ip) == nil {
		return nil
	}

	url := p.viewDNSBase() + "/reverseip/?host=" + ip + "&apikey=" + apiKey + "&output=json"
	body, err := p.client.Get(ctx, url)
	if err != nil {
		return nil
	}

	// Parse JSON response
	var response struct {
		Response struct {
			DomainCount string `json:"domain_count"`
			Domains     []struct {
				Name         string `json:"name"`
				LastResolved string `json:"last_resolved"`
			} `json:"domains"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil
	}

	var hosts []string
	for _, d := range response.Response.Domains {
		if d.Name != "" {
			hosts = append(hosts, d.Name)
		}
	}
	return hosts
}

// scoredReverseIPFinding builds a hostname finding, attaches its evidence, and
// reports whether the aggregate clears the discard floor. The three lookup
// methods (PTR, HackerTarget, ViewDNS) differ only in provenance, so they share
// one scoring path.
func scoredReverseIPFinding(source, host, ip, method string, input plugins.Input, isCDN bool) (plugins.Finding, bool) {
	f := plugins.Finding{
		Type:   plugins.FindingDomain,
		Value:  host,
		Source: source,
		Data: map[string]any{
			"org":         input.OrgName,
			"ip":          ip,
			"method":      method,
			"base_domain": input.Domain,
			"is_cdn":      isCDN,
		},
	}
	scoreReverseIP(&f, host, input.Domain, input.OrgName, ip, method, isCDN)
	return f, plugins.TotalConfidence(f) >= confReverseIPDiscardFloor
}

// scoreReverseIP appends one evidence entry per independent signal supporting a
// reverse-IP hostname. The known-domain and org-name entries are mutually
// exclusive: a hostname under the known domain is the same "belongs to the
// target" claim in a stronger form, so crediting both would double-count it.
func scoreReverseIP(f *plugins.Finding, hostname, baseDomain, orgName, ip, method string, isCDN bool) {
	hostname = strings.ToLower(hostname)
	baseDomain = strings.ToLower(baseDomain)
	orgName = strings.ToLower(orgName)

	plugins.AddConfidence(f, confReverseIPAssociated,
		fmt.Sprintf("%s associated hostname %q with discovered IP %s",
			reverseIPMethodName(method), hostname, ip), reverseIPReferences(method, ip)...)

	if !isCDN {
		plugins.AddConfidence(f, confReverseIPNonCDN,
			fmt.Sprintf("IP %s did not match Pius's built-in CDN prefix list, reducing the likelihood that this is shared CDN infrastructure", ip))
	}

	normalizedOrg := strings.ReplaceAll(orgName, " ", "")

	if baseDomain != "" && (hostname == baseDomain || strings.HasSuffix(hostname, "."+baseDomain)) {
		plugins.AddConfidence(f, confReverseIPKnownDomain,
			fmt.Sprintf("Hostname %q matches the known target domain %q", hostname, baseDomain))
	} else if normalizedOrg != "" && strings.Contains(hostname, normalizedOrg) {
		plugins.AddConfidence(f, confReverseIPOrgName,
			fmt.Sprintf("Hostname %q contains the normalized organization name %q", hostname, normalizedOrg))
	}
}

func reverseIPMethodName(method string) string {
	switch method {
	case "ptr":
		return "DNS PTR lookup"
	case "hackertarget":
		return "HackerTarget reverse-IP lookup"
	case "viewdns":
		return "ViewDNS reverse-IP lookup"
	default:
		return "Reverse-IP lookup"
	}
}

func reverseIPReferences(method, ip string) []plugins.Reference {
	switch method {
	case "hackertarget":
		return []plugins.Reference{{
			Label: "HackerTarget reverse-IP request",
			URL:   "https://api.hackertarget.com/reverseiplookup/?" + url.Values{"q": {ip}}.Encode(),
		}}
	case "viewdns":
		return []plugins.Reference{{
			Label: "ViewDNS reverse-IP request (API key redacted)",
			URL: "https://api.viewdns.info/reverseip/?" + url.Values{
				"apikey": {"REDACTED"},
				"host":   {ip},
				"output": {"json"},
			}.Encode(),
		}}
	default:
		return nil
	}
}

// Known CDN/cloud provider IP ranges (simplified - common prefixes)
var cdnPrefixes = []string{
	// Cloudflare
	"103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.", "104.18.", "104.19.",
	"104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
	"108.162.", "131.0.72.", "141.101.", "162.158.", "172.64.", "172.65.", "172.66.", "172.67.",
	"173.245.", "188.114.", "190.93.", "197.234.", "198.41.",
	// Fastly
	"151.101.", "199.232.",
	// Akamai (partial)
	"23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.", "23.38.", "23.39.",
	"23.40.", "23.41.", "23.42.", "23.43.", "23.44.", "23.45.", "23.46.", "23.47.",
	"23.48.", "23.49.", "23.50.", "23.51.", "23.52.", "23.53.", "23.54.", "23.55.",
	"23.56.", "23.57.", "23.58.", "23.59.", "23.60.", "23.61.", "23.62.", "23.63.",
	// AWS CloudFront (partial)
	"13.32.", "13.33.", "13.35.", "13.224.", "13.225.", "13.226.", "13.227.",
	"52.84.", "52.85.", "54.182.", "54.192.", "54.230.", "54.239.", "54.240.",
	"99.84.", "99.86.",
	// Google Cloud CDN / GFE
	"34.96.", "34.97.", "34.98.", "34.102.", "34.107.", "34.110.", "34.111.",
	"35.186.", "35.190.", "35.191.",
}

// isKnownCDN checks if an IP belongs to a known CDN provider
func isKnownCDN(ip string) bool {
	for _, prefix := range cdnPrefixes {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}
