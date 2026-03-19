package lib

import (
	"fmt"
	"slices"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

// CapabilityName is the registered name for the Pius discovery capability.
const CapabilityName = "pius-discovery"

// pluginNames lists all available Pius plugins for the UI select-box.
// Plugins marked "pending" are in-flight PRs (LAB-*) and will be picked up
// automatically once they register via init().
var pluginNames = []string{
	// Domain plugins (passive)
	"crt-sh", "apollo", "github-org", "gleif", "passive-dns", "reverse-whois",
	"urlscan",        // LAB-1339
	"wayback",        // LAB-1341
	"wikidata",       // LAB-1346
	"google-dorks",   // LAB-1352
	"reverse-ip",     // LAB-1337 (pending)
	"otx-alienvault", // LAB-1340 (pending)
	// Domain plugins (active)
	"dns-brute", "dns-zone-transfer", "doh-enum", "dns-permutation", "favicon-hash",
	// CIDR plugins
	"asn-bgp", "whois", "edgar",
	"arin", "ripe", "lacnic", "apnic", "afrinic",
	// API-key plugins (ENG-1908)
	"shodan", "dnsdb", "crunchbase", "opencorporates",
	"proxycurl", "diffbot", "securitytrails", "virustotal",
	"binaryedge", "censys", "viewdns",
}

// piusParams returns the shared parameter list for both capability variants.
func piusParams(defaultMode string) []capability.Parameter {
	return []capability.Parameter{
		capability.String("mode", "Plugin mode filter: passive, active, or all").
			WithDefault(defaultMode).
			WithOptions("passive", "active", "all"),
		capability.String("plugins", "Comma-separated plugin whitelist (empty = all applicable)").
			WithOptions(pluginNames...),
		capability.String("disable", "Comma-separated plugin blacklist"),
		capability.Int("concurrency", "Max concurrent plugins").
			WithDefault("5"),

		// API key parameters for active plugins.
		// Injected via job.Config from Guard4 integration credentials.
		capability.String("shodan_api_key", "Shodan API key"),
		capability.String("dnsdb_api_key", "DNSDB API key"),
		capability.String("crunchbase_api_key", "Crunchbase API key"),
		capability.String("opencorporates_api_key", "OpenCorporates API key"),
		capability.String("proxycurl_api_key", "Proxycurl API key"),
		capability.String("diffbot_api_key", "Diffbot API key"),
		capability.String("securitytrails_api_key", "SecurityTrails API key"),
		capability.String("virustotal_api_key", "VirusTotal API key"),
		capability.String("binaryedge_api_key", "BinaryEdge API key"),
		capability.String("apollo_api_key", "Apollo.io API key"),
		capability.String("censys_api_key", "Censys API key"),
		capability.String("censys_org_id", "Censys organization ID"),
		capability.String("viewdns_api_key", "ViewDNS API key"),

		// --- Per-plugin configuration ---

		// doh-enum parameters
		capability.String("doh_servers", "Comma-separated DoH resolver URLs (default: Cloudflare, Google, AdGuard)"),
		capability.String("doh_gateways", "Comma-separated pre-deployed gateway URLs for DoH enumeration"),
		capability.String("doh_deploy_gateways", "Deploy AWS API Gateways as DoH proxies (true/false)"),

		// dns-brute parameters
		capability.Int("dns_brute_concurrency", "Max concurrent DNS queries for dns-brute (default: 50)"),

		// google-dorks parameters
		capability.Int("google_dorks_max_subsidiaries", "Max subsidiaries to resolve via Google dorks (default: 30)"),

		// github-org parameters (token bridged via integration credentials)
		capability.String("github_token", "GitHub personal access token for improved rate limits"),
	}
}

// --- Preseed variant (org-based discovery) ---

var _ capability.Capability[capmodel.Preseed] = (*Discovery)(nil)

// Discovery implements capability.Capability[capmodel.Preseed] for organizational
// asset discovery using the Pius pipeline.
type Discovery struct{}

var matchedPreseedTypes = []string{
	"whois+company",
	"whois+name",
	"edgar+company",
}

func (d *Discovery) Name() string        { return CapabilityName }
func (d *Discovery) Description() string {
	return "discovers domains and CIDRs for an organization using Pius multi-plugin pipeline"
}
func (d *Discovery) Input() any          { return capmodel.Preseed{} }
func (d *Discovery) Parameters() []capability.Parameter { return piusParams("passive") }

func (d *Discovery) Match(_ capability.ExecutionContext, input capmodel.Preseed) error {
	if !slices.Contains(matchedPreseedTypes, input.Type) {
		return fmt.Errorf("%s: unsupported preseed type %q, want one of %v", CapabilityName, input.Type, matchedPreseedTypes)
	}
	if input.Value == "" {
		return fmt.Errorf("%s: empty preseed value", CapabilityName)
	}
	return nil
}

// --- Domain variant (domain-based discovery including active plugins) ---

var _ capability.Capability[capmodel.Domain] = (*DomainDiscovery)(nil)

// DomainDiscovery implements capability.Capability[capmodel.Domain] for running
// Pius plugins that accept a domain as input, including active plugins
// (dns-brute, dns-zone-transfer) and passive domain plugins (crt-sh, passive-dns).
// It registers under the SAME name "pius-discovery" as the preseed variant.
type DomainDiscovery struct{}

func (d *DomainDiscovery) Name() string        { return CapabilityName }
func (d *DomainDiscovery) Description() string {
	return "discovers domains and CIDRs for an organization using Pius multi-plugin pipeline"
}
func (d *DomainDiscovery) Input() any          { return capmodel.Domain{} }
func (d *DomainDiscovery) Parameters() []capability.Parameter { return piusParams("all") }

func (d *DomainDiscovery) Match(_ capability.ExecutionContext, input capmodel.Domain) error {
	if input.Domain == "" {
		return fmt.Errorf("%s: empty domain", CapabilityName)
	}
	return nil
}
