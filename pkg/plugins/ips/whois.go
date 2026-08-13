package ips

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

const confIPWhoisContact = 85

type networkPreseedCandidate struct {
	field string
	role  string
	value string
}

func init() {
	plugins.Register("ip-whois", func() plugins.Plugin { return &WhoisPlugin{} })
}

type WhoisPlugin struct {
	HTTPClient *http.Client
	lookup     func(context.Context, string, ...whois.Option) (whois.NetworkResult, error)
}

func NewWhoisPlugin(httpClient *http.Client) *WhoisPlugin {
	return &WhoisPlugin{HTTPClient: httpClient}
}

func (p *WhoisPlugin) Name() string        { return "ip-whois" }
func (p *WhoisPlugin) Description() string { return "IP and CIDR WHOIS via RDAP and TCP 43" }
func (p *WhoisPlugin) Category() string    { return "ip" }
func (p *WhoisPlugin) Phase() int          { return 0 }
func (p *WhoisPlugin) Mode() string        { return plugins.ModePassive }

func (p *WhoisPlugin) Accepts(input plugins.Input) bool {
	target, ok := networkTarget(input)
	return ok && whois.ValidateNetworkTarget(target) == nil
}

func (p *WhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	target, ok := networkTarget(input)
	if !ok {
		return nil, fmt.Errorf("ip-whois: expected exactly one IP or CIDR")
	}

	lookup := p.lookup
	if lookup == nil {
		lookup = whois.LookupNetwork
	}
	var options []whois.Option
	if p.HTTPClient != nil {
		options = append(options, whois.WithHTTPClient(p.HTTPClient))
	}
	result, err := lookup(ctx, target, options...)
	if err != nil {
		return nil, err
	}

	findings := []plugins.Finding{networkResultFinding(result)}
	findings = append(findings, networkPreseeds(result)...)
	return findings, nil
}

func networkTarget(input plugins.Input) (string, bool) {
	if (input.IP == "") == (input.CIDR == "") {
		return "", false
	}
	if input.IP != "" {
		return input.IP, true
	}
	return input.CIDR, true
}

func networkResultFinding(result whois.NetworkResult) plugins.Finding {
	return plugins.Finding{
		Type:   plugins.FindingIPWhoisResult,
		Value:  result.Query,
		Source: "ip-whois",
		Data:   plugins.FindingData(result),
	}
}

func networkPreseeds(result whois.NetworkResult) []plugins.Finding {
	candidates := networkPreseedCandidates(result.Contacts, preferredNetworkRole(result.Contacts))
	candidates = strutil.UniqueFunc(candidates, func(candidate networkPreseedCandidate) [2]string {
		return [2]string{candidate.field, strings.ToLower(candidate.value)}
	})

	findings := make([]plugins.Finding, 0, len(candidates))
	for _, candidate := range candidates {
		findings = append(findings, networkPreseedFinding(result, candidate))
	}
	return findings
}

func preferredNetworkRole(contacts []whois.NetworkContact) string {
	return whois.PreferredNetworkRole(contacts)
}

func networkPreseedCandidates(contacts []whois.NetworkContact, preferredRole string) []networkPreseedCandidate {
	var candidates []networkPreseedCandidate
	for _, contact := range contacts {
		if !eligibleNetworkContact(contact, preferredRole) {
			continue
		}
		candidates = append(candidates, contactPreseedCandidates(contact)...)
	}
	return candidates
}

func eligibleNetworkContact(contact whois.NetworkContact, preferredRole string) bool {
	return contact.Direct && contact.HasRole(preferredRole) && !contact.IsMaintainer()
}

func contactPreseedCandidates(contact whois.NetworkContact) []networkPreseedCandidate {
	roles := slices.Clone(contact.Roles)
	slices.Sort(roles)
	role := strings.Join(roles, ",")
	possible := []networkPreseedCandidate{
		contactIdentityCandidate(contact, role),
		{field: "email", role: role, value: contact.Email},
	}
	candidates := make([]networkPreseedCandidate, 0, len(possible))
	for _, candidate := range possible {
		candidate.value = strings.TrimSpace(candidate.value)
		if validNetworkPreseedCandidate(candidate) {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func validNetworkPreseedCandidate(candidate networkPreseedCandidate) bool {
	if candidate.value == "" || whois.IsPrivacy(candidate.value) {
		return false
	}
	return candidate.field != "email" || whois.IsEmail(candidate.value)
}

func contactIdentityCandidate(contact whois.NetworkContact, role string) networkPreseedCandidate {
	switch contact.Kind {
	case "org":
		return networkPreseedCandidate{field: "company", role: role, value: cmp.Or(contact.Organization, contact.Name)}
	case "individual":
		return networkPreseedCandidate{field: "name", role: role, value: contact.Name}
	default:
		if contact.Organization != "" {
			return networkPreseedCandidate{field: "company", role: role, value: contact.Organization}
		}
		return networkPreseedCandidate{}
	}
}

func networkPreseedFinding(result whois.NetworkResult, candidate networkPreseedCandidate) plugins.Finding {
	finding := plugins.Finding{
		Type:   plugins.FindingPreseed,
		Value:  candidate.value,
		Source: "ip-whois",
		Data: map[string]any{
			"preseed_type":     "whois+" + candidate.field,
			"preseed_title":    candidate.value,
			"roles":            candidate.role,
			"query":            result.Query,
			"network_handle":   result.Handle,
			"allocation_start": result.StartAddress,
			"allocation_end":   result.EndAddress,
			"registry":         result.Registry,
			"server":           result.Server,
			"rdap_server":      result.RDAPServer,
			"whois_server":     result.WhoisServer,
			"sources":          result.Sources,
		},
	}
	plugins.AddConfidence(&finding, confIPWhoisContact, networkPreseedJustification(result, candidate))
	return finding
}

func networkPreseedJustification(result whois.NetworkResult, candidate networkPreseedCandidate) string {
	source := networkResultSource(result)

	return fmt.Sprintf(
		"%s records %q as the %s contact %s for allocation %q spanning %s-%s, returned for query %q",
		source, candidate.value, candidate.role, candidate.field, result.Handle,
		result.StartAddress, result.EndAddress, result.Query,
	)
}

func networkResultSource(result whois.NetworkResult) string {
	var sources []string
	if slices.Contains(result.Sources, "rdap") {
		sources = append(sources, protocolServer("IP RDAP", cmp.Or(result.RDAPServer, result.Server)))
	}
	if slices.Contains(result.Sources, "whois") {
		sources = append(sources, protocolServer("IP WHOIS", cmp.Or(result.WhoisServer, result.Server)))
	}
	if len(sources) == 0 {
		return "IP registry"
	}
	return strings.Join(sources, " and ")
}

func protocolServer(protocol, server string) string {
	if server == "" {
		return protocol
	}
	return fmt.Sprintf("%s server %q", protocol, server)
}
