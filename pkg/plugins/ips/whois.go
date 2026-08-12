package ips

import (
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
	type candidate struct {
		field string
		role  string
		value string
	}

	var candidates []candidate
	for _, contact := range result.Contacts {
		roles := slices.Clone(contact.Roles)
		slices.Sort(roles)
		role := strings.Join(roles, ",")
		for _, item := range []candidate{
			{field: "company", role: role, value: contact.Organization},
			{field: "name", role: role, value: contact.Name},
			{field: "email", role: role, value: contact.Email},
		} {
			item.value = strings.TrimSpace(item.value)
			if item.value == "" || whois.IsPrivacy(item.value) {
				continue
			}
			if item.field == "email" && !whois.IsEmail(item.value) {
				continue
			}
			candidates = append(candidates, item)
		}
	}

	unique := strutil.UniqueFunc(candidates, func(candidate candidate) [2]string {
		return [2]string{candidate.field, strings.ToLower(candidate.value)}
	})

	findings := make([]plugins.Finding, 0, len(unique))
	for _, candidate := range unique {
		finding := plugins.Finding{
			Type:   plugins.FindingPreseed,
			Value:  candidate.value,
			Source: "ip-whois",
			Data: map[string]any{
				"preseed_type":   "whois+" + candidate.field,
				"preseed_title":  candidate.value,
				"roles":          candidate.role,
				"network_handle": result.Handle,
				"registry":       result.Registry,
			},
		}
		plugins.AddConfidence(&finding, confIPWhoisContact, fmt.Sprintf(
			"IP registry records %q as the %s contact %s for allocation %q",
			candidate.value, candidate.role, candidate.field, result.Handle))
		findings = append(findings, finding)
	}
	return findings
}
