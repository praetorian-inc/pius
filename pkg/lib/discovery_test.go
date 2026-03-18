package lib

import (
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscovery_Name(t *testing.T) {
	d := &Discovery{}
	assert.Equal(t, "pius-discovery", d.Name())
}

func TestDiscovery_Description(t *testing.T) {
	d := &Discovery{}
	assert.NotEmpty(t, d.Description())
}

func TestDiscovery_Input(t *testing.T) {
	d := &Discovery{}
	assert.IsType(t, capmodel.Preseed{}, d.Input())
}

func TestDiscovery_Parameters(t *testing.T) {
	d := &Discovery{}
	params := d.Parameters()
	// 4 base + 12 API key + 6 plugin config parameters = 22 total
	assert.Len(t, params, 22)

	names := make([]string, len(params))
	for i, p := range params {
		names[i] = p.Name
	}
	assert.Contains(t, names, "mode")
	assert.Contains(t, names, "plugins")
	assert.Contains(t, names, "disable")
	assert.Contains(t, names, "concurrency")

	// Verify all 12 API key parameters
	apiKeys := []string{
		"shodan_api_key", "dnsdb_api_key", "crunchbase_api_key",
		"opencorporates_api_key", "proxycurl_api_key", "diffbot_api_key",
		"securitytrails_api_key", "virustotal_api_key", "binaryedge_api_key",
		"apollo_api_key", "censys_api_key", "viewdns_api_key",
	}
	for _, key := range apiKeys {
		assert.Contains(t, names, key)
	}
}

func TestDiscovery_Match_WhoisCompany(t *testing.T) {
	d := &Discovery{}
	err := d.Match(capability.ExecutionContext{}, capmodel.Preseed{
		Type:  "whois+company",
		Title: "Acme Corp",
		Value: "Acme Corp",
	})
	require.NoError(t, err)
}

func TestDiscovery_Match_WhoisName(t *testing.T) {
	d := &Discovery{}
	err := d.Match(capability.ExecutionContext{}, capmodel.Preseed{
		Type:  "whois+name",
		Title: "Acme Corp",
		Value: "Acme Corp",
	})
	require.NoError(t, err)
}

func TestDiscovery_Match_EdgarCompany(t *testing.T) {
	d := &Discovery{}
	err := d.Match(capability.ExecutionContext{}, capmodel.Preseed{
		Type:  "edgar+company",
		Title: "Acme Corp",
		Value: "Acme Corp",
	})
	require.NoError(t, err)
}

func TestDiscovery_Match_UnsupportedType(t *testing.T) {
	d := &Discovery{}
	err := d.Match(capability.ExecutionContext{}, capmodel.Preseed{
		Type:  "cidr-handle",
		Title: "ORG@RIPE",
		Value: "ORG@RIPE",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported preseed type")
}

func TestDiscovery_Match_EmptyValue(t *testing.T) {
	d := &Discovery{}
	err := d.Match(capability.ExecutionContext{}, capmodel.Preseed{
		Type:  "whois+company",
		Title: "Acme Corp",
		Value: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty preseed value")
}

func TestDiscovery_CompileTimeInterfaceCheck(t *testing.T) {
	// This test verifies the compile-time interface check
	var _ capability.Capability[capmodel.Preseed] = (*Discovery)(nil)
}

// --- DomainDiscovery tests ---

func TestDomainDiscovery_Name(t *testing.T) {
	d := &DomainDiscovery{}
	assert.Equal(t, "pius-discovery", d.Name(), "both variants share the same capability name")
}

func TestDomainDiscovery_Description(t *testing.T) {
	d := &DomainDiscovery{}
	assert.NotEmpty(t, d.Description())
}

func TestDomainDiscovery_Input(t *testing.T) {
	d := &DomainDiscovery{}
	assert.IsType(t, capmodel.Domain{}, d.Input())
}

func TestDomainDiscovery_Parameters(t *testing.T) {
	d := &DomainDiscovery{}
	params := d.Parameters()
	// 4 base + 12 API key + 6 plugin config parameters = 22 total
	assert.Len(t, params, 22)

	// Verify default mode is "all" (not "passive" like preseed variant)
	for _, p := range params {
		if p.Name == "mode" {
			assert.Equal(t, "all", p.Default, "domain variant defaults to 'all' to include active plugins")
		}
	}
}

func TestDomainDiscovery_Parameters_DefaultModeDiffersFromPreseed(t *testing.T) {
	preseed := &Discovery{}
	domain := &DomainDiscovery{}

	var preseedDefault, domainDefault string
	for _, p := range preseed.Parameters() {
		if p.Name == "mode" {
			preseedDefault = p.Default
		}
	}
	for _, p := range domain.Parameters() {
		if p.Name == "mode" {
			domainDefault = p.Default
		}
	}

	assert.Equal(t, "passive", preseedDefault, "preseed variant defaults to passive")
	assert.Equal(t, "all", domainDefault, "domain variant defaults to all")
}

func TestDomainDiscovery_Match_ValidDomain(t *testing.T) {
	d := &DomainDiscovery{}
	err := d.Match(capability.ExecutionContext{}, capmodel.Domain{
		Domain: "example.com",
	})
	require.NoError(t, err)
}

func TestDomainDiscovery_Match_EmptyDomain(t *testing.T) {
	d := &DomainDiscovery{}
	err := d.Match(capability.ExecutionContext{}, capmodel.Domain{
		Domain: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty domain")
}

func TestDomainDiscovery_CompileTimeInterfaceCheck(t *testing.T) {
	var _ capability.Capability[capmodel.Domain] = (*DomainDiscovery)(nil)
}

func TestBothVariants_ShareSameName(t *testing.T) {
	preseed := &Discovery{}
	domain := &DomainDiscovery{}
	assert.Equal(t, preseed.Name(), domain.Name(), "both must register under the same capability name")
}

func TestDiscovery_Parameters_PluginCount(t *testing.T) {
	d := &Discovery{}
	params := d.Parameters()

	var pluginParam capability.Parameter
	for _, p := range params {
		if p.Name == "plugins" {
			pluginParam = p
			break
		}
	}

	assert.Len(t, pluginParam.Options, len(pluginNames),
		"Discovery plugins param options count must match pluginNames slice (currently %d); update this test when adding new plugins", len(pluginNames))
}

func TestDomainDiscovery_Parameters_PluginCount(t *testing.T) {
	d := &DomainDiscovery{}
	params := d.Parameters()

	var pluginParam capability.Parameter
	for _, p := range params {
		if p.Name == "plugins" {
			pluginParam = p
			break
		}
	}

	assert.Len(t, pluginParam.Options, len(pluginNames),
		"DomainDiscovery plugins param options count must match pluginNames slice (currently %d); update this test when adding new plugins", len(pluginNames))
}

func TestDomainDiscovery_Parameters_SharesSamePluginOptions(t *testing.T) {
	preseed := &Discovery{}
	domain := &DomainDiscovery{}

	var preseedOptions, domainOptions []string
	for _, p := range preseed.Parameters() {
		if p.Name == "plugins" {
			preseedOptions = p.Options
		}
	}
	for _, p := range domain.Parameters() {
		if p.Name == "plugins" {
			domainOptions = p.Options
		}
	}

	assert.ElementsMatch(t, preseedOptions, domainOptions,
		"both capability variants must expose identical plugin options since they share piusParams")
}

func TestBothVariants_PluginSelectBox(t *testing.T) {
	d := &Discovery{}
	params := d.Parameters()

	var pluginParam capability.Parameter
	for _, p := range params {
		if p.Name == "plugins" {
			pluginParam = p
			break
		}
	}

	require.NotEmpty(t, pluginParam.Options, "plugins parameter must have options for UI select-box")
	assert.Contains(t, pluginParam.Options, "crt-sh")
	assert.Contains(t, pluginParam.Options, "arin")
	assert.Contains(t, pluginParam.Options, "ripe")
	assert.Contains(t, pluginParam.Options, "lacnic", "LACNIC must be available (improvement over deprecated collect_cidr)")
	assert.Contains(t, pluginParam.Options, "apnic")
	assert.Contains(t, pluginParam.Options, "afrinic")
	assert.Contains(t, pluginParam.Options, "dns-brute")
	assert.Contains(t, pluginParam.Options, "dns-zone-transfer")
	// Upcoming plugins (LAB-* PRs)
	assert.Contains(t, pluginParam.Options, "urlscan")
	assert.Contains(t, pluginParam.Options, "wayback")
	assert.Contains(t, pluginParam.Options, "wikidata")
	assert.Contains(t, pluginParam.Options, "google-dorks")
	assert.Contains(t, pluginParam.Options, "reverse-ip")
	assert.Contains(t, pluginParam.Options, "otx-alienvault")
}
