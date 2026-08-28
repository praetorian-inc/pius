package domains_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	_ "github.com/praetorian-inc/pius/pkg/plugins/all"
	"github.com/praetorian-inc/pius/pkg/plugins/domains"
	"github.com/praetorian-inc/pius/pkg/whois"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhoisHistoryPlugin_Metadata(t *testing.T) {
	plugin, ok := plugins.Get("whois-domain-history")
	require.True(t, ok)

	assert.Equal(t, "whois-domain-history", plugin.Name())
	assert.Equal(t, "domain", plugin.Category())
	assert.Equal(t, 0, plugin.Phase())
	assert.Equal(t, plugins.ModePassive, plugin.Mode())
	assert.NotEmpty(t, plugin.Description())
	assert.True(t, plugin.Accepts(plugins.Input{Domain: "example.com"}))
	assert.False(t, plugin.Accepts(plugins.Input{}))
}

func TestWhoisHistoryPlugin_Run(t *testing.T) {
	whoxy := &pluginHistoryClient{
		name: whois.ProviderWhoxy,
		records: []whois.DomainHistoryRecord{{
			DomainResult: whois.DomainResult{
				Domain:    "example.com",
				Registrar: "Example Registrar",
				Sources:   []string{whois.ProviderWhoxy},
			},
			QueryTime: "2026-08-01 00:00:00",
		}},
	}
	whoisFreaks := &pluginHistoryClient{name: whois.ProviderWhoisFreaks}
	plugin := newHistoryPlugin(whoxy, whoisFreaks, &pluginHistoryClient{name: whois.ProviderWhoisXML})

	findings, err := plugin.Run(context.Background(), plugins.Input{Domain: "www.example.com"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, plugins.FindingWhoisHistory, findings[0].Type)
	assert.Equal(t, "example.com", findings[0].Value)
	assert.Equal(t, "whois-domain-history", findings[0].Source)
	assert.Equal(t, 1, whoxy.calls)
	assert.Zero(t, whoisFreaks.calls)

	data := decodeWhoisHistoryFinding(t, findings[0])
	require.Len(t, data.Records, 1)
	assert.Equal(t, "Example Registrar", data.Records[0].Registrar)
	assert.Equal(t, "2026-08-01 00:00:00", data.Records[0].QueryTime)
}

func TestWhoisHistoryPlugin_RunEmitsEmptyFinding(t *testing.T) {
	plugin := newHistoryPlugin(
		&pluginHistoryClient{name: whois.ProviderWhoxy},
		&pluginHistoryClient{name: whois.ProviderWhoisFreaks},
		&pluginHistoryClient{name: whois.ProviderWhoisXML},
	)

	findings, err := plugin.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Empty(t, decodeWhoisHistoryFinding(t, findings[0]).Records)
}

func TestWhoisHistoryPlugin_RunReturnsProviderFailure(t *testing.T) {
	lookupErr := errors.New("provider unavailable")
	plugin := newHistoryPlugin(
		&pluginHistoryClient{name: whois.ProviderWhoxy, err: lookupErr},
		&pluginHistoryClient{name: whois.ProviderWhoisFreaks, err: lookupErr},
		&pluginHistoryClient{name: whois.ProviderWhoisXML, err: lookupErr},
	)

	findings, err := plugin.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.Error(t, err)
	assert.ErrorIs(t, err, lookupErr)
	assert.Nil(t, findings)
}

func TestWhoisHistoryPlugin_RunRejectsInvalidDomain(t *testing.T) {
	plugin := newHistoryPlugin(
		&pluginHistoryClient{name: whois.ProviderWhoxy},
		&pluginHistoryClient{name: whois.ProviderWhoisFreaks},
		&pluginHistoryClient{name: whois.ProviderWhoisXML},
	)

	_, err := plugin.Run(context.Background(), plugins.Input{Domain: "127.0.0.1"})

	assert.ErrorContains(t, err, "no registrable domain")
}

func newHistoryPlugin(clients ...*pluginHistoryClient) *domains.WhoisHistoryPlugin {
	return domains.NewWhoisHistoryPlugin(nil, func(client *whois.WHOIS) {
		client.WhoxyClient = clients[0]
		client.WhoisFreaksClient = clients[1]
		client.WhoisXMLClient = clients[2]
	})
}

func decodeWhoisHistoryFinding(t *testing.T, finding plugins.Finding) domains.WhoisHistoryFindingData {
	t.Helper()
	encoded, err := json.Marshal(finding.Data)
	require.NoError(t, err)

	var data domains.WhoisHistoryFindingData
	require.NoError(t, json.Unmarshal(encoded, &data))
	return data
}

type pluginHistoryClient struct {
	name    string
	records []whois.DomainHistoryRecord
	err     error
	calls   int
}

func (c *pluginHistoryClient) Name() string { return c.name }

func (c *pluginHistoryClient) LookupDomain(context.Context, string) (whois.DomainResult, error) {
	return whois.DomainResult{}, whois.ErrNoCredential
}

func (c *pluginHistoryClient) LookupDomainHistory(context.Context, string) ([]whois.DomainHistoryRecord, error) {
	c.calls++
	return c.records, c.err
}
