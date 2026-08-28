package domains_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	_ "github.com/praetorian-inc/pius/pkg/plugins/all"
	"github.com/praetorian-inc/pius/pkg/plugins/domains"
	"github.com/praetorian-inc/pius/pkg/whois"
	"github.com/stretchr/testify/assert"
)

func TestWhoisPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("whois")
	if !ok {
		t.Skip("whois plugin not registered")
	}
	assert.True(t, p.Accepts(plugins.Input{Domain: "example.com"}))
	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.False(t, p.Accepts(plugins.Input{}))
}

func TestNewWhoisPlugin_ExplicitHTTPOptionOverridesConstructorClient(t *testing.T) {
	constructorTransport := &countingTransport{}
	optionTransport := &countingTransport{}
	constructorClient := &http.Client{Transport: constructorTransport}
	optionClient := &http.Client{Transport: optionTransport}
	unavailable := &unavailableWhoisClient{}

	plugin := domains.NewWhoisPlugin(
		constructorClient,
		whois.WithHTTPClient(optionClient),
		whois.WithWhoxyAPIKey("test-key"),
		func(w *whois.WHOIS) {
			w.RDAPClient = unavailable
			w.TCP43Client = unavailable
			w.WhoisFreaksClient = unavailable
			w.WhoisXMLClient = unavailable
		},
	)

	_, _ = plugin.Run(context.Background(), plugins.Input{Domain: "example.com"})

	assert.Zero(t, constructorTransport.calls)
	assert.Equal(t, 1, optionTransport.calls)
}

func TestWhoisPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("whois")
	if !ok {
		t.Skip("whois plugin not registered")
	}
	assert.Equal(t, "whois", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, plugins.ModePassive, p.Mode())
	assert.NotEmpty(t, p.Description())
}

type countingTransport struct {
	calls int
}

func (t *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, errors.New("request blocked by test")
}

type unavailableWhoisClient struct{}

func (*unavailableWhoisClient) Name() string { return "unavailable" }

func (*unavailableWhoisClient) LookupDomain(context.Context, string) (whois.DomainResult, error) {
	return whois.DomainResult{}, whois.ErrNoCredential
}

func (*unavailableWhoisClient) LookupNetwork(context.Context, string) (whois.NetworkResult, error) {
	return whois.NetworkResult{}, whois.ErrNoCredential
}
