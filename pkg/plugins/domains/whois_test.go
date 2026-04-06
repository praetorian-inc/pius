package domains_test

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	_ "github.com/praetorian-inc/pius/pkg/plugins/all"
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
