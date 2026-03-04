package cidrs_test

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	_ "github.com/praetorian-inc/pius/pkg/plugins/all"
	"github.com/stretchr/testify/assert"
)

// ── whois ──────────────────────────────────────────────────────────────────

func TestWhoisPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("whois")
	if !ok {
		t.Skip("whois plugin not registered")
	}
	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.False(t, p.Accepts(plugins.Input{OrgName: ""}))
	assert.False(t, p.Accepts(plugins.Input{}))
}

func TestWhoisPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("whois")
	if !ok {
		t.Skip("whois plugin not registered")
	}
	assert.Equal(t, "whois", p.Name())
	assert.Equal(t, 1, p.Phase())
	assert.Equal(t, "cidr", p.Category())
	assert.NotEmpty(t, p.Description())
}

// ── ripe ───────────────────────────────────────────────────────────────────

func TestRIPEPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("ripe")
	if !ok {
		t.Skip("ripe plugin not registered")
	}
	assert.True(t, p.Accepts(plugins.Input{
		OrgName: "Acme",
		Meta:    map[string]string{"ripe_handles": "RIPE-123"},
	}))
	assert.False(t, p.Accepts(plugins.Input{
		OrgName: "Acme",
		Meta:    map[string]string{},
	}))
	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme", Meta: nil}))
}

func TestRIPEPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("ripe")
	if !ok {
		t.Skip("ripe plugin not registered")
	}
	assert.Equal(t, "ripe", p.Name())
	assert.Equal(t, 2, p.Phase())
	assert.Equal(t, "cidr", p.Category())
}

// ── apnic ──────────────────────────────────────────────────────────────────

func TestAPNICPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("apnic")
	if !ok {
		t.Skip("apnic plugin not registered")
	}
	assert.True(t, p.Accepts(plugins.Input{
		OrgName: "Acme",
		Meta:    map[string]string{"apnic_handles": "APNIC-1"},
	}))
	assert.False(t, p.Accepts(plugins.Input{
		OrgName: "Acme",
		Meta:    map[string]string{},
	}))
}

func TestAPNICPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("apnic")
	if !ok {
		t.Skip("apnic plugin not registered")
	}
	assert.Equal(t, "apnic", p.Name())
	assert.Equal(t, 2, p.Phase())
	assert.Equal(t, "cidr", p.Category())
}

// ── afrinic ────────────────────────────────────────────────────────────────

func TestAFRINICPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("afrinic")
	if !ok {
		t.Skip("afrinic plugin not registered")
	}
	assert.True(t, p.Accepts(plugins.Input{
		OrgName: "Acme",
		Meta:    map[string]string{"afrinic_handles": "AFRINIC-1"},
	}))
	assert.False(t, p.Accepts(plugins.Input{
		OrgName: "Acme",
		Meta:    map[string]string{},
	}))
}

func TestAFRINICPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("afrinic")
	if !ok {
		t.Skip("afrinic plugin not registered")
	}
	assert.Equal(t, "afrinic", p.Name())
	assert.Equal(t, 2, p.Phase())
	assert.Equal(t, "cidr", p.Category())
}

// ── edgar ──────────────────────────────────────────────────────────────────

func TestEdgarPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("edgar")
	if !ok {
		t.Skip("edgar plugin not registered")
	}
	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.False(t, p.Accepts(plugins.Input{OrgName: ""}))
}

func TestEdgarPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("edgar")
	if !ok {
		t.Skip("edgar plugin not registered")
	}
	assert.Equal(t, "edgar", p.Name())
	assert.Equal(t, 1, p.Phase())
	assert.Equal(t, "cidr", p.Category())
}

// ── asn-bgp ────────────────────────────────────────────────────────────────

func TestAsnBgpPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("asn-bgp")
	if !ok {
		t.Skip("asn-bgp plugin not registered")
	}
	// Accepts when ASN is provided
	assert.True(t, p.Accepts(plugins.Input{ASN: "AS12345"}))
	// Rejects when ASN is empty
	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme", ASN: ""}))
}

func TestAsnBgpPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("asn-bgp")
	if !ok {
		t.Skip("asn-bgp plugin not registered")
	}
	assert.Equal(t, "asn-bgp", p.Name())
	assert.Equal(t, 0, p.Phase()) // Independent plugin
	assert.Equal(t, "cidr", p.Category())
}
