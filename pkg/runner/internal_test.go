package runner

import (
	"context"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── enrichWithHandles ─────────────────────────────────────────────────────────

func TestEnrichWithHandles_SingleRegistry(t *testing.T) {
	input := plugins.Input{OrgName: "Acme", Meta: make(map[string]string)}
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDRHandle, Value: "ACME-1", Source: "reverse-rir",
			Data: map[string]any{"registry": "arin"}},
		{Type: plugins.FindingCIDRHandle, Value: "ACME-2", Source: "reverse-rir",
			Data: map[string]any{"registry": "arin"}},
	}
	result := enrichWithHandles(input, findings)
	assert.Equal(t, "ACME-1,ACME-2", result.Meta["arin_handles"])
	assert.Empty(t, result.Meta["ripe_handles"])
	assert.Empty(t, result.Meta["apnic_handles"])
	assert.Empty(t, result.Meta["afrinic_handles"])
}

func TestEnrichWithHandles_MultipleRegistries(t *testing.T) {
	input := plugins.Input{OrgName: "Acme", Meta: make(map[string]string)}
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDRHandle, Value: "ACME-ARIN", Source: "reverse-rir",
			Data: map[string]any{"registry": "arin"}},
		{Type: plugins.FindingCIDRHandle, Value: "ORG-RIPE", Source: "reverse-rir",
			Data: map[string]any{"registry": "ripe"}},
		{Type: plugins.FindingCIDRHandle, Value: "APNIC-1", Source: "reverse-rir",
			Data: map[string]any{"registry": "apnic"}},
	}
	result := enrichWithHandles(input, findings)
	assert.Equal(t, "ACME-ARIN", result.Meta["arin_handles"])
	assert.Equal(t, "ORG-RIPE", result.Meta["ripe_handles"])
	assert.Equal(t, "APNIC-1", result.Meta["apnic_handles"])
	assert.Empty(t, result.Meta["afrinic_handles"])
}

func TestEnrichWithHandles_UnknownRegistryBroadcastsToAll(t *testing.T) {
	// Tests Phase 11 fix: a FindingCIDRHandle with no/empty registry key
	// must be broadcast to ALL FOUR RIRs (arin, ripe, apnic, afrinic).
	input := plugins.Input{OrgName: "Acme", Meta: make(map[string]string)}
	findings := []plugins.Finding{
		{
			Type:   plugins.FindingCIDRHandle,
			Value:  "UNKNOWN-HANDLE",
			Source: "edgar",
			Data:   map[string]any{}, // no "registry" key → unknown
		},
	}
	result := enrichWithHandles(input, findings)
	assert.Equal(t, "UNKNOWN-HANDLE", result.Meta["arin_handles"])
	assert.Equal(t, "UNKNOWN-HANDLE", result.Meta["ripe_handles"])
	assert.Equal(t, "UNKNOWN-HANDLE", result.Meta["apnic_handles"])
	assert.Equal(t, "UNKNOWN-HANDLE", result.Meta["afrinic_handles"])
}

func TestEnrichWithHandles_PreservesExistingMeta(t *testing.T) {
	input := plugins.Input{
		OrgName: "Acme",
		Meta:    map[string]string{"arin_handles": "EXISTING-1"},
	}
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDRHandle, Value: "NEW-1", Source: "reverse-rir",
			Data: map[string]any{"registry": "arin"}},
	}
	result := enrichWithHandles(input, findings)
	// Must contain both the pre-existing and new handle
	assert.Contains(t, result.Meta["arin_handles"], "EXISTING-1")
	assert.Contains(t, result.Meta["arin_handles"], "NEW-1")
}

func TestEnrichWithHandles_IgnoresNonHandleFindings(t *testing.T) {
	input := plugins.Input{OrgName: "Acme", Meta: make(map[string]string)}
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDR, Value: "192.168.1.0/24"},   // ignored
		{Type: plugins.FindingDomain, Value: "example.com"},    // ignored
		{Type: plugins.FindingCIDRHandle, Value: "ACME-1",
			Data: map[string]any{"registry": "arin"}},          // processed
	}
	result := enrichWithHandles(input, findings)
	assert.Equal(t, "ACME-1", result.Meta["arin_handles"])
	// CIDR and Domain values must NOT appear in any Meta key
	for k, v := range result.Meta {
		assert.NotContains(t, v, "192.168.1.0/24", "unexpected CIDR in meta key %s", k)
		assert.NotContains(t, v, "example.com", "unexpected domain in meta key %s", k)
	}
}

// ── filterOutput ─────────────────────────────────────────────────────────────

func TestFilterOutput_RemovesHandleFindings(t *testing.T) {
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDRHandle, Value: "ACME-1"},
		{Type: plugins.FindingCIDR, Value: "192.168.1.0/24"},
		{Type: plugins.FindingDomain, Value: "example.com"},
		{Type: plugins.FindingCIDRHandle, Value: "ACME-2"},
	}
	result := filterOutput(findings)
	require.Len(t, result, 2)
	assert.Equal(t, plugins.FindingCIDR, result[0].Type)
	assert.Equal(t, plugins.FindingDomain, result[1].Type)
}

func TestFilterOutput_EmptySlice(t *testing.T) {
	assert.Empty(t, filterOutput(nil))
	assert.Empty(t, filterOutput([]plugins.Finding{}))
}

func TestFilterOutput_AllHandlesRemoved(t *testing.T) {
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDRHandle, Value: "H1"},
		{Type: plugins.FindingCIDRHandle, Value: "H2"},
	}
	assert.Empty(t, filterOutput(findings))
}

// ── selectPlugins ─────────────────────────────────────────────────────────────

func TestSelectPlugins_WhitelistOnly(t *testing.T) {
	plugins.Reset()
	t.Cleanup(plugins.Reset)
	plugins.Register("p1", func() plugins.Plugin { return &mockPlugin{name: "p1"} })
	plugins.Register("p2", func() plugins.Plugin { return &mockPlugin{name: "p2"} })
	plugins.Register("p3", func() plugins.Plugin { return &mockPlugin{name: "p3"} })

	result := selectPlugins("p1,p2", "", "all")
	names := pluginNames(result)
	assert.ElementsMatch(t, []string{"p1", "p2"}, names)
}

func TestSelectPlugins_BlacklistOnly(t *testing.T) {
	plugins.Reset()
	t.Cleanup(plugins.Reset)
	plugins.Register("p1", func() plugins.Plugin { return &mockPlugin{name: "p1"} })
	plugins.Register("p2", func() plugins.Plugin { return &mockPlugin{name: "p2"} })
	plugins.Register("p3", func() plugins.Plugin { return &mockPlugin{name: "p3"} })

	result := selectPlugins("", "p2", "all")
	names := pluginNames(result)
	assert.ElementsMatch(t, []string{"p1", "p3"}, names)
}

func TestSelectPlugins_WhitelistTakesPrecedenceOverBlacklist(t *testing.T) {
	plugins.Reset()
	t.Cleanup(plugins.Reset)
	plugins.Register("p1", func() plugins.Plugin { return &mockPlugin{name: "p1"} })

	// Even when p1 is also in the blacklist, whitelist wins
	result := selectPlugins("p1", "p1", "all")
	names := pluginNames(result)
	assert.Equal(t, []string{"p1"}, names)
}

func TestSelectPlugins_DefaultReturnsAll(t *testing.T) {
	plugins.Reset()
	t.Cleanup(plugins.Reset)
	plugins.Register("p1", func() plugins.Plugin { return &mockPlugin{name: "p1"} })
	plugins.Register("p2", func() plugins.Plugin { return &mockPlugin{name: "p2"} })
	plugins.Register("p3", func() plugins.Plugin { return &mockPlugin{name: "p3"} })

	result := selectPlugins("", "", "all")
	assert.Len(t, result, 3)
}

func TestSelectPlugins_ModePassiveOnly(t *testing.T) {
	plugins.Reset()
	t.Cleanup(plugins.Reset)
	plugins.Register("p-passive", func() plugins.Plugin {
		return &mockPlugin{name: "p-passive", mode: plugins.ModePassive}
	})
	plugins.Register("p-active", func() plugins.Plugin {
		return &mockPlugin{name: "p-active", mode: plugins.ModeActive}
	})

	result := selectPlugins("", "", "passive")
	names := pluginNames(result)
	assert.ElementsMatch(t, []string{"p-passive"}, names)
}

func TestSelectPlugins_ModeActiveOnly(t *testing.T) {
	plugins.Reset()
	t.Cleanup(plugins.Reset)
	plugins.Register("p-passive", func() plugins.Plugin {
		return &mockPlugin{name: "p-passive", mode: plugins.ModePassive}
	})
	plugins.Register("p-active", func() plugins.Plugin {
		return &mockPlugin{name: "p-active", mode: plugins.ModeActive}
	})

	result := selectPlugins("", "", "active")
	names := pluginNames(result)
	assert.ElementsMatch(t, []string{"p-active"}, names)
}

func TestSelectPlugins_ModeAllReturnsEverything(t *testing.T) {
	plugins.Reset()
	t.Cleanup(plugins.Reset)
	plugins.Register("p-passive", func() plugins.Plugin {
		return &mockPlugin{name: "p-passive", mode: plugins.ModePassive}
	})
	plugins.Register("p-active", func() plugins.Plugin {
		return &mockPlugin{name: "p-active", mode: plugins.ModeActive}
	})

	result := selectPlugins("", "", "all")
	assert.Len(t, result, 2)
}

func TestSelectPlugins_WhitelistWithModeFiltering(t *testing.T) {
	plugins.Reset()
	t.Cleanup(plugins.Reset)
	plugins.Register("dns-brute", func() plugins.Plugin {
		return &mockPlugin{name: "dns-brute", mode: plugins.ModeActive}
	})
	plugins.Register("crt-sh", func() plugins.Plugin {
		return &mockPlugin{name: "crt-sh", mode: plugins.ModePassive}
	})
	plugins.Register("reverse-rir", func() plugins.Plugin {
		return &mockPlugin{name: "reverse-rir", mode: plugins.ModePassive}
	})

	// Whitelist includes both passive and active plugins, but mode=passive filters to only passive
	result := selectPlugins("dns-brute,crt-sh,reverse-rir", "", "passive")
	names := pluginNames(result)
	assert.ElementsMatch(t, []string{"crt-sh", "reverse-rir"}, names, "mode filter applies after whitelist selection")
}

func pluginNames(ps []plugins.Plugin) []string {
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = p.Name()
	}
	return names
}

// ── runPipeline ───────────────────────────────────────────────────────────────

func TestRunPipeline_PhaseOrdering(t *testing.T) {
	ctx := context.Background()
	input := plugins.Input{OrgName: "TestOrg", Meta: make(map[string]string)}

	// Phase 1: emits a handle with registry "arin"
	phase1 := &mockPlugin{
		name:  "mock-phase1",
		phase: 1,
		findings: []plugins.Finding{
			{
				Type:   plugins.FindingCIDRHandle,
				Value:  "MOCK-HANDLE",
				Source: "mock-phase1",
				Data:   map[string]any{"registry": "arin"},
			},
		},
		accepts: true,
	}

	// Phase 2: captures its input for inspection; returns a CIDR
	phase2 := &capturingPlugin{
		name:  "mock-phase2",
		phase: 2,
		findings: []plugins.Finding{
			{Type: plugins.FindingCIDR, Value: "192.168.1.0/24", Source: "mock-phase2"},
		},
	}

	findings, err := runPipeline(ctx, input, []plugins.Plugin{phase1, phase2}, 5)

	require.NoError(t, err)
	// Phase 2 must have received the enriched input
	assert.Equal(t, "MOCK-HANDLE", phase2.capturedInput.Meta["arin_handles"])
	// Final output: FindingCIDR present, FindingCIDRHandle filtered out
	require.Len(t, findings, 1)
	assert.Equal(t, plugins.FindingCIDR, findings[0].Type)
	assert.Equal(t, "192.168.1.0/24", findings[0].Value)
}

func TestRunPipeline_PluginErrorNonPropagation(t *testing.T) {
	ctx := context.Background()
	input := plugins.Input{OrgName: "TestOrg", Meta: make(map[string]string)}

	// Independent plugin that errors
	errPlug := &errorPlugin{name: "error-plugin"}

	// Independent plugin that succeeds
	goodPlug := &mockPlugin{
		name:    "good-plugin",
		phase:   0,
		accepts: true,
		findings: []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "example.com", Source: "good-plugin"},
		},
	}

	findings, err := runPipeline(ctx, input, []plugins.Plugin{errPlug, goodPlug}, 5)

	// Pipeline must NOT fail when a plugin errors
	require.NoError(t, err)
	// Good plugin result still present
	require.Len(t, findings, 1)
	assert.Equal(t, plugins.FindingDomain, findings[0].Type)
	assert.Equal(t, "example.com", findings[0].Value)
}

// ── enrichWithDomains ────────────────────────────────────────────────────────

func TestEnrichWithDomains_CollectsDomainFindings(t *testing.T) {
	input := plugins.Input{OrgName: "Acme", Meta: make(map[string]string)}
	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "api.example.com"},
		{Type: plugins.FindingDomain, Value: "mail.example.com"},
		{Type: plugins.FindingCIDR, Value: "192.168.1.0/24"}, // ignored
	}
	result := enrichWithDomains(input, findings)
	assert.Equal(t, "api.example.com,mail.example.com", result.Meta["discovered_domains"])
}

func TestEnrichWithDomains_DeduplicatesDomains(t *testing.T) {
	input := plugins.Input{OrgName: "Acme", Meta: make(map[string]string)}
	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "api.example.com"},
		{Type: plugins.FindingDomain, Value: "API.EXAMPLE.COM"}, // duplicate (case)
		{Type: plugins.FindingDomain, Value: "api.example.com"}, // exact dup
	}
	result := enrichWithDomains(input, findings)
	assert.Equal(t, "api.example.com", result.Meta["discovered_domains"])
}

func TestEnrichWithDomains_NoDomains(t *testing.T) {
	input := plugins.Input{OrgName: "Acme", Meta: make(map[string]string)}
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDR, Value: "192.168.1.0/24"},
	}
	result := enrichWithDomains(input, findings)
	assert.Empty(t, result.Meta["discovered_domains"])
}

func TestEnrichWithDomains_PreservesExistingMeta(t *testing.T) {
	input := plugins.Input{
		OrgName: "Acme",
		Meta:    map[string]string{"arin_handles": "ACME-1"},
	}
	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "api.example.com"},
	}
	result := enrichWithDomains(input, findings)
	assert.Equal(t, "ACME-1", result.Meta["arin_handles"])
	assert.Equal(t, "api.example.com", result.Meta["discovered_domains"])
}

// ── Phase 3 pipeline integration ─────────────────────────────────────────────

func TestRunPipeline_Phase3ReceivesDiscoveredDomains(t *testing.T) {
	ctx := context.Background()
	input := plugins.Input{OrgName: "TestOrg", Meta: make(map[string]string)}

	// Phase 0: emits domain findings
	phase0 := &mockPlugin{
		name:    "mock-domain-discovery",
		phase:   0,
		accepts: true,
		findings: []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "api.example.com", Source: "mock-domain-discovery"},
			{Type: plugins.FindingDomain, Value: "mail.example.com", Source: "mock-domain-discovery"},
		},
	}

	// Phase 3: captures its input for inspection
	phase3 := &phase3CapturingPlugin{
		name:  "mock-phase3",
		phase: 3,
		findings: []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "dev-api.example.com", Source: "mock-phase3"},
		},
	}

	findings, err := runPipeline(ctx, input, []plugins.Plugin{phase0, phase3}, 5)

	require.NoError(t, err)
	// Phase 3 must have received the enriched input with discovered domains
	assert.Contains(t, phase3.capturedInput.Meta["discovered_domains"], "api.example.com")
	assert.Contains(t, phase3.capturedInput.Meta["discovered_domains"], "mail.example.com")
	// Phase 3 result and Phase 0 results should both appear
	values := make(map[string]bool)
	for _, f := range findings {
		values[f.Value] = true
	}
	assert.True(t, values["api.example.com"])
	assert.True(t, values["mail.example.com"])
	assert.True(t, values["dev-api.example.com"])
}

func TestRunPipeline_Phase3SkippedWhenNoDomains(t *testing.T) {
	ctx := context.Background()
	input := plugins.Input{OrgName: "TestOrg", Meta: make(map[string]string)}

	// Phase 3 that requires discovered_domains (should not run)
	phase3 := &phase3CapturingPlugin{
		name:  "mock-phase3",
		phase: 3,
	}

	findings, err := runPipeline(ctx, input, []plugins.Plugin{phase3}, 5)
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Empty(t, phase3.capturedInput.Meta, "Phase 3 should not have been called")
}
