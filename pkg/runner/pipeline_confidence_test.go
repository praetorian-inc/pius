package runner

import (
	"context"
	"sync"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scoringPlugin is a mock that emits pre-scored findings and records the Input it
// was handed, so a test can assert on both what came out and what went in.
type scoringPlugin struct {
	name     string
	phase    int
	findings []plugins.Finding

	mu       sync.Mutex
	captured plugins.Input
}

func (m *scoringPlugin) Name() string               { return m.name }
func (m *scoringPlugin) Description() string        { return "scoring mock" }
func (m *scoringPlugin) Category() string           { return "test" }
func (m *scoringPlugin) Phase() int                 { return m.phase }
func (m *scoringPlugin) Mode() string               { return plugins.ModePassive }
func (m *scoringPlugin) Accepts(plugins.Input) bool { return true }

func (m *scoringPlugin) Run(_ context.Context, input plugins.Input) ([]plugins.Finding, error) {
	m.mu.Lock()
	m.captured = input
	m.mu.Unlock()
	return m.findings, nil
}

// input returns the Input this plugin received.
func (m *scoringPlugin) input() plugins.Input {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.captured
}

// scored builds a finding carrying one evidence entry.
func scored(typ plugins.FindingType, value, source string, score float64, justification string, data map[string]any) plugins.Finding {
	f := plugins.Finding{Type: typ, Value: value, Source: source, Data: data}
	plugins.AddConfidence(&f, score, justification)
	return f
}

// fullPipeline builds one plugin per phase, each emitting scored findings.
func fullPipeline() (independent, phase1, phase2, phase3 *scoringPlugin) {
	independent = &scoringPlugin{
		name:  "mock-independent",
		phase: 0,
		findings: []plugins.Finding{
			scored(plugins.FindingDomain, "api.example.com", "mock-independent", 0.70,
				`Certificate Transparency logs contain "api.example.com" in results for known domain "example.com"`, nil),
			scored(plugins.FindingPreseed, "Example Holdings Ltd", "mock-independent", 0.60,
				`WHOIS for "example.com" lists "Example Holdings Ltd" as the registrant organization`,
				map[string]any{"preseed_type": "whois+company", "preseed_title": "Example Holdings Ltd"}),
		},
	}
	phase1 = &scoringPlugin{
		name:  "mock-phase1",
		phase: 1,
		findings: []plugins.Finding{
			scored(plugins.FindingCIDRHandle, "MOCK-HANDLE", "mock-phase1", 0.45,
				`ARIN organization search for "TestOrg" returned handle "MOCK-HANDLE"`,
				map[string]any{"registry": "arin", "org": "TestOrg"}),
		},
	}
	phase2 = &scoringPlugin{
		name:  "mock-phase2",
		phase: 2,
		findings: []plugins.Finding{
			scored(plugins.FindingCIDR, "203.0.113.0/24", "mock-phase2", 0.45,
				`ARIN maps CIDR "203.0.113.0/24" to handle "MOCK-HANDLE"`, nil),
		},
	}
	phase3 = &scoringPlugin{
		name:  "mock-phase3",
		phase: 3,
		findings: []plugins.Finding{
			scored(plugins.FindingDomain, "api-dev.example.com", "mock-phase3", 0.45,
				`Permutation of seed "api.example.com" produced "api-dev.example.com"`, nil),
		},
	}
	return independent, phase1, phase2, phase3
}

// runFullPipeline runs one plugin per phase and returns their findings alongside
// the mocks, so a test can assert on the output and on what each phase received.
func runFullPipeline(t *testing.T) ([]plugins.Finding, *scoringPlugin, *scoringPlugin, *scoringPlugin, *scoringPlugin) {
	t.Helper()

	independent, phase1, phase2, phase3 := fullPipeline()
	input := plugins.Input{OrgName: "TestOrg", Domain: "example.com", Meta: make(map[string]string)}

	findings, err := runPipeline(context.Background(), input,
		[]plugins.Plugin{independent, phase1, phase2, phase3}, 5)
	require.NoError(t, err)

	return findings, independent, phase1, phase2, phase3
}

// TestRunPipeline_EveryUserFacingFindingIsScored is the end-to-end invariant.
//
// Anything the pipeline returns reaches Guard, and an unscored finding there
// falls back to a downstream default instead of carrying pius's own judgement.
// The check covers all three user-facing types across all four phases, because a
// regression in any single plugin's construction path shows up here as an
// unscored value rather than as a silently defaulted asset in production.
func TestRunPipeline_EveryUserFacingFindingIsScored(t *testing.T) {
	findings, _, _, _, _ := runFullPipeline(t)
	require.NotEmpty(t, findings)

	var domains, cidrs, preseeds int
	for _, f := range findings {
		require.NotEmpty(t, f.Confidences,
			"unscored %s finding %q from %s", f.Type, f.Value, f.Source)
		for _, c := range f.Confidences {
			assert.NotEmpty(t, c.Justification,
				"empty justification on %s finding %q", f.Type, f.Value)
		}
		assert.Greater(t, plugins.TotalConfidence(f), 0.0,
			"%s finding %q totals zero", f.Type, f.Value)

		switch f.Type {
		case plugins.FindingDomain:
			domains++
		case plugins.FindingCIDR:
			cidrs++
		case plugins.FindingPreseed:
			preseeds++
		case plugins.FindingCIDRHandle:
			t.Errorf("internal handle finding %q reached user-facing output", f.Value)
		}
	}

	assert.Positive(t, domains, "expected domain findings in the invariant sample")
	assert.Positive(t, cidrs, "expected CIDR findings in the invariant sample")
	assert.Positive(t, preseeds, "expected preseed findings in the invariant sample")
}

// TestRunPipeline_HandleFindingsAreScoredForProvenance covers the exception to
// "internal findings need not be scored": a handle finding is filtered from
// output but IS the evidence a Phase 2 CIDR composes with, so an unscored handle
// silently zeroes every netblock derived from it.
func TestRunPipeline_HandleFindingsAreScoredForProvenance(t *testing.T) {
	_, _, _, phase2, _ := runFullPipeline(t)

	upstream := phase2.input().UpstreamFindings
	require.NotEmpty(t, upstream, "Phase 2 received no provenance")

	var handles int
	for _, f := range upstream {
		if f.Type != plugins.FindingCIDRHandle {
			continue
		}
		handles++
		require.NotEmpty(t, f.Confidences, "unscored handle %q reached Phase 2", f.Value)
		assert.Greater(t, plugins.TotalConfidence(f), 0.0)
	}
	assert.Equal(t, 1, handles)
}

// TestRunPipeline_Phase2ReceivesHandleProvenance pins both views arriving
// together: Meta for the lookup, UpstreamFindings for the attribution.
func TestRunPipeline_Phase2ReceivesHandleProvenance(t *testing.T) {
	_, _, _, phase2, _ := runFullPipeline(t)

	received := phase2.input()
	assert.Equal(t, "MOCK-HANDLE", received.Meta["arin_handles"], "the value-only view still works")

	require.Len(t, received.UpstreamFindings, 1)
	carried := received.UpstreamFindings[0]
	assert.Equal(t, "MOCK-HANDLE", carried.Value)
	assert.Equal(t, "mock-phase1", carried.Source)
	assert.Equal(t, "arin", carried.Data["registry"])
	require.Len(t, carried.Confidences, 1)
	assert.Equal(t, `ARIN organization search for "TestOrg" returned handle "MOCK-HANDLE"`,
		carried.Confidences[0].Justification)
}

// TestRunPipeline_Phase3ReceivesDomainAndCIDRProvenance is the same contract for
// the phase that consumes discovered domains: dns-permutation composes seed
// evidence out of exactly this.
func TestRunPipeline_Phase3ReceivesDomainAndCIDRProvenance(t *testing.T) {
	_, _, _, _, phase3 := runFullPipeline(t)

	received := phase3.input()
	assert.Equal(t, "api.example.com", received.Meta["discovered_domains"])
	assert.Equal(t, "203.0.113.0/24", received.Meta["cidrs"])

	byValue := make(map[string]plugins.Finding, len(received.UpstreamFindings))
	for _, f := range received.UpstreamFindings {
		byValue[f.Value] = f
	}

	// The handle from Phase 1, the CIDR from Phase 2 and the domain from the
	// independent phase all accumulate onto Phase 3's input.
	for _, value := range []string{"MOCK-HANDLE", "203.0.113.0/24", "api.example.com"} {
		carried, ok := byValue[value]
		require.True(t, ok, "Phase 3 lost provenance for %q", value)
		require.NotEmpty(t, carried.Confidences, "provenance for %q arrived unscored", value)
	}

	seed := byValue["api.example.com"]
	assert.Equal(t, "mock-independent", seed.Source,
		"the seed's discoverer must survive so a permutation can name it")
}

// TestRunPipeline_UnscoredPluginStillFlows is the deliberate negative: the
// pipeline does not manufacture confidence for a plugin that declined to score.
// Absence of evidence has to stay distinguishable from evidence of zero, which is
// what lets the SDK emitter fall back for producers that predate scoring.
func TestRunPipeline_UnscoredPluginStillFlows(t *testing.T) {
	unscored := &scoringPlugin{
		name:  "mock-unscored",
		phase: 0,
		findings: []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "legacy.example.com", Source: "mock-unscored"},
		},
	}
	input := plugins.Input{OrgName: "TestOrg", Domain: "example.com", Meta: make(map[string]string)}

	findings, err := runPipeline(context.Background(), input, []plugins.Plugin{unscored}, 5)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Empty(t, findings[0].Confidences, "the pipeline must not invent evidence")
	assert.True(t, plugins.NeedsReview(findings[0]))
}
