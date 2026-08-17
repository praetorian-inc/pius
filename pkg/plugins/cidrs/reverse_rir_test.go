package cidrs

import (
	"context"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReverseRIRPlugin_RegistryFindingsUseConsistentConfidence(t *testing.T) {
	const org = "Acme Corp"
	tests := []struct {
		name          string
		response      string
		query         func(*ReverseRIRPlugin) []plugins.Finding
		handle        string
		registry      string
		justification string
		reference     string
	}{
		{
			name:     "ARIN organization entity",
			response: `{"orgs":{"orgRef":{"@handle":"ACME-ARIN"}}}`,
			query: func(plugin *ReverseRIRPlugin) []plugins.Finding {
				return plugin.queryArinEntity(context.Background(), "orgs", org)
			},
			handle:        "ACME-ARIN",
			registry:      "arin",
			justification: `ARIN orgs database returned organization handle "ACME-ARIN" for organization search "Acme Corp"`,
			reference:     `https://whois.arin.net/rest/orgs;name=*Acme%20Corp*`,
		},
		{
			name:     "RIPE",
			response: `{"objects":{"object":[{"primary-key":{"attribute":[{"name":"organisation","value":"ORG-ACME-RIPE"}]}}]}}`,
			query: func(plugin *ReverseRIRPlugin) []plugins.Finding {
				findings, _ := plugin.queryRIPE(context.Background(), org)
				return findings
			},
			handle:        "ORG-ACME-RIPE",
			registry:      "ripe",
			justification: `RIPE database returned organization handle "ORG-ACME-RIPE" for organization search "Acme Corp"`,
			reference:     `https://rest.db.ripe.net/search?query-string=Acme+Corp`,
		},
		{
			name:     "APNIC",
			response: `[{"objectType":"organisation","primaryKey":"ORG-ACME-AP"}]`,
			query: func(plugin *ReverseRIRPlugin) []plugins.Finding {
				findings, _ := plugin.queryAPNIC(context.Background(), org)
				return findings
			},
			handle:        "ORG-ACME-AP",
			registry:      "apnic",
			justification: `APNIC WHOIS database returned organization handle "ORG-ACME-AP" for organization search "Acme Corp"`,
			reference:     `https://wq.apnic.net/query?searchtext=Acme+Corp&type=organisation`,
		},
		{
			name:     "AFRINIC",
			response: `{"entitySearchResults":[{"handle":"ORG-ACME-AFRINIC"}]}`,
			query: func(plugin *ReverseRIRPlugin) []plugins.Finding {
				findings, _ := plugin.queryAFRINIC(context.Background(), org)
				return findings
			},
			handle:        "ORG-ACME-AFRINIC",
			registry:      "afrinic",
			justification: `AFRINIC RDAP database returned organization handle "ORG-ACME-AFRINIC" for organization search "Acme Corp"`,
			reference:     `https://rdap.afrinic.net/rdap/entities?fn=Acme+Corp`,
		},
		{
			name:     "LACNIC",
			response: `{"entities":[{"handle":"BR-ACME-LACNIC"}]}`,
			query: func(plugin *ReverseRIRPlugin) []plugins.Finding {
				findings, _ := plugin.queryLACNIC(context.Background(), org)
				return findings
			},
			handle:        "BR-ACME-LACNIC",
			registry:      "lacnic",
			justification: `LACNIC RDAP database returned organization handle "BR-ACME-LACNIC" for organization search "Acme Corp"`,
			reference:     `https://rdap.lacnic.net/rdap/entities?fn=Acme+Corp`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newStubClient([]byte(tt.response))
			plugin := &ReverseRIRPlugin{client: c}
			findings := tt.query(plugin)

			require.Len(t, findings, 1)
			finding := findings[0]
			assert.Equal(t, tt.handle, finding.Value)
			assert.Equal(t, tt.registry, finding.Data["registry"])
			require.Len(t, finding.Confidences, 1)
			assert.Equal(t, confReverseRIRHandle, finding.Confidences[0].Score)
			assert.Equal(t, tt.justification, finding.Confidences[0].Justification)
			require.Len(t, finding.Confidences[0].References, 1)
			assert.Equal(t, tt.reference, finding.Confidences[0].References[0].URL)
			assert.NotContains(t, finding.Data, "confidence")
			assert.NotContains(t, finding.Data, "confidences")
		})
	}
}

// A handle a phase-two plugin could not act on must not leave this plugin at
// all. Consumers cannot repair any of these, so filtering here is the only place
// it happens once rather than in every embedder.
func TestReverseRIRQueryURL_UnknownRegistryIsEmpty(t *testing.T) {
	assert.Empty(t, reverseRIRQueryURL("unknown", "test database", "Acme Corp"))
}

func TestReverseRIRPlugin_DropsUnusableHandles(t *testing.T) {
	tests := map[string]struct {
		handle   string
		registry string
		org      string
	}{
		"empty handle":          {"", "arin", "Acme Corp"},
		"whitespace handle":     {"   ", "arin", "Acme Corp"},
		"empty org":             {"ACME-1", "arin", ""},
		"whitespace org":        {"ACME-1", "arin", "  "},
		"unknown registry":      {"ACME-1", "unknown", "Acme Corp"},
		"unresolvable registry": {"ACME-1", "twnic", "Acme Corp"},
		"empty registry":        {"ACME-1", "", "Acme Corp"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, ok := newReverseRIRFinding(tt.handle, tt.registry, "test database", tt.org)
			assert.False(t, ok)
		})
	}
}

func TestReverseRIRPlugin_TrimsHandleAndOrg(t *testing.T) {
	finding, ok := newReverseRIRFinding("  ACME-1  ", "arin", "ARIN orgs database", "  Acme Corp  ")
	require.True(t, ok)

	assert.Equal(t, "ACME-1", finding.Value)
	assert.Equal(t, "Acme Corp", finding.Data["org"])
}

// Every registry reverse-rir queries must be one a phase-two plugin can resolve,
// or discovery would emit handles with no way to look them up.
func TestReverseRIRPlugin_EveryQueriedRegistryIsResolvable(t *testing.T) {
	for _, registry := range []string{"arin", "ripe", "apnic", "afrinic", "lacnic"} {
		assert.True(t, resolvableRegistry(registry), "%s must be resolvable", registry)
	}
	assert.False(t, resolvableRegistry("unknown"), "edgar's placeholder is not resolvable")
}

// RIPE and LACNIC return a record with a blank handle rather than omitting it,
// so these two paths are where an empty finding would otherwise escape.
func TestReverseRIRPlugin_BlankHandlesFromRIPEAndLACNIC(t *testing.T) {
	c, _ := newStubClient([]byte(`{"objects":{"object":[{"primary-key":{"attribute":[{"name":"organisation","value":""}]}}]}}`))
	plugin := &ReverseRIRPlugin{client: c}
	findings, _ := plugin.queryRIPE(context.Background(), "Acme Corp")
	assert.Empty(t, findings, "RIPE must not emit a blank handle")

	c, _ = newStubClient([]byte(`{"entities":[{"handle":""}]}`))
	plugin = &ReverseRIRPlugin{client: c}
	findings, _ = plugin.queryLACNIC(context.Background(), "Acme Corp")
	assert.Empty(t, findings, "LACNIC must not emit a blank handle")
}

// Run is the boundary an embedder sees, so the guarantee has to hold there too:
// an org that is only whitespace yields nothing rather than unattributed handles.
func TestReverseRIRPlugin_RunEmitsNothingForABlankOrg(t *testing.T) {
	c, _ := newStubClient([]byte(`{"orgs":{"orgRef":{"@handle":"ACME-1"}}}`))
	plugin := &ReverseRIRPlugin{client: c}

	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "   "})
	require.NoError(t, err)
	assert.Empty(t, findings)
}
