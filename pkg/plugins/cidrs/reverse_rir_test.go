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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &ReverseRIRPlugin{client: &stubHTTPDoer{body: []byte(tt.response)}}
			findings := tt.query(plugin)

			require.Len(t, findings, 1)
			finding := findings[0]
			assert.Equal(t, tt.handle, finding.Value)
			assert.Equal(t, tt.registry, finding.Data["registry"])
			require.Len(t, finding.Confidences, 1)
			assert.InDelta(t, confReverseRIRHandle, finding.Confidences[0].Score, 0.001)
			assert.Equal(t, tt.justification, finding.Confidences[0].Justification)
			assert.NotContains(t, finding.Data, "confidence")
			assert.NotContains(t, finding.Data, "confidences")
		})
	}
}
