package cidrs

import (
	"context"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubHTTPDoer struct {
	body []byte
	url  string
}

func (d *stubHTTPDoer) Get(_ context.Context, requestURL string) ([]byte, error) {
	d.url = requestURL
	return d.body, nil
}

func (d *stubHTTPDoer) GetWithHeaders(_ context.Context, requestURL string, _ map[string]string) ([]byte, error) {
	d.url = requestURL
	return d.body, nil
}

func TestASNBGPPlugin_Run_AddsRIPERISConfidence(t *testing.T) {
	doer := &stubHTTPDoer{body: []byte(`{"data":{"prefixes":[{"prefix":"203.0.113.0/24"}]}}`)}
	plugin := &ASNBGPPlugin{client: doer}

	findings, err := plugin.Run(context.Background(), plugins.Input{ASN: "AS64500", OrgName: "Acme Corp"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	finding := findings[0]
	require.Len(t, finding.Confidences, 1)
	assert.InDelta(t, confASNBGPAnnouncedPrefix, finding.Confidences[0].Score, 0.001)
	assert.Equal(t,
		`RIPE RIS returned CIDR "203.0.113.0/24" for queried ASN "AS64500" (https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64500)`,
		finding.Confidences[0].Justification)
	assert.Equal(t, "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64500", doer.url)
	assert.NotContains(t, finding.Data, "confidence")
	assert.NotContains(t, finding.Data, "confidences")
}
