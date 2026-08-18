package cidrs

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubHTTPTransport struct {
	body []byte
	url  string
}

func (t *stubHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.url = req.URL.String()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(t.body)),
		Request:    req,
	}, nil
}

func newStubClient(body []byte) (*client.Client, *stubHTTPTransport) {
	transport := &stubHTTPTransport{body: body}
	httpClient := &http.Client{Transport: transport}
	return client.NewWithHTTPClient(httpClient), transport
}

func TestASNBGPPlugin_Run_AddsRIPERISConfidence(t *testing.T) {
	c, transport := newStubClient([]byte(`{"data":{"prefixes":[{"prefix":"203.0.113.0/24"}]}}`))
	plugin := &ASNBGPPlugin{client: c}

	findings, err := plugin.Run(context.Background(), plugins.Input{ASN: "AS64500", OrgName: "Acme Corp"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	finding := findings[0]
	require.Len(t, finding.Confidences, 1)
	assert.Equal(t, confASNBGPAnnouncedPrefix, finding.Confidences[0].Score)
	assert.Equal(t,
		`RIPE RIS returned CIDR "203.0.113.0/24" for queried ASN "AS64500" (https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64500)`,
		finding.Confidences[0].Justification)
	assert.Equal(t, "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64500", transport.url)
	assert.NotContains(t, finding.Data, "confidence")
	assert.NotContains(t, finding.Data, "confidences")
}
