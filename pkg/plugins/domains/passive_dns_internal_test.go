package domains

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type passiveDNSRoundTripper func(*http.Request) (*http.Response, error)

func (f passiveDNSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestPassiveDNSPlugin_Run_Confidence(t *testing.T) {
	httpClient := &http.Client{Transport: passiveDNSRoundTripper(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, "test-key", req.Header.Get("APIKEY"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"subdomains":["WWW","www","api"]}`)),
			Request:    req,
		}, nil
	})}
	p := NewPassiveDNSPlugin(client.NewWithHTTPClient(httpClient), "test-key")

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})
	require.NoError(t, err)
	require.Len(t, findings, 2, "duplicate API records should produce one finding")

	for _, finding := range findings {
		require.Len(t, finding.Confidences, 1)
		assert.Equal(t, confPassiveDNSHistoricalObservation, finding.Confidences[0].Score)
		assert.Contains(t, finding.Confidences[0].Justification, finding.Value)
		assert.Contains(t, finding.Confidences[0].Justification, "example.com")
		assert.Contains(t, finding.Confidences[0].Justification, "SecurityTrails")
		assert.Contains(t, finding.Confidences[0].Justification, "historical/passive DNS")
		require.Len(t, finding.Confidences[0].References, 1)
		assert.Equal(t,
			"https://api.securitytrails.com/v1/domain/example.com/subdomains?include_inactive=true",
			finding.Confidences[0].References[0].URL)
		assert.NotContains(t, finding.Data, "confidence")
		assert.NotContains(t, finding.Data, "confidences")
	}
}
