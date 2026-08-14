package cidrs

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRDAPPlugin_FetchCIDRs_IPv4(t *testing.T) {
	rdapJSON := `{
		"handle": "ACME-1",
		"networks": [{
			"cidr0_cidrs": [
				{"v4prefix": "192.168.1.0", "length": 24},
				{"v4prefix": "10.0.0.0", "length": 16}
			]
		}]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = fmt.Fprint(w, rdapJSON)
	}))
	defer srv.Close()

	p := &rdapPlugin{
		cfg: rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		c:   client.NewWithHTTPClient(srv.Client()),
	}

	cidrs, err := p.fetchCIDRs(context.Background(), "ACME-1")
	require.NoError(t, err)
	require.Len(t, cidrs, 2)
	assert.Equal(t, "192.168.1.0/24", cidrs[0].value)
	assert.Equal(t, "10.0.0.0/16", cidrs[1].value)
	for _, result := range cidrs {
		require.Len(t, result.confidences, 1)
		assert.Equal(t, confRDAPHandleNetwork, result.confidences[0].Score)
		assert.NotEmpty(t, result.confidences[0].Justification)
		assert.Contains(t, result.confidences[0].Justification, "ARIN")
		assert.Contains(t, result.confidences[0].Justification, "ACME-1")
		assert.Contains(t, result.confidences[0].Justification, result.value)
	}
}

func TestRDAPPlugin_FetchCIDRs_IPv6(t *testing.T) {
	rdapJSON := `{
		"handle": "ACME-1",
		"networks": [{
			"cidr0_cidrs": [
				{"v6prefix": "2001:db8::", "length": 32}
			]
		}]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, rdapJSON)
	}))
	defer srv.Close()

	p := &rdapPlugin{
		cfg: rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		c:   client.NewWithHTTPClient(srv.Client()),
	}

	cidrs, err := p.fetchCIDRs(context.Background(), "ACME-1")
	require.NoError(t, err)
	require.Len(t, cidrs, 1)
	assert.Equal(t, "2001:db8::/32", cidrs[0].value)
}

func TestRDAPPlugin_Run_EmitsFindingCIDR(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"handle":"ACME-1","networks":[{"cidr0_cidrs":[{"v4prefix":"203.0.113.0","length":24}]}]}`)
	}))
	defer srv.Close()

	p := &rdapPlugin{
		cfg: rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		c:   client.NewWithHTTPClient(srv.Client()),
	}
	input := plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"arin_handles": "ACME-1"},
	}

	findings, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, plugins.FindingCIDR, findings[0].Type)
	assert.Equal(t, "203.0.113.0/24", findings[0].Value)
	assert.Equal(t, "arin", findings[0].Source)
	assert.Equal(t, "ACME-1", findings[0].Data["handle"])
	require.Len(t, findings[0].Confidences, 1)
	assert.Equal(t, confRDAPHandleNetwork, findings[0].Confidences[0].Score)
	assert.Equal(t, `ARIN RDAP records CIDR "203.0.113.0/24" under organization handle "ACME-1"`, findings[0].Confidences[0].Justification)
	require.Len(t, findings[0].Confidences[0].References, 1)
	assert.Equal(t, "RDAP entity record", findings[0].Confidences[0].References[0].Label)
	assert.Equal(t, fmt.Sprintf("%s/ACME-1", srv.URL), findings[0].Confidences[0].References[0].URL)
	assert.NotContains(t, findings[0].Data, "confidence")
	assert.NotContains(t, findings[0].Data, "confidences")
}

func TestRDAPPlugin_Run_MultipleHandles(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_, _ = fmt.Fprintf(w, `{"handle":"H%d","networks":[{"cidr0_cidrs":[{"v4prefix":"10.%d.0.0","length":16}]}]}`, callCount, callCount)
	}))
	defer srv.Close()

	p := &rdapPlugin{
		cfg: rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		c:   client.NewWithHTTPClient(srv.Client()),
	}
	input := plugins.Input{
		Meta: map[string]string{"arin_handles": "H1,H2,H3"},
	}

	findings, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	assert.Len(t, findings, 3)
	assert.Equal(t, 3, callCount, "should make one RDAP call per handle")
}

func TestRDAPPlugin_Run_ContinuesOnFailedHandle(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.WriteHeader(http.StatusNotFound) // first handle fails
			return
		}
		_, _ = fmt.Fprint(w, `{"networks":[{"cidr0_cidrs":[{"v4prefix":"10.0.0.0","length":8}]}]}`)
	}))
	defer srv.Close()

	p := &rdapPlugin{
		cfg: rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		c:   client.NewWithHTTPClient(srv.Client()),
	}
	input := plugins.Input{Meta: map[string]string{"arin_handles": "FAIL-1,OK-2"}}

	findings, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	assert.Len(t, findings, 1, "should return results from successful handles")
}
