package cidrs

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHTTPDoer implements httpDoer using an httptest.Server.
type mockHTTPDoer struct {
	server *httptest.Server
}

func (m *mockHTTPDoer) Get(ctx context.Context, url string) ([]byte, error) {
	return m.GetWithHeaders(ctx, url, nil)
}

func (m *mockHTTPDoer) GetWithHeaders(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := m.server.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 512)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf, nil
}

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
		cfg:  rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		doer: &mockHTTPDoer{server: srv},
	}

	cidrs, err := p.fetchCIDRs(context.Background(), "ACME-1")
	require.NoError(t, err)
	assert.Contains(t, cidrs, "192.168.1.0/24")
	assert.Contains(t, cidrs, "10.0.0.0/16")
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
		cfg:  rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		doer: &mockHTTPDoer{server: srv},
	}

	cidrs, err := p.fetchCIDRs(context.Background(), "ACME-1")
	require.NoError(t, err)
	assert.Contains(t, cidrs, "2001:db8::/32")
}

func TestRDAPPlugin_Run_EmitsFindingCIDR(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"handle":"ACME-1","networks":[{"cidr0_cidrs":[{"v4prefix":"203.0.113.0","length":24}]}]}`)
	}))
	defer srv.Close()

	p := &rdapPlugin{
		cfg:  rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		doer: &mockHTTPDoer{server: srv},
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
}

func TestRDAPPlugin_Run_MultipleHandles(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_, _ = fmt.Fprintf(w, `{"handle":"H%d","networks":[{"cidr0_cidrs":[{"v4prefix":"10.%d.0.0","length":16}]}]}`, callCount, callCount)
	}))
	defer srv.Close()

	p := &rdapPlugin{
		cfg:  rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		doer: &mockHTTPDoer{server: srv},
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
		cfg:  rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		doer: &mockHTTPDoer{server: srv},
	}
	input := plugins.Input{Meta: map[string]string{"arin_handles": "FAIL-1,OK-2"}}

	findings, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	assert.Len(t, findings, 1, "should return results from successful handles")
}
