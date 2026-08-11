package cidrs

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rdapDIResponse = `{"handle":"ACME-1","networks":[{"cidr0_cidrs":[{"v4prefix":"203.0.113.0","length":24}]}]}`

// recordingTransport is an http.RoundTripper that records every request URL and
// answers from a canned body. Injecting it through client.NewWithHTTPClient is
// what proves an exported constructor issues its requests through the client it
// was handed: nothing leaves the process, and a plugin that silently fell back
// to client.New() would record zero calls here.
type recordingTransport struct {
	mu   sync.Mutex
	urls []string
	body string
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.urls = append(t.urls, req.URL.String())
	t.mu.Unlock()
	return &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(t.body)),
		Request:    req,
	}, nil
}

func (t *recordingTransport) calls() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.urls...)
}

// injectedClient returns a real *client.Client whose transport records calls
// instead of performing them.
func injectedClient(body string) (*client.Client, *recordingTransport) {
	transport := &recordingTransport{body: body}
	return client.NewWithHTTPClient(&http.Client{Transport: transport}), transport
}

func TestRDAPConstructors_UseInjectedClient(t *testing.T) {
	tests := []struct {
		name      string
		construct func(*client.Client) *RDAPPlugin
		metaKey   string
		wantURL   string
	}{
		{
			name:      "arin",
			construct: NewARINPlugin,
			metaKey:   "arin_handles",
			wantURL:   "https://rdap.arin.net/registry/entity/ACME-1",
		},
		{
			name:      "ripe",
			construct: NewRIPEPlugin,
			metaKey:   "ripe_handles",
			wantURL:   "https://rdap.db.ripe.net/entity/ACME-1",
		},
		{
			name:      "lacnic",
			construct: NewLACNICPlugin,
			metaKey:   "lacnic_handles",
			wantURL:   "https://rdap.lacnic.net/rdap/entity/ACME-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injected, transport := injectedClient(rdapDIResponse)
			plugin := tt.construct(injected)

			findings, err := plugin.Run(context.Background(), plugins.Input{
				OrgName: "Acme",
				Meta:    map[string]string{tt.metaKey: "ACME-1"},
			})

			require.NoError(t, err)
			require.Len(t, findings, 1)
			assert.Equal(t, "203.0.113.0/24", findings[0].Value)
			assert.Equal(t, tt.name, findings[0].Source)

			calls := transport.calls()
			require.NotEmpty(t, calls, "injected client was never used: the plugin fell back to its own client")
			assert.Equal(t, []string{tt.wantURL}, calls)
		})
	}
}

func TestNewReverseRIRPlugin_UsesInjectedClient(t *testing.T) {
	injected, transport := injectedClient(`{"orgs":{"orgRef":{"@handle":"ACME-ARIN"}}}`)
	plugin := NewReverseRIRPlugin(injected)

	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "Acme"})

	require.NoError(t, err)
	calls := transport.calls()
	require.NotEmpty(t, calls, "injected client was never used: the plugin fell back to its own client")
	assert.Contains(t, calls, "https://whois.arin.net/rest/orgs;name=*Acme*")

	values := make([]string, 0, len(findings))
	for _, finding := range findings {
		values = append(values, finding.Value)
	}
	assert.Contains(t, values, "ACME-ARIN")
}

// TestRegistryConfigHelpers_MatchPreRefactorRegistrations guards against the
// two-sources-of-truth drift the config helpers exist to prevent: the helper,
// the plugin the registry hands out, and the exported constructor must all
// carry the same values that init() inlined before the refactor.
func TestRegistryConfigHelpers_MatchPreRefactorRegistrations(t *testing.T) {
	tests := []struct {
		name      string
		helper    func() rdapConfig
		construct func(*client.Client) *RDAPPlugin
		want      rdapConfig
	}{
		{
			name:      "arin",
			helper:    arinConfig,
			construct: NewARINPlugin,
			want: rdapConfig{
				name:        "arin",
				description: "ARIN RDAP: resolves org handles to CIDR blocks",
				baseURL:     "https://rdap.arin.net/registry/entity",
				metaKey:     "arin_handles",
				registry:    "arin",
				mode:        plugins.ModePassive,
			},
		},
		{
			name:      "ripe",
			helper:    ripeConfig,
			construct: NewRIPEPlugin,
			want: rdapConfig{
				name:        "ripe",
				description: "RIPE RDAP: resolves org handles to CIDR blocks",
				baseURL:     "https://rdap.db.ripe.net/entity",
				metaKey:     "ripe_handles",
				registry:    "ripe",
				mode:        plugins.ModePassive,
			},
		},
		{
			name:      "lacnic",
			helper:    lacnicConfig,
			construct: NewLACNICPlugin,
			want: rdapConfig{
				name:        "lacnic",
				description: "LACNIC RDAP: resolves org handles to CIDR blocks (Latin America & Caribbean)",
				baseURL:     "https://rdap.lacnic.net/rdap/entity",
				metaKey:     "lacnic_handles",
				registry:    "lacnic",
				mode:        plugins.ModePassive,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.helper(), "config helper drifted from the values init() registered")

			registered, ok := plugins.Get(tt.name)
			require.True(t, ok, "plugin %q must stay registered", tt.name)
			registeredRDAP, ok := registered.(*RDAPPlugin)
			require.True(t, ok, "registry must still hand out an *RDAPPlugin for %q", tt.name)
			assert.Equal(t, tt.want, registeredRDAP.cfg, "registered plugin config drifted from the helper")
			assert.Equal(t, tt.name, registeredRDAP.Name())
			assert.Equal(t, plugins.ModePassive, registeredRDAP.Mode())
			assert.Equal(t, 2, registeredRDAP.Phase())
			assert.Equal(t, "cidr", registeredRDAP.Category())

			assert.Equal(t, tt.want, tt.construct(nil).cfg, "exported constructor config drifted from the helper")
		})
	}
}

// TestConstructors_NilClientFallsBackToDefaultDoer pins the documented nil rule:
// a nil argument yields the default client, never a plugin that panics on first
// use. require.NotNil is reflect-based, so it also fails on a nil *client.Client
// stored inside a non-nil httpDoer interface - exactly the shape whose first
// request would panic dereferencing Client.http.
func TestConstructors_NilClientFallsBackToDefaultDoer(t *testing.T) {
	rdapConstructors := []struct {
		name      string
		construct func(*client.Client) *RDAPPlugin
	}{
		{"NewARINPlugin", NewARINPlugin},
		{"NewRIPEPlugin", NewRIPEPlugin},
		{"NewLACNICPlugin", NewLACNICPlugin},
	}

	for _, tt := range rdapConstructors {
		t.Run(tt.name, func(t *testing.T) {
			plugin := tt.construct(nil)
			require.NotNil(t, plugin)
			require.NotNil(t, plugin.doer, "nil argument must fall back to a usable doer")
			assert.NotPanics(t, func() { _ = plugin.Accepts(plugins.Input{}) })
		})
	}

	t.Run("NewReverseRIRPlugin", func(t *testing.T) {
		plugin := NewReverseRIRPlugin(nil)
		require.NotNil(t, plugin)
		require.NotNil(t, plugin.client, "nil argument must fall back to a usable doer")
		assert.NotPanics(t, func() { _ = plugin.Accepts(plugins.Input{}) })
	})
}

// TestNewRDAPPluginWithDoer_UsesInjectedDoer covers the package-internal seam
// the exported constructors are built on.
func TestNewRDAPPluginWithDoer_UsesInjectedDoer(t *testing.T) {
	stub := &stubHTTPDoer{body: []byte(rdapDIResponse)}
	plugin := newRDAPPluginWithDoer(arinConfig(), stub)

	findings, err := plugin.Run(context.Background(), plugins.Input{
		OrgName: "Acme",
		Meta:    map[string]string{"arin_handles": "ACME-1"},
	})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "https://rdap.arin.net/registry/entity/ACME-1", stub.url, "injected doer was never used")
}
