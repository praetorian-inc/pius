package cidrs

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingTransport is an embedder's transport: the point of the injected-client
// constructors is that every request lands here rather than on the package
// default, so the embedder can observe and intercept it.
type recordingTransport struct {
	mu     sync.Mutex
	paths  []string
	handle http.RoundTripper
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.paths = append(t.paths, req.URL.Path)
	t.mu.Unlock()
	return t.handle.RoundTrip(req)
}

func (t *recordingTransport) seen() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.paths...)
}

// injectedClient builds a pius client whose egress is recorded and served by srv,
// whatever host the plugin's configured URL names.
func injectedClient(t *testing.T, srv *httptest.Server) (*client.Client, *recordingTransport) {
	t.Helper()
	transport := &recordingTransport{handle: rewriteTo(srv)}
	return client.NewWithHTTPClient(&http.Client{Transport: transport}), transport
}

// rewriteTo sends every request to srv regardless of the URL's real host, so a
// plugin pointed at rdap.arin.net can be exercised offline.
func rewriteTo(srv *httptest.Server) http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		routed := req.Clone(req.Context())
		routed.URL.Scheme = "http"
		routed.URL.Host = srv.Listener.Addr().String()
		return srv.Client().Transport.RoundTrip(routed)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// ── RDAP constructors ─────────────────────────────────────────────────────────

var rdapConstructors = map[string]func(*client.Client) plugins.Plugin{
	"arin":   NewARINPlugin,
	"ripe":   NewRIPEPlugin,
	"lacnic": NewLACNICPlugin,
}

func TestRDAPConstructors_SupportedRegistries(t *testing.T) {
	baseURLs := map[string]string{
		"arin":   "https://rdap.arin.net/registry/entity",
		"ripe":   "https://rdap.db.ripe.net/entity",
		"lacnic": "https://rdap.lacnic.net/rdap/entity",
	}

	for registry, newPlugin := range rdapConstructors {
		t.Run(registry, func(t *testing.T) {
			rdap, ok := newPlugin(client.New()).(*rdapPlugin)
			require.True(t, ok)
			assert.Equal(t, registry, rdap.Name())
			assert.Equal(t, registry, rdap.cfg.registry)
			assert.Equal(t, baseURLs[registry], rdap.cfg.baseURL)
			assert.Equal(t, registry+"_handles", rdap.cfg.metaKey)
			assert.Equal(t, 2, rdap.Phase())
			assert.Equal(t, plugins.ModePassive, rdap.Mode())
		})
	}
}

func TestRDAPConstructors_NilClientTakesTheDefault(t *testing.T) {
	for registry, newPlugin := range rdapConstructors {
		t.Run(registry, func(t *testing.T) {
			require.NotNil(t, newPlugin(nil).(*rdapPlugin).c)
		})
	}
}

func TestNewARINPlugin_UsesTheInjectedClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/rdap+json", r.Header.Get("Accept"))
		_, _ = fmt.Fprint(w, `{"handle":"ACME-1","networks":[{"cidr0_cidrs":[
			{"v4prefix":"203.0.113.0","length":24},
			{"v6prefix":"2001:db8::","length":32}
		]}]}`)
	}))
	defer srv.Close()

	c, transport := injectedClient(t, srv)
	p := NewARINPlugin(c)

	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"arin_handles": "ACME-1"},
	})
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Equal(t, []string{"/registry/entity/ACME-1"}, transport.seen(),
		"the injected client must carry the request")

	assert.Equal(t, "203.0.113.0/24", findings[0].Value)
	assert.Equal(t, "2001:db8::/32", findings[1].Value)
	for _, finding := range findings {
		assert.Equal(t, plugins.FindingCIDR, finding.Type)
		assert.Equal(t, "arin", finding.Source)
		assert.Equal(t, "arin", finding.Data["registry"])
		assert.Equal(t, "ACME-1", finding.Data["handle"])
		assert.Equal(t, "Acme Corp", finding.Data["org"])
		require.Len(t, finding.Confidences, 1)
		assert.Equal(t, confRDAPHandleNetwork, finding.Confidences[0].Score)
		assert.Contains(t, finding.Confidences[0].Justification, "ARIN RDAP records CIDR")
		assert.Contains(t, finding.Confidences[0].Justification, finding.Value)
	}
}

// The registered plugins and exported constructors must stay the same plugins:
// a registry whose config drifted between the two would behave differently
// embedded than standalone.
func TestRDAPConstructors_MatchRegisteredPlugins(t *testing.T) {
	for registry, newPlugin := range rdapConstructors {
		registered, found := plugins.Get(registry)
		require.True(t, found)

		constructed := newPlugin(client.New())
		assert.Equal(t, registered.(*rdapPlugin).cfg, constructed.(*rdapPlugin).cfg)
	}
}

// ── NewReverseRIRPlugin ───────────────────────────────────────────────────────

func TestNewReverseRIRPlugin_NilClientTakesTheDefault(t *testing.T) {
	assert.NotNil(t, NewReverseRIRPlugin(nil).client)
}

// reverse-rir fans out across five registries; all five must go through the
// embedder's client, or Guard would silently egress around its collector.
func TestNewReverseRIRPlugin_EveryRegistryUsesTheInjectedClient(t *testing.T) {
	bodies := map[string]string{
		"/rest/orgs;name=*Acme*Corp*":      `{"orgs":{"orgRef":{"@handle":"ACME-ARIN"}}}`,
		"/rest/customers;name=*Acme*Corp*": `{}`,
		"/search":                          `{"objects":{"object":[{"primary-key":{"attribute":[{"name":"organisation","value":"ORG-ACME-RIPE"}]}}]}}`,
		"/query":                           `[{"objectType":"organisation","primaryKey":"ORG-ACME-AP"}]`,
		"/rdap/entities":                   `{"entitySearchResults":[{"handle":"ORG-ACME-AFRINIC"}],"entities":[{"handle":"BR-ACME-LACNIC"}]}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()

	c, transport := injectedClient(t, srv)
	findings, err := NewReverseRIRPlugin(c).Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	// Two resolvable ARIN entity types plus one query each for RIPE, APNIC,
	// AFRINIC, and LACNIC. AFRINIC and LACNIC share a path here; both are still queried.
	assert.Equal(t, []string{
		"/rest/orgs;name=*Acme*Corp*",
		"/rest/customers;name=*Acme*Corp*",
		"/search",
		"/query",
		"/rdap/entities",
		"/rdap/entities",
	}, transport.seen(), "every registry query must go through the injected client")

	byRegistry := map[string]string{}
	for _, finding := range findings {
		assert.Equal(t, plugins.FindingCIDRHandle, finding.Type)
		assert.Equal(t, "reverse-rir", finding.Source)
		assert.Equal(t, "Acme Corp", finding.Data["org"])
		require.Len(t, finding.Confidences, 1)
		assert.Equal(t, confReverseRIRHandle, finding.Confidences[0].Score)
		assert.NotEmpty(t, finding.Confidences[0].Justification)
		byRegistry[finding.Data["registry"].(string)] = finding.Value
	}
	assert.Equal(t, map[string]string{
		"arin":    "ACME-ARIN",
		"ripe":    "ORG-ACME-RIPE",
		"apnic":   "ORG-ACME-AP",
		"afrinic": "ORG-ACME-AFRINIC",
		"lacnic":  "BR-ACME-LACNIC",
	}, byRegistry)
}

func TestNewReverseRIRPlugin_MatchesRegisteredPlugin(t *testing.T) {
	registered, found := plugins.Get("reverse-rir")
	require.True(t, found)

	constructed := NewReverseRIRPlugin(client.New())
	assert.Equal(t, registered.Name(), constructed.Name())
	assert.Equal(t, registered.Phase(), constructed.Phase())
	assert.Equal(t, registered.Mode(), constructed.Mode())
	assert.Equal(t, registered.Description(), constructed.Description())
}
