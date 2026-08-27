package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReverseRIRPlugin_RegistryFindingsUseReturnedOrgSimilarity(t *testing.T) {
	const (
		queriedOrg  = "Acme Corp"
		returnedOrg = "Acme Corp Holdings"
	)
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
			response: `{"orgs":{"orgRef":{"@handle":"ACME-ARIN","@name":"Acme Corp Holdings"}}}`,
			query: func(plugin *ReverseRIRPlugin) []plugins.Finding {
				return plugin.queryArinEntity(context.Background(), arinOrganizations, queriedOrg)
			},
			handle:        "ACME-ARIN",
			registry:      "arin",
			justification: `ARIN orgs database returned organization handle "ACME-ARIN" for organization search "Acme Corp"`,
		},
		{
			name:     "RIPE",
			response: `{"objects":{"object":[{"primary-key":{"attribute":[{"name":"organisation","value":"ORG-ACME-RIPE"}]},"attributes":{"attribute":[{"name":"org-name","value":"Acme Corp Holdings"}]}}]}}`,
			query: func(plugin *ReverseRIRPlugin) []plugins.Finding {
				findings, _ := plugin.queryRIPE(context.Background(), queriedOrg)
				return findings
			},
			handle:        "ORG-ACME-RIPE",
			registry:      "ripe",
			justification: `RIPE database returned organization handle "ORG-ACME-RIPE" for organization search "Acme Corp"`,
		},
		{
			name:     "APNIC",
			response: `[{"objectType":"organisation","primaryKey":"ORG-ACME-AP","attributes":[{"name":"org-name","values":["Acme Corp Holdings"]}]}]`,
			query: func(plugin *ReverseRIRPlugin) []plugins.Finding {
				findings, _ := plugin.queryAPNIC(context.Background(), queriedOrg)
				return findings
			},
			handle:        "ORG-ACME-AP",
			registry:      "apnic",
			justification: `APNIC WHOIS database returned organization handle "ORG-ACME-AP" for organization search "Acme Corp"`,
		},
		{
			name:     "AFRINIC",
			response: `{"entitySearchResults":[{"handle":"ORG-ACME-AFRINIC","vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Acme Corp Holdings"]]]}]}`,
			query: func(plugin *ReverseRIRPlugin) []plugins.Finding {
				findings, _ := plugin.queryAFRINIC(context.Background(), queriedOrg)
				return findings
			},
			handle:        "ORG-ACME-AFRINIC",
			registry:      "afrinic",
			justification: `AFRINIC RDAP database returned organization handle "ORG-ACME-AFRINIC" for organization search "Acme Corp"`,
		},
		{
			name:     "LACNIC",
			response: `{"entities":[{"handle":"BR-ACME-LACNIC","vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Acme Corp Holdings"]]]}]}`,
			query: func(plugin *ReverseRIRPlugin) []plugins.Finding {
				findings, _ := plugin.queryLACNIC(context.Background(), queriedOrg)
				return findings
			},
			handle:        "BR-ACME-LACNIC",
			registry:      "lacnic",
			justification: `LACNIC RDAP database returned organization handle "BR-ACME-LACNIC" for organization search "Acme Corp"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newStubClient([]byte(tt.response))
			plugin := &ReverseRIRPlugin{client: c}
			findings := tt.query(plugin)

			require.Len(t, findings, 2)
			finding := findings[0]
			result := findings[1]
			assert.Equal(t, tt.handle, finding.Value)
			assert.Equal(t, tt.registry, finding.Data["registry"])
			assert.Equal(t, returnedOrg, finding.Data["org"])
			require.Len(t, finding.Confidences, 2)
			assert.Equal(t, confReverseRIRHandle, finding.Confidences[0].Score)
			assert.Equal(t, tt.justification, finding.Confidences[0].Justification)
			assert.Equal(t, confReverseRIROrgSimilarity, finding.Confidences[1].Score)
			assert.Equal(t,
				`RIR organization name "Acme Corp Holdings" matches the queried organization "Acme Corp"`,
				finding.Confidences[1].Justification)
			assert.Equal(t, 85, plugins.TotalConfidence(finding))
			assert.NotContains(t, finding.Data, "confidence")
			assert.NotContains(t, finding.Data, "confidences")

			assert.Equal(t, plugins.FindingRIRResult, result.Type)
			assert.Equal(t, tt.handle, result.Value)
			assert.Equal(t, tt.registry, result.Data["registry"])
			assert.Equal(t, returnedOrg, result.Data["name"])
			assert.Equal(t, queriedOrg, result.Data["queriedOrganization"])
			assert.NotNil(t, result.Data["record"])
			assert.Equal(t, finding.Confidences, result.Confidences)
		})
	}
}

func TestReverseRIRPlugin_OrgSimilarityThreshold(t *testing.T) {
	tests := []struct {
		name        string
		returnedOrg string
		wantBonus   bool
	}{
		{name: "at threshold", returnedOrg: "Acme Holdings", wantBonus: true},
		{name: "below threshold", returnedOrg: "Acme Network Holdings", wantBonus: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := newReverseRIRFinding("ARIN orgs database", ReverseRIRFindingData{
				Registry:            "arin",
				Handle:              "ACME-1",
				Name:                tt.returnedOrg,
				QueriedOrganization: "Acme Global Corp",
			})
			require.Len(t, findings, 2)

			wantConfidenceEntries := 1
			if tt.wantBonus {
				wantConfidenceEntries = 2
			}
			assert.Len(t, findings[0].Confidences, wantConfidenceEntries)
		})
	}
}

func TestARINNamePattern(t *testing.T) {
	tests := []struct {
		name string
		org  string
		want string
	}{
		{name: "single space", org: "Acme Corp", want: "*Acme*Corp*"},
		{name: "mixed whitespace", org: "  Acme\t Corp\nHoldings  ", want: "*Acme*Corp*Holdings*"},
		{name: "escapes each token", org: "Acme / Holdings", want: "*Acme*%2F*Holdings*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, arinNamePattern(tt.org))
		})
	}
}

func TestReverseRIRPlugin_MissingReturnedOrgKeepsBaseConfidence(t *testing.T) {
	findings := newReverseRIRFinding("ARIN orgs database", ReverseRIRFindingData{
		Registry:            "arin",
		Handle:              "ACME-1",
		QueriedOrganization: "Acme Corp",
	})
	require.Len(t, findings, 2)

	assert.Equal(t, "", findings[0].Data["org"])
	require.Len(t, findings[0].Confidences, 1)
	assert.Equal(t, confReverseRIRHandle, findings[0].Confidences[0].Score)
}

func TestReverseRIRPlugin_ARINRequestUsesWhitespaceTolerantPattern(t *testing.T) {
	c, transport := newStubClient([]byte(`{"orgs":{"orgRef":{"@handle":"ACME-ARIN"}}}`))
	plugin := &ReverseRIRPlugin{client: c}

	findings := plugin.queryArinEntity(context.Background(), arinOrganizations, "Acme Corp")

	require.Len(t, findings, 2)
	assert.Equal(t, "https://whois.arin.net/rest/orgs;name=*Acme*Corp*", transport.url)
}

// A handle a phase-two plugin could not act on must not leave this plugin at
// all. Consumers cannot repair any of these, so filtering here is the only place
// it happens once rather than in every embedder.
func TestReverseRIRPlugin_DropsUnusableHandles(t *testing.T) {
	tests := map[string]struct {
		handle     string
		registry   string
		queriedOrg string
	}{
		"empty handle":           {"", "arin", "Acme Corp"},
		"whitespace handle":      {"   ", "arin", "Acme Corp"},
		"empty queried org":      {"ACME-1", "arin", ""},
		"whitespace queried org": {"ACME-1", "arin", "  "},
		"unknown registry":       {"ACME-1", "unknown", "Acme Corp"},
		"unresolvable registry":  {"ACME-1", "twnic", "Acme Corp"},
		"empty registry":         {"ACME-1", "", "Acme Corp"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			findings := newReverseRIRFinding("test database", ReverseRIRFindingData{
				Registry:            tt.registry,
				Handle:              tt.handle,
				Name:                "Returned Org",
				QueriedOrganization: tt.queriedOrg,
			})
			assert.Empty(t, findings)
		})
	}
}

func TestReverseRIRPlugin_TrimsHandleAndOrg(t *testing.T) {
	findings := newReverseRIRFinding("ARIN orgs database", ReverseRIRFindingData{
		Registry:            "arin",
		Handle:              "  ACME-1  ",
		Name:                "  Acme Corporation  ",
		QueriedOrganization: "  Acme Corp  ",
	})
	require.Len(t, findings, 2)

	assert.Equal(t, "ACME-1", findings[0].Value)
	assert.Equal(t, "Acme Corporation", findings[0].Data["org"])
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

func TestReverseRIRResult_ARINNormalizesDetailedCustomer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/rest/customers;name=*google*":
			_, _ = fmt.Fprint(w, `{"customers":{"customerRef":{"@handle":"C00976518","@name":"GOOGLE","$":"https://whois.arin.net/rest/customer/C00976518"}}}`)
		case "/rest/customer/C00976518":
			_, _ = fmt.Fprint(w, `{"customer":{"name":{"$":"GOOGLE"},"handle":{"$":"C00976518"},"streetAddress":{"line":{"$":"2400 Bayshore Parkway"}},"city":{"$":"Mountain View"},"iso3166-2":{"$":"CA"},"postalCode":{"$":"94043"},"iso3166-1":{"code2":{"$":"US"}},"registrationDate":{"$":"2004-12-21T00:00:00Z"},"updateDate":{"$":"2016-06-21T00:00:00Z"},"ref":{"$":"https://whois.arin.net/rest/customer/C00976518"}}}`)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	client, _ := injectedClient(t, server)
	findings := NewReverseRIRPlugin(client).queryArinEntity(
		context.Background(), arinCustomers, "google")
	result := requireRIRResult(t, findings)

	require.Equal(t, "arin", result.Registry)
	require.Equal(t, "C00976518", result.Handle)
	require.Equal(t, "GOOGLE", result.Name)
	require.Equal(t, []string{"2400 Bayshore Parkway"}, result.Street)
	require.Equal(t, "Mountain View", result.City)
	require.Equal(t, "CA", result.StateProvince)
	require.Equal(t, "94043", result.PostalCode)
	require.Equal(t, "US", result.Country)
	require.Equal(t, "2004-12-21T00:00:00Z", result.RegistrationDate)
	require.Equal(t, "2016-06-21T00:00:00Z", result.LastUpdated)
	require.Equal(t, "https://whois.arin.net/rest/customer/C00976518", result.SourceURL)
	require.NotNil(t, result.Record)
}

func TestReverseRIRResult_RIPENormalizesOrganisation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"objects":{"object":[{"type":"organisation","link":{"href":"https://rest.db.ripe.net/ripe/organisation/ORG-GOOG1-RIPE"},"primary-key":{"attribute":[{"name":"organisation","value":"ORG-GOOG1-RIPE"}]},"attributes":{"attribute":[{"name":"org-name","value":"Google LLC"},{"name":"address","value":"Gordon House"},{"name":"address","value":"Dublin"},{"name":"country","value":"IE"},{"name":"created","value":"2004-12-21T00:00:00Z"},{"name":"last-modified","value":"2016-06-21T00:00:00Z"}]}}]}}`)
	}))
	defer server.Close()

	client, _ := injectedClient(t, server)
	findings, err := NewReverseRIRPlugin(client).queryRIPE(context.Background(), "google")
	require.NoError(t, err)
	result := requireRIRResult(t, findings)

	require.Equal(t, "ripe", result.Registry)
	require.Equal(t, "Google LLC", result.Name)
	require.Equal(t, []string{"Gordon House", "Dublin"}, result.Street)
	require.Equal(t, "IE", result.Country)
	require.Equal(t, "2004-12-21T00:00:00Z", result.RegistrationDate)
	require.Equal(t, "2016-06-21T00:00:00Z", result.LastUpdated)
	require.Equal(t, "https://rest.db.ripe.net/ripe/organisation/ORG-GOOG1-RIPE", result.SourceURL)
}

func TestReverseRIRResult_APNICNormalizesRDAPEntity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/query":
			_, _ = fmt.Fprint(w, `[{"objectType":"organisation","primaryKey":"ORG-GA17-AP","attributes":[{"name":"org-name","values":["google"]},{"name":"address","values":["Birgunj"]},{"name":"country","values":["IN"]},{"name":"last-modified","values":["2017-12-30T12:57:12Z"]}]}]`)
		case "/entity/ORG-GA17-AP":
			_, _ = fmt.Fprint(w, rdapEntityJSON("ORG-GA17-AP", "google", "Birgunj", "", "", "", "IN"))
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	client, _ := injectedClient(t, server)
	findings, err := NewReverseRIRPlugin(client).queryAPNIC(context.Background(), "google")
	require.NoError(t, err)
	result := requireRIRResult(t, findings)

	require.Equal(t, "apnic", result.Registry)
	require.Equal(t, "google", result.Name)
	require.Equal(t, []string{"Birgunj"}, result.Street)
	require.Equal(t, "IN", result.Country)
	require.Equal(t, "2004-12-21T00:00:00Z", result.RegistrationDate)
	require.Equal(t, "2016-06-21T00:00:00Z", result.LastUpdated)
	require.Equal(t, "https://rdap.example/entity/ORG-GA17-AP", result.SourceURL)
}

func TestReverseRIRResult_AFRINICNormalizesRDAPEntity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"entitySearchResults":[%s]}`,
			rdapEntityJSON("ORG-GKL1-AFRINIC", "Google Kenya Limited", "ICEA Building", "Nairobi", "", "", "KE"))
	}))
	defer server.Close()

	client, _ := injectedClient(t, server)
	findings, err := NewReverseRIRPlugin(client).queryAFRINIC(context.Background(), "google")
	require.NoError(t, err)
	result := requireRIRResult(t, findings)

	require.Equal(t, "afrinic", result.Registry)
	require.Equal(t, "Google Kenya Limited", result.Name)
	require.Equal(t, []string{"ICEA Building"}, result.Street)
	require.Equal(t, "Nairobi", result.City)
	require.Equal(t, "KE", result.Country)
	require.Equal(t, "2004-12-21T00:00:00Z", result.RegistrationDate)
	require.Equal(t, "2016-06-21T00:00:00Z", result.LastUpdated)
}

func TestReverseRIRResult_LACNICNormalizesRDAPEntity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"entities":[%s]}`,
			rdapEntityJSON("UY-TELE-LACNIC", "Telefonica", "Av. Luis A. de Herrera", "Montevideo", "", "11200", "UY"))
	}))
	defer server.Close()

	client, _ := injectedClient(t, server)
	findings, err := NewReverseRIRPlugin(client).queryLACNIC(context.Background(), "telefonica")
	require.NoError(t, err)
	result := requireRIRResult(t, findings)

	require.Equal(t, "lacnic", result.Registry)
	require.Equal(t, "Telefonica", result.Name)
	require.Equal(t, []string{"Av. Luis A. de Herrera"}, result.Street)
	require.Equal(t, "Montevideo", result.City)
	require.Equal(t, "11200", result.PostalCode)
	require.Equal(t, "UY", result.Country)
	require.Equal(t, "2004-12-21T00:00:00Z", result.RegistrationDate)
	require.Equal(t, "2016-06-21T00:00:00Z", result.LastUpdated)
}

func requireRIRResult(t *testing.T, findings []plugins.Finding) ReverseRIRFindingData {
	t.Helper()
	for _, finding := range findings {
		if finding.Type != plugins.FindingRIRResult {
			continue
		}
		encoded, err := json.Marshal(finding.Data)
		require.NoError(t, err)
		var result ReverseRIRFindingData
		require.NoError(t, json.Unmarshal(encoded, &result))
		return result
	}
	t.Fatal("RIR result finding not emitted")
	return ReverseRIRFindingData{}
}

func rdapEntityJSON(handle, name, street, city, state, postalCode, country string) string {
	return fmt.Sprintf(`{"handle":%q,"links":[{"rel":"self","href":"https://rdap.example/entity/%s"}],"events":[{"eventAction":"registration","eventDate":"2004-12-21T00:00:00Z"},{"eventAction":"last changed","eventDate":"2016-06-21T00:00:00Z"}],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text",%q],["adr",{},"text",["","",%q,%q,%q,%q,%q]]]]}`,
		handle, handle, name, street, city, state, postalCode, country)
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
	// AFRINIC, and LACNIC. APNIC also performs a per-handle RDAP detail lookup.
	// AFRINIC and LACNIC share a path here; both are still queried.
	assert.Equal(t, []string{
		"/rest/orgs;name=*Acme*Corp*",
		"/rest/customers;name=*Acme*Corp*",
		"/search",
		"/query",
		"/entity/ORG-ACME-AP",
		"/rdap/entities",
		"/rdap/entities",
	}, transport.seen(), "every registry query must go through the injected client")

	byRegistry := map[string]string{}
	resultCount := 0
	for _, finding := range findings {
		assert.Equal(t, "reverse-rir", finding.Source)
		require.Len(t, finding.Confidences, 1)
		assert.Equal(t, confReverseRIRHandle, finding.Confidences[0].Score)
		assert.NotEmpty(t, finding.Confidences[0].Justification)
		if finding.Type == plugins.FindingRIRResult {
			resultCount++
			continue
		}

		assert.Equal(t, plugins.FindingCIDRHandle, finding.Type)
		assert.Equal(t, "", finding.Data["org"])
		byRegistry[finding.Data["registry"].(string)] = finding.Value
	}
	require.Equal(t, 5, resultCount)
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

// ── ArinRefs UnmarshalJSON (reverse_rir.go) ─────────────────────────────────

func TestArinRefs_UnmarshalArray(t *testing.T) {
	data := `[{"@handle":"ACME-1","@name":"Acme"},{"@handle":"ACME-2","@name":"Acme Inc"}]`
	var refs ArinRefs
	require.NoError(t, json.Unmarshal([]byte(data), &refs))
	require.Len(t, refs, 2)
	assert.Equal(t, "ACME-1", refs[0].Handle)
	assert.Equal(t, "ACME-2", refs[1].Handle)
}

func TestArinRefs_UnmarshalSingleObject(t *testing.T) {
	data := `{"@handle":"PS-1576","@name":"Praetorian Security, Inc."}`
	var refs ArinRefs
	require.NoError(t, json.Unmarshal([]byte(data), &refs))
	require.Len(t, refs, 1)
	assert.Equal(t, "PS-1576", refs[0].Handle)
}

func TestArinRefs_UnmarshalNull(t *testing.T) {
	data := `null`
	var refs ArinRefs
	require.NoError(t, json.Unmarshal([]byte(data), &refs))
	assert.Empty(t, refs)
}

func TestReverseRIRPlugin_Accepts(t *testing.T) {
	plugin, ok := plugins.Get("reverse-rir")
	require.True(t, ok)
	assert.True(t, plugin.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.False(t, plugin.Accepts(plugins.Input{OrgName: ""}))
	assert.False(t, plugin.Accepts(plugins.Input{OrgName: " \t\n"}))
	assert.False(t, plugin.Accepts(plugins.Input{}))
}

func TestReverseRIRPlugin_Metadata(t *testing.T) {
	plugin, ok := plugins.Get("reverse-rir")
	require.True(t, ok)
	assert.Equal(t, "reverse-rir", plugin.Name())
	assert.Equal(t, 1, plugin.Phase())
	assert.Equal(t, "cidr", plugin.Category())
	assert.NotEmpty(t, plugin.Description())
}
