package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const whoisFreaksTestKey = "whoisfreaks-key-must-never-leak"

// Captured from the live API for praetorian.com, trimmed to the contact block.
// Note the redacted name/street beside a populated Organization, and an email
// that is a contact-form URL rather than an address.
const whoisFreaksRealRaw = `
Domain Name: praetorian.com
Registrar WHOIS Server: whois.squarespace.domains
Registrar: Squarespace Domains II LLC
Creation Date: 2004-02-15T19:09:32Z
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: Praetorian
Registrant Street: REDACTED FOR PRIVACY
Registrant State/Province: TX
Registrant Country: US
Registrant Email: https://domains.squarespace.com/whois-contact-form
Name Server: dom.ns.cloudflare.com
`

func newTestWhoisFreaks(t *testing.T, handler http.HandlerFunc) *WhoisFreaksPlugin {
	t.Helper()
	t.Setenv("WHOISFREAKS_API_KEY", whoisFreaksTestKey)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &WhoisFreaksPlugin{client: client.New(), baseURL: server.URL}
}

func TestWhoisFreaks_Metadata(t *testing.T) {
	p, ok := plugins.Get("whoisfreaks")
	require.True(t, ok, "whoisfreaks plugin must be registered")

	assert.Equal(t, "whoisfreaks", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, plugins.ModePassive, p.Mode())
	assert.Contains(t, p.Description(), "WHOISFREAKS_API_KEY")
}

func TestWhoisFreaks_Accepts_WithKeyAndDomain(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	p := &WhoisFreaksPlugin{client: client.New()}

	assert.True(t, p.Accepts(plugins.Input{Domain: "acme.com"}))
}

func TestWhoisFreaks_Accepts_RejectsWithoutKey(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "")
	p := &WhoisFreaksPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{Domain: "acme.com"}))
}

// This plugin keys off Domain, not OrgName — an org-only seed must not run it.
func TestWhoisFreaks_Accepts_RejectsWithoutDomain(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	p := &WhoisFreaksPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
}

func TestWhoisFreaks_Run_ExtractsPreseedsFromRealPayload(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"domain_name":       "praetorian.com",
		"domain_registered": "yes",
		"whois_raw_domain":  whoisFreaksRealRaw,
	})
	require.NoError(t, err)

	p := newTestWhoisFreaks(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "live", r.URL.Query().Get("whois"))
		assert.Equal(t, "praetorian.com", r.URL.Query().Get("domainName"))
		assert.Equal(t, whoisFreaksTestKey, r.URL.Query().Get("apiKey"))
		_, _ = w.Write(body)
	})

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "praetorian.com"})
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	// Routing the raw record through extractPreseeds is what keeps typing and
	// privacy filtering identical to the port-43 whois plugin.
	var companies []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingPreseed, f.Type)
		assert.Equal(t, "whoisfreaks", f.Source)
		if f.Data["preseed_type"] == "whois+company" {
			companies = append(companies, f.Value)
		}
	}
	assert.Equal(t, []string{"Praetorian"}, companies)
}

// "REDACTED FOR PRIVACY" is in whoisPrivacyNames, so it must not become a
// whois+name pivot even though the vendor returned it as the registrant name.
func TestWhoisFreaks_Run_FiltersRedactedRegistrantName(t *testing.T) {
	p := newTestWhoisFreaks(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"domain_registered":"yes","whois_raw_domain":` +
			mustJSONString(whoisFreaksRealRaw) + `}`))
	})

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "praetorian.com"})
	require.NoError(t, err)

	for _, f := range findings {
		assert.NotEqual(t, "whois+name", f.Data["preseed_type"],
			"redacted registrant name must not become a pivot: %q", f.Value)
	}
}

// A contact-form URL is not an address; extractPreseeds guards on mail.ParseAddress.
func TestWhoisFreaks_Run_ContactFormURLIsNotAnEmailPreseed(t *testing.T) {
	p := newTestWhoisFreaks(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"domain_registered":"yes","whois_raw_domain":` +
			mustJSONString(whoisFreaksRealRaw) + `}`))
	})

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "praetorian.com"})
	require.NoError(t, err)

	for _, f := range findings {
		assert.NotEqual(t, "whois+email", f.Data["preseed_type"],
			"a contact-form URL must not be emitted as an email pivot: %q", f.Value)
	}
}

// Thin registries return only the registry-level record, under a key the vendor
// misspells.
func TestWhoisFreaks_Run_FallsBackToRegistryRaw(t *testing.T) {
	p := newTestWhoisFreaks(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"domain_registered":"yes","whois_raw_domain":"",` +
			`"registry_data":{"whois_raw_registery":"Domain Name: thin-registry.org\nRegistrant Organization: Thin Registry Co\n"}}`))
	})

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "thin-registry.org"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "Thin Registry Co", findings[0].Value)
	assert.Equal(t, "whois+company", findings[0].Data["preseed_type"])
}

// Guards the upstream misspelling against a well-meaning "fix".
func TestWhoisFreaks_RegistryRawJSONTagIsTheUpstreamMisspelling(t *testing.T) {
	var payload whoisFreaksLiveResponse
	require.NoError(t, json.Unmarshal(
		[]byte(`{"registry_data":{"whois_raw_registery":"sentinel"}}`), &payload))

	assert.Equal(t, "sentinel", payload.RegistryData.RawRegistry,
		`upstream spells this "whois_raw_registery"; correcting the tag silently breaks thin-registry lookups`)
}

func TestWhoisFreaks_Run_UnregisteredIsNotAnError(t *testing.T) {
	p := newTestWhoisFreaks(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"domain_name":"nope.com","domain_registered":"no"}`))
	})

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "nope.com"})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestWhoisFreaks_Run_NoRawRecordIsAnError(t *testing.T) {
	p := newTestWhoisFreaks(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"domain_registered":"yes"}`))
	})

	_, err := p.Run(context.Background(), plugins.Input{Domain: "empty-record.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no raw WHOIS record")
}

func TestWhoisFreaks_Run_SubdomainReducesToRootDomain(t *testing.T) {
	var queried string
	p := newTestWhoisFreaks(t, func(w http.ResponseWriter, r *http.Request) {
		queried = r.URL.Query().Get("domainName")
		_, _ = w.Write([]byte(`{"domain_registered":"yes","whois_raw_domain":"Domain Name: acme.com\nRegistrant Organization: Acme\n"}`))
	})

	_, err := p.Run(context.Background(), plugins.Input{Domain: "www.dev.acme.com"})
	require.NoError(t, err)
	assert.Equal(t, "acme.com", queried)
}

// Auth is a query parameter, so a wrapped transport error would carry the key
// into logs. pkg/client's own sanitizeURL does not redact the camelCase
// "apiKey" name, so the plugin must discard the error rather than rely on it.
func TestWhoisFreaks_Run_ErrorNeverContainsTheAPIKey(t *testing.T) {
	p := newTestWhoisFreaks(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})

	_, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), whoisFreaksTestKey)
	assert.NotContains(t, err.Error(), "apiKey=")
}

func TestWhoisFreaks_Run_RejectsUnusableDomain(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", whoisFreaksTestKey)
	p := &WhoisFreaksPlugin{client: client.New(), baseURL: "http://127.0.0.1:1"}

	_, err := p.Run(context.Background(), plugins.Input{Domain: "localhost"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root domain")
}

// A cancelled run must abort rather than emit preseeds.
func TestWhoisFreaks_Run_HonoursContextCancellation(t *testing.T) {
	p := newTestWhoisFreaks(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"domain_registered":"yes","whois_raw_domain":"Domain Name: acme.com\nRegistrant Organization: Acme\n"}`))
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Run(ctx, plugins.Input{Domain: "acme.com"})
	require.Error(t, err)
}

// mustJSONString quotes s as a JSON string so multi-line raw WHOIS text can be
// embedded in a literal response body.
func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
