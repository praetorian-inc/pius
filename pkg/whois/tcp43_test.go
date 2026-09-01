package whois

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubTCP43RawFn overrides the package-level tcp43RawFn test seam with a
// canned server->response map and records the ordered list of servers
// dialed. It restores the original via t.Cleanup, so tests remain hermetic
// (no real network I/O) and isolated from each other.
//
// NOT safe for use with t.Parallel(): tests using this helper mutate the
// shared package-level tcp43RawFn and would race against one another.
func stubTCP43RawFn(t *testing.T, responses map[string]string) *[]string {
	t.Helper()

	dialed := make([]string, 0, maxReferrals)
	originalRaw := tcp43RawFn
	originalLookup := lookupWhoisSRVFn
	tcp43RawFn = func(_ context.Context, _ string, server string) (string, error) {
		dialed = append(dialed, server)
		raw, ok := responses[server]
		if !ok {
			return "", fmt.Errorf("stub: unexpected server dialed: %q", server)
		}
		return raw, nil
	}
	lookupWhoisSRVFn = func(context.Context, string) ([]*net.SRV, error) { return nil, nil }
	t.Cleanup(func() {
		tcp43RawFn = originalRaw
		lookupWhoisSRVFn = originalLookup
	})

	return &dialed
}

func TestTCP43Raw_UsesTLDWhoisSRVBeforeIANA(t *testing.T) {
	const registry = "whois.nic.uk"
	dialed := stubTCP43RawFn(t, map[string]string{
		registry: "Registrant Organization: Example Inc\n",
	})
	lookupWhoisSRVFn = func(_ context.Context, tld string) ([]*net.SRV, error) {
		assert.Equal(t, "uk", tld)
		return []*net.SRV{{Target: registry + ".", Port: 43}}, nil
	}

	record, server, err := tcp43Raw(context.Background(), "example.org.uk")

	require.NoError(t, err)
	assert.Contains(t, record, "Example Inc")
	assert.Equal(t, registry, server)
	assert.Equal(t, []string{registry}, *dialed)
}

func TestTCP43Raw_FallsBackToIANAWithoutWhoisSRV(t *testing.T) {
	const registry = "whois.nic.example"
	dialed := stubTCP43RawFn(t, map[string]string{
		defaultServer: "refer: " + registry + "\n",
		registry:      "Registrant Organization: Example Inc\n",
	})

	_, _, err := tcp43Raw(context.Background(), "example.test")

	require.NoError(t, err)
	assert.Equal(t, []string{defaultServer, registry}, *dialed)
}

func TestTCP43Lookup_AppliesDNSPTFallback(t *testing.T) {
	const registry = "whois.dns.pt"
	stubTCP43RawFn(t, map[string]string{
		defaultServer: "refer: " + registry + "\n",
		registry:      readDomainFixture(t, "dns_pt.raw"),
	})

	result, err := tcp43Lookup(context.Background(), "example.pt")

	require.NoError(t, err)
	assert.Equal(t, registry, result.WhoisServer)
	assert.Equal(t, "Example Networks", result.Registrant.Name)
	assert.Equal(t, "Example Networks", result.RegistrantIdentity)
	assert.Equal(t, "1 Example Street", result.Registrant.Street)
	assert.Equal(t, "Lisbon", result.Registrant.City)
	assert.Equal(t, "Lisbon", result.Registrant.Province)
	assert.Equal(t, "1000-001", result.Registrant.PostalCode)
	assert.Equal(t, "PT", result.Registrant.Country)
	assert.Equal(t, "Example Registrar", result.Admin.Name)
	assert.Equal(t, "PT", result.Admin.Country)
	assert.Equal(t, []string{"ns1.example.net", "ns2.example.net"}, result.NameServers)
}

func TestTCP43Lookup_PreservesRegistryCORecordAfterRegistrarFailure(t *testing.T) {
	const registry = "whois.registry.co"
	stubTCP43RawFn(t, map[string]string{
		defaultServer: "refer: " + registry + "\n",
		registry:      readDomainFixture(t, "registry_co.raw"),
	})

	result, err := tcp43Lookup(context.Background(), "example.co")

	require.NoError(t, err)
	assert.Equal(t, registry, result.WhoisServer)
	assert.Equal(t, "Example Registrar, LLC", result.Registrar)
	assert.Equal(t, "unsigned", result.DNSSEC)
	assert.Empty(t, result.RegistrantIdentity)
	assert.Empty(t, result.ContactEmail)
}

func TestTCP43Lookup_RecoversNICChileRecord(t *testing.T) {
	const registry = "whois.nic.cl"
	stubTCP43RawFn(t, map[string]string{
		defaultServer: "refer: " + registry + "\n",
		registry:      readDomainFixture(t, "nic_cl.raw"),
	})

	result, err := tcp43Lookup(context.Background(), "example.cl")

	require.NoError(t, err)
	assert.Equal(t, registry, result.WhoisServer)
	assert.Equal(t, "Example Media LLC", result.RegistrantIdentity)
	assert.Equal(t, "Example Registrar", result.Registrar)
}

func TestTCP43Lookup_RejectsRegistryDenial(t *testing.T) {
	const registry = "whois.nic.ch"
	stubTCP43RawFn(t, map[string]string{
		defaultServer: "refer: " + registry + "\n",
		registry:      readDomainFixture(t, "nic_ch_denied.raw"),
	})

	result, err := tcp43Lookup(context.Background(), "example.ch")

	assert.ErrorIs(t, err, errRegistryAccessDenied)
	assert.Equal(t, DomainResult{}, result)
}

func TestApplyRawDomainFallback_DispatchesByTLD(t *testing.T) {
	result := DomainResult{Domain: "example.co.il"}
	const raw = `% registry record
domain: example.co.il

# holder record
descr: Example Ltd.
e-mail: admin AT example.com
`

	applyRawDomainFallback(&result, newRawDomainRecord(raw))

	assert.Equal(t, "Example Ltd.", result.Registrant.Organization)
	assert.Equal(t, "admin@example.com", result.Registrant.Email)
}

func TestApplyDNSPTFallback_PreservesParsedValues(t *testing.T) {
	result := DomainResult{
		Domain: "example.pt",
		Registrant: Contact{
			Name:    "Parsed Owner",
			Country: "GB",
		},
	}

	const raw = "Owner Name: Fallback Owner\nOwner Address: 1 Main St\nOwner Country Code: US\n"
	applyRawDomainFallback(&result, newRawDomainRecord(raw))

	assert.Equal(t, "Parsed Owner", result.Registrant.Name)
	assert.Equal(t, "GB", result.Registrant.Country)
	assert.Equal(t, "1 Main St", result.Registrant.Street)
}

func TestTCP43Raw_RegistryTimeoutDoesNotSalvageBootstrap(t *testing.T) {
	const registry = "whois.nic.net.sb"
	originalRaw := tcp43RawFn
	originalLookup := lookupWhoisSRVFn
	lookupWhoisSRVFn = func(context.Context, string) ([]*net.SRV, error) { return nil, nil }
	tcp43RawFn = func(_ context.Context, _ string, server string) (string, error) {
		if server == defaultServer {
			return "refer: " + registry + "\n", nil
		}
		return "", context.DeadlineExceeded
	}
	t.Cleanup(func() {
		tcp43RawFn = originalRaw
		lookupWhoisSRVFn = originalLookup
	})

	raw, server, err := tcp43Raw(context.Background(), "example.sb")

	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Empty(t, raw)
	assert.Empty(t, server)
}

// ENG-5450: a referral naming the bootstrap server with a trailing root dot
// (e.g. "whois.iana.org.") must still be recognized as the bootstrap server.
// DNS names are equal under a trailing dot; strings.EqualFold disagrees,
// which lets the IANA seed record (describing the TLD registry operator, not
// the domain's registrant) get salvaged into the returned record.
func TestTCP43Raw_BootstrapTrailingDotReferralNotSalvaged(t *testing.T) {
	tests := []struct {
		name            string
		bootstrapDotted string
	}{
		{"lowercase trailing dot", "whois.iana.org."},
		// Proves the fix keeps existing case-insensitivity rather than
		// trading it away for trailing-dot handling.
		{"mixed case trailing dot", "WHOIS.IANA.ORG."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responses := map[string]string{
				defaultServer:      "refer: " + tt.bootstrapDotted + "\n",
				tt.bootstrapDotted: "organisation: IANA Registry Operator\n",
			}
			stubTCP43RawFn(t, responses)

			record, _, err := tcp43Raw(context.Background(), "example.com")

			require.Error(t, err)
			assert.Contains(t, err.Error(), "no record beyond bootstrap")
			assert.Empty(t, record)
			assert.NotContains(t, record, "IANA Registry Operator")
		})
	}
}

// ENG-5450: a self-referral that differs from the current server only by a
// trailing dot must terminate the referral loop immediately, not burn an
// extra hop from the maxReferrals budget.
func TestTCP43Raw_SelfReferralTrailingDotNoExtraHop(t *testing.T) {
	const registrar = "whois.nic.example"
	const registrarDotted = registrar + "."

	responses := map[string]string{
		defaultServer:   "refer: " + registrar + "\n",
		registrar:       "Example Inc\nrefer: " + registrarDotted + "\n",
		registrarDotted: "Example Inc\nrefer: " + registrarDotted + "\n",
	}
	dialed := stubTCP43RawFn(t, responses)

	record, _, err := tcp43Raw(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Contains(t, record, "Example Inc")
	// Buggy behavior dials a third time (registrarDotted) because the
	// trailing-dot self-referral isn't recognized as identical to the
	// server already dialed.
	assert.Equal(t, []string{defaultServer, registrar}, *dialed)
}

// Regression guard: an ordinary referral chain with no trailing-dot
// weirdness must be unaffected by the fix.
func TestTCP43Raw_RegressionOrdinaryChainUnaffected(t *testing.T) {
	const registrar = "whois.nic.example"

	responses := map[string]string{
		defaultServer: "refer: " + registrar + "\n",
		registrar:     "Registrant Organization: Example Inc\n",
	}
	dialed := stubTCP43RawFn(t, responses)

	record, server, err := tcp43Raw(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Contains(t, record, "Example Inc")
	assert.NotContains(t, record, "IANA Registry Operator")
	assert.Equal(t, []string{defaultServer, registrar}, *dialed)
	assert.Equal(t, registrar, server)
}

// The returned server must be the one that answered the returned record — the
// deepest server reached, not the bootstrap server the chain started from and
// not the referral target that was never successfully queried.
func TestTCP43Raw_ReportsAnsweringServer(t *testing.T) {
	const registry = "whois.nic.example"
	const registrar = "whois.registrar.example"

	t.Run("deepest server in the chain", func(t *testing.T) {
		responses := map[string]string{
			defaultServer: "refer: " + registry + "\n",
			registry:      "Registrar WHOIS Server: " + registrar + "\n",
			registrar:     "Registrant Organization: Example Inc\n",
		}
		stubTCP43RawFn(t, responses)

		record, server, err := tcp43Raw(context.Background(), "example.com")

		require.NoError(t, err)
		assert.Contains(t, record, "Example Inc")
		assert.Equal(t, registrar, server)
	})

	// When a hop fails the last good record is salvaged; the reported server
	// must be the one that produced that record, not the hop that failed.
	t.Run("salvaged record reports the server that produced it", func(t *testing.T) {
		responses := map[string]string{
			defaultServer: "refer: " + registry + "\n",
			registry:      "Registrant Organization: Example Inc\nRegistrar WHOIS Server: " + registrar + "\n",
			// registrar absent: the stub errors on it.
		}
		stubTCP43RawFn(t, responses)

		record, server, err := tcp43Raw(context.Background(), "example.com")

		require.NoError(t, err)
		assert.Contains(t, record, "Example Inc")
		assert.Equal(t, registry, server)
	})

	// A record obtained only from the bootstrap server is never salvaged, so
	// there is no answering server to report either.
	t.Run("bootstrap-only chain reports nothing", func(t *testing.T) {
		stubTCP43RawFn(t, map[string]string{
			defaultServer: "organisation: IANA Registry Operator\n",
		})

		record, server, err := tcp43Raw(context.Background(), "example.com")

		require.Error(t, err)
		assert.Empty(t, record)
		assert.Empty(t, server)
	})
}
