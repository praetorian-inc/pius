package whois

import (
	"context"
	"fmt"
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
	orig := tcp43RawFn
	tcp43RawFn = func(_ context.Context, _ string, server string) (string, error) {
		dialed = append(dialed, server)
		raw, ok := responses[server]
		if !ok {
			return "", fmt.Errorf("stub: unexpected server dialed: %q", server)
		}
		return raw, nil
	}
	t.Cleanup(func() { tcp43RawFn = orig })

	return &dialed
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

// ENG-5457: a referral cycle (A→B→A) must be detected and short-circuited
// rather than burning the entire hop budget.
func TestTCP43Raw_ReferralCycleDetected(t *testing.T) {
	const serverA = "whois.a.example"
	const serverB = "whois.b.example"

	responses := map[string]string{
		defaultServer: "refer: " + serverA + "\n",
		serverA:       "Registrant Organization: Example Inc\nrefer: " + serverB + "\n",
		serverB:       "Registrant Organization: Example Inc\nrefer: " + serverA + "\n",
	}
	dialed := stubTCP43RawFn(t, responses)

	record, _, err := tcp43Raw(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Contains(t, record, "Example Inc")
	// Without cycle detection the chain would continue to serverA again.
	// With it, the chain stops after visiting defaultServer, A, B.
	assert.Equal(t, []string{defaultServer, serverA, serverB}, *dialed)
}

// ENG-5457: a referral cycle disguised by a trailing dot must still be
// caught. "whois.a.example" and "whois.a.example." are the same DNS name.
func TestTCP43Raw_ReferralCycleNormalizedComparison(t *testing.T) {
	const registry = "whois.registry.example"
	const registrar = "whois.registrar.example"

	responses := map[string]string{
		defaultServer: "refer: " + registry + "\n",
		registry:      "Registrant Organization: Example Inc\nrefer: " + registrar + "\n",
		registrar:     "Registrant Organization: Example Inc\nrefer: " + registry + ".\n",
	}
	dialed := stubTCP43RawFn(t, responses)

	record, _, err := tcp43Raw(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Contains(t, record, "Example Inc")
	// The trailing-dot referral targets "whois.registry.example." which
	// normalizes to the already-visited "whois.registry.example".
	assert.Equal(t, []string{defaultServer, registry, registrar}, *dialed)
}

// ENG-5457: a referral that cycles back to the bootstrap seed server must
// be caught, and the post-bootstrap record salvaged.
func TestTCP43Raw_ReferralCycleBackToSeedSalvages(t *testing.T) {
	const registry = "whois.nic.example"

	responses := map[string]string{
		defaultServer: "refer: " + registry + "\n",
		registry:      "Registrant Organization: Example Inc\nrefer: " + defaultServer + "\n",
	}
	dialed := stubTCP43RawFn(t, responses)

	record, server, err := tcp43Raw(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Contains(t, record, "Example Inc")
	assert.Equal(t, registry, server)
	// The cycle back to the bootstrap is detected; no third dial.
	assert.Equal(t, []string{defaultServer, registry}, *dialed)
}

func TestNormalizeServer(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"bare hostname", "whois.nic.uk", "whois.nic.uk"},
		{"trailing dot", "whois.nic.uk.", "whois.nic.uk"},
		{"uppercase", "WHOIS.NIC.UK", "whois.nic.uk"},
		{"http prefix", "http://whois.nic.uk", "whois.nic.uk"},
		{"https prefix", "https://whois.nic.uk/", "whois.nic.uk"},
		{"explicit port", "whois.nic.uk:43", "whois.nic.uk"},
		{"all combined", "HTTPS://Whois.NIC.UK.:43/", "whois.nic.uk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, normalizeServer(tt.input))
		})
	}
}
