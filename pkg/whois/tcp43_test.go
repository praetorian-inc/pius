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

			record, err := tcp43Raw(context.Background(), "example.com")

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

	record, err := tcp43Raw(context.Background(), "example.com")

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

	record, err := tcp43Raw(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Contains(t, record, "Example Inc")
	assert.NotContains(t, record, "IANA Registry Operator")
	assert.Equal(t, []string{defaultServer, registrar}, *dialed)
}
