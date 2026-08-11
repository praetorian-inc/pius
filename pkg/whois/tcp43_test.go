package whois

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/pius/pkg/lib/netutil"
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

// stubTCP43RawFnFunc swaps the package-level tcp43RawFn test seam for a
// caller-supplied function, restoring the original via t.Cleanup. Unlike
// stubTCP43RawFn's fixed response map, this lets a test drive per-hop
// errors and side effects (e.g. cancelling the context mid-chain), which
// the classification tests below need.
//
// NOT safe for use with t.Parallel(): mutates shared package-level state.
func stubTCP43RawFnFunc(t *testing.T, fn func(ctx context.Context, domain, server string) (string, error)) {
	t.Helper()

	orig := tcp43RawFn
	tcp43RawFn = fn
	t.Cleanup(func() { tcp43RawFn = orig })
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

			result, err := tcp43Raw(context.Background(), "example.com")

			require.Error(t, err)
			assert.Contains(t, err.Error(), "no record beyond bootstrap")
			assert.Empty(t, result.Raw)
			assert.NotContains(t, result.Raw, "IANA Registry Operator")
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

	result, err := tcp43Raw(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Contains(t, result.Raw, "Example Inc")
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

	result, err := tcp43Raw(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Contains(t, result.Raw, "Example Inc")
	assert.NotContains(t, result.Raw, "IANA Registry Operator")
	assert.Equal(t, []string{defaultServer, registrar}, *dialed)
	assert.Equal(t, registrar, result.Server)
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

		result, err := tcp43Raw(context.Background(), "example.com")

		require.NoError(t, err)
		assert.Contains(t, result.Raw, "Example Inc")
		assert.Equal(t, registrar, result.Server)
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

		result, err := tcp43Raw(context.Background(), "example.com")

		require.NoError(t, err)
		assert.Contains(t, result.Raw, "Example Inc")
		assert.Equal(t, registry, result.Server)
	})

	// A record obtained only from the bootstrap server is never salvaged, so
	// there is no answering server to report either.
	t.Run("bootstrap-only chain reports nothing", func(t *testing.T) {
		stubTCP43RawFn(t, map[string]string{
			defaultServer: "organisation: IANA Registry Operator\n",
		})

		result, err := tcp43Raw(context.Background(), "example.com")

		require.Error(t, err)
		assert.Empty(t, result.Raw)
		assert.Empty(t, result.Server)
	})
}

// ENG-5453: when a hop's transport error wraps netutil.ErrSSRFRefused but a
// prior good record already exists, the chain salvages that record (nil
// error) exactly as it would for any other hop failure — but the returned
// Reason must still identify the failure as an SSRF refusal, not a generic
// referral failure. This is the signal an attempted-attack case must not
// lose just because the chain happened to have something to fall back on.
func TestTCP43Raw_SSRFRefusalWithPriorRecordSalvagesWithReason(t *testing.T) {
	const registry = "whois.nic.example"
	const registrar = "whois.registrar.example"

	stubTCP43RawFnFunc(t, func(_ context.Context, _ string, server string) (string, error) {
		switch server {
		case defaultServer:
			return "refer: " + registry + "\n", nil
		case registry:
			return "Registrant Organization: Example Inc\nRegistrar WHOIS Server: " + registrar + "\n", nil
		case registrar:
			return "", fmt.Errorf("dial %s: %w", registrar, netutil.ErrSSRFRefused)
		default:
			return "", fmt.Errorf("stub: unexpected server dialed: %q", server)
		}
	})

	result, err := tcp43Raw(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Contains(t, result.Raw, "Example Inc")
	assert.Equal(t, registry, result.Server)
	assert.Equal(t, chainSSRFRefused, result.Reason)
}

// ENG-5453: when a hop's transport error wraps netutil.ErrSSRFRefused and
// there is no prior record to salvage, tcp43Raw returns an error — but the
// Reason must still report chainSSRFRefused. The whole point of this
// ticket is that an attempted-attack trace must be distinguishable from
// background noise even on the failure path.
func TestTCP43Raw_SSRFRefusalWithNoPriorRecordReportsReason(t *testing.T) {
	const registry = "whois.nic.example"

	stubTCP43RawFnFunc(t, func(_ context.Context, _ string, server string) (string, error) {
		switch server {
		case defaultServer:
			return "refer: " + registry + "\n", nil
		case registry:
			return "", fmt.Errorf("dial %s: %w", registry, netutil.ErrSSRFRefused)
		default:
			return "", fmt.Errorf("stub: unexpected server dialed: %q", server)
		}
	})

	result, err := tcp43Raw(context.Background(), "example.com")

	require.Error(t, err)
	assert.Equal(t, chainSSRFRefused, result.Reason)
}

// ENG-5453: a generic (non-SSRF) hop transport error must classify as
// chainReferral, not chainSSRFRefused. Before this ticket both cases
// produced an identical generic transport error; this test proves the two
// causes are now distinguishable — that distinction is the entire point of
// the ticket.
func TestTCP43Raw_GenericHopErrorReportsReferralReason(t *testing.T) {
	const registry = "whois.nic.example"

	stubTCP43RawFnFunc(t, func(_ context.Context, _ string, server string) (string, error) {
		switch server {
		case defaultServer:
			return "refer: " + registry + "\n", nil
		case registry:
			return "", errors.New("connection refused")
		default:
			return "", fmt.Errorf("stub: unexpected server dialed: %q", server)
		}
	})

	result, err := tcp43Raw(context.Background(), "example.com")

	require.Error(t, err)
	assert.Equal(t, chainReferral, result.Reason)
}

// ENG-5453: a chain that completes normally (referral target answers with
// no further referral) must report chainComplete.
func TestTCP43Raw_CleanChainReportsComplete(t *testing.T) {
	const registrar = "whois.nic.example"

	responses := map[string]string{
		defaultServer: "refer: " + registrar + "\n",
		registrar:     "Registrant Organization: Example Inc\n",
	}
	stubTCP43RawFn(t, responses)

	result, err := tcp43Raw(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Contains(t, result.Raw, "Example Inc")
	assert.Equal(t, chainComplete, result.Reason)
}

// ENG-5453: a chain that keeps emitting a fresh referral on every hop
// exhausts maxReferrals with a referral still pending (never followed).
// That must classify as chainBudget, distinct from a chain that ended
// because a hop actually failed.
func TestTCP43Raw_BudgetExhaustedWithPendingReferralReportsBudgetReason(t *testing.T) {
	dials := 0
	stubTCP43RawFnFunc(t, func(_ context.Context, _ string, server string) (string, error) {
		dials++
		next := fmt.Sprintf("whois.hop%d.example", dials)
		return "Registrant Organization: Hop Org\nrefer: " + next + "\n", nil
	})

	result, err := tcp43Raw(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Contains(t, result.Raw, "Hop Org")
	assert.Equal(t, chainBudget, result.Reason)
}

// ENG-5453: a ctx cancellation/deadline observed mid-chain, with a prior
// good record already collected, must salvage that record (nil error) and
// report chainDeadline — distinguishing "we ran out of time" from either
// referral failure or SSRF refusal.
func TestTCP43Raw_DeadlineMidChainSalvagesWithReason(t *testing.T) {
	const registry = "whois.nic.example"
	const registrar = "whois.registrar.example"

	ctx, cancel := context.WithCancel(context.Background())

	stubTCP43RawFnFunc(t, func(_ context.Context, _ string, server string) (string, error) {
		switch server {
		case defaultServer:
			return "refer: " + registry + "\n", nil
		case registry:
			// Cancel here so the loop observes ctx.Err() before dialing
			// the next hop (registrar), which must never be reached.
			cancel()
			return "Registrant Organization: Example Inc\nrefer: " + registrar + "\n", nil
		default:
			return "", fmt.Errorf("stub: unexpected server dialed: %q", server)
		}
	})

	result, err := tcp43Raw(ctx, "example.com")

	require.NoError(t, err)
	assert.Contains(t, result.Raw, "Example Inc")
	assert.Equal(t, chainDeadline, result.Reason)
}
