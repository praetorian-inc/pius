package netutil

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ENG-5453: a refused dial must be identifiable as an SSRF guard refusal via
// errors.Is, not by string-matching the error message. This is what lets a
// caller (tcp43Raw) distinguish "the guard stopped a probe" from "the server
// was merely unreachable" — every other transport failure has a benign
// explanation, but a guard refusal never does.
func TestSSRFSafeControl_RefusesDisallowedAddress(t *testing.T) {
	err := SSRFSafeControl("tcp", "127.0.0.1:43", nil)

	require := assert.New(t)
	require.Error(err)
	require.True(errors.Is(err, ErrSSRFRefused), "expected errors.Is(err, ErrSSRFRefused) to match, got: %v", err)
}

// The guard's error is returned from inside net.Dialer.Control, so by the
// time any real caller observes it, the Go net package has wrapped it in a
// *net.OpError. If the sentinel doesn't survive that wrapping, the guard's
// refusal becomes indistinguishable from a real network error the moment a
// real dial fails — which is the exact bug this ticket fixes.
func TestSSRFSafeControl_SurvivesOpErrorWrapping(t *testing.T) {
	guardErr := SSRFSafeControl("tcp", "169.254.169.254:43", nil)
	require := assert.New(t)
	require.Error(guardErr)

	wrapped := &net.OpError{Op: "dial", Net: "tcp", Err: guardErr}

	require.True(errors.Is(wrapped, ErrSSRFRefused), "expected errors.Is to find ErrSSRFRefused through *net.OpError, got: %v", wrapped)
}

// Proves the sentinel is matched structurally (via %w wrapping), not by
// message text: rewording the wrapping error entirely must not break the
// match. A test that only exercised the original message text would pass
// even if the implementation used strings.Contains(err.Error(), "ssrf
// guard") — that string-matching approach is exactly what this ticket
// forbids, because any reword of the guard's message would silently break
// the classification.
func TestSSRFSafeControl_SurvivesRewordedWrapping(t *testing.T) {
	guardErr := SSRFSafeControl("tcp", "10.0.0.1:43", nil)
	require := assert.New(t)
	require.Error(guardErr)

	reworded := fmt.Errorf("completely different wording, nothing about ssrf here: %w", guardErr)

	require.True(errors.Is(reworded, ErrSSRFRefused), "expected errors.Is to match through arbitrary rewording, got: %v", reworded)
}

// A public address must be dialed normally. If the sentinel wrapping
// accidentally broadened what IsDisallowedIP refuses, this catches it.
func TestSSRFSafeControl_AllowsPublicAddress(t *testing.T) {
	err := SSRFSafeControl("tcp", "1.1.1.1:43", nil)

	assert.NoError(t, err)
}

// Malformed addresses and non-IP hosts are parse failures, not evidence of
// an SSRF attempt — a hostile referral never fails to parse, it names a
// disallowed IP. These branches must not be misclassified as
// ErrSSRFRefused, or a truly benign parse failure would be reported to
// operators as an attempted attack.
func TestSSRFSafeControl_MalformedAndNonIPNotReportedAsSSRFRefusal(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{"malformed address (no port)", "not-a-valid-address"},
		{"non-IP host", "example.com:43"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SSRFSafeControl("tcp", tt.address, nil)

			assert := assert.New(t)
			assert.Error(err)
			assert.False(errors.Is(err, ErrSSRFRefused), "expected errors.Is(err, ErrSSRFRefused) to be false for %q, got: %v", tt.address, err)
		})
	}
}
