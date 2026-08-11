package whoisfreaks

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCreditsFor pins the billing formula:
//   - !ok            -> 0 (429/4xx/empty are free)
//   - !Chain         -> 1 (base request only; chainCerts ignored)
//   - Chain          -> 1 + ceil(chainCerts/2), with chainCerts floored at 0 and
//     capped at maxChainCertsForCredit so a provider-inflated
//     sslCertificates[] cannot inflate local billing (security T7).
//
// The plan's core row is chainCerts {0,1,2,3,4} -> {1,2,2,3,3} with Chain=true.
func TestCreditsFor(t *testing.T) {
	t.Parallel()

	chain := SSLOptions{Chain: true}
	noChain := SSLOptions{Chain: false}

	tests := []struct {
		name       string
		opts       SSLOptions
		chainCerts int
		ok         bool
		want       int
	}{
		// Plan's canonical table: Chain=true, ceil(c/2)+1.
		{name: "chain 0 certs", opts: chain, chainCerts: 0, ok: true, want: 1},
		{name: "chain 1 cert", opts: chain, chainCerts: 1, ok: true, want: 2},
		{name: "chain 2 certs", opts: chain, chainCerts: 2, ok: true, want: 2},
		{name: "chain 3 certs", opts: chain, chainCerts: 3, ok: true, want: 3},
		{name: "chain 4 certs", opts: chain, chainCerts: 4, ok: true, want: 3},

		// Chain=false: always 1, chainCerts irrelevant.
		{name: "no chain, 0 certs", opts: noChain, chainCerts: 0, ok: true, want: 1},
		{name: "no chain ignores cert count", opts: noChain, chainCerts: 5, ok: true, want: 1},

		// !ok: always 0, regardless of options/cert count.
		{name: "not ok with chain", opts: chain, chainCerts: 4, ok: false, want: 0},
		{name: "not ok without chain", opts: noChain, chainCerts: 0, ok: false, want: 0},

		// Negative cert count floored to 0 (defensive against provider garbage).
		{name: "negative cert count floored to 0", opts: chain, chainCerts: -5, ok: true, want: 1},

		// Cap at maxChainCertsForCredit (16) -> 1 + ceil(16/2) = 9. [T7]
		{name: "cap boundary at 16", opts: chain, chainCerts: maxChainCertsForCredit, ok: true, want: 9},
		{name: "just below cap at 15", opts: chain, chainCerts: 15, ok: true, want: 9},
		{name: "just below cap at 14", opts: chain, chainCerts: 14, ok: true, want: 8},
		{name: "one over cap clamps to cap", opts: chain, chainCerts: 17, ok: true, want: 9},
		{name: "far over cap clamps to cap", opts: chain, chainCerts: 100, ok: true, want: 9},

		// Raw option adds nothing to the cost.
		{name: "raw option does not change cost", opts: SSLOptions{Chain: true, Raw: true}, chainCerts: 2, ok: true, want: 2},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := creditsFor(tt.opts, tt.chainCerts, tt.ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestCreditMeter_TotalAccumulatesAndNoOps verifies a fresh meter starts at 0,
// accumulates positive charges, and treats non-positive charges (a free
// 429/4xx/empty outcome) as a no-op.
func TestCreditMeter_TotalAccumulatesAndNoOps(t *testing.T) {
	t.Parallel()

	m := NewCreditMeter()
	assert.Equal(t, 0, m.Total(), "fresh meter starts at 0")

	m.charge(0)
	assert.Equal(t, 0, m.Total(), "zero charge is a no-op")

	m.charge(-5)
	assert.Equal(t, 0, m.Total(), "negative charge is a no-op")

	m.charge(3)
	assert.Equal(t, 3, m.Total())

	m.charge(2)
	assert.Equal(t, 5, m.Total(), "charges accumulate")

	m.charge(0)
	assert.Equal(t, 5, m.Total(), "later no-op leaves the total unchanged")
}

// TestCreditMeter_ChargeConcurrent_RaceClean drives charge from many goroutines
// at once and asserts the total is exactly the sum of the positive charges.
// Interleaved non-positive charges must not corrupt or inflate the total. Run
// under -race to prove the mutex actually guards the accumulator.
func TestCreditMeter_ChargeConcurrent_RaceClean(t *testing.T) {
	t.Parallel()

	m := NewCreditMeter()

	const posWorkers = 200
	const perCharge = 3
	const noopWorkers = 100

	var wg sync.WaitGroup
	for i := 0; i < posWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.charge(perCharge)
		}()
	}
	// Concurrent no-ops (free outcomes) must not affect the total.
	for i := 0; i < noopWorkers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m.charge(0)
			m.charge(-(i + 1))
		}(i)
	}
	wg.Wait()

	assert.Equal(t, posWorkers*perCharge, m.Total(), "total must equal the sum of positive charges only")
}
