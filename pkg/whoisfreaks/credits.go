package whoisfreaks

import "sync"

// maxChainCertsForCredit caps the number of chain certificates that can drive
// credit math. It matches the chain-validation processing cap (T6/§3.7) so a
// provider-inflated sslCertificates[] cannot inflate local credit accounting
// (security T7): credits are derived from the request plus a capped, never a
// blindly provider-controlled, cert count.
const maxChainCertsForCredit = 16

// creditsFor computes the credits a single ssl/live call costs.
//
//   - ok=false (429 / 4xx / empty response): 0 — those outcomes are free.
//   - Chain=false: 1 — the base ssl/live request only.
//   - Chain=true: 1 + ceil(chainCerts/2), i.e. +1 per two chain certificates,
//     with chainCerts floored at 0 and capped at maxChainCertsForCredit.
//
// The Raw option adds nothing.
func creditsFor(o SSLOptions, chainCerts int, ok bool) int {
	if !ok {
		return 0
	}
	n := 1
	if o.Chain {
		c := chainCerts
		if c < 0 {
			c = 0
		}
		if c > maxChainCertsForCredit {
			c = maxChainCertsForCredit
		}
		n += (c + 1) / 2 // ceil(c/2)
	}
	return n
}

// CreditMeter accumulates the credits charged across calls. It is safe for
// concurrent use and is injectable via WithCreditMeter so a caller can share one
// meter across many lookups.
type CreditMeter struct {
	mu    sync.Mutex
	total int
}

// NewCreditMeter returns a ready-to-use CreditMeter.
func NewCreditMeter() *CreditMeter {
	return &CreditMeter{}
}

// Total returns the running sum of charged credits.
func (m *CreditMeter) Total() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.total
}

// charge adds n credits to the running total. Non-positive charges (e.g. a free
// 429/4xx/empty outcome) are a no-op.
func (m *CreditMeter) charge(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	m.total += n
	m.mu.Unlock()
}
