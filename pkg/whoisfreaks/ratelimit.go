package whoisfreaks

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Category identifies a WhoisFreaks rate-limit bucket. The provider meters
// separate endpoint families independently, so each category tracks its own
// remaining/reset window.
type Category int

const (
	CatLive Category = iota
	CatBulk
	CatHistoricalReverse
)

// Response headers carrying the provider's rate-limit signals.
const (
	headerRemaining = "x-ratelimit-remaining"
	headerReset     = "x-ratelimit-reset"
)

// Backoff clamps (security T7). Parsed provider reset values are never trusted
// blindly: a value below the floor is raised to it, a value above the cap is
// lowered to it, and a missing/garbage value on a 429 falls back to the
// conservative default. These bound self-inflicted denial from a hostile or
// buggy provider sending an absurd reset.
const (
	minResetWait     = 100 * time.Millisecond // floor for any tracked backoff window
	maxResetWait     = 5 * time.Minute        // cap so a huge reset can't stall the fleet
	defaultResetWait = 2 * time.Second        // conservative default when a 429 lacks a usable reset
)

// Limiter paces requests per category. It is an interface so a caller (Guard's
// fleet governor) can inject a process-shared limiter without any client
// change; the package default is headerLimiter.
type Limiter interface {
	// Wait blocks until a request in cat is allowed or ctx is done. It returns
	// ctx.Err() if the context is cancelled while waiting.
	Wait(ctx context.Context, cat Category) error
	// Observe updates a category's state from a response's rate-limit headers
	// and status code.
	Observe(cat Category, h http.Header, statusCode int)
}

// rlState is the mutable per-category state. Its mutex guards only its own
// fields, so distinct categories never contend.
type rlState struct {
	mu        sync.Mutex
	remaining int
	resetAt   time.Time
}

// headerLimiter is the default reactive limiter: it derives its window from the
// provider's x-ratelimit-* headers rather than a fixed rate. Per-category state
// is isolated and mutex-guarded; the states map is built once at construction
// and never written again, so concurrent reads of it are race-free.
type headerLimiter struct {
	states map[Category]*rlState
}

// newHeaderLimiter returns a headerLimiter with isolated state pre-allocated for
// every defined category.
func newHeaderLimiter() *headerLimiter {
	states := make(map[Category]*rlState, 3)
	for _, c := range []Category{CatLive, CatBulk, CatHistoricalReverse} {
		states[c] = &rlState{}
	}
	return &headerLimiter{states: states}
}

// state returns the isolated state for cat, or nil for an unknown category
// (treated as unconstrained). The map is read-only after construction.
func (l *headerLimiter) state(cat Category) *rlState {
	return l.states[cat]
}

// Wait blocks until the category's window permits a request or ctx is done.
func (l *headerLimiter) Wait(ctx context.Context, cat Category) error {
	s := l.state(cat)
	if s == nil {
		return ctxErr(ctx)
	}

	s.mu.Lock()
	remaining := s.remaining
	resetAt := s.resetAt
	s.mu.Unlock()

	// Tokens available, or we have no window to honor yet: proceed (still
	// respecting an already-cancelled context).
	if remaining > 0 || resetAt.IsZero() {
		return ctxErr(ctx)
	}

	wait := time.Until(resetAt)
	if wait <= 0 {
		return ctxErr(ctx)
	}
	if wait > maxResetWait { // defensive belt over the clamp applied in Observe
		wait = maxResetWait
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Observe folds a response's rate-limit signals into the category's state.
func (l *headerLimiter) Observe(cat Category, h http.Header, statusCode int) {
	s := l.state(cat)
	if s == nil {
		return
	}

	resetAt, resetOK := parseResetHeader(h)

	s.mu.Lock()
	defer s.mu.Unlock()

	if statusCode == http.StatusTooManyRequests {
		// Rate limited: exhaust the window and back off until reset. A missing
		// or garbage reset header falls back to the conservative default rather
		// than being trusted or ignored.
		s.remaining = 0
		if resetOK {
			s.resetAt = resetAt
		} else {
			s.resetAt = time.Now().Add(defaultResetWait)
		}
		return
	}

	if n, ok := parseRemaining(h.Get(headerRemaining)); ok {
		s.remaining = n
	}
	if resetOK {
		s.resetAt = resetAt
	}
}

// parseRemaining parses x-ratelimit-remaining. A missing, non-numeric, or
// negative value is rejected (ok=false) so a spoofed header can't mislead
// pacing.
func parseRemaining(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// parseResetNanos parses the x-ratelimit-reset header value, which the provider
// expresses in NANOSECONDS (spec §3.3 — the "ns gotcha": the value is already
// nanoseconds, so it converts to a time.Duration 1:1, never multiplied). It
// returns ok=false for a missing, non-numeric, or negative value (security T7:
// reject negatives/NaN). Absurdly large values parse successfully here and are
// clamped by the caller.
//
// Interpretation [VERIFY §11]: the value is a duration-until-reset. Switching to
// an absolute epoch-ns timestamp is the single-line change in parseResetHeader.
func parseResetNanos(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return time.Duration(n), true // nanoseconds → Duration (1 ns == 1)
}

// parseResetHeader converts the reset header into an absolute instant, clamping
// the delay to [minResetWait, maxResetWait]. ok=false when the header is
// unusable.
func parseResetHeader(h http.Header) (time.Time, bool) {
	d, ok := parseResetNanos(h.Get(headerReset))
	if !ok {
		return time.Time{}, false
	}
	// Interpretation [VERIFY §11]: duration-until-reset.
	// Absolute epoch-ns would instead be: time.Unix(0, int64(d)).
	return time.Now().Add(clampWait(d)), true
}

// clampWait bounds a backoff duration to a sane window.
func clampWait(d time.Duration) time.Duration {
	switch {
	case d < minResetWait:
		return minResetWait
	case d > maxResetWait:
		return maxResetWait
	default:
		return d
	}
}

// ctxErr returns ctx.Err() if the context is already done, else nil, without
// blocking.
func ctxErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
