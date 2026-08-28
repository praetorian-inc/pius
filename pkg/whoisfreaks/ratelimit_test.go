package whoisfreaks

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nsString renders a duration as its integer nanosecond count, the wire form of
// the x-ratelimit-reset header (spec §3.3: the value is already nanoseconds).
func nsString(d time.Duration) string {
	return strconv.FormatInt(int64(d), 10)
}

// readState reads a category's window under its own mutex so the concurrent
// -race test stays clean while these white-box assertions inspect the effect of
// Observe directly.
func readState(s *rlState) (remaining int, resetAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remaining, s.resetAt
}

// --- parseResetNanos: the "ns gotcha" and negative/huge handling [T7] ---------
//
// Both reset interpretations (duration-until-reset today; absolute epoch-ns is
// the documented single-line switch in parseResetHeader) funnel their raw value
// through parseResetNanos, which converts nanoseconds -> time.Duration 1:1 and
// never clamps. So this is the one place both readings are pinned: the numeric
// contract is identical, only the caller's now-relative vs. absolute framing
// differs.
func TestParseResetNanos(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		raw    string
		want   time.Duration
		wantOK bool
	}{
		{name: "empty string rejected", raw: "", want: 0, wantOK: false},
		{name: "whitespace-only rejected", raw: "   ", want: 0, wantOK: false},
		{name: "non-numeric rejected", raw: "soon", want: 0, wantOK: false},
		{name: "negative rejected (T7)", raw: "-1", want: 0, wantOK: false},
		{name: "large negative rejected (T7)", raw: "-1000000000", want: 0, wantOK: false},
		{name: "zero accepted as duration 0", raw: "0", want: 0, wantOK: true},
		{name: "one nanosecond maps 1:1", raw: "1", want: 1 * time.Nanosecond, wantOK: true},
		{name: "100ms in ns maps 1:1 (no multiply)", raw: nsString(100 * time.Millisecond), want: 100 * time.Millisecond, wantOK: true},
		{name: "2s in ns maps 1:1", raw: nsString(2 * time.Second), want: 2 * time.Second, wantOK: true},
		{name: "surrounding whitespace trimmed", raw: "  500  ", want: 500 * time.Nanosecond, wantOK: true},
		// Absurdly large but in-range int64: parses OK here; clamping is the
		// caller's job (see TestClampWait / TestHeaderLimiter_Observe).
		{name: "huge in-range value accepted unclamped", raw: nsString(30 * 24 * time.Hour), want: 30 * 24 * time.Hour, wantOK: true},
		// Beyond int64 nanoseconds: ParseInt overflows -> rejected.
		{name: "int64 overflow rejected", raw: "99999999999999999999999", want: 0, wantOK: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseResetNanos(tt.raw)
			assert.Equal(t, tt.wantOK, ok, "ok mismatch for %q", tt.raw)
			assert.Equal(t, tt.want, got, "duration mismatch for %q", tt.raw)
		})
	}
}

// --- parseRemaining: reject spoofable/garbage values ---------------------------
func TestParseRemaining(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		raw    string
		want   int
		wantOK bool
	}{
		{name: "empty rejected", raw: "", want: 0, wantOK: false},
		{name: "non-numeric rejected", raw: "lots", want: 0, wantOK: false},
		{name: "negative rejected", raw: "-1", want: 0, wantOK: false},
		{name: "zero accepted", raw: "0", want: 0, wantOK: true},
		{name: "positive accepted", raw: "5", want: 5, wantOK: true},
		{name: "surrounding whitespace trimmed", raw: "  10  ", want: 10, wantOK: true},
		{name: "int overflow rejected", raw: "99999999999999999999999", want: 0, wantOK: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseRemaining(tt.raw)
			assert.Equal(t, tt.wantOK, ok, "ok mismatch for %q", tt.raw)
			assert.Equal(t, tt.want, got, "value mismatch for %q", tt.raw)
		})
	}
}

// --- clampWait: bound backoff to [minResetWait, maxResetWait] [T7] --------------
func TestClampWait(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "below floor raised to min", in: 50 * time.Millisecond, want: minResetWait},
		{name: "zero raised to min", in: 0, want: minResetWait},
		{name: "one ns raised to min", in: 1 * time.Nanosecond, want: minResetWait},
		{name: "negative raised to min (defensive)", in: -5 * time.Second, want: minResetWait},
		{name: "at floor unchanged", in: minResetWait, want: minResetWait},
		{name: "in range unchanged", in: 2 * time.Second, want: 2 * time.Second},
		{name: "at cap unchanged", in: maxResetWait, want: maxResetWait},
		{name: "above cap lowered to max", in: 10 * time.Minute, want: maxResetWait},
		{name: "absurdly huge lowered to max", in: 30 * 24 * time.Hour, want: maxResetWait},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, clampWait(tt.in))
		})
	}
}

// --- Wait: prompt / blocks-until-reset / cancel --------------------------------

// Wait returns promptly when tokens remain, even if a future resetAt is set —
// remaining>0 must win over a pending window.
func TestHeaderLimiter_Wait_PromptWhenRemaining(t *testing.T) {
	t.Parallel()

	l := newHeaderLimiter()
	h := http.Header{}
	h.Set(headerRemaining, "5")
	h.Set(headerReset, nsString(5*time.Minute)) // a real, far-future window
	l.Observe(CatLive, h, http.StatusOK)

	start := time.Now()
	err := l.Wait(context.Background(), CatLive)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, elapsed, 50*time.Millisecond, "Wait should not block while remaining>0")
}

// Wait blocks approximately until resetAt once the window is exhausted (429),
// then returns nil. The reset is a few hundred ms so the test stays fast; we
// assert it clearly blocked (well above the prompt case) rather than pinning an
// exact upper bound the scheduler can't guarantee.
func TestHeaderLimiter_Wait_BlocksUntilResetWhenExhausted(t *testing.T) {
	t.Parallel()

	const reset = 200 * time.Millisecond
	l := newHeaderLimiter()
	h := http.Header{}
	h.Set(headerReset, nsString(reset))
	l.Observe(CatLive, h, http.StatusTooManyRequests) // remaining -> 0, resetAt ~ now+reset

	start := time.Now()
	err := l.Wait(context.Background(), CatLive)
	elapsed := time.Since(start)

	require.NoError(t, err)
	// Blocked meaningfully: at least the min floor, comfortably below the reset.
	assert.GreaterOrEqual(t, elapsed, minResetWait, "Wait returned too early to have honored the window")
	assert.Less(t, elapsed, 5*time.Second, "Wait blocked far longer than the reset window")
}

// Wait returns ctx.Err() when the context is cancelled while it is blocked on a
// window. The window is set to 2s so the timer would otherwise dominate; the
// cancel fires ~25ms in, proving the ctx path returns first.
func TestHeaderLimiter_Wait_ReturnsCtxErrOnCancel(t *testing.T) {
	t.Parallel()

	l := newHeaderLimiter()
	h := http.Header{}
	h.Set(headerReset, nsString(2*time.Second))
	l.Observe(CatLive, h, http.StatusTooManyRequests)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel mid-wait: long enough that Wait is blocked on the timer, short
	// enough to keep the test fast.
	timer := time.AfterFunc(25*time.Millisecond, cancel)
	defer timer.Stop()

	start := time.Now()
	err := l.Wait(ctx, CatLive)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, elapsed, 1*time.Second, "Wait returned via the timer, not the cancel")
}

// --- Observe: header parsing, ns interpretation, 429 window, default fallback --

// Observe folds headers into per-category state. These white-box assertions read
// the resulting window directly (the numeric ns math and the 429/default
// branches are otherwise only observable as multi-second Wait durations).
func TestHeaderLimiter_Observe(t *testing.T) {
	t.Parallel()

	t.Run("200 updates remaining and reset window", func(t *testing.T) {
		t.Parallel()
		l := newHeaderLimiter()
		h := http.Header{}
		h.Set(headerRemaining, "7")
		h.Set(headerReset, nsString(250*time.Millisecond))

		before := time.Now()
		l.Observe(CatLive, h, http.StatusOK)
		rem, resetAt := readState(l.state(CatLive))

		assert.Equal(t, 7, rem)
		// 250ms is within [min,max] so it passes clampWait unchanged: the ns
		// value converted 1:1 (a multiply/misread would land far outside).
		delta := resetAt.Sub(before)
		assert.GreaterOrEqual(t, delta, 250*time.Millisecond)
		assert.Less(t, delta, 250*time.Millisecond+100*time.Millisecond)
	})

	t.Run("429 exhausts window and sets reset from header", func(t *testing.T) {
		t.Parallel()
		l := newHeaderLimiter()
		h := http.Header{}
		h.Set(headerReset, nsString(300*time.Millisecond))

		before := time.Now()
		l.Observe(CatBulk, h, http.StatusTooManyRequests)
		rem, resetAt := readState(l.state(CatBulk))

		assert.Equal(t, 0, rem, "429 must exhaust the window")
		assert.False(t, resetAt.IsZero(), "429 must set a reset instant")
		delta := resetAt.Sub(before)
		assert.GreaterOrEqual(t, delta, 300*time.Millisecond)
		assert.Less(t, delta, 300*time.Millisecond+100*time.Millisecond)
	})

	t.Run("429 without usable reset falls back to conservative default", func(t *testing.T) {
		t.Parallel()
		l := newHeaderLimiter()
		h := http.Header{} // no reset header at all

		before := time.Now()
		l.Observe(CatLive, h, http.StatusTooManyRequests)
		rem, resetAt := readState(l.state(CatLive))

		assert.Equal(t, 0, rem)
		delta := resetAt.Sub(before)
		assert.GreaterOrEqual(t, delta, defaultResetWait)
		assert.Less(t, delta, defaultResetWait+100*time.Millisecond)
	})

	t.Run("429 with garbage reset falls back to conservative default", func(t *testing.T) {
		t.Parallel()
		l := newHeaderLimiter()
		h := http.Header{}
		h.Set(headerReset, "not-a-number")

		before := time.Now()
		l.Observe(CatHistoricalReverse, h, http.StatusTooManyRequests)
		rem, resetAt := readState(l.state(CatHistoricalReverse))

		assert.Equal(t, 0, rem)
		delta := resetAt.Sub(before)
		assert.GreaterOrEqual(t, delta, defaultResetWait)
		assert.Less(t, delta, defaultResetWait+100*time.Millisecond)
	})

	t.Run("tiny reset is clamped up to the floor [T7]", func(t *testing.T) {
		t.Parallel()
		l := newHeaderLimiter()
		h := http.Header{}
		h.Set(headerReset, "1") // 1ns, well below minResetWait

		before := time.Now()
		l.Observe(CatLive, h, http.StatusTooManyRequests)
		_, resetAt := readState(l.state(CatLive))

		delta := resetAt.Sub(before)
		assert.GreaterOrEqual(t, delta, minResetWait, "tiny reset must clamp up to the floor")
		assert.Less(t, delta, minResetWait+100*time.Millisecond)
	})

	t.Run("huge reset is clamped down to the cap [T7]", func(t *testing.T) {
		t.Parallel()
		l := newHeaderLimiter()
		h := http.Header{}
		h.Set(headerReset, nsString(10*time.Minute)) // above maxResetWait

		before := time.Now()
		l.Observe(CatLive, h, http.StatusTooManyRequests)
		_, resetAt := readState(l.state(CatLive))

		delta := resetAt.Sub(before)
		assert.GreaterOrEqual(t, delta, maxResetWait, "huge reset must clamp down to the cap")
		assert.Less(t, delta, maxResetWait+100*time.Millisecond)
	})

	t.Run("200 with malformed remaining leaves remaining unchanged", func(t *testing.T) {
		t.Parallel()
		l := newHeaderLimiter()

		// Seed a known remaining via a clean 200.
		seed := http.Header{}
		seed.Set(headerRemaining, "9")
		l.Observe(CatLive, seed, http.StatusOK)

		// A garbage remaining header must not overwrite the prior value.
		bad := http.Header{}
		bad.Set(headerRemaining, "-4")
		l.Observe(CatLive, bad, http.StatusOK)

		rem, _ := readState(l.state(CatLive))
		assert.Equal(t, 9, rem, "malformed remaining must be ignored, not applied")
	})
}

// Unknown categories are treated as unconstrained: Wait returns promptly and
// Observe is a no-op (no panic on the nil-state guard).
func TestHeaderLimiter_UnknownCategory(t *testing.T) {
	t.Parallel()

	l := newHeaderLimiter()
	unknown := Category(99)

	assert.NotPanics(t, func() {
		h := http.Header{}
		h.Set(headerReset, nsString(time.Second))
		l.Observe(unknown, h, http.StatusTooManyRequests)
	}, "Observe on an unknown category must not panic")

	start := time.Now()
	err := l.Wait(context.Background(), unknown)
	elapsed := time.Since(start)
	assert.NoError(t, err)
	assert.Less(t, elapsed, 50*time.Millisecond, "unknown category must be unconstrained")
}

// The limiter must be safe under concurrent Observe (writers) and Wait (readers)
// across all categories. Run under -race; the cancelled context keeps every Wait
// prompt so the test exercises the mutex-guarded state without real blocking.
func TestHeaderLimiter_Concurrent_RaceClean(t *testing.T) {
	t.Parallel()

	l := newHeaderLimiter()
	cats := []Category{CatLive, CatBulk, CatHistoricalReverse}

	var wg sync.WaitGroup
	const workers = 200
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cat := cats[i%len(cats)]

			h := http.Header{}
			h.Set(headerRemaining, "5")
			h.Set(headerReset, nsString(100*time.Millisecond))
			status := http.StatusOK
			if i%5 == 0 {
				status = http.StatusTooManyRequests // exercise the 429 write branch too
			}
			l.Observe(cat, h, status)

			// Pre-cancelled ctx: Wait still locks and reads state under the
			// mutex, but returns immediately regardless of the window.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_ = l.Wait(ctx, cat)
		}(i)
	}
	wg.Wait()
}

// Wait reserves a token under the same lock that reads it (SEC-BE-002): each Wait
// on a positive window decrements remaining, so concurrent callers cannot all see
// the same positive value and stampede. This is asserted deterministically via
// readState — no timing dependency — with a far-future reset so remaining>0 is the
// only thing driving the decrement.
func TestHeaderLimiter_Wait_ReservesTokenUnderLock(t *testing.T) {
	t.Parallel()

	l := newHeaderLimiter()
	h := http.Header{}
	h.Set(headerRemaining, "2")
	h.Set(headerReset, nsString(5*time.Minute)) // far-future window; remaining drives Wait
	l.Observe(CatLive, h, http.StatusOK)

	require.NoError(t, l.Wait(context.Background(), CatLive))
	rem, _ := readState(l.state(CatLive))
	assert.Equal(t, 1, rem, "first Wait must reserve one token (2 -> 1)")

	require.NoError(t, l.Wait(context.Background(), CatLive))
	rem, _ = readState(l.state(CatLive))
	assert.Equal(t, 0, rem, "second Wait must reserve the last token (1 -> 0)")
}
