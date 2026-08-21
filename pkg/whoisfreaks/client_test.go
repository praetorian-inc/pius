package whoisfreaks

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise client.go's transport (do), constructor (New), and Usage
// endpoint against an in-process httptest.Server. They are fully offline: no real
// network, no real WhoisFreaks endpoint, and no real API key — the ~/.whoisfreaks.key
// on disk is never read, opened, or referenced. Every key the client sends here is
// an obviously-synthetic sentinel (WF_TRANSPORT_SENTINEL / WF_STATUS_SENTINEL /
// WF_USAGE_SENTINEL), never a credential, and each leak-sensitive test uses a
// UNIQUE sentinel so an assertion can prove that exact value is absent.
//
// The security spine is the key-never-leaks invariant: the apiKey rides ONLY as
// an escaped query parameter and must never surface in a returned error, whatever
// the failure mode (T1 transport path, T2 status path) or the wire encoding (T1/T3
// query-not-header), and the production base URL is https-only (T5).

// assertKeyFree fails if err is nil or if its message leaks either the apiKey
// value (sentinel) or the "apiKey=" query fragment. It is the executable form of
// the T1 (transport) and T2 (status) key-leak invariants.
func assertKeyFree(t *testing.T, err error, sentinel string) {
	t.Helper()
	require.Error(t, err, "the failing path must return an error")
	msg := err.Error()
	assert.NotContainsf(t, msg, sentinel, "error leaks the apiKey value: %q", msg)
	assert.NotContainsf(t, msg, "apiKey=", "error leaks the apiKey query parameter: %q", msg)
}

// TestNew_APIKeyRequired: New without a non-empty key fails with errMissingAPIKey
// (errors.Is), and succeeds once WithAPIKey supplies one.
func TestNew_APIKeyRequired(t *testing.T) {
	t.Parallel()

	t.Run("missing key is rejected", func(t *testing.T) {
		t.Parallel()
		c, err := New()
		assert.Nil(t, c, "no client is returned without a key")
		assert.ErrorIs(t, err, errMissingAPIKey)
	})

	t.Run("empty key is rejected", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithAPIKey(""))
		assert.Nil(t, c)
		assert.ErrorIs(t, err, errMissingAPIKey)
	})

	t.Run("a supplied key is accepted", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithAPIKey("WF_ANY_SENTINEL"))
		require.NoError(t, err)
		require.NotNil(t, c)
	})
}

// TestProdBaseURL_IsHTTPS is the T5 invariant: the hardcoded production base URL
// is https and never plaintext http, so a production Client can never be pointed
// at an unencrypted endpoint where the query-string apiKey would travel in the
// clear. A default-constructed client actually adopts that URL.
func TestProdBaseURL_IsHTTPS(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "https://api.whoisfreaks.com", defaultBaseURL,
		"the production base URL must be the hardcoded https endpoint")
	assert.True(t, strings.HasPrefix(defaultBaseURL, "https://"),
		"production base URL must use the https scheme")
	assert.False(t, strings.HasPrefix(defaultBaseURL, "http://"),
		"production base URL must never use plaintext http")

	c, err := New(WithAPIKey("WF_ANY_SENTINEL"))
	require.NoError(t, err)
	assert.Equal(t, defaultBaseURL, c.baseURL, "New must start from the hardcoded prod base URL")
}

// TestTransportError_KeyNeverLeaks is the LOAD-BEARING T1 sentinel test. It forces
// a real transport failure — the server is closed before the request, so the dial
// is refused — with the apiKey set to WF_TRANSPORT_SENTINEL. http.Client surfaces
// such a failure as a *url.Error whose Error() embeds the full request URL,
// including apiKey=WF_TRANSPORT_SENTINEL. do() must drop that entirely and return
// the static, key-free sentinel. This exercises the exact path a URL sanitizer
// never sees.
func TestTransportError_KeyNeverLeaks(t *testing.T) {
	t.Parallel()

	const sentinel = "WF_TRANSPORT_SENTINEL"

	// Stand a server up only to borrow a valid loopback URL, then close it so the
	// next dial is refused — a deterministic, fully offline transport failure.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base := srv.URL
	srv.Close()

	// Teeth check: a RAW *url.Error for this request WOULD leak the key. This
	// proves the assertions below can actually fail on a regression that wraps the
	// transport error (fmt.Errorf("...: %w", err)) instead of dropping it.
	leaked := (&url.Error{
		Op:  "Get",
		URL: base + pathUsage + "?apiKey=" + sentinel,
		Err: errors.New("connect: connection refused"),
	}).Error()
	require.Contains(t, leaked, sentinel,
		"sanity: an unscrubbed url.Error leaks the key — so the check below has teeth")
	require.Contains(t, leaked, "apiKey=",
		"sanity: an unscrubbed url.Error leaks the query parameter")

	c, err := New(WithAPIKey(sentinel), WithBaseURL(base))
	require.NoError(t, err)

	_, err = c.Usage(context.Background())

	// The real returned error must be the static, key-free sentinel.
	assertKeyFree(t, err, sentinel)
	assert.ErrorIs(t, err, errRequestFailed,
		"the transport branch must return the static key-free sentinel")
}

// TestStatusError_KeyNeverLeaks is the T2 sentinel test: a non-2xx response yields
// an error carrying only the bare status code — never the apiKey value and never
// the apiKey= query fragment (the camelCase miss that motivated the must-fix). The
// handler echoes the secret-bearing query in the body to prove the client folds
// neither the body nor the URL into its error.
func TestStatusError_KeyNeverLeaks(t *testing.T) {
	t.Parallel()

	const sentinel = "WF_STATUS_SENTINEL"

	for _, status := range []int{
		http.StatusInternalServerError, // 500
		http.StatusTooManyRequests,     // 429
		http.StatusNotFound,            // 404
		http.StatusForbidden,           // 403
	} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(r.URL.RawQuery))
			}))
			t.Cleanup(srv.Close)

			c, err := New(WithAPIKey(sentinel), WithBaseURL(srv.URL))
			require.NoError(t, err)

			_, err = c.Usage(context.Background())

			assertKeyFree(t, err, sentinel)
			assert.Containsf(t, err.Error(), strconv.Itoa(status),
				"the status error should carry the bare status code %d", status)
		})
	}
}

// TestUsage_HappyPath verifies the usage endpoint maps to Usage{Remaining,Used,
// Total} and — the T1/T3 wire-format invariant — that the apiKey travels as a
// query parameter and appears in NO request header.
func TestUsage_HappyPath(t *testing.T) {
	t.Parallel()

	const sentinel = "WF_USAGE_SENTINEL"

	type captured struct {
		apiKeyQuery     string
		authHeader      string
		anyHeaderHasKey bool
	}
	reqCh := make(chan captured, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anyHeaderHasKey := false
		for _, vals := range r.Header {
			for _, v := range vals {
				if strings.Contains(v, sentinel) {
					anyHeaderHasKey = true
				}
			}
		}
		reqCh <- captured{
			apiKeyQuery:     r.URL.Query().Get("apiKey"),
			authHeader:      r.Header.Get("Authorization"),
			anyHeaderHasKey: anyHeaderHasKey,
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"remaining":900,"used":100,"total":1000}`))
	}))
	t.Cleanup(srv.Close)

	c, err := New(WithAPIKey(sentinel), WithBaseURL(srv.URL))
	require.NoError(t, err)

	usage, err := c.Usage(context.Background())
	require.NoError(t, err)
	assert.Equal(t, Usage{Remaining: 900, Used: 100, Total: 1000}, usage,
		"usage fields must map from the response body")

	got := <-reqCh
	assert.Equal(t, sentinel, got.apiKeyQuery, "apiKey must ride as a query parameter")
	assert.Empty(t, got.authHeader, "the apiKey must never be sent as an Authorization header")
	assert.False(t, got.anyHeaderHasKey, "the apiKey must not appear in any request header")
}

// TestResponseBodyCap enforces the 10 MiB response cap (T6 DoS guard): a body one
// byte over the limit is rejected with errResponseTooLarge rather than read
// unboundedly. The oversized body is generated in-test, never committed.
func TestResponseBodyCap(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, maxResponseBytes+1))
	}))
	t.Cleanup(srv.Close)

	c, err := New(WithAPIKey("WF_ANY_SENTINEL"), WithBaseURL(srv.URL))
	require.NoError(t, err)

	_, err = c.Usage(context.Background())
	assert.ErrorIs(t, err, errResponseTooLarge, "an over-cap body must be rejected, not read")
}

// TestUsage_MalformedBodyKeyFreeNeverPanics exercises Usage's decode-error branch
// (client.go): a 200 whose body is not valid usage JSON must surface a decode
// error that (a) is non-nil, (b) leaks neither the apiKey value nor the apiKey=
// query fragment nor the request URL, and (c) never panics. The transport
// succeeds here, so this is the ONLY Usage path that reaches json.Unmarshal — the
// sibling tests cover the transport, non-2xx, oversized, and happy-body paths but
// never a malformed 200. The zero Usage is returned on failure.
func TestUsage_MalformedBodyKeyFreeNeverPanics(t *testing.T) {
	t.Parallel()

	const sentinel = "WF_USAGE_DECODE_SENTINEL"

	// Bodies that all make json.Unmarshal into usageResponse fail. "null" and an
	// empty body are deliberately excluded: "null" decodes to the zero struct with
	// no error, so it is not a malformed-body case.
	cases := []struct {
		name string
		body string
	}{
		{"truncated object", "{"},
		{"garbage text", "not json at all"},
		{"array not object", "[]"},
		{"wrong-typed field", `{"remaining":"not-an-int"}`},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)

			c, err := New(WithAPIKey(sentinel), WithBaseURL(srv.URL))
			require.NoError(t, err)

			var usage Usage
			require.NotPanics(t, func() { usage, err = c.Usage(context.Background()) },
				"a malformed 200 body must surface an error, never a panic")

			// (a) non-nil and (b) key-free — assertKeyFree requires the error and
			// proves neither the sentinel value nor the apiKey= fragment leaks.
			assertKeyFree(t, err, sentinel)
			assert.NotContains(t, err.Error(), srv.URL,
				"the decode error must not carry the request URL")
			assert.Equal(t, Usage{}, usage, "a decode failure returns the zero Usage")
		})
	}
}

// roundTripFunc adapts a function to http.RoundTripper so a test can inject a
// deterministic transport outcome — a specific error or response — without any
// real network dial. It is the offline injection point for do()'s transport
// branch when the failure must be shaped precisely (here: a caller cancellation
// mid-request), which an httptest.Server cannot express as directly.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestDo_CallerCancellationDuringRequest_SurfacesContextError pins do()'s
// obligation to preserve the CAUSE of a cancelled request. When the caller's
// context is cancelled while http.Client.Do is in flight, Do returns a
// *url.Error wrapping context.Canceled — and do() must surface the bare,
// key-free ctx.Err() so the caller can distinguish a cancellation/deadline from
// a generic failure (errors.Is(err, context.Canceled)). Flattening every
// transport error to the static errRequestFailed erases that signal.
//
// The two invariants are asserted together because they trade off: the naive
// "return the transport error" fix would surface context.Canceled BUT also leak
// the keyed *url.Error, so the test proves the cause is preserved AND the key
// never rides along.
func TestDo_CallerCancellationDuringRequest_SurfacesContextError(t *testing.T) {
	t.Parallel()

	const sentinel = "WF_CANCEL_SENTINEL"

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// The transport stands in for a request the caller cancels mid-flight: it
	// cancels ctx, then returns the *url.Error http.Client surfaces for a
	// cancelled GET. The URL is the REAL, live keyed request URL
	// (req.URL.String(), i.e. ...?apiKey=WF_CANCEL_SENTINEL) so a regression that
	// folds this error into the returned one would leak the key — giving the
	// leak assertions below teeth.
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		cancel()
		return nil, &url.Error{
			Op:  "Get",
			URL: req.URL.String(),
			Err: context.Canceled,
		}
	})

	c, err := New(WithAPIKey(sentinel), WithHTTPClient(&http.Client{Transport: rt}))
	require.NoError(t, err)

	// Teeth check: the keyed URL this request carries genuinely leaks both the
	// sentinel value and the apiKey= fragment, so the key-free assertions below
	// can actually fail on a regression that surfaces the raw *url.Error.
	leaked := (&url.Error{Op: "Get", URL: c.usageURL(), Err: context.Canceled}).Error()
	require.Contains(t, leaked, sentinel,
		"sanity: the keyed request URL leaks the apiKey value — so the checks below have teeth")
	require.Contains(t, leaked, "apiKey=",
		"sanity: the keyed request URL leaks the apiKey query parameter")

	_, err = c.Usage(ctx)

	require.Error(t, err, "a cancelled request must surface an error")
	// LOAD-BEARING: the caller cancellation must be observable as
	// context.Canceled, not flattened to the generic sentinel. do() currently
	// returns errRequestFailed on every transport error, dropping the cause.
	assert.ErrorIs(t, err, context.Canceled,
		"a caller cancellation must surface as context.Canceled, not a flattened sentinel")

	// Security spine (T1/T3): whatever error do() returns, it must stay key-free.
	// The bare ctx error carries no URL; the dropped *url.Error must never
	// resurface with the keyed URL in tow.
	assertKeyFree(t, err, sentinel)
	assert.NotContains(t, err.Error(), "api.whoisfreaks.com",
		"the surfaced error must not carry the request host")
}
