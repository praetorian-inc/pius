package whoisfreaks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// defaultBaseURL is the hardcoded production endpoint (security T5). It is a
// constant, not a field default that prod callers can override: New always
// starts from this value, and only the test-only WithBaseURL replaces it. The
// scheme is fixed https:// so a production Client can never be pointed at a
// plaintext endpoint, and no runtime scheme check is required because the value
// is not attacker- or config-reachable in production.
const defaultBaseURL = "https://api.whoisfreaks.com"

const (
	userAgent          = "pius-whoisfreaks/1.0 (+github.com/praetorian-inc/pius)"
	maxResponseBytes   = 10 << 20 // 10 MiB cap on any single response body.
	defaultHTTPTimeout = 30 * time.Second
)

// Endpoint paths (appended to baseURL). Verified against architecture-backend.md
// §data-flow and the WhoisFreaks API: ssl/live is GET {base}/v1.0/ssl/live and
// account usage is GET {base}/v1.0/whoisapi/usage.
const (
	pathSSLLive = "/v1.0/ssl/live"
	pathUsage   = "/v1.0/whoisapi/usage"
)

// Query parameter names. The apiKey travels ONLY as an escaped query parameter
// (paramAPIKey) built via url.Values.Encode; it is never placed in a header, in
// the path, or in any log line (security T1/T3). paramChain/paramSSLRaw are
// consumed by ssl.go.
const (
	paramAPIKey     = "apiKey"
	paramDomainName = "domainName"
	paramChain      = "chain"
	paramSSLRaw     = "sslRaw"
)

// Package-level error sentinels. errRequestFailed is deliberately static and
// key-free: it is the ONLY error the transport path returns, so a *url.Error
// carrying the keyed request URL can never escape through it (security T1/T3).
var (
	errRequestFailed    = errors.New("whoisfreaks: request failed")
	errResponseTooLarge = errors.New("whoisfreaks: response exceeded size limit")
	errMissingAPIKey    = errors.New("whoisfreaks: WithAPIKey is required")
)

// Client is a WhoisFreaks SSL-certificate API client. It owns its own
// *http.Client (never http.DefaultClient), paces requests through an injectable
// Limiter, and accounts billed credits through an injectable CreditMeter. A
// Client is safe for concurrent use once constructed; New is the only
// constructor.
type Client struct {
	apiKey  string
	baseURL string
	http    *http.Client
	limiter Limiter
	meter   *CreditMeter
}

// Option configures a Client during New. Options are applied in order after the
// secure defaults are installed.
type Option func(*Client)

// WithAPIKey sets the WhoisFreaks API key. It is REQUIRED: New returns
// errMissingAPIKey when the key is empty. The key is carried only as an escaped
// query parameter and is never logged (security T1/T3).
func WithAPIKey(key string) Option {
	return func(c *Client) { c.apiKey = key }
}

// WithHTTPClient injects a custom *http.Client (e.g. a shared, instrumented
// transport). A nil client is ignored so the secure default is preserved.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.http = hc
		}
	}
}

// WithRateLimiter injects a process-shared Limiter (e.g. Guard's fleet
// governor). A nil limiter is ignored so the per-client default is preserved.
func WithRateLimiter(l Limiter) Option {
	return func(c *Client) {
		if l != nil {
			c.limiter = l
		}
	}
}

// WithCreditMeter injects a shared CreditMeter so credits can be accounted
// across many lookups. A nil meter is ignored so the per-client default is
// preserved.
func WithCreditMeter(m *CreditMeter) Option {
	return func(c *Client) {
		if m != nil {
			c.meter = m
		}
	}
}

// WithBaseURL overrides the API base URL. It is TEST-ONLY: production code must
// rely on the hardcoded https:// defaultBaseURL (security T5). It exists so
// tests can point the client at an httptest.Server.
func WithBaseURL(raw string) Option {
	return func(c *Client) { c.baseURL = raw }
}

// New constructs a Client. It installs the secure defaults first — an owned
// *http.Client with a bounded timeout (never http.DefaultClient), a per-client
// header limiter, a fresh credit meter, and the hardcoded production base URL —
// then applies opts in order. WithAPIKey is required; New returns
// errMissingAPIKey if no non-empty key was supplied.
func New(opts ...Option) (*Client, error) {
	c := &Client{
		baseURL: defaultBaseURL,
		http:    &http.Client{Timeout: defaultHTTPTimeout},
		limiter: newHeaderLimiter(),
		meter:   NewCreditMeter(),
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.apiKey == "" {
		return nil, errMissingAPIKey
	}
	return c, nil
}

// do performs a single GET against reqURL in rate-limit category cat and returns
// the (size-capped) response body. It performs NO internal retry — one request
// per call. reqURL already carries the escaped apiKey query parameter, so it is
// treated as a secret: it is never placed in an error, a log line, or a metric
// (security T1/T3).
func (c *Client) do(ctx context.Context, cat Category, reqURL string) ([]byte, error) {
	if err := c.limiter.Wait(ctx, cat); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		// The construction error can echo the (keyed) URL; return the key-free
		// sentinel rather than propagating it (security T1/T3).
		return nil, errRequestFailed
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// T1 (LOAD-BEARING): an *http.Client.Do failure is returned as a
		// *url.Error whose Error() string embeds the full request URL — which
		// carries the apiKey query parameter. It MUST NEVER be %w-wrapped or
		// %v-formatted into a returned or logged error. We detect the shape only
		// to make the drop explicit, then deliberately discard urlErr and return
		// the static, key-free sentinel. Do NOT "modernize" this into
		// fmt.Errorf("...: %w", err) — that would leak the key.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return nil, errRequestFailed // urlErr carries the keyed URL — intentionally dropped
		}
		return nil, errRequestFailed
	}
	defer func() { _ = resp.Body.Close() }()

	// Hand the response's rate-limit headers and status to the limiter before any
	// status branching so pacing state is updated even on error responses.
	c.limiter.Observe(cat, resp.Header, resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		// Bare status code only — never the URL (security T3).
		return nil, fmt.Errorf("whoisfreaks: request failed with status %d", resp.StatusCode)
	}

	// Cap the body: read one byte past the limit so an over-sized response is
	// detected rather than silently truncated.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, errRequestFailed
	}
	if int64(len(body)) > maxResponseBytes {
		return nil, errResponseTooLarge
	}
	return body, nil
}

// usageURL builds the account-usage request URL with the escaped apiKey query
// parameter.
func (c *Client) usageURL() string {
	v := url.Values{}
	v.Set(paramAPIKey, c.apiKey)
	return c.baseURL + pathUsage + "?" + v.Encode()
}

// Usage returns the account's credit usage (remaining/used/total) from
// GET /v1.0/whoisapi/usage. Transport failures surface as the key-free sentinel
// from do; a malformed body is reported as a decode error that carries no URL.
func (c *Client) Usage(ctx context.Context) (Usage, error) {
	body, err := c.do(ctx, CatLive, c.usageURL())
	if err != nil {
		return Usage{}, err
	}
	var dto usageResponse
	if err := json.Unmarshal(body, &dto); err != nil {
		// The decode error describes the JSON, not the request URL — safe to wrap.
		return Usage{}, fmt.Errorf("whoisfreaks: decode usage response: %w", err)
	}
	return Usage(dto), nil
}
