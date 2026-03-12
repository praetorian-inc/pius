package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"time"
)

const (
	defaultTimeout  = 30 * time.Second
	defaultRetries  = 3
	maxResponseSize = 10 << 20 // 10 MB
	userAgent       = "pius/1.0 (github.com/praetorian-inc/pius)"
)

// Client is a shared HTTP client with retry logic.
type Client struct {
	http    *http.Client
	retries int
}

// New creates a Client with default timeout and retry settings.
func New() *Client {
	return &Client{
		http:    &http.Client{Timeout: defaultTimeout},
		retries: defaultRetries,
	}
}

// sanitizeURL redacts sensitive query parameters (API keys, tokens) from URLs
// to prevent accidental credential exposure in error messages and logs.
func sanitizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid URL]"
	}
	q := parsed.Query()
	redacted := false
	for _, key := range []string{"key", "apikey", "api_key", "token", "access_token"} {
		if q.Has(key) {
			q.Set(key, "REDACTED")
			redacted = true
		}
	}
	if !redacted {
		return rawURL // Return original if nothing to redact
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// Get performs an HTTP GET request with retry on transient failures.
// The Accept header defaults to "application/json".
func (c *Client) Get(ctx context.Context, url string) ([]byte, error) {
	return c.GetWithHeaders(ctx, url, map[string]string{
		"Accept": "application/json",
	})
}

// GetWithHeaders performs an HTTP GET with custom headers, retrying on 429/5xx.
// On failure, all retry errors are aggregated for better debugging of intermittent issues.
func (c *Client) GetWithHeaders(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	var retryErrs []error
	for attempt := 0; attempt < c.retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			retryErrs = append(retryErrs, fmt.Errorf("attempt %d: %w", attempt+1, err))
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			retryErrs = append(retryErrs, fmt.Errorf("attempt %d: rate limited by %s", attempt+1, sanitizeURL(url)))
			continue
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			retryErrs = append(retryErrs, fmt.Errorf("attempt %d: server error %d from %s", attempt+1, resp.StatusCode, sanitizeURL(url)))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, sanitizeURL(url))
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		if int64(len(body)) > maxResponseSize {
			return nil, fmt.Errorf("response too large (>%d bytes) from %s", maxResponseSize, sanitizeURL(url))
		}
		return body, nil
	}
	return nil, fmt.Errorf("after %d attempts: %w", c.retries, errors.Join(retryErrs...))
}
