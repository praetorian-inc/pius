package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
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

// Get performs an HTTP GET request with retry on transient failures.
// The Accept header defaults to "application/json".
func (c *Client) Get(ctx context.Context, url string) ([]byte, error) {
	return c.GetWithHeaders(ctx, url, map[string]string{
		"Accept": "application/json",
	})
}

// GetWithHeaders performs an HTTP GET with custom headers, retrying on 429/5xx.
func (c *Client) GetWithHeaders(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, url, nil, func(req *http.Request) {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	})
}

// PostWithHeaders performs an HTTP POST with custom headers, retrying on 429/5xx.
func (c *Client) PostWithHeaders(ctx context.Context, url string, body []byte, headers map[string]string) ([]byte, error) {
	return c.do(ctx, http.MethodPost, url, body, func(req *http.Request) {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	})
}

// do is the shared retry loop for all HTTP methods.
// prepareFn customises the request (headers, auth) before it is sent.
func (c *Client) do(ctx context.Context, method, url string, body []byte, prepareFn func(*http.Request)) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < c.retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)
		if prepareFn != nil {
			prepareFn(req)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			lastErr = fmt.Errorf("rate limited by %s", url)
			continue
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("server error %d from %s", resp.StatusCode, url)
			continue
		}
		if method == http.MethodGet && resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
		}

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		if int64(len(respBody)) > maxResponseSize {
			return nil, fmt.Errorf("response too large (>%d bytes) from %s", maxResponseSize, url)
		}
		return respBody, nil
	}
	return nil, fmt.Errorf("after %d attempts: %w", c.retries, lastErr)
}
