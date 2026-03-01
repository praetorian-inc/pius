package client

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
	defaultRetries = 3
	userAgent      = "pius/1.0 (github.com/praetorian-inc/pius)"
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
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("rate limited by %s", url)
			continue
		}
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error %d from %s", resp.StatusCode, url)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		return body, nil
	}
	return nil, fmt.Errorf("after %d attempts: %w", c.retries, lastErr)
}
