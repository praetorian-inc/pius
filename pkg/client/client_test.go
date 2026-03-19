package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Get_LimitsResponseSize(t *testing.T) {
	// Create a server that returns 11 MB of data (exceeds 10 MB limit)
	largeResponse := strings.Repeat("x", 11*1024*1024) // 11 MB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(largeResponse))
	}))
	defer server.Close()

	c := client.New()
	body, err := c.Get(context.Background(), server.URL)

	// Should return explicit error for oversized response
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response too large")
	assert.Nil(t, body)
}

func TestClient_Get_AllowsResponsesUnder10MB(t *testing.T) {
	// Create a server that returns 5 MB of data (under 10 MB limit)
	smallResponse := strings.Repeat("y", 5*1024*1024) // 5 MB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(smallResponse))
	}))
	defer server.Close()

	c := client.New()
	body, err := c.Get(context.Background(), server.URL)

	require.NoError(t, err)
	assert.Equal(t, 5*1024*1024, len(body), "small response should be fully read")
}

func TestClient_PostWithHeaders_SendsHeadersAndBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "Bearer my-token", r.Header.Get("Authorization"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	c := client.New()
	body, err := c.PostWithHeaders(context.Background(), server.URL, []byte(`{"q":"test"}`), map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer my-token",
	})
	require.NoError(t, err)
	assert.Contains(t, string(body), `"ok":true`)
}

func TestClient_PostWithHeaders_LimitsResponseSize(t *testing.T) {
	largeResponse := strings.Repeat("x", 11*1024*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(largeResponse))
	}))
	defer server.Close()

	c := client.New()
	body, err := c.PostWithHeaders(context.Background(), server.URL, []byte(`{}`), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response too large")
	assert.Nil(t, body)
}

func TestClient_Get_SanitizesAPIKeyInErrorMessages(t *testing.T) {
	// Create a server that returns 403 to trigger an error with the URL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	c := client.New()

	// URL with API key in query parameter (like Shodan)
	urlWithKey := server.URL + "/api?key=SECRET_API_KEY_12345&query=test"
	_, err := c.Get(context.Background(), urlWithKey)

	require.Error(t, err)
	// Error should contain REDACTED, not the actual key
	assert.Contains(t, err.Error(), "REDACTED", "error should contain REDACTED placeholder")
	assert.NotContains(t, err.Error(), "SECRET_API_KEY_12345", "error should NOT contain actual API key")
}

func TestClient_Get_SanitizesMultipleKeyFormats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	tests := []struct {
		name      string
		queryParam string
		secretValue string
	}{
		{"key param", "key", "SHODAN_KEY"},
		{"apikey param", "apikey", "VIEWDNS_KEY"},
		{"api_key param", "api_key", "SOME_API_KEY"},
		{"token param", "token", "AUTH_TOKEN"},
		{"access_token param", "access_token", "OAUTH_TOKEN"},
	}

	c := client.New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urlWithKey := server.URL + "/api?" + tt.queryParam + "=" + tt.secretValue
			_, err := c.Get(context.Background(), urlWithKey)

			require.Error(t, err)
			assert.NotContains(t, err.Error(), tt.secretValue,
				"error should NOT contain actual secret for %s", tt.queryParam)
			assert.Contains(t, err.Error(), "REDACTED",
				"error should contain REDACTED for %s", tt.queryParam)
		})
	}
}

func TestClient_Get_PreservesNonSensitiveURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	c := client.New()

	// URL without sensitive params should be preserved
	urlWithoutKey := server.URL + "/api?query=test&page=1"
	_, err := c.Get(context.Background(), urlWithoutKey)

	require.Error(t, err)
	// Should contain the full URL since no sensitive params
	assert.Contains(t, err.Error(), "query=test", "non-sensitive params should be preserved")
	assert.Contains(t, err.Error(), "page=1", "non-sensitive params should be preserved")
	assert.NotContains(t, err.Error(), "REDACTED", "should not contain REDACTED when no sensitive params")
}
