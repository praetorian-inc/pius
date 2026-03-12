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
