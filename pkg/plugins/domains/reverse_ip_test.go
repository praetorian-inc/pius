package domains

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReverseIPPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("reverse-ip")
	require.True(t, ok, "reverse-ip plugin not registered")

	assert.Equal(t, "reverse-ip", p.Name())
	assert.Contains(t, p.Description(), "Reverse IP")
	assert.Contains(t, p.Description(), "PTR")
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, plugins.ModePassive, p.Mode())
}

func TestReverseIPPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("reverse-ip")
	require.True(t, ok)

	tests := []struct {
		name     string
		input    plugins.Input
		expected bool
	}{
		{
			name:     "accepts with domain",
			input:    plugins.Input{Domain: "example.com"},
			expected: true,
		},
		{
			name:     "rejects without domain",
			input:    plugins.Input{OrgName: "Acme Corp"},
			expected: false,
		},
		{
			name:     "rejects with empty domain",
			input:    plugins.Input{Domain: ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.Accepts(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestReverseIPPlugin_HackerTargetLookup(t *testing.T) {
	// Mock HackerTarget API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/reverseiplookup/")
		ip := r.URL.Query().Get("q")
		if ip == "192.0.2.1" {
			w.Write([]byte("www.example.com\napi.example.com\nmail.example.com"))
		} else if ip == "192.0.2.99" {
			w.Write([]byte("API count exceeded - 100 per day"))
		} else {
			w.Write([]byte(""))
		}
	}))
	defer server.Close()

	p := &ReverseIPPlugin{
		client:  client.New(),
		baseURL: server.URL,
	}

	t.Run("successful lookup", func(t *testing.T) {
		hosts := p.hackerTargetLookup(context.Background(), "192.0.2.1")
		assert.Len(t, hosts, 3)
		assert.Contains(t, hosts, "www.example.com")
		assert.Contains(t, hosts, "api.example.com")
		assert.Contains(t, hosts, "mail.example.com")
	})

	t.Run("API rate limit", func(t *testing.T) {
		hosts := p.hackerTargetLookup(context.Background(), "192.0.2.99")
		assert.Empty(t, hosts)
	})

	t.Run("no results", func(t *testing.T) {
		hosts := p.hackerTargetLookup(context.Background(), "192.0.2.50")
		assert.Empty(t, hosts)
	})

	t.Run("invalid IP", func(t *testing.T) {
		hosts := p.hackerTargetLookup(context.Background(), "not-an-ip")
		assert.Empty(t, hosts)
	})
}

func TestReverseIPPlugin_HackerTargetResponseParsing(t *testing.T) {
	tests := []struct {
		name     string
		response string
		expected []string
	}{
		{
			name:     "simple hostnames",
			response: "www.example.com\napi.example.com",
			expected: []string{"www.example.com", "api.example.com"},
		},
		{
			name:     "with empty lines",
			response: "www.example.com\n\napi.example.com\n",
			expected: []string{"www.example.com", "api.example.com"},
		},
		{
			name:     "error message",
			response: "error invalid input",
			expected: nil,
		},
		{
			name:     "API limit message",
			response: "API count exceeded - 100 per day",
			expected: nil,
		},
		{
			name:     "mixed valid and invalid",
			response: "www.example.com\nerror message\napi.example.com",
			expected: []string{"www.example.com", "api.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			p := &ReverseIPPlugin{
				client:  client.New(),
				baseURL: server.URL,
			}

			hosts := p.hackerTargetLookup(context.Background(), "192.0.2.1")
			assert.Equal(t, tt.expected, hosts)
		})
	}
}
