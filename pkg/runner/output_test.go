package runner

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	fnErr := fn()

	w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	os.Stdout = old
	return buf.String(), fnErr
}

func TestPrintFindings_TerminalFormat_WithFindings(t *testing.T) {
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDR, Value: "10.0.0.0/8", Source: "arin"},
		{Type: plugins.FindingDomain, Value: "example.com", Source: "crt-sh"},
	}

	out, err := captureStdout(t, func() error {
		return printFindings(findings, "terminal")
	})

	require.NoError(t, err)
	assert.Contains(t, out, "10.0.0.0/8")
	assert.Contains(t, out, "example.com")
	assert.Contains(t, out, "arin")
	assert.Contains(t, out, "crt-sh")
	// Format: [TYPE] VALUE (SOURCE)
	assert.Contains(t, out, "[cidr]")
	assert.Contains(t, out, "[domain]")
}

func TestPrintFindings_TerminalFormat_Empty(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return printFindings([]plugins.Finding{}, "terminal")
	})

	require.NoError(t, err)
	assert.Contains(t, out, "No assets found.")
}

func TestPrintFindings_JSONFormat(t *testing.T) {
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDR, Value: "192.168.1.0/24", Source: "arin"},
		{Type: plugins.FindingDomain, Value: "test.example.com", Source: "crt-sh"},
	}

	out, err := captureStdout(t, func() error {
		return printFindings(findings, "json")
	})

	require.NoError(t, err)
	// Must be valid JSON array
	var parsed []plugins.Finding
	require.NoError(t, json.Unmarshal([]byte(out), &parsed), "output must be valid JSON array")
	require.Len(t, parsed, 2)
	assert.Equal(t, plugins.FindingCIDR, parsed[0].Type)
	assert.Equal(t, "192.168.1.0/24", parsed[0].Value)
}

func TestPrintFindings_NDJSONFormat(t *testing.T) {
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDR, Value: "10.0.0.0/8", Source: "arin"},
		{Type: plugins.FindingDomain, Value: "example.com", Source: "crt-sh"},
	}

	out, err := captureStdout(t, func() error {
		return printFindings(findings, "ndjson")
	})

	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	validLines := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		assert.True(t, json.Valid([]byte(line)), "line should be valid JSON: %q", line)
		validLines++
	}
	assert.Equal(t, len(findings), validLines, "one JSON line per finding")
}
