package ips

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPPlugin_Run(t *testing.T) {
	database := filepath.Join(t.TempDir(), "asn.tsv")
	require.NoError(t, writeASNDatabase(database, `1.1.1.0 1.1.1.255 13335 US CLOUDFLARENET
2001:4860:: 2001:4860:ffff:ffff:ffff:ffff:ffff:ffff 15169 US GOOGLE
`))
	plugin := NewIPPlugin(database)

	tests := []struct {
		name  string
		input plugins.Input
		want  IPResult
	}{
		{
			name:  "IPv4",
			input: plugins.Input{IP: "1.1.1.1"},
			want: IPResult{
				Query: "1.1.1.1", StartAddress: "1.1.1.0", EndAddress: "1.1.1.255",
				Number: 13335, Country: "US", Name: "CLOUDFLARENET",
			},
		},
		{
			name:  "canonical CIDR",
			input: plugins.Input{CIDR: "1.1.1.7/24"},
			want: IPResult{
				Query: "1.1.1.0/24", StartAddress: "1.1.1.0", EndAddress: "1.1.1.255",
				Number: 13335, Country: "US", Name: "CLOUDFLARENET",
			},
		},
		{
			name:  "IPv6",
			input: plugins.Input{CIDR: "2001:4860:4860::8888/32"},
			want: IPResult{
				Query: "2001:4860::/32", StartAddress: "2001:4860::", EndAddress: "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff",
				Number: 15169, Country: "US", Name: "GOOGLE",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := plugin.Run(context.Background(), test.input)
			require.NoError(t, err)
			require.Len(t, findings, 1)
			assert.Equal(t, plugins.FindingIPResult, findings[0].Type)
			assert.Equal(t, test.want.Query, findings[0].Value)
			assert.Equal(t, plugins.FindingData(test.want), findings[0].Data)
		})
	}
}

func TestIPPlugin_RunReturnsNoFindingWithoutMatch(t *testing.T) {
	database := filepath.Join(t.TempDir(), "asn.tsv")
	require.NoError(t, writeASNDatabase(database, "1.1.1.0 1.1.1.255 13335 US CLOUDFLARENET\n"))

	findings, err := NewIPPlugin(database).Run(context.Background(), plugins.Input{IP: "8.8.8.8"})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestIPPlugin_RunRejectsMissingDatabase(t *testing.T) {
	_, err := NewIPPlugin(filepath.Join(t.TempDir(), "missing.tsv")).Run(context.Background(), plugins.Input{IP: "1.1.1.1"})
	assert.ErrorContains(t, err, "open ASN database")
}

func TestIPPlugin_Accepts(t *testing.T) {
	plugin := NewIPPlugin("asn.tsv")
	assert.True(t, plugin.Accepts(plugins.Input{IP: "1.1.1.1"}))
	assert.True(t, plugin.Accepts(plugins.Input{CIDR: "1.1.1.0/24"}))
	assert.False(t, plugin.Accepts(plugins.Input{IP: "invalid"}))
	assert.False(t, plugin.Accepts(plugins.Input{IP: "1.1.1.1", CIDR: "1.1.1.0/24"}))
	assert.False(t, NewIPPlugin("").Accepts(plugins.Input{IP: "1.1.1.1"}))
}

func writeASNDatabase(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
