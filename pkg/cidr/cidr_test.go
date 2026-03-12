package cidr_test

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/cidr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertIPv4RangeToCIDR_SingleHost(t *testing.T) {
	tests := []struct {
		name    string
		start   string
		end     string
		want    []string
		wantErr bool
	}{
		{
			name:  "single /32 host",
			start: "192.168.1.1",
			end:   "192.168.1.1",
			want:  []string{"192.168.1.1/32"},
		},
		{
			name:  "single /24 network",
			start: "10.0.0.0",
			end:   "10.0.0.255",
			want:  []string{"10.0.0.0/24"},
		},
		{
			name:  "single /16 network",
			start: "172.16.0.0",
			end:   "172.16.255.255",
			want:  []string{"172.16.0.0/16"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cidr.ConvertIPv4RangeToCIDR(tt.start, tt.end)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertIPv4RangeToCIDR_MultipleBlocks(t *testing.T) {
	tests := []struct {
		name  string
		start string
		end   string
		want  []string
	}{
		{
			name:  "crosses /24 boundary - coalesces to /23",
			start: "10.0.0.0",
			end:   "10.0.1.255",
			want:  []string{"10.0.0.0/23"}, // netipx optimizes to single /23
		},
		{
			name:  "multiple /24 blocks",
			start: "192.168.0.0",
			end:   "192.168.3.255",
			want:  []string{"192.168.0.0/22"},
		},
		{
			name:  "non-aligned range",
			start: "10.0.0.128",
			end:   "10.0.0.255",
			want:  []string{"10.0.0.128/25"},
		},
		{
			name:  "small range within /24",
			start: "192.168.1.10",
			end:   "192.168.1.13",
			want:  []string{"192.168.1.10/31", "192.168.1.12/31"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cidr.ConvertIPv4RangeToCIDR(tt.start, tt.end)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertIPv4RangeToCIDR_InvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		start   string
		end     string
		wantErr bool
	}{
		{
			name:    "invalid start IP",
			start:   "not-an-ip",
			end:     "10.0.0.1",
			wantErr: true,
		},
		{
			name:    "invalid end IP",
			start:   "10.0.0.0",
			end:     "invalid",
			wantErr: true,
		},
		{
			name:    "both invalid",
			start:   "bad",
			end:     "also-bad",
			wantErr: true,
		},
		{
			name:    "empty start",
			start:   "",
			end:     "10.0.0.1",
			wantErr: true,
		},
		{
			name:    "empty end",
			start:   "10.0.0.0",
			end:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cidr.ConvertIPv4RangeToCIDR(tt.start, tt.end)
			assert.Error(t, err, "should return error for invalid input")
			assert.Nil(t, got, "should return nil result on error")
		})
	}
}

func TestConvertIPv4RangeToCIDR_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		start string
		end   string
		want  []string
	}{
		{
			name:  "entire /8 network",
			start: "10.0.0.0",
			end:   "10.255.255.255",
			want:  []string{"10.0.0.0/8"},
		},
		{
			name:  "two adjacent /32s",
			start: "192.168.1.10",
			end:   "192.168.1.11",
			want:  []string{"192.168.1.10/31"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cidr.ConvertIPv4RangeToCIDR(tt.start, tt.end)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSplitCIDR_AlreadySmall(t *testing.T) {
	tests := []struct {
		name  string
		cidr  string
		want  []string
	}{
		{
			name: "/24 returns itself",
			cidr: "192.168.1.0/24",
			want: []string{"192.168.1.0/24"},
		},
		{
			name: "/25 returns itself",
			cidr: "10.0.0.0/25",
			want: []string{"10.0.0.0/25"},
		},
		{
			name: "/32 returns itself",
			cidr: "192.168.1.1/32",
			want: []string{"192.168.1.1/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cidr.SplitCIDR(tt.cidr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSplitCIDR_SplitsLargerNetworks(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		wantCount int
		wantFirst string
		wantLast  string
	}{
		{
			name:      "/23 splits into 2 /24s",
			cidr:      "10.0.0.0/23",
			wantCount: 2,
			wantFirst: "10.0.0.0/24",
			wantLast:  "10.0.1.0/24",
		},
		{
			name:      "/22 splits into 4 /24s",
			cidr:      "192.168.0.0/22",
			wantCount: 4,
			wantFirst: "192.168.0.0/24",
			wantLast:  "192.168.3.0/24",
		},
		{
			name:      "/16 splits into 256 /24s",
			cidr:      "172.16.0.0/16",
			wantCount: 256,
			wantFirst: "172.16.0.0/24",
			wantLast:  "172.16.255.0/24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cidr.SplitCIDR(tt.cidr)
			assert.Len(t, got, tt.wantCount, "should split into expected number of /24s")
			if len(got) > 0 {
				assert.Equal(t, tt.wantFirst, got[0], "first subnet should match")
				assert.Equal(t, tt.wantLast, got[len(got)-1], "last subnet should match")
			}
		})
	}
}

func TestSplitCIDR_InvalidCIDR(t *testing.T) {
	tests := []struct {
		name string
		cidr string
	}{
		{
			name: "invalid format",
			cidr: "not-a-cidr",
		},
		{
			name: "missing prefix length",
			cidr: "192.168.1.0",
		},
		{
			name: "invalid IP",
			cidr: "999.999.999.999/24",
		},
		{
			name: "empty string",
			cidr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cidr.SplitCIDR(tt.cidr)
			assert.Empty(t, got, "invalid CIDR should return empty slice")
		})
	}
}

func TestSplitCIDR_IPv6NotSupported(t *testing.T) {
	tests := []struct {
		name string
		cidr string
	}{
		{
			name: "IPv6 /64",
			cidr: "2001:db8::/64",
		},
		{
			name: "IPv6 /48",
			cidr: "2001:db8::/48",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cidr.SplitCIDR(tt.cidr)
			assert.Empty(t, got, "IPv6 CIDR should return empty slice (not supported)")
		})
	}
}

func TestSplitCIDR_BoundaryOctetHandling(t *testing.T) {
	// Test that octet overflow is handled correctly (255 → 0, carry to next octet)
	got := cidr.SplitCIDR("10.0.254.0/23")

	require.Len(t, got, 2, "should split /23 into 2 /24s")
	assert.Equal(t, "10.0.254.0/24", got[0], "first /24 in /23")
	assert.Equal(t, "10.0.255.0/24", got[1], "second /24 in /23")
}
