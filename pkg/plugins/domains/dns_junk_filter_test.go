package domains

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMin float64
		wantMax float64
	}{
		{
			name:    "empty string",
			input:   "",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "single repeated character",
			input:   "aaaaaa",
			wantMin: 0,
			wantMax: 0.01,
		},
		{
			name:    "normal hostname label",
			input:   "staging",
			wantMin: 2.0,
			wantMax: 3.0,
		},
		{
			name:    "random token",
			input:   "jvoind698msu93mkf5na9l2igbihsccp5d1buy",
			wantMin: 3.5,
			wantMax: 5.0,
		},
		{
			name:    "hex string",
			input:   "a1b2c3d4e5f6a7b8c9d0",
			wantMin: 3.5,
			wantMax: 5.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.input)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("shannonEntropy(%q) = %f, want between %f and %f", tt.input, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestShannonEntropy_MaxEntropy(t *testing.T) {
	// Maximum entropy for N distinct characters = log2(N)
	// For all lowercase letters (26): ~4.7
	input := "abcdefghijklmnopqrstuvwxyz"
	got := shannonEntropy(input)
	expected := math.Log2(26)
	if math.Abs(got-expected) > 0.01 {
		t.Errorf("shannonEntropy(alphabet) = %f, want ~%f", got, expected)
	}
}

func TestIsJunkLabel(t *testing.T) {
	tests := []struct {
		name  string
		label string
		want  bool
	}{
		// Normal labels — should NOT be flagged
		{name: "short normal", label: "api", want: false},
		{name: "staging", label: "staging", want: false},
		{name: "api-v2", label: "api-v2", want: false},
		{name: "mail01", label: "mail01", want: false},
		{name: "us-east-1", label: "us-east-1", want: false},
		{name: "www", label: "www", want: false},
		{name: "production", label: "production", want: false},
		{name: "k8s-ingress", label: "k8s-ingress", want: false},
		{name: "vpn-gateway", label: "vpn-gateway", want: false},

		// Junk labels — SHOULD be flagged
		{name: "OOB canary token", label: "jvoind698msu93mkf5na9l2igbihsccp5d1buy", want: true},
		{name: "hex token", label: "a1b2c3d4e5f6a7b8c9d0e1f2", want: true},
		{name: "very long label", label: "thislabeliswaytoolongtobearealsubdomainlabelinanydnssetup", want: true},
		{name: "random alphanumeric", label: "x7k9m2p4q8r1s5t3u6v0w", want: true},

		// Edge cases
		{name: "short high-entropy", label: "xyz", want: false},     // too short for entropy check
		{name: "9 chars mixed", label: "a1b2c3d4e", want: false},   // under minEntropyLength
		{name: "exactly 40 chars high entropy", label: "abcdefghijklmnopqrstuvwxyz01234567890123", want: true}, // high entropy + long
		{name: "long but repetitive", label: "aaa-bbb-aaa-bbb-aaa-bbb-aaa", want: false}, // repetitive = low entropy
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isJunkLabel(tt.label)
			if got != tt.want {
				entropy := shannonEntropy(tt.label)
				t.Errorf("isJunkLabel(%q) = %v, want %v (len=%d, entropy=%.2f)", tt.label, got, tt.want, len(tt.label), entropy)
			}
		})
	}
}

func TestContainsOOBPattern(t *testing.T) {
	tests := []struct {
		name string
		fqdn string
		want bool
	}{
		{name: "oob.guard domain", fqdn: "foo.oob.guard.example.com", want: true},
		{name: "interact.sh", fqdn: "token123.interact.sh", want: true},
		{name: "interactsh", fqdn: "abc.interactsh.com", want: true},
		{name: "burp collaborator", fqdn: "xyz.burpcollaborator.net", want: true},
		{name: "canarytokens", fqdn: "test.canarytokens.com", want: true},
		{name: "dnslog", fqdn: "foo.dnslog.cn", want: true},
		{name: "bxss", fqdn: "test.bxss.me", want: true},
		{name: "ceye", fqdn: "abc.ceye.io", want: true},
		{name: "oast", fqdn: "test.oast.fun", want: true},
		{name: "normal domain", fqdn: "api.staging.example.com", want: false},
		{name: "empty", fqdn: "", want: false},
		{name: "case insensitive", fqdn: "FOO.OOB.GUARD.EXAMPLE.COM", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsOOBPattern(tt.fqdn)
			if got != tt.want {
				t.Errorf("containsOOBPattern(%q) = %v, want %v", tt.fqdn, got, tt.want)
			}
		})
	}
}

func TestFilterJunkDomains(t *testing.T) {
	input := []string{
		"api.example.com",
		"staging.example.com",
		"www.example.com",
		"jvoind698msu93mkf5na9l2igbihsccp5d1buy.oob.guard.example.com",
		"serverjvoind698msu93mkf5na9l2igbihsccp5d1buy.oob.guard.example.com",
		"a1b2c3d4e5f6a7b8c9d0e1f2.example.com",
		"containerjvoind698msu93mkf5na9l2igbihsccp5d1buy.oob.guard.example.com",
		"mail.example.com",
		"token.interact.sh",
	}

	got := FilterJunkDomains(input)

	// Should keep only the normal domains
	expected := map[string]bool{
		"api.example.com":     true,
		"staging.example.com": true,
		"www.example.com":     true,
		"mail.example.com":    true,
	}

	if len(got) != len(expected) {
		t.Errorf("FilterJunkDomains returned %d domains, want %d", len(got), len(expected))
		for _, d := range got {
			t.Logf("  kept: %s", d)
		}
	}

	for _, d := range got {
		if !expected[d] {
			t.Errorf("FilterJunkDomains kept unexpected domain: %s", d)
		}
	}

	for d := range expected {
		found := false
		for _, g := range got {
			if g == d {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("FilterJunkDomains dropped expected domain: %s", d)
		}
	}
}

func TestFilterJunkDomains_Empty(t *testing.T) {
	got := FilterJunkDomains(nil)
	if len(got) != 0 {
		t.Errorf("FilterJunkDomains(nil) returned %d domains, want 0", len(got))
	}

	got = FilterJunkDomains([]string{})
	if len(got) != 0 {
		t.Errorf("FilterJunkDomains([]) returned %d domains, want 0", len(got))
	}
}

func TestFilterJunkDomains_AllJunk(t *testing.T) {
	input := []string{
		"jvoind698msu93mkf5na9l2igbihsccp5d1buy.oob.guard.example.com",
		"token.interact.sh",
	}
	got := FilterJunkDomains(input)
	if len(got) != 0 {
		t.Errorf("FilterJunkDomains(all junk) returned %d domains, want 0", len(got))
	}
}
