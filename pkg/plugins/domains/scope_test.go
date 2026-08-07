package domains

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ── OwnedZones ───────────────────────────────────────────────────────────

func TestOwnedZones(t *testing.T) {
	tests := []struct {
		name           string
		meta           map[string]string
		fallbackDomain string
		want           map[string]bool
	}{
		{
			name:           "nil meta falls back to queried domain's zone",
			meta:           nil,
			fallbackDomain: "example.com",
			want:           map[string]bool{"example.com": true},
		},
		{
			name:           "empty meta falls back to queried domain's zone",
			meta:           map[string]string{},
			fallbackDomain: "example.com",
			want:           map[string]bool{"example.com": true},
		},
		{
			name:           "owned_domains present widens beyond the queried zone",
			meta:           map[string]string{MetaOwnedDomains: "example.com,otherbrand.com"},
			fallbackDomain: "example.com",
			want:           map[string]bool{"example.com": true, "otherbrand.com": true},
		},
		{
			name:           "owned_domains takes priority over the fallback domain",
			meta:           map[string]string{MetaOwnedDomains: "otherbrand.com"},
			fallbackDomain: "example.com",
			want:           map[string]bool{"otherbrand.com": true},
		},
		{
			name: "multi-part public suffix reduces to the registrable zone",
			meta: map[string]string{MetaOwnedDomains: "a.example.co.uk"},
			want: map[string]bool{"example.co.uk": true},
		},
		{
			name:           "nothing usable from either source returns nil",
			meta:           nil,
			fallbackDomain: "",
			want:           nil,
		},
		{
			name:           "unparseable owned_domains entries and empty fallback return nil",
			meta:           map[string]string{MetaOwnedDomains: ","},
			fallbackDomain: "",
			want:           nil,
		},
		{
			name:           "unparseable owned_domains falls through to fallback",
			meta:           map[string]string{MetaOwnedDomains: ""},
			fallbackDomain: "example.com",
			want:           map[string]bool{"example.com": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OwnedZones(tt.meta, tt.fallbackDomain)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── InOwnedZone ──────────────────────────────────────────────────────────

func TestInOwnedZone(t *testing.T) {
	tests := []struct {
		name  string
		host  string
		zones map[string]bool
		want  bool
	}{
		{
			name:  "subdomain of an owned zone is in scope",
			host:  "host.example.com",
			zones: map[string]bool{"example.com": true},
			want:  true,
		},
		{
			name:  "the owned zone itself is in scope",
			host:  "example.com",
			zones: map[string]bool{"example.com": true},
			want:  true,
		},
		{
			name:  "an unrelated domain is out of scope",
			host:  "host.other.com",
			zones: map[string]bool{"example.com": true},
			want:  false,
		},
		{
			name:  "nil zones puts nothing in scope",
			host:  "example.com",
			zones: nil,
			want:  false,
		},
		{
			// The reason registrableZone uses the public suffix list instead
			// of counting labels: "a.example.co.uk" and "example.co.uk" share
			// a registrable zone, so a subdomain of a multi-part-suffix owned
			// domain must be recognized as in scope.
			name:  "subdomain under a multi-part public suffix zone is in scope",
			host:  "a.example.co.uk",
			zones: map[string]bool{"example.co.uk": true},
			want:  true,
		},
		{
			// Label counting would read "co.uk" as the shared zone and put
			// every UK domain in scope. The public suffix list must reject
			// this: sharing "co.uk" is not sharing a registrable zone.
			name:  "a different domain under the same multi-part suffix is NOT in scope",
			host:  "other.co.uk",
			zones: map[string]bool{"example.co.uk": true},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InOwnedZone(tt.host, tt.zones)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── DropWildcard ─────────────────────────────────────────────────────────

func TestDropWildcard(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantOK   bool
	}{
		{
			name:     "wildcard parent is recovered",
			input:    "*.foo.example.com",
			wantName: "foo.example.com",
			wantOK:   true,
		},
		{
			name:     "bare wildcard yields nothing",
			input:    "*",
			wantName: "",
			wantOK:   false,
		},
		{
			name:     "empty string yields nothing",
			input:    "",
			wantName: "",
			wantOK:   false,
		},
		{
			name:     "non-wildcard name passes through normalized",
			input:    "API.Example.Com.",
			wantName: "api.example.com",
			wantOK:   true,
		},
		{
			name:     "a second embedded wildcard still leaves a wildcard behind",
			input:    "*.*.example.com",
			wantName: "",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotOK := DropWildcard(tt.input)
			assert.Equal(t, tt.wantName, gotName)
			assert.Equal(t, tt.wantOK, gotOK)
		})
	}
}
