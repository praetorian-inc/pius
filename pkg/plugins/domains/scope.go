package domains

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// MetaOwnedDomains is the Input.Meta key carrying the caller's set of
// already-known owned domains, comma-separated.
//
// Certificate Transparency and passive-DNS sources return every name on a
// matching certificate or record, which routinely includes names outside the
// zone that was queried. Some of those are the same organization's other
// brands — a certificate covering fox.com also covering foxweather.com is the
// single most valuable thing these sources produce — and some belong to
// unrelated tenants sharing a CDN certificate. Neither the plugin nor the
// queried domain can tell those apart: only a caller holding the org's full
// attack surface can. So the caller passes what it knows, and OwnedZones
// widens the scope check from "the queried zone" to "any zone the org owns".
//
// The key is unset for the pius CLI, which has no such inventory. Scope then
// falls back to the queried domain's own registrable zone, which is the
// conservative reading and matches the CLI's single-domain framing.
const MetaOwnedDomains = "owned_domains"

// OwnedZones reads the caller's owned-domain set out of Input.Meta and reduces
// it to registrable zones. Falls back to fallbackDomain's own zone when the
// caller supplied nothing.
//
// Returns nil when neither source yields a usable zone, which InOwnedZone
// reports as out-of-scope rather than silently admitting everything: a scope
// check that fails open would put the whole internet in scope on a
// misconfiguration.
func OwnedZones(meta map[string]string, fallbackDomain string) map[string]bool {
	zones := make(map[string]bool)
	for _, d := range strings.Split(meta[MetaOwnedDomains], ",") {
		if zone := registrableZone(d); zone != "" {
			zones[zone] = true
		}
	}
	if len(zones) == 0 {
		if zone := registrableZone(fallbackDomain); zone != "" {
			zones[zone] = true
		}
	}
	if len(zones) == 0 {
		return nil
	}
	return zones
}

// InOwnedZone reports whether host sits under any of the owned zones.
func InOwnedZone(host string, zones map[string]bool) bool {
	zone := registrableZone(host)
	return zone != "" && zones[zone]
}

// registrableZone reduces a name to its registrable domain (eTLD+1) using the
// public suffix list, so "a.b.example.co.uk" and "example.co.uk" compare equal
// while "example.co.uk" and "other.co.uk" do not. Label counting cannot do
// this: it reads "co.uk" as the zone and puts every UK domain in scope.
//
// Returns "" for a public suffix itself, an empty string, or anything the
// suffix list cannot resolve — all of which callers treat as out-of-scope.
func registrableZone(name string) string {
	name = normalizeDomain(name)
	if name == "" {
		return ""
	}
	zone, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return ""
	}
	return zone
}

// DropWildcard turns a wildcard certificate name into the zone it covers:
// "*.foo.example.com" becomes "foo.example.com". The parent is a real zone that
// had a certificate issued for it, so discarding the entry outright — as the
// crt.sh plugin did — throws away a confirmed name rather than a redundant one.
//
// Reports false for a bare "*" or anything left empty after stripping.
func DropWildcard(name string) (string, bool) {
	name = normalizeDomain(name)
	name = strings.TrimPrefix(name, "*.")
	if name == "" || strings.Contains(name, "*") {
		return "", false
	}
	return name, true
}
