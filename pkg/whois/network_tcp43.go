package whois

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

func tcp43NetworkLookup(ctx context.Context, target networkTarget) (NetworkResult, error) {
	raw, server, err := tcp43Raw(ctx, target.prefix.Addr().String())
	if err != nil {
		return NetworkResult{}, err
	}
	result, err := parseTCP43NetworkResult(target, raw, server)
	if err != nil {
		return NetworkResult{}, err
	}
	return result, nil
}

func parseTCP43NetworkResult(target networkTarget, raw, server string) (NetworkResult, error) {
	fields := parseTCP43Fields(raw)
	start, end, ok := containingTCP43Range(fields, target)
	if !ok {
		return NetworkResult{}, fmt.Errorf("whois: response has no allocation containing %s", target.query)
	}

	result := NetworkResult{
		Query:        target.query,
		StartAddress: start.String(),
		EndAddress:   end.String(),
		Handle:       firstField(fields, "nethandle", "handle"),
		Name:         firstField(fields, "netname", "network name"),
		Type:         firstField(fields, "nettype", "status"),
		Country:      firstField(fields, "country"),
		ParentHandle: firstField(fields, "parent", "parenthandle"),
		Registry:     server,
		Contacts:     tcp43NetworkContacts(fields),
		Sources:      []string{"whois"},
		Raw:          raw,
	}
	if err := requireContainingAllocation(result, target); err != nil {
		return NetworkResult{}, err
	}
	return result, nil
}

func parseTCP43Fields(raw string) map[string][]string {
	fields := make(map[string][]string)
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		fields[key] = append(fields[key], strings.TrimSpace(value))
	}
	return fields
}

func containingTCP43Range(fields map[string][]string, target networkTarget) (netip.Addr, netip.Addr, bool) {
	if start, startErr := netip.ParseAddr(firstField(fields, "startaddress")); startErr == nil {
		if end, endErr := netip.ParseAddr(firstField(fields, "endaddress")); endErr == nil && allocationContainsTarget(start.Unmap(), end.Unmap(), target) {
			return start.Unmap(), end.Unmap(), true
		}
	}

	for _, key := range []string{"netrange", "inetnum"} {
		for _, value := range fields[key] {
			startText, endText, ok := strings.Cut(value, "-")
			if !ok {
				continue
			}
			start, startErr := netip.ParseAddr(strings.TrimSpace(startText))
			end, endErr := netip.ParseAddr(strings.TrimSpace(endText))
			if startErr == nil && endErr == nil && allocationContainsTarget(start.Unmap(), end.Unmap(), target) {
				return start.Unmap(), end.Unmap(), true
			}
		}
	}

	for _, key := range []string{"cidr", "route", "route6", "inet6num"} {
		for _, value := range fields[key] {
			for prefixText := range strings.SplitSeq(value, ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(prefixText))
				if err != nil {
					continue
				}
				prefix = prefix.Masked()
				if allocationContainsTarget(prefix.Addr(), lastAddress(prefix), target) {
					return prefix.Addr(), lastAddress(prefix), true
				}
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, false
}

func tcp43NetworkContacts(fields map[string][]string) []NetworkContact {
	var contacts []NetworkContact
	for _, field := range []struct {
		key  string
		role string
	}{
		{"orgname", "registrant"},
		{"org-name", "registrant"},
		{"organization", "registrant"},
		{"owner", "registrant"},
		{"custname", "customer"},
		{"customer", "customer"},
	} {
		for _, value := range fields[field.key] {
			contacts = append(contacts, NetworkContact{Roles: []string{field.role}, Organization: clearIfPrivacy(value)})
		}
	}
	for _, field := range []struct {
		key  string
		role string
	}{
		{"person", "unknown"},
		{"personname", "unknown"},
		{"contact", "unknown"},
	} {
		for _, value := range fields[field.key] {
			contacts = append(contacts, NetworkContact{Roles: []string{field.role}, Name: clearIfPrivacy(value)})
		}
	}
	for _, field := range []struct {
		key  string
		role string
	}{
		{"orgabuseemail", "abuse"},
		{"abuse-mailbox", "abuse"},
		{"orgtechemail", "technical"},
		{"orgnocemail", "noc"},
		{"e-mail", "unknown"},
		{"email", "unknown"},
	} {
		for _, value := range fields[field.key] {
			for token := range strings.FieldsSeq(value) {
				token = strings.Trim(token, "<>,;()")
				if IsEmail(token) {
					contacts = append(contacts, NetworkContact{Roles: []string{field.role}, Email: token})
					break
				}
			}
		}
	}
	return mergeNetworkContacts(nil, contacts)
}

func firstField(fields map[string][]string, keys ...string) string {
	for _, key := range keys {
		if values := fields[key]; len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
