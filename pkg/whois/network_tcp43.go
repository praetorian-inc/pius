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
		Server:       server,
		WhoisServer:  server,
		Contacts:     tcp43NetworkContacts(fields),
		Sources:      []string{"whois"},
		Raw:          raw,
	}
	result.Clean()
	if err := requireContainingAllocation(result, target); err != nil {
		return NetworkResult{}, err
	}
	return result, nil
}

func containingTCP43Range(fields map[string][]string, target networkTarget) (netip.Addr, netip.Addr, bool) {
	if start, end, ok := addressFieldRange(fields, target); ok {
		return start, end, true
	}
	if start, end, ok := dashedFieldRange(fields, target); ok {
		return start, end, true
	}
	return prefixFieldRange(fields, target)
}

func addressFieldRange(fields map[string][]string, target networkTarget) (netip.Addr, netip.Addr, bool) {
	start, startErr := netip.ParseAddr(firstField(fields, "startaddress"))
	end, endErr := netip.ParseAddr(firstField(fields, "endaddress"))
	if startErr != nil || endErr != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	return containingRange(start, end, target)
}

func dashedFieldRange(fields map[string][]string, target networkTarget) (netip.Addr, netip.Addr, bool) {
	for _, key := range []string{"netrange", "inetnum"} {
		for _, value := range fields[key] {
			start, end, ok := parseDashedRange(value)
			if ok && allocationContainsTarget(start, end, target) {
				return start, end, true
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, false
}

func parseDashedRange(value string) (netip.Addr, netip.Addr, bool) {
	startText, endText, ok := strings.Cut(value, "-")
	if !ok {
		return netip.Addr{}, netip.Addr{}, false
	}
	start, startErr := netip.ParseAddr(strings.TrimSpace(startText))
	end, endErr := netip.ParseAddr(strings.TrimSpace(endText))
	if startErr != nil || endErr != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	return start.Unmap(), end.Unmap(), true
}

func prefixFieldRange(fields map[string][]string, target networkTarget) (netip.Addr, netip.Addr, bool) {
	for _, key := range []string{"cidr", "route", "route6", "inetnum", "inet6num"} {
		for _, value := range fields[key] {
			for prefixText := range strings.SplitSeq(value, ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(prefixText))
				if err != nil {
					continue
				}
				prefix = prefix.Masked()
				start, end := prefix.Addr(), lastAddress(prefix)
				if allocationContainsTarget(start, end, target) {
					return start, end, true
				}
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, false
}

func containingRange(start, end netip.Addr, target networkTarget) (netip.Addr, netip.Addr, bool) {
	start, end = start.Unmap(), end.Unmap()
	return start, end, allocationContainsTarget(start, end, target)
}

func tcp43NetworkContacts(fields map[string][]string) []NetworkContact {
	contacts := organizationContacts(fields)
	contacts = append(contacts, individualContacts(fields)...)
	contacts = append(contacts, emailContacts(fields)...)
	return mergeNetworkContacts(nil, contacts)
}

func organizationContacts(fields map[string][]string) []NetworkContact {
	organizations := []struct {
		role  string
		value string
	}{
		{"customer", firstField(fields, "custname", "customer")},
		{"registrant", firstField(fields, "orgname", "org-name", "organization", "owner")},
	}

	contacts := make([]NetworkContact, 0, len(organizations))
	for _, organization := range organizations {
		if organization.value == "" {
			continue
		}
		contacts = append(contacts, NetworkContact{
			Roles:        []string{organization.role},
			Kind:         "org",
			Direct:       true,
			Organization: organization.value,
		})
	}
	return contacts
}

func individualContacts(fields map[string][]string) []NetworkContact {
	contactFields := []struct {
		key  string
		role string
	}{
		{"person", "unknown"},
		{"personname", "unknown"},
		{"contact", "unknown"},
	}

	var contacts []NetworkContact
	for _, field := range contactFields {
		for _, value := range fields[field.key] {
			contacts = append(contacts, NetworkContact{
				Roles:  []string{field.role},
				Kind:   "individual",
				Direct: true,
				Name:   value,
			})
		}
	}
	return contacts
}

func emailContacts(fields map[string][]string) []NetworkContact {
	emailFields := []struct {
		key  string
		role string
	}{
		{"orgabuseemail", "abuse"},
		{"abuse-mailbox", "abuse"},
		{"orgtechemail", "technical"},
		{"orgnocemail", "noc"},
		{"e-mail", "unknown"},
		{"email", "unknown"},
	}

	var contacts []NetworkContact
	for _, field := range emailFields {
		for _, value := range fields[field.key] {
			email := firstEmail(value)
			if email == "" {
				continue
			}
			contacts = append(contacts, NetworkContact{
				Roles: []string{field.role}, Direct: true, Email: email,
			})
		}
	}
	return contacts
}

func firstEmail(value string) string {
	for token := range strings.FieldsSeq(value) {
		token = strings.Trim(token, "<>,;()")
		if IsEmail(token) {
			return token
		}
	}
	return ""
}
