package cidr

import (
	"fmt"
	"log/slog"
	"net"

	"go4.org/netipx"
)

// ConvertIPv4RangeToCIDR converts an IP range like "10.0.0.0 - 10.0.1.255"
// to a list of CIDR strings like ["10.0.0.0/24", "10.0.1.0/24"].
//
// Ported from chariot/backend/pkg/lib/cidr/cidr.go:220-232
func ConvertIPv4RangeToCIDR(ipStart string, ipEnd string) ([]string, error) {
	r, err := netipx.ParseIPRange(fmt.Sprintf("%s-%s", ipStart, ipEnd))
	if err != nil {
		return nil, err
	}

	var cidrs []string
	for _, prefix := range r.Prefixes() {
		cidrs = append(cidrs, prefix.String())
	}

	return cidrs, nil
}

// SplitCIDR splits a CIDR string into /24 subnets for scanning.
// CIDRs that are /24 or smaller are returned as-is.
// IPv6 CIDRs are not supported and return an empty slice.
//
// Ported from chariot/backend/pkg/lib/cidr/cidr.go:235-270
func SplitCIDR(cidrStr string) []string {
	var subnets []string

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return subnets
	}

	ipv4 := ipNet.IP.To4()
	if ipv4 == nil {
		slog.Warn("IPv6 subnets are not supported", "cidr", cidrStr)
		return subnets
	}

	size, _ := ipNet.Mask.Size()
	if size >= 24 {
		return []string{cidrStr}
	}

	ranges := 1 << (24 - size)

	subnets = append(subnets, fmt.Sprintf("%s/24", ipv4.String()))
	for range ranges - 1 {
		for j := 2; j >= 0; j-- {
			if ipv4[j] == byte(255) {
				ipv4[j] = byte(0)
				continue
			}
			ipv4[j] = ipv4[j] + byte(1)
			break
		}
		subnets = append(subnets, fmt.Sprintf("%s/24", ipv4.String()))
	}

	return subnets
}
