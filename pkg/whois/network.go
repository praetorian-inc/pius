package whois

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// ErrAllocationDoesNotContainTarget means applying the returned registration
// to the complete input range would make an unsafe ownership claim.
var ErrAllocationDoesNotContainTarget = errors.New("allocation does not contain target")

// ValidateNetworkTarget checks that query is an IP address or CIDR.
func ValidateNetworkTarget(query string) error {
	_, err := parseNetworkTarget(query)
	return err
}

// LookupNetwork resolves an IP or CIDR using the default WHOIS cascade.
// It is retained as a compatibility wrapper around WHOIS.LookupNetwork.
func LookupNetwork(ctx context.Context, query string, opts ...Option) (NetworkResult, error) {
	return New(opts...).LookupNetwork(ctx, query)
}

// networkLookupState holds the mutable state for one network cascade walk.
type networkLookupState struct {
	target networkTarget
	result NetworkResult
	errs   []error
}

// LookupNetwork resolves an IP or CIDR through the configured RDAP and TCP-43
// network clients.
func (w *WHOIS) LookupNetwork(ctx context.Context, query string) (NetworkResult, error) {
	target, err := parseNetworkTarget(query)
	if err != nil {
		return NetworkResult{}, err
	}

	state := networkLookupState{target: target}
	w.doNetworkLookup(ctx, w.RDAPClient, &state)
	if ctx.Err() != nil || state.result.hasPreferredContact() {
		return state.finish()
	}

	w.doNetworkLookup(ctx, w.TCP43Client, &state)
	return state.finish()
}

// doNetworkLookup runs one network leg, validates its allocation, and merges it into state.
func (w *WHOIS) doNetworkLookup(ctx context.Context, client WHOISClient, state *networkLookupState) {
	if err := ctx.Err(); err != nil {
		state.errs = append(state.errs, err)
		return
	}

	result, err := client.LookupNetwork(ctx, state.target.query)
	if err != nil {
		state.errs = append(state.errs, err)
		return
	}

	result.Query = state.target.query
	result.Normalize()
	if err := requireContainingAllocation(result, state.target); err != nil {
		state.errs = append(state.errs, fmt.Errorf("%s network lookup: %w", client.Name(), err))
		return
	}

	state.result.Merge(result)
}

func (state *networkLookupState) finish() (NetworkResult, error) {
	if state.result.hasAllocation() {
		state.result.Query = state.target.query
		state.result.Normalize()
		return state.result, nil
	}
	if joined := errors.Join(state.errs...); joined != nil {
		return NetworkResult{}, fmt.Errorf("whois: all methods failed for %s: %w", state.target.query, joined)
	}
	return NetworkResult{}, fmt.Errorf("whois: no source had a record for %s", state.target.query)
}

type networkTarget struct {
	query  string
	prefix netip.Prefix
}

func parseNetworkTarget(query string) (networkTarget, error) {
	if prefix, err := netip.ParsePrefix(query); err == nil {
		prefix = prefix.Masked()
		return networkTarget{query: prefix.String(), prefix: prefix}, nil
	}

	addr, err := netip.ParseAddr(query)
	if err != nil {
		return networkTarget{}, fmt.Errorf("whois: invalid IP or CIDR %q", query)
	}
	return networkTarget{
		query:  addr.String(),
		prefix: netip.PrefixFrom(addr, addr.BitLen()),
	}, nil
}

func allocationContainsTarget(start, end netip.Addr, target networkTarget) bool {
	if !start.IsValid() || !end.IsValid() || start.BitLen() != target.prefix.Addr().BitLen() || end.BitLen() != start.BitLen() {
		return false
	}
	return start.Compare(target.prefix.Addr()) <= 0 && end.Compare(lastAddress(target.prefix)) >= 0
}

func lastAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr()
	bytes := addr.AsSlice()
	for bit := prefix.Bits(); bit < addr.BitLen(); bit++ {
		bytes[bit/8] |= 1 << (7 - bit%8)
	}
	last, _ := netip.AddrFromSlice(bytes)
	return last.Unmap()
}

func requireContainingAllocation(result NetworkResult, target networkTarget) error {
	start, startErr := netip.ParseAddr(result.StartAddress)
	end, endErr := netip.ParseAddr(result.EndAddress)
	if startErr != nil || endErr != nil {
		return fmt.Errorf("whois: response has no usable allocation range")
	}
	if !allocationContainsTarget(start.Unmap(), end.Unmap(), target) {
		return fmt.Errorf("%w: %s-%s does not contain %s", ErrAllocationDoesNotContainTarget, start, end, target.query)
	}
	return nil
}
