// SPDX-License-Identifier: Apache-2.0

// Package discovery finds hosts and services in the networks the user
// allows Varde to look at. Every connection Varde makes to the local
// network, by a scan or an integration, goes through a Scope: nothing
// outside the allowed private ranges is ever contacted.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Limits on what a user can allow.
const (
	// MaxNetworks is the number of ranges a scope can hold.
	MaxNetworks = 8
	// MaxScanAddresses bounds one scan (a /20 in IPv4).
	MaxScanAddresses = 4096
)

// private lists the ranges Varde may be pointed at: RFC 1918, carrier-grade
// NAT (Tailscale and similar overlays use it) and IPv6 unique local
// addresses. Public ranges are refused so a scan can never hit third
// parties.
var private = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// ErrOutOfScope is returned when an address lies outside the allowed
// networks.
var ErrOutOfScope = errors.New("address is outside the networks Varde may contact")

// Scope is the set of networks Varde may contact.
type Scope struct {
	nets []netip.Prefix
}

// ParseScope parses a comma or whitespace separated list of CIDR ranges.
// A single address is accepted as a /32 or /128.
func ParseScope(s string) (Scope, error) {
	var sc Scope
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
	for _, f := range fields {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			a, aerr := netip.ParseAddr(f)
			if aerr != nil {
				return Scope{}, fmt.Errorf("%q is not a network range such as 192.168.1.0/24", f)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		p = p.Masked()
		if !isPrivate(p) {
			return Scope{}, fmt.Errorf("%s is not a private range; only home and internal networks can be allowed", p)
		}
		sc.nets = append(sc.nets, p)
	}
	if len(sc.nets) > MaxNetworks {
		return Scope{}, fmt.Errorf("at most %d ranges can be allowed", MaxNetworks)
	}
	sort.Slice(sc.nets, func(i, j int) bool { return sc.nets[i].String() < sc.nets[j].String() })
	return sc, nil
}

func isPrivate(p netip.Prefix) bool {
	for _, q := range private {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Empty reports whether no network is allowed.
func (s Scope) Empty() bool { return len(s.nets) == 0 }

// Networks returns the allowed ranges.
func (s Scope) Networks() []netip.Prefix { return append([]netip.Prefix(nil), s.nets...) }

// String returns the ranges in their canonical form, comma separated.
func (s Scope) String() string {
	parts := make([]string, len(s.nets))
	for i, p := range s.nets {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}

// Contains reports whether a lies in an allowed network.
func (s Scope) Contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Addresses lists the IPv4 host addresses of the scope for a scan, without
// network and broadcast addresses. IPv6 ranges are too large to scan and are
// only used to allow integrations.
func (s Scope) Addresses() ([]netip.Addr, error) {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, p := range s.nets {
		if !p.Addr().Is4() {
			continue
		}
		size := 1 << (32 - p.Bits())
		if len(out)+size > MaxScanAddresses+2*MaxNetworks {
			return nil, fmt.Errorf("the allowed IPv4 ranges hold more than %d addresses; scan smaller ranges (at most a /20)", MaxScanAddresses)
		}
		a := p.Addr()
		for i := 0; i < size; i++ {
			skip := p.Bits() <= 30 && (i == 0 || i == size-1)
			if !skip && !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
			a = a.Next()
		}
	}
	if len(out) > MaxScanAddresses {
		return nil, fmt.Errorf("the allowed IPv4 ranges hold more than %d addresses; scan smaller ranges (at most a /20)", MaxScanAddresses)
	}
	return out, nil
}

// DialContext connects to addr only if every address it resolves to lies in
// the scope. The check runs on the resolved address, so a host name that
// later points elsewhere cannot widen the scope.
func (s Scope) DialContext(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		lastErr := ErrOutOfScope
		for _, ip := range ips {
			if !s.Contains(ip) {
				continue
			}
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return c, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}
