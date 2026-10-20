package model

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var tableNames = map[string]int{"default": TableDefault, "main": TableMain, "local": TableLocal}

// ParseTable turns "", a name or a number into a routing table id.
func ParseTable(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return TableMain, nil
	}
	if n, ok := tableNames[s]; ok {
		return n, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 0x7fffffff {
		return 0, fmt.Errorf("invalid table %q", s)
	}
	return n, nil
}

// TableName is the inverse of ParseTable, for display.
func TableName(n int) string {
	for k, v := range tableNames {
		if v == n {
			return k
		}
	}
	return strconv.Itoa(n)
}

// ParseCIDR accepts "a.b.c.d", "a.b.c.d/n" and (if allowDefault) "default".
// A bare IP becomes a /32. Host bits are kept (as `ip addr` needs them).
func ParseCIDR(s string, allowDefault bool) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if allowDefault && (s == "default" || s == "0.0.0.0/0") {
		return &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}, nil
	}
	if !strings.Contains(s, "/") {
		s += "/32"
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid IPv4 address or network %q", s)
	}
	n.IP = n.IP.To4()
	return n, nil
}

// ParseAddr is like ParseCIDR but keeps the host part: 10.0.0.1/16 -> ip 10.0.0.1 mask /16.
func ParseAddr(s string) (*net.IPNet, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil || !p.Addr().Is4() {
		return nil, fmt.Errorf("invalid IPv4 address %q (use ip/prefix, e.g. 10.0.0.1/24)", s)
	}
	ip := p.Addr().As4()
	return &net.IPNet{IP: ip[:], Mask: net.CIDRMask(p.Bits(), 32)}, nil
}

func validIface(s string) bool {
	return s == "" || (len(s) <= 15 && !strings.ContainsAny(s, " /\t\n\"'"))
}

// Validate checks one address entry.
func (a Address) Validate() error {
	if a.Interface == "" || !validIface(a.Interface) {
		return fmt.Errorf("interface is required")
	}
	_, err := ParseAddr(a.Address)
	return err
}

func (r Route) Validate() error {
	if _, err := ParseCIDR(r.Dst, true); err != nil {
		return err
	}
	if r.Gateway != "" && net.ParseIP(r.Gateway).To4() == nil {
		return fmt.Errorf("invalid gateway %q", r.Gateway)
	}
	if !validIface(r.Dev) {
		return fmt.Errorf("invalid interface %q", r.Dev)
	}
	if _, err := ParseTable(r.Table); err != nil {
		return err
	}
	switch r.Type {
	case "", "unicast":
		if r.Gateway == "" && r.Dev == "" {
			return fmt.Errorf("a route needs a gateway or an interface")
		}
	case "blackhole", "unreachable", "prohibit":
	default:
		return fmt.Errorf("invalid route type %q", r.Type)
	}
	if r.Metric < 0 {
		return fmt.Errorf("invalid metric")
	}
	return nil
}

func (r Rule) Validate() error {
	if r.Priority < 0 || r.Priority > 32765 {
		return fmt.Errorf("priority must be between 0 and 32765")
	}
	for _, s := range []string{r.Src, r.Dst} {
		if s != "" {
			if _, err := ParseCIDR(s, false); err != nil {
				return err
			}
		}
	}
	if !validIface(r.Iif) || !validIface(r.Oif) {
		return fmt.Errorf("invalid interface name")
	}
	switch r.Action {
	case "", "lookup":
		if _, err := ParseTable(r.Table); err != nil {
			return err
		}
		if r.Table == "" {
			return fmt.Errorf("table is required for lookup rules")
		}
	case "blackhole", "unreachable", "prohibit":
	default:
		return fmt.Errorf("invalid action %q", r.Action)
	}
	return nil
}

func parsePorts(s string) error {
	if s == "" {
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		for i, v := range []string{lo, hi} {
			if i == 1 && !isRange {
				break
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("invalid port %q", s)
			}
		}
	}
	return nil
}

func (r FWRule) Validate() error {
	switch r.Chain {
	case ChainInput, ChainForward, ChainOutput, ChainPrerouting, ChainPostrouting:
	default:
		return fmt.Errorf("invalid chain %q", r.Chain)
	}
	nat := r.Chain == ChainPrerouting || r.Chain == ChainPostrouting
	switch r.Action {
	case "accept", "drop", "reject", "return":
		if nat && r.Action != "accept" && r.Action != "return" {
			return fmt.Errorf("action %q is not valid in a NAT chain", r.Action)
		}
	case "masquerade":
		if r.Chain != ChainPostrouting {
			return fmt.Errorf("masquerade only works in srcnat")
		}
	case "snat":
		if r.Chain != ChainPostrouting {
			return fmt.Errorf("snat only works in srcnat")
		}
		if net.ParseIP(r.ToAddr).To4() == nil {
			return fmt.Errorf("snat needs to_addr")
		}
	case "dnat":
		if r.Chain != ChainPrerouting {
			return fmt.Errorf("dnat only works in dstnat")
		}
		if net.ParseIP(r.ToAddr).To4() == nil {
			return fmt.Errorf("dnat needs to_addr")
		}
	default:
		return fmt.Errorf("invalid action %q", r.Action)
	}
	for _, s := range []string{r.Src, r.Dst} {
		if s != "" {
			if _, err := ParseCIDR(s, false); err != nil {
				return err
			}
		}
	}
	if !validIface(r.InIface) || !validIface(r.OutIface) {
		return fmt.Errorf("invalid interface name")
	}
	switch r.Proto {
	case "", "tcp", "udp", "icmp":
	default:
		return fmt.Errorf("invalid protocol %q", r.Proto)
	}
	if (r.SrcPort != "" || r.DstPort != "" || r.ToPort != 0) && r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("ports need proto tcp or udp")
	}
	if err := parsePorts(r.SrcPort); err != nil {
		return err
	}
	if err := parsePorts(r.DstPort); err != nil {
		return err
	}
	if r.ConnState != "" {
		for _, s := range strings.Split(r.ConnState, ",") {
			switch strings.TrimSpace(s) {
			case "new", "established", "related", "invalid", "untracked":
			default:
				return fmt.Errorf("invalid connection state %q", s)
			}
		}
	}
	return nil
}

// Validate checks the whole config, returning the first problem found.
func (c *Config) Validate() error {
	seen := map[string]bool{}
	check := func(kind, id string) error {
		if id == "" {
			return fmt.Errorf("%s without id", kind)
		}
		if seen[id] {
			return fmt.Errorf("duplicate id %q", id)
		}
		seen[id] = true
		return nil
	}
	for _, a := range c.Addresses {
		if err := check("address", a.ID); err != nil {
			return err
		}
		if err := a.Validate(); err != nil {
			return fmt.Errorf("address %s: %w", a.Address, err)
		}
	}
	for _, r := range c.Routes {
		if err := check("route", r.ID); err != nil {
			return err
		}
		if err := r.Validate(); err != nil {
			return fmt.Errorf("route %s: %w", r.Dst, err)
		}
	}
	for _, r := range c.Rules {
		if err := check("rule", r.ID); err != nil {
			return err
		}
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule %d: %w", r.Priority, err)
		}
	}
	for _, r := range c.Firewall.Rules {
		if err := check("firewall rule", r.ID); err != nil {
			return err
		}
		if err := r.Validate(); err != nil {
			return fmt.Errorf("firewall rule %s: %w", r.ID, err)
		}
	}
	for _, p := range []string{c.Firewall.Policy.Input, c.Firewall.Policy.Forward, c.Firewall.Policy.Output} {
		if p != "" && p != "accept" && p != "drop" {
			return fmt.Errorf("invalid chain policy %q", p)
		}
	}
	for _, cl := range c.ClientRouting.Clients {
		if err := check("client route", cl.ID); err != nil {
			return err
		}
		if _, err := ParseCIDR(cl.Src, false); err != nil {
			return fmt.Errorf("client %s: %w", cl.Name, err)
		}
		if cl.In == "" || cl.Out == "" || !validIface(cl.In) || !validIface(cl.Out) {
			return fmt.Errorf("client %s: in and out interfaces are required", cl.Name)
		}
	}
	return nil
}
