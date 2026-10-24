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

// ParseCIDR accepts an IPv4 or IPv6 address or network, and (if allowDefault)
// "default" (the IPv4 default). A bare IP becomes a /32 or /128. Host bits
// are kept.
func ParseCIDR(s string, allowDefault bool) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if allowDefault && s == "default" {
		s = "0.0.0.0/0"
	}
	v6 := strings.Contains(s, ":")
	if !strings.Contains(s, "/") {
		if v6 {
			s += "/128"
		} else {
			s += "/32"
		}
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address or network %q", s)
	}
	if v6 {
		if ip.To4() != nil && !strings.Contains(strings.SplitN(s, "/", 2)[0], "::") {
			return nil, fmt.Errorf("invalid IPv6 address %q", s)
		}
		n.IP = n.IP.To16()
	} else {
		n.IP = n.IP.To4()
	}
	return n, nil
}

// IsV6 reports whether n is an IPv6 network.
func IsV6(n *net.IPNet) bool { return n.IP.To4() == nil }

// ParseAddr is like ParseCIDR but keeps the host part: 10.0.0.1/16 -> ip 10.0.0.1 mask /16.
func ParseAddr(s string) (*net.IPNet, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invalid address %q (use ip/prefix, e.g. 10.0.0.1/24 or fd00::1/64)", s)
	}
	a := p.Addr().Unmap()
	if p.Addr().Is4In6() {
		return nil, fmt.Errorf("invalid address %q", s)
	}
	if a.Is4() {
		ip := a.As4()
		return &net.IPNet{IP: ip[:], Mask: net.CIDRMask(p.Bits(), 32)}, nil
	}
	ip := a.As16()
	return &net.IPNet{IP: ip[:], Mask: net.CIDRMask(p.Bits(), 128)}, nil
}

// V6 reports the family of a route: from its destination, or from the
// gateway when the destination is the generic "default".
func (r Route) V6() bool {
	if d := strings.TrimSpace(r.Dst); d != "" && d != "default" {
		if n, err := ParseCIDR(d, true); err == nil {
			return IsV6(n)
		}
	}
	return strings.Contains(r.Gateway, ":")
}

// NormDst is the destination with "default" resolved to its family's zero prefix.
func (r Route) NormDst() string {
	if strings.TrimSpace(r.Dst) == "default" && r.V6() {
		return "::/0"
	}
	return r.Dst
}

// V6 reports the family of a rule: explicit, else from src/dst, else IPv4.
func (r Rule) V6() bool {
	switch r.Family {
	case "ipv6":
		return true
	case "ipv4":
		return false
	}
	for _, s := range []string{r.Src, r.Dst} {
		if n, err := ParseCIDR(s, false); err == nil && s != "" {
			return IsV6(n)
		}
	}
	return false
}

// EffFamily is "ipv4", "ipv6", or "" when the rule applies to both. It is
// explicit if set, else inferred from the addresses it mentions.
func (r FWRule) EffFamily() string {
	if r.Family != "" {
		return r.Family
	}
	for _, s := range []string{r.Src, r.Dst, r.ToAddr} {
		if s == "" {
			continue
		}
		if n, err := ParseCIDR(s, false); err == nil {
			if IsV6(n) {
				return "ipv6"
			}
			return "ipv4"
		}
	}
	return ""
}

// checkFamilies makes sure every address given belongs to the same family.
func checkFamilies(want string, addrs ...string) error {
	for _, s := range addrs {
		if s == "" {
			continue
		}
		n, err := ParseCIDR(s, false)
		if err != nil {
			return err
		}
		got := "ipv4"
		if IsV6(n) {
			got = "ipv6"
		}
		if want == "" {
			want = got
		} else if want != got {
			return fmt.Errorf("%s is %s but the rest of the entry is %s", s, got, want)
		}
	}
	return nil
}

func validFamily(f string) bool { return f == "" || f == "ipv4" || f == "ipv6" }

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
	if r.Gateway != "" {
		if net.ParseIP(r.Gateway) == nil {
			return fmt.Errorf("invalid gateway %q", r.Gateway)
		}
		want := "ipv4"
		if r.V6() {
			want = "ipv6"
		}
		if err := checkFamilies(want, r.Gateway); err != nil {
			return fmt.Errorf("gateway: %w", err)
		}
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
	if !validFamily(r.Family) {
		return fmt.Errorf("invalid family %q", r.Family)
	}
	if err := checkFamilies(r.Family, r.Src, r.Dst); err != nil {
		return err
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
		if net.ParseIP(r.ToAddr) == nil {
			return fmt.Errorf("snat needs to_addr")
		}
	case "dnat":
		if r.Chain != ChainPrerouting {
			return fmt.Errorf("dnat only works in dstnat")
		}
		if net.ParseIP(r.ToAddr) == nil {
			return fmt.Errorf("dnat needs to_addr")
		}
	default:
		return fmt.Errorf("invalid action %q", r.Action)
	}
	if !validFamily(r.Family) {
		return fmt.Errorf("invalid family %q", r.Family)
	}
	if err := checkFamilies(r.Family, r.Src, r.Dst, r.ToAddr); err != nil {
		return err
	}
	if !validIface(r.InIface) || !validIface(r.OutIface) {
		return fmt.Errorf("invalid interface name")
	}
	switch r.Proto {
	case "", "tcp", "udp", "icmp", "icmpv6":
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
		if p != "" && p != "accept" && p != "drop" && p != "reject" {
			return fmt.Errorf("invalid chain policy %q", p)
		}
	}
	if r := c.Update.Repo; r != "" {
		if o, n, ok := strings.Cut(r, "/"); !ok || o == "" || n == "" || strings.ContainsAny(r, " \t\n?#") || strings.Count(r, "/") != 1 {
			return fmt.Errorf("update.repo must look like owner/name, got %q", r)
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
