package model

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/alirezasn3/mini-net-man/internal/tuning"
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

// validIfaceMatch is validIface for firewall matches, which also take a
// trailing * to mean "any name starting with this" (wg* matches wg0, wgBridge1).
func validIfaceMatch(s string) bool {
	if i := strings.IndexByte(s, '*'); i >= 0 {
		if i != len(s)-1 {
			return false
		}
		s = s[:i]
	}
	return validIface(s)
}

// ValidUsername limits panel user names to something safe to show and log:
// 1 to 32 printable characters, no spaces.
func ValidUsername(s string) error {
	if s == "" || len(s) > 32 {
		return fmt.Errorf("the username must be 1 to 32 characters")
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("the username can't contain spaces or control characters")
		}
	}
	return nil
}

// MaxListTimeout is the longest an add-to-list entry may live: a year.
const MaxListTimeout = 365 * 24 * 3600

// ValidListName limits address list names to what nftables accepts in a set
// name (starting with a letter) and short enough for the longest suffix.
func ValidListName(s string) error {
	if s == "" {
		return fmt.Errorf("an address list name is required")
	}
	if len(s) > 24 {
		return fmt.Errorf("an address list name can be at most 24 characters")
	}
	for i, r := range s {
		letter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		digit := r >= '0' && r <= '9'
		if !(letter || i > 0 && (digit || r == '_' || r == '-' || r == '.')) {
			return fmt.Errorf("list name %q: start with a letter, then letters, digits, _ - or . only", s)
		}
	}
	return nil
}

// SplitListRef reads a list reference in a firewall rule: "name", or "!name"
// for "not in the list".
func SplitListRef(s string) (name string, not bool) {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "!"); ok {
		return strings.TrimSpace(rest), true
	}
	return s, false
}

// ParseListAddress reads one address list entry: an IP, a network
// (10.0.0.0/8) or an inclusive range (10.0.0.5-10.0.0.20), IPv4 or IPv6. It
// returns the first and last address covered.
func ParseListAddress(s string) (first, last netip.Addr, err error) {
	s = strings.TrimSpace(s)
	bad := func() (netip.Addr, netip.Addr, error) {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("%q is not an IP address, network (10.0.0.0/8) or range (10.0.0.5-10.0.0.20)", s)
	}
	if a, b, ok := strings.Cut(s, "-"); ok {
		fa, e1 := netip.ParseAddr(strings.TrimSpace(a))
		la, e2 := netip.ParseAddr(strings.TrimSpace(b))
		if e1 != nil || e2 != nil || fa.Is4() != la.Is4() || fa.Is4In6() || la.Is4In6() || fa.Zone() != "" || la.Zone() != "" {
			return bad()
		}
		if fa.Compare(la) > 0 {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("range %q ends before it starts", s)
		}
		return fa, la, nil
	}
	if strings.Contains(s, "/") {
		p, e := netip.ParsePrefix(s)
		if e != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return bad()
		}
		p = p.Masked()
		return p.Addr(), lastAddr(p), nil
	}
	a, e := netip.ParseAddr(s)
	if e != nil || a.Is4In6() || a.Zone() != "" {
		return bad()
	}
	return a, a, nil
}

// lastAddr is the highest address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// Validate checks one address list entry.
func (e AddressEntry) Validate() error {
	if err := ValidListName(e.List); err != nil {
		return err
	}
	_, _, err := ParseListAddress(e.Address)
	return err
}

// Validate checks one bridge entry.
func (b Bridge) Validate() error {
	if b.Name == "" || !validIface(b.Name) || strings.Contains(b.Name, "*") {
		return fmt.Errorf("the bridge needs a name of up to 15 characters, without spaces")
	}
	if b.Name == "lo" {
		return fmt.Errorf("lo can't be a bridge")
	}
	if b.MTU != 0 && (b.MTU < 68 || b.MTU > 65535) {
		return fmt.Errorf("MTU must be 0 (leave it) or between 68 and 65535")
	}
	seen := map[string]bool{}
	for _, p := range b.Ports {
		switch {
		case p == "" || !validIface(p) || strings.Contains(p, "*"):
			return fmt.Errorf("invalid port name %q", p)
		case p == b.Name:
			return fmt.Errorf("a bridge can't be its own port")
		case p == "lo":
			return fmt.Errorf("lo can't be a bridge port")
		case seen[p]:
			return fmt.Errorf("port %s is listed twice", p)
		}
		seen[p] = true
	}
	return nil
}

// Validate checks one interface setting.
func (l LinkSetting) Validate() error {
	if l.Name == "" || !validIface(l.Name) || strings.Contains(l.Name, "*") {
		return fmt.Errorf("the interface needs a name")
	}
	switch l.State {
	case "", "up", "down":
	default:
		return fmt.Errorf("state must be empty, up or down")
	}
	if l.Name == "lo" && l.State == "down" {
		return fmt.Errorf("lo can't be taken down: the panel and local services use it")
	}
	if l.MTU != 0 && (l.MTU < 68 || l.MTU > 65535) {
		return fmt.Errorf("MTU must be 0 (leave it) or between 68 and 65535")
	}
	if l.State == "" && l.MTU == 0 {
		return fmt.Errorf("choose a state or an MTU to keep, otherwise this entry does nothing")
	}
	return nil
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
	case ChainInput, ChainForward, ChainOutput, ChainMangle, ChainMangleIn, ChainMangleOut, ChainPrerouting, ChainPostrouting:
	default:
		return fmt.Errorf("invalid chain %q", r.Chain)
	}
	nat := r.Chain == ChainPrerouting || r.Chain == ChainPostrouting
	marking := r.Action == ActionMarkConnection || r.Action == ActionRestoreMark
	switch r.Chain {
	case ChainMangle:
		if r.Action != ActionClampMSS {
			return fmt.Errorf("the mangle chain only takes %s rules", ActionClampMSS)
		}
	case ChainMangleIn, ChainMangleOut:
		if !marking && r.Action != ActionAddSrcToList && r.Action != ActionAddDstToList {
			return fmt.Errorf("the %s chain only takes %s, %s and the add-to-list rules", r.Chain, ActionMarkConnection, ActionRestoreMark)
		}
	}
	switch r.Action {
	case "accept", "drop", "reject", "return":
		if nat && r.Action != "accept" && r.Action != "return" {
			return fmt.Errorf("action %q is not valid in a NAT chain", r.Action)
		}
	case ActionMarkConnection, ActionRestoreMark:
		if r.Chain != ChainMangleIn && r.Chain != ChainMangleOut {
			return fmt.Errorf("%s only works in the mangle-in and mangle-out chains", r.Action)
		}
		if r.Action == ActionMarkConnection && r.Mark == 0 {
			return fmt.Errorf("mark-connection needs a mark above 0")
		}
	case ActionClampMSS:
		if r.Chain != ChainMangle {
			return fmt.Errorf("%s only works in the mangle chain", ActionClampMSS)
		}
		if r.Proto != "" && r.Proto != "tcp" {
			return fmt.Errorf("%s only applies to tcp", ActionClampMSS)
		}
		if r.MSS != 0 && (r.MSS < 536 || r.MSS > 9000) {
			return fmt.Errorf("mss must be 0 (fit the route's MTU) or between 536 and 9000")
		}
	case ActionAddSrcToList, ActionAddDstToList:
		if r.Chain == ChainMangle {
			return fmt.Errorf("%s doesn't work in the mangle chain", r.Action)
		}
		if err := ValidListName(r.List); err != nil {
			return fmt.Errorf("%s: %w", r.Action, err)
		}
		if r.Timeout < 0 || r.Timeout > MaxListTimeout {
			return fmt.Errorf("timeout must be 0 (no expiry) to %d seconds", MaxListTimeout)
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
	if !validIfaceMatch(r.InIface) || !validIfaceMatch(r.OutIface) {
		return fmt.Errorf("invalid interface name")
	}
	for _, ref := range []string{r.SrcList, r.DstList} {
		if ref == "" {
			continue
		}
		name, _ := SplitListRef(ref)
		if err := ValidListName(name); err != nil {
			return err
		}
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
	inList := map[string]bool{}
	for _, e := range c.AddressLists {
		if err := check("address list entry", e.ID); err != nil {
			return err
		}
		if err := e.Validate(); err != nil {
			return fmt.Errorf("address list %s: %w", e.List, err)
		}
		if e.Disabled {
			continue
		}
		first, last, _ := ParseListAddress(e.Address)
		key := e.List + "|" + first.String() + "-" + last.String()
		if inList[key] {
			return fmt.Errorf("address list %s already has %s", e.List, e.Address)
		}
		inList[key] = true
	}
	bridgeName, portOf := map[string]bool{}, map[string]string{}
	for _, b := range c.Bridges {
		if err := check("bridge", b.ID); err != nil {
			return err
		}
		if err := b.Validate(); err != nil {
			return fmt.Errorf("bridge %s: %w", b.Name, err)
		}
		if b.Disabled {
			continue
		}
		if bridgeName[b.Name] {
			return fmt.Errorf("there are two bridges called %s", b.Name)
		}
		bridgeName[b.Name] = true
	}
	for _, b := range c.Bridges {
		if b.Disabled {
			continue
		}
		for _, p := range b.Ports {
			if bridgeName[p] {
				return fmt.Errorf("bridge %s: %s is a bridge itself", b.Name, p)
			}
			if other, ok := portOf[p]; ok {
				return fmt.Errorf("%s is a port of both %s and %s; an interface can only be in one bridge", p, other, b.Name)
			}
			portOf[p] = b.Name
		}
	}
	setting := map[string]bool{}
	for _, l := range c.Interfaces {
		if err := check("interface", l.ID); err != nil {
			return err
		}
		if err := l.Validate(); err != nil {
			return fmt.Errorf("interface %s: %w", l.Name, err)
		}
		if !l.Disabled {
			if setting[l.Name] {
				return fmt.Errorf("interface %s has two settings entries; keep one", l.Name)
			}
			setting[l.Name] = true
		}
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
	ids := make([]string, 0, len(c.Sysctl.Tuning))
	for id := range c.Sysctl.Tuning {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := tuning.Validate(id, c.Sysctl.Tuning[id]); err != nil {
			return err
		}
	}
	checkIDs := map[string]bool{}
	for _, ck := range c.Checks {
		if err := check("health check", ck.ID); err != nil {
			return err
		}
		if err := ck.Validate(); err != nil {
			return fmt.Errorf("health check %q: %w", ck.Name, err)
		}
		checkIDs[ck.ID] = true
	}
	for _, r := range c.Rules {
		if r.Check != "" && !checkIDs[r.Check] {
			return fmt.Errorf("rule %d depends on a health check that doesn't exist", r.Priority)
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

// Defaults for a health check's timing; units are seconds and milliseconds.
const (
	DefaultCheckInterval = 5
	DefaultCheckTimeout  = 1000
	DefaultFailAfter     = 3
	DefaultRecoverAfter  = 2
)

func orDefault(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}

// Interval, Timeout, Fails and Recovers return the check's settings with defaults applied.
func (c Check) Interval() int { return orDefault(c.IntervalSecs, DefaultCheckInterval) }
func (c Check) Timeout() int  { return orDefault(c.TimeoutMs, DefaultCheckTimeout) }
func (c Check) Fails() int    { return orDefault(c.FailAfter, DefaultFailAfter) }
func (c Check) Recovers() int { return orDefault(c.RecoverAfter, DefaultRecoverAfter) }

// V6 reports whether the target is an IPv6 address.
func (c Check) V6() bool { return strings.Contains(c.Target, ":") }

func (c Check) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("a name is required")
	}
	if net.ParseIP(strings.TrimSpace(c.Target)) == nil {
		return fmt.Errorf("target must be an IPv4 or IPv6 address, got %q", c.Target)
	}
	if c.Interface == "" || !validIface(c.Interface) {
		return fmt.Errorf("an interface is required")
	}
	if c.Table != "" {
		if _, err := ParseTable(c.Table); err != nil {
			return err
		}
	}
	if v := c.Interval(); v < 1 || v > 3600 {
		return fmt.Errorf("interval must be between 1 and 3600 seconds")
	}
	if v := c.Timeout(); v < 100 || v > 30000 {
		return fmt.Errorf("timeout must be between 100 and 30000 ms")
	}
	if c.Timeout() > c.Interval()*1000 {
		return fmt.Errorf("the timeout (%d ms) can't be longer than the interval (%d s)", c.Timeout(), c.Interval())
	}
	if c.Fails() < 1 || c.Fails() > 100 || c.Recovers() < 1 || c.Recovers() > 100 {
		return fmt.Errorf("fail-after and recover-after must be between 1 and 100")
	}
	return nil
}
