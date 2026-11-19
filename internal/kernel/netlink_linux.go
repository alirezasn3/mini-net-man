//go:build linux

package kernel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Linux is the real Kernel: netlink for links, addresses, routes and rules,
// and nftables for the firewall.
type Linux struct{}

func NewLinux() *Linux { return &Linux{} }

// New returns the Kernel for this OS.
func New() (Kernel, error) { return NewLinux(), nil }

// ---- links and addresses -------------------------------------------------

func (Linux) Links() ([]model.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	byIdx := map[int][]string{}
	for _, a := range addrs {
		if a.IP.To4() == nil && a.IP.IsLinkLocalUnicast() {
			continue // fe80:: addresses are noise in the overview
		}
		byIdx[a.LinkIndex] = append(byIdx[a.LinkIndex], a.IPNet.String())
	}
	names := map[int]string{}
	for _, l := range links {
		names[l.Attrs().Index] = l.Attrs().Name
	}
	out := make([]model.Link, 0, len(links))
	for _, l := range links {
		at := l.Attrs()
		m := model.Link{
			Name: at.Name, Index: at.Index, Type: l.Type(), Master: names[at.MasterIndex],
			Up:      at.Flags&net.FlagUp != 0,
			Running: at.Flags&net.FlagRunning != 0,
			MTU:     at.MTU, MAC: at.HardwareAddr.String(), Addrs: byIdx[at.Index],
		}
		if s := at.Statistics; s != nil {
			m.RxBytes, m.TxBytes = s.RxBytes, s.TxBytes
		}
		out = append(out, m)
	}
	return out, nil
}

func (Linux) SetLinkUp(name string, up bool) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if up {
		return netlink.LinkSetUp(l)
	}
	return netlink.LinkSetDown(l)
}

func (Linux) SetLinkMTU(name string, mtu int) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(l, mtu)
}

func (Linux) AddBridge(name string) error {
	return netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name}})
}

func (Linux) DelBridge(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if l.Type() != "bridge" {
		return fmt.Errorf("%s is a %s, not a bridge", name, l.Type())
	}
	return netlink.LinkDel(l)
}

// SetBridgeSTP sets IFLA_BR_STP_STATE. The library has no field for it, so the
// message is built by hand.
func (Linux) SetBridgeSTP(name string, on bool) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if l.Type() != "bridge" {
		return fmt.Errorf("%s is a %s, not a bridge", name, l.Type())
	}
	req := nl.NewNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_ACK)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(l.Attrs().Index)
	req.AddData(msg)
	info := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	info.AddRtAttr(nl.IFLA_INFO_KIND, nl.NonZeroTerminated("bridge"))
	data := info.AddRtAttr(nl.IFLA_INFO_DATA, nil)
	state := uint32(0)
	if on {
		state = 1
	}
	data.AddRtAttr(nl.IFLA_BR_STP_STATE, nl.Uint32Attr(state))
	req.AddData(info)
	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func (Linux) SetMaster(iface, bridge string) error {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	if bridge == "" {
		return netlink.LinkSetNoMaster(l)
	}
	b, err := netlink.LinkByName(bridge)
	if err != nil {
		return err
	}
	return netlink.LinkSetMaster(l, b)
}

func (Linux) ListAddrs() ([]Addr, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	names := map[int]string{}
	links, _ := netlink.LinkList()
	for _, l := range links {
		names[l.Attrs().Index] = l.Attrs().Name
	}
	var out []Addr
	for _, a := range addrs {
		out = append(out, Addr{Interface: names[a.LinkIndex], Address: a.IPNet.String()})
	}
	return out, nil
}

func (Linux) AddAddr(iface, cidr string) error {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	n, err := model.ParseAddr(cidr)
	if err != nil {
		return err
	}
	return netlink.AddrReplace(l, &netlink.Addr{IPNet: n})
}

func (Linux) DelAddr(iface, cidr string) error {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	n, err := model.ParseAddr(cidr)
	if err != nil {
		return err
	}
	return netlink.AddrDel(l, &netlink.Addr{IPNet: n})
}

// ---- routes --------------------------------------------------------------

var routeTypes = map[string]int{"": unix.RTN_UNICAST, "unicast": unix.RTN_UNICAST,
	"blackhole": unix.RTN_BLACKHOLE, "unreachable": unix.RTN_UNREACHABLE, "prohibit": unix.RTN_PROHIBIT}

var protoNames = map[netlink.RouteProtocol]string{
	unix.RTPROT_KERNEL: "kernel", unix.RTPROT_BOOT: "boot", unix.RTPROT_STATIC: "static",
	unix.RTPROT_DHCP: "dhcp", unix.RTPROT_RA: "ra", Owner: "mini-net-man",
}

func toNetlinkRoute(r model.Route) (*netlink.Route, error) {
	v6 := r.V6()
	dst, err := model.ParseCIDR(r.NormDst(), true)
	if err != nil {
		return nil, err
	}
	table, err := model.ParseTable(r.Table)
	if err != nil {
		return nil, err
	}
	nr := &netlink.Route{
		Family: netlink.FAMILY_V4, Table: table, Priority: r.Metric,
		Protocol: Owner, Type: routeTypes[r.Type], Scope: netlink.SCOPE_UNIVERSE,
	}
	if v6 {
		nr.Family = netlink.FAMILY_V6
	}
	// Always send the destination, even for a default route: netlink refuses
	// a route that has only an interface and no Dst, Src or Gw.
	nr.Dst = dst
	if r.Gateway != "" {
		nr.Gw = net.ParseIP(r.Gateway)
		if !v6 {
			nr.Gw = nr.Gw.To4()
		}
	}
	if r.Dev != "" {
		l, err := netlink.LinkByName(r.Dev)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", r.Dev, err)
		}
		nr.LinkIndex = l.Attrs().Index
		// Only IPv4 distinguishes on-link routes by scope; IPv6 is always universe.
		if !v6 && nr.Gw == nil && nr.Type == unix.RTN_UNICAST {
			nr.Scope = netlink.SCOPE_LINK
		}
	}
	return nr, nil
}

func (Linux) ReplaceRoute(r model.Route) error {
	nr, err := toNetlinkRoute(r)
	if err != nil {
		return err
	}
	return netlink.RouteReplace(nr)
}

func (Linux) DelRoute(r model.Route) error {
	nr, err := toNetlinkRoute(model.Route{Dst: r.Dst, Table: r.Table, Metric: r.Metric, Type: r.Type, Gateway: r.Gateway})
	if nr != nil && nr.Family == netlink.FAMILY_V6 && r.Metric == 0 {
		nr.Priority = 1024 // what the kernel stored for an IPv6 route added without a metric
	}
	if err != nil {
		return err
	}
	// Match on key only: the output interface may be gone already, and
	// scope "nowhere" means any scope (an on-link IPv4 route has link scope).
	nr.Scope = netlink.SCOPE_NOWHERE
	return netlink.RouteDel(nr)
}

func (Linux) ListRoutes() ([]LiveRoute, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	names := map[int]string{}
	links, _ := netlink.LinkList()
	for _, l := range links {
		names[l.Attrs().Index] = l.Attrs().Name
	}
	var out []LiveRoute
	for _, r := range routes {
		if r.Table == unix.RT_TABLE_LOCAL || r.Type == unix.RTN_BROADCAST || r.Type == unix.RTN_LOCAL ||
			r.Type == unix.RTN_MULTICAST || r.Type == unix.RTN_ANYCAST {
			continue
		}
		v6 := r.Family == netlink.FAMILY_V6 || (r.Dst != nil && r.Dst.IP.To4() == nil) || (r.Gw != nil && r.Gw.To4() == nil)
		mr := model.Route{Dst: "default", Dev: names[r.LinkIndex], Table: model.TableName(r.Table), Metric: r.Priority}
		if v6 {
			mr.Dst = "::/0"
		}
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones > 0 {
				mr.Dst = r.Dst.String()
			}
		}
		if r.Gw != nil {
			mr.Gateway = r.Gw.String()
		}
		for name, t := range routeTypes {
			if t == r.Type && name != "" && name != "unicast" {
				mr.Type = name
			}
		}
		proto, ok := protoNames[r.Protocol]
		if !ok {
			proto = fmt.Sprint(int(r.Protocol))
		}
		out = append(out, LiveRoute{Route: mr, Owned: r.Protocol == Owner, Proto: proto})
	}
	return out, nil
}

// ---- rules ---------------------------------------------------------------

var ruleActions = map[string]uint8{"": nl.FR_ACT_TO_TBL, "lookup": nl.FR_ACT_TO_TBL,
	"blackhole": nl.FR_ACT_BLACKHOLE, "unreachable": nl.FR_ACT_UNREACHABLE, "prohibit": nl.FR_ACT_PROHIBIT}

func toNetlinkRule(r model.Rule, owned bool) (*netlink.Rule, error) {
	nr := netlink.NewRule()
	nr.Family = netlink.FAMILY_V4
	if r.V6() {
		nr.Family = netlink.FAMILY_V6
	}
	nr.Priority = r.Priority
	nr.IifName, nr.OifName, nr.Mark = r.Iif, r.Oif, r.Fwmark
	for _, p := range []struct {
		s   string
		dst **net.IPNet
	}{{r.Src, &nr.Src}, {r.Dst, &nr.Dst}} {
		if p.s == "" {
			continue
		}
		n, err := model.ParseCIDR(p.s, false)
		if err != nil {
			return nil, err
		}
		*p.dst = n
	}
	act, ok := ruleActions[r.Action]
	if !ok {
		return nil, fmt.Errorf("invalid action %q", r.Action)
	}
	nr.Type = act
	if act == nl.FR_ACT_TO_TBL {
		t, err := model.ParseTable(r.Table)
		if err != nil {
			return nil, err
		}
		nr.Table = t
	} else {
		nr.Table = 0
	}
	if owned {
		nr.Protocol = Owner
	}
	return nr, nil
}

func (Linux) AddRule(r model.Rule) error {
	nr, err := toNetlinkRule(r, true)
	if err != nil {
		return err
	}
	return netlink.RuleAdd(nr)
}

// DelRule doesn't send our protocol tag, so it removes the rule whether or
// not it was created by us.
func (Linux) DelRule(r model.Rule) error {
	nr, err := toNetlinkRule(r, false)
	if err != nil {
		return err
	}
	return netlink.RuleDel(nr)
}

// ListRules dumps rules itself because netlink.RuleList drops the action
// (blackhole/unreachable/prohibit) of each rule.
func (Linux) ListRules() ([]LiveRule, error) {
	var out []LiveRule
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := listRules(fam)
		if err != nil {
			return nil, err
		}
		out = append(out, rules...)
	}
	return out, nil
}

func listRules(family int) ([]LiveRule, error) {
	req := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP|unix.NLM_F_REQUEST)
	req.AddData(nl.NewIfInfomsg(family))
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWRULE)
	if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
		return nil, err
	}
	var out []LiveRule
	for _, m := range msgs {
		hdr := nl.DeserializeRtMsg(m)
		attrs, err := nl.ParseRouteAttr(m[hdr.Len():])
		if err != nil {
			return nil, err
		}
		var (
			r     model.Rule
			table int
			proto uint8
		)
		if family == netlink.FAMILY_V6 {
			r.Family = "ipv6"
		}
		for _, a := range attrs {
			v := a.Value
			switch a.Attr.Type {
			case unix.RTA_TABLE:
				table = int(nl.NativeEndian().Uint32(v))
			case nl.FRA_SRC:
				r.Src = (&net.IPNet{IP: v, Mask: net.CIDRMask(int(hdr.Src_len), 8*len(v))}).String()
			case nl.FRA_DST:
				r.Dst = (&net.IPNet{IP: v, Mask: net.CIDRMask(int(hdr.Dst_len), 8*len(v))}).String()
			case nl.FRA_FWMARK:
				r.Fwmark = nl.NativeEndian().Uint32(v)
			case nl.FRA_IIFNAME:
				r.Iif = strings.TrimRight(string(v), "\x00")
			case nl.FRA_OIFNAME:
				r.Oif = strings.TrimRight(string(v), "\x00")
			case nl.FRA_PRIORITY:
				r.Priority = int(nl.NativeEndian().Uint32(v))
			case nl.FRA_PROTOCOL:
				proto = v[0]
			}
		}
		switch hdr.Type {
		case nl.FR_ACT_BLACKHOLE:
			r.Action = "blackhole"
		case nl.FR_ACT_UNREACHABLE:
			r.Action = "unreachable"
		case nl.FR_ACT_PROHIBIT:
			r.Action = "prohibit"
		case nl.FR_ACT_TO_TBL:
			r.Action, r.Table = "lookup", model.TableName(table)
		default:
			continue // goto/nop and friends: not ours to manage
		}
		out = append(out, LiveRule{Rule: r, Owned: proto == Owner})
	}
	return out, nil
}

// ---- sysctl --------------------------------------------------------------

func forwardPath(v6 bool) string {
	if v6 {
		return "/proc/sys/net/ipv6/conf/all/forwarding"
	}
	return "/proc/sys/net/ipv4/ip_forward"
}

func (Linux) IPForward(v6 bool) (bool, error) {
	b, err := os.ReadFile(forwardPath(v6))
	return strings.TrimSpace(string(b)) == "1", err
}

func (Linux) SetIPForward(v6, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return os.WriteFile(forwardPath(v6), []byte(v), 0o644)
}

// ---- watch ---------------------------------------------------------------

func (Linux) Watch(ctx context.Context) (<-chan struct{}, error) {
	out := make(chan struct{}, 1)
	done := ctx.Done()
	ping := func() {
		select {
		case out <- struct{}{}:
		default:
		}
	}
	links := make(chan netlink.LinkUpdate)
	addrs := make(chan netlink.AddrUpdate)
	routes := make(chan netlink.RouteUpdate)
	if err := netlink.LinkSubscribe(links, done); err != nil {
		return nil, err
	}
	if err := netlink.AddrSubscribe(addrs, done); err != nil {
		return nil, err
	}
	if err := netlink.RouteSubscribe(routes, done); err != nil {
		return nil, err
	}
	go func() {
		for {
			select {
			case <-done:
				return
			case <-links:
			case <-addrs:
			case <-routes:
			}
			ping()
		}
	}()
	return out, nil
}

// FirewallRuleset shells out to nft purely for display.
func (Linux) FirewallRuleset() (string, error) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		return "", nil
	}
	b, err := exec.Command(nft, "list", "table", "inet", TableName).CombinedOutput()
	if err != nil {
		return "", nil // table doesn't exist yet
	}
	return string(b), nil
}
