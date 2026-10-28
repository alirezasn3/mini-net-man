package kernel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// Mock is an in-memory Kernel. It behaves like the real thing where it
// matters (unknown interfaces are rejected, duplicate rules collide) so the
// engine and the web UI can be exercised without Linux.
type Mock struct {
	mu       sync.Mutex
	links    []model.Link
	addrs    []Addr
	routes   []LiveRoute
	rules    []LiveRule
	fw       *model.Firewall
	forward  [2]bool // v4, v6
	acct     bool
	pingFail map[string]bool
	sysctls  map[string]string
	missing  map[string]bool // keys this "kernel" doesn't have
	noBBR    bool
	stp      map[string]bool
	watchers []chan struct{}
}

// NewMock returns a kernel pre-populated with a typical VPN gateway.
func NewMock() *Mock {
	m := &Mock{}
	add := func(name, typ string, up bool, addrs ...string) {
		m.links = append(m.links, model.Link{Name: name, Index: len(m.links) + 1, Type: typ, Up: up, Running: up, MTU: 1420,
			MAC: fmt.Sprintf("02:00:00:00:00:%02x", len(m.links)+1)})
		for _, a := range addrs {
			m.addrs = append(m.addrs, Addr{Interface: name, Address: a})
		}
	}
	add("lo", "loopback", true, "127.0.0.1/8")
	add("ens192", "device", true, "192.168.71.10/24")
	add("wgServer", "wireguard", true, "10.0.0.1/16", "fd00:10::1/64")
	add("wgBridge0", "wireguard", true, "10.8.0.2/32", "fd00:8::2/128")
	add("wgBridge1", "wireguard", true, "10.9.0.2/32")
	m.routes = []LiveRoute{
		{Route: model.Route{Dst: "default", Gateway: "192.168.71.1", Dev: "ens192", Table: "main", Metric: 100}, Proto: "static"},
		{Route: model.Route{Dst: "192.168.71.0/24", Dev: "ens192", Table: "main"}, Proto: "kernel"},
		{Route: model.Route{Dst: "10.0.0.0/16", Dev: "wgServer", Table: "main"}, Proto: "kernel"},
		{Route: model.Route{Dst: "fd00:10::/64", Dev: "wgServer", Table: "main", Metric: 256}, Proto: "kernel"},
	}
	m.rules = []LiveRule{
		{Rule: model.Rule{Priority: 0, Action: "lookup", Table: "local"}},
		{Rule: model.Rule{Priority: 32766, Action: "lookup", Table: "main"}},
		{Rule: model.Rule{Priority: 32767, Action: "lookup", Table: "default"}},
		{Rule: model.Rule{Priority: 0, Family: "ipv6", Action: "lookup", Table: "local"}},
		{Rule: model.Rule{Priority: 32766, Family: "ipv6", Action: "lookup", Table: "main"}},
	}
	return m
}

func (m *Mock) notify() {
	for _, w := range m.watchers {
		select {
		case w <- struct{}{}:
		default:
		}
	}
}

// AddLink creates an interface, as `ip link add` plus `set up` would. With
// notify false no event is sent, which models an event the daemon missed.
func (m *Mock) AddLink(name string, notify bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links = append(m.links, model.Link{Name: name, Index: len(m.links) + 1, Type: "wireguard", Up: true, Running: true, MTU: 1420})
	if notify {
		m.notify()
	}
}

// Poke sends a kernel event without changing anything, like unrelated
// interfaces and addresses coming and going during boot.
func (m *Mock) Poke() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notify()
}

// SetLinkUp flips an interface up or down, like `ip link set`. Routes through
// a downed interface disappear, as they do in Linux.
func (m *Mock) SetLinkUp(name string, up bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.links {
		if m.links[i].Name == name {
			m.links[i].Up, m.links[i].Running = up, up
			if !up {
				kept := m.routes[:0]
				for _, r := range m.routes {
					if r.Dev != name {
						kept = append(kept, r)
					}
				}
				m.routes = kept
			}
			m.notify()
			return nil
		}
	}
	return fmt.Errorf("no such interface %q", name)
}

func (m *Mock) SetLinkMTU(name string, mtu int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.link(name)
	if l == nil {
		return fmt.Errorf("no such interface %q", name)
	}
	l.MTU = mtu
	m.notify()
	return nil
}

func (m *Mock) AddBridge(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.link(name) != nil {
		return fmt.Errorf("file exists")
	}
	m.links = append(m.links, model.Link{Name: name, Index: len(m.links) + 1, Type: "bridge", MTU: 1500,
		MAC: fmt.Sprintf("02:00:00:00:00:%02x", len(m.links)+1)})
	m.notify()
	return nil
}

func (m *Mock) DelBridge(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.links {
		if m.links[i].Name != name {
			continue
		}
		if m.links[i].Type != "bridge" {
			return fmt.Errorf("%s is a %s, not a bridge", name, m.links[i].Type)
		}
		for j := range m.links {
			if m.links[j].Master == name {
				m.links[j].Master = ""
			}
		}
		m.links = append(m.links[:i], m.links[i+1:]...)
		delete(m.stp, name)
		m.notify()
		return nil
	}
	return fmt.Errorf("no such interface %q", name)
}

// BridgeSTP reports whether spanning tree is on for a bridge (for tests).
func (m *Mock) BridgeSTP(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stp[name]
}

func (m *Mock) SetBridgeSTP(name string, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l := m.link(name); l == nil || l.Type != "bridge" {
		return fmt.Errorf("%s is not a bridge", name)
	}
	if m.stp == nil {
		m.stp = map[string]bool{}
	}
	m.stp[name] = on
	m.notify()
	return nil
}

func (m *Mock) SetMaster(iface, bridge string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.link(iface)
	if l == nil {
		return fmt.Errorf("no such interface %q", iface)
	}
	if bridge != "" {
		if b := m.link(bridge); b == nil || b.Type != "bridge" {
			return fmt.Errorf("%s is not a bridge", bridge)
		}
	}
	l.Master = bridge
	m.notify()
	return nil
}

func (m *Mock) link(name string) *model.Link {
	for i := range m.links {
		if m.links[i].Name == name {
			return &m.links[i]
		}
	}
	return nil
}

func (m *Mock) Links() ([]model.Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.Link, len(m.links))
	copy(out, m.links)
	for i := range out {
		out[i].Addrs = nil
		for _, a := range m.addrs {
			if a.Interface == out[i].Name {
				out[i].Addrs = append(out[i].Addrs, a.Address)
			}
		}
	}
	return out, nil
}

func (m *Mock) ListAddrs() ([]Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Addr(nil), m.addrs...), nil
}

func (m *Mock) AddAddr(iface, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.link(iface) == nil {
		return fmt.Errorf("no such interface %q", iface)
	}
	for _, a := range m.addrs {
		if a.Interface == iface && a.Address == cidr {
			return fmt.Errorf("file exists")
		}
	}
	m.addrs = append(m.addrs, Addr{iface, cidr})
	m.notify()
	return nil
}

func (m *Mock) DelAddr(iface, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, a := range m.addrs {
		if a.Interface == iface && a.Address == cidr {
			m.addrs = append(m.addrs[:i], m.addrs[i+1:]...)
			m.notify()
			return nil
		}
	}
	return fmt.Errorf("address not found")
}

func (m *Mock) ListRoutes() ([]LiveRoute, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]LiveRoute(nil), m.routes...), nil
}

func (m *Mock) ReplaceRoute(r model.Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Dev != "" {
		l := m.link(r.Dev)
		if l == nil {
			return fmt.Errorf("no such interface %q", r.Dev)
		}
		if !l.Up {
			return fmt.Errorf("interface %q is down", r.Dev)
		}
	}
	r.Table = model.TableName(canon(r.Table))
	lr := LiveRoute{Route: r, Owned: true, Proto: "mini-net-man"}
	lr.ID, lr.Comment, lr.Disabled, lr.Source = "", "", false, ""
	for i, e := range m.routes {
		if e.Key() == r.Key() {
			m.routes[i] = lr
			m.notify()
			return nil
		}
	}
	m.routes = append(m.routes, lr)
	m.notify()
	return nil
}

func canon(t string) int {
	n, _ := model.ParseTable(t)
	return n
}

func (m *Mock) DelRoute(r model.Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, e := range m.routes {
		if e.Key() == r.Key() {
			m.routes = append(m.routes[:i], m.routes[i+1:]...)
			m.notify()
			return nil
		}
	}
	return fmt.Errorf("no such route")
}

func (m *Mock) ListRules() ([]LiveRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]LiveRule(nil), m.rules...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, nil
}

func (m *Mock) AddRule(r model.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.rules {
		if e.Key() == r.Key() {
			return fmt.Errorf("file exists")
		}
	}
	lr := LiveRule{Rule: r, Owned: true}
	lr.ID, lr.Comment, lr.Disabled, lr.Source = "", "", false, ""
	m.rules = append(m.rules, lr)
	m.notify()
	return nil
}

func (m *Mock) DelRule(r model.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, e := range m.rules {
		if e.Key() == r.Key() {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			m.notify()
			return nil
		}
	}
	return fmt.Errorf("no such rule")
}

// AddForeignRule/AddForeignRoute simulate objects created by hand with `ip`.
func (m *Mock) AddForeignRule(r model.Rule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = append(m.rules, LiveRule{Rule: r})
}

func (m *Mock) AddForeignRoute(r model.Route) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = append(m.routes, LiveRoute{Route: r, Proto: "boot"})
}

func (m *Mock) ApplyFirewall(fw model.Firewall) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := fw
	cp.Rules = append([]model.FWRule(nil), fw.Rules...)
	m.fw = &cp
	return nil
}

func (m *Mock) FirewallRuleset() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fw == nil {
		return "", nil
	}
	return RenderNFT(*m.fw), nil
}

func fwdIdx(v6 bool) int {
	if v6 {
		return 1
	}
	return 0
}

func (m *Mock) IPForward(v6 bool) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.forward[fwdIdx(v6)], nil
}

func (m *Mock) SetIPForward(v6, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forward[fwdIdx(v6)] = on
	return nil
}

func (m *Mock) ConntrackAcct() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acct, nil
}

func (m *Mock) SetConntrackAcct(on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acct = on
	return nil
}

// Conntrack returns a believable table: two VPN clients leaving through
// different exits (masqueraded), an IPv6 client, a port forward and a few
// connections to this machine itself.
func (m *Mock) Conntrack() (model.ConntrackInfo, []model.Conn, error) {
	m.mu.Lock()
	acct := m.acct
	m.mu.Unlock()
	nat := func(c model.Conn, to string) model.Conn {
		c.ReplySrc, c.ReplySrcPort, c.ReplyDst, c.ReplyDstPort = c.Dst, c.DstPort, to, c.SrcPort
		return c
	}
	var conns []model.Conn
	add := func(c model.Conn, out, in uint64) {
		if acct {
			c.BytesOut, c.BytesIn = out, in
		}
		conns = append(conns, c)
	}
	web := []struct {
		dst string
		out uint64
	}{{"142.250.74.78", 48_000}, {"151.101.1.69", 1_200_000}, {"104.16.132.229", 9_500}, {"93.184.216.34", 310_000}, {"35.186.224.25", 22_000}}
	for i, w := range web {
		add(nat(model.Conn{Family: "ipv4", Proto: "tcp", State: "ESTABLISHED", Src: "10.0.0.5", SrcPort: 50000 + i, Dst: w.dst, DstPort: 443, Timeout: 431_990 - i*70, Assured: true}, "10.9.0.2"), w.out, w.out*14)
	}
	add(nat(model.Conn{Family: "ipv4", Proto: "udp", Src: "10.0.0.5", SrcPort: 41000, Dst: "8.8.8.8", DstPort: 53, Timeout: 25}, "10.9.0.2"), 80, 160)
	add(nat(model.Conn{Family: "ipv4", Proto: "tcp", State: "TIME_WAIT", Src: "10.0.0.6", SrcPort: 52100, Dst: "172.217.19.14", DstPort: 443, Timeout: 90, Assured: true}, "10.8.0.2"), 3_400, 51_000)
	add(nat(model.Conn{Family: "ipv4", Proto: "tcp", State: "ESTABLISHED", Src: "10.0.0.6", SrcPort: 52144, Dst: "140.82.112.3", DstPort: 443, Timeout: 431_000, Assured: true}, "10.8.0.2"), 880_000, 4_100_000)
	add(nat(model.Conn{Family: "ipv4", Proto: "tcp", State: "SYN_SENT", Src: "10.0.0.6", SrcPort: 52190, Dst: "203.0.113.9", DstPort: 8443, Timeout: 118, Unreplied: true}, "10.8.0.2"), 60, 0)
	add(model.Conn{Family: "ipv6", Proto: "tcp", State: "ESTABLISHED", Src: "fd00:10::5", SrcPort: 43210, Dst: "2606:4700::6810:84e5", DstPort: 443, Timeout: 431_500,
		ReplySrc: "2606:4700::6810:84e5", ReplySrcPort: 443, ReplyDst: "fd00:8::2", ReplyDstPort: 43210, Assured: true}, 12_000, 190_000)
	add(model.Conn{Family: "ipv4", Proto: "tcp", State: "ESTABLISHED", Src: "203.0.113.50", SrcPort: 60022, Dst: "192.168.71.10", DstPort: 8443,
		ReplySrc: "10.0.0.20", ReplySrcPort: 443, ReplyDst: "203.0.113.50", ReplyDstPort: 60022, Timeout: 431_900, Assured: true}, 5_000, 70_000)
	add(model.Conn{Family: "ipv4", Proto: "tcp", State: "ESTABLISHED", Src: "203.0.113.7", SrcPort: 51822, Dst: "192.168.71.10", DstPort: 22,
		ReplySrc: "192.168.71.10", ReplySrcPort: 22, ReplyDst: "203.0.113.7", ReplyDstPort: 51822, Timeout: 431_990, Assured: true}, 9_000, 41_000)
	add(model.Conn{Family: "ipv4", Proto: "tcp", State: "ESTABLISHED", Src: "127.0.0.1", SrcPort: 38000, Dst: "127.0.0.1", DstPort: 8080,
		ReplySrc: "127.0.0.1", ReplySrcPort: 8080, ReplyDst: "127.0.0.1", ReplyDstPort: 38000, Timeout: 431_000, Assured: true}, 700, 2_300)
	add(model.Conn{Family: "ipv4", Proto: "icmp", Src: "192.168.71.10", Dst: "192.168.71.1", Timeout: 28,
		ReplySrc: "192.168.71.1", ReplyDst: "192.168.71.10"}, 84, 84)
	return model.ConntrackInfo{Available: true, Count: len(conns) + 4_200, Max: 65_536, Acct: acct}, conns, nil
}

func (m *Mock) sysctlDefaults() map[string]string {
	return map[string]string{
		"net.ipv4.tcp_congestion_control": "cubic", "net.core.default_qdisc": "fq_codel",
		"net.core.rmem_max": "212992", "net.core.wmem_max": "212992",
		"net.ipv4.tcp_mtu_probing": "0", "net.ipv4.tcp_slow_start_after_idle": "1",
		"net.netfilter.nf_conntrack_max": "65536", "net.netfilter.nf_conntrack_tcp_timeout_established": "432000",
		"net.ipv4.conf.all.rp_filter": "2", "net.ipv4.conf.default.rp_filter": "2",
		"net.ipv4.conf.all.accept_redirects": "1", "net.ipv4.conf.default.accept_redirects": "1",
		"net.ipv6.conf.all.accept_redirects": "1", "net.ipv6.conf.default.accept_redirects": "1",
		"net.ipv4.conf.all.send_redirects": "1", "net.ipv4.conf.default.send_redirects": "1",
		"net.ipv4.conf.all.log_martians": "0", "net.ipv4.conf.default.log_martians": "0",
	}
}

// SetKernelWithout removes a setting from the mock kernel, as a kernel built
// without it, and SetBBRAvailable models a kernel that does or doesn't have BBR.
func (m *Mock) SetKernelWithout(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.missing == nil {
		m.missing = map[string]bool{}
	}
	m.missing[key] = true
}

func (m *Mock) SetBBRAvailable(ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.noBBR = !ok
}

func (m *Mock) Sysctl(key string) (string, error) {
	if err := checkSysctlKey(key, false); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.missing[key] {
		return "", fmt.Errorf("this kernel doesn't have %s", key)
	}
	if key == "net.ipv4.tcp_available_congestion_control" {
		if m.noBBR {
			return "reno cubic", nil
		}
		return "reno cubic bbr", nil
	}
	if key == "net.core.available_qdisc" {
		return "fq fq_codel cake pfifo_fast", nil
	}
	if m.sysctls == nil {
		m.sysctls = m.sysctlDefaults()
	}
	return m.sysctls[key], nil
}

func (m *Mock) SetSysctl(key, value string) error {
	if err := checkSysctlKey(key, true); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.missing[key] {
		return fmt.Errorf("this kernel doesn't have %s", key)
	}
	if key == "net.ipv4.tcp_congestion_control" && value == "bbr" && m.noBBR {
		return errors.New("bbr isn't available in this kernel (it offers: reno, cubic) and its tcp_bbr module could not be loaded")
	}
	if m.sysctls == nil {
		m.sysctls = m.sysctlDefaults()
	}
	m.sysctls[key] = value
	return nil
}

// SetPingFail makes pings out of iface time out (true) or work again (false).
func (m *Mock) SetPingFail(iface string, fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pingFail == nil {
		m.pingFail = map[string]bool{}
	}
	m.pingFail[iface] = fail
}

// Ping answers in 12 ms unless the interface is missing, down, or told to fail.
func (m *Mock) Ping(ctx context.Context, iface, target string, timeout time.Duration) (time.Duration, error) {
	m.mu.Lock()
	l := m.link(iface)
	fail := m.pingFail[iface]
	m.mu.Unlock()
	switch {
	case l == nil:
		return 0, fmt.Errorf("no such interface %q", iface)
	case !l.Up:
		return 0, fmt.Errorf("interface %q is down", iface)
	case fail:
		return 0, errors.New("timed out")
	}
	return 12 * time.Millisecond, nil
}

// Sockets returns a believable listener list, including this very process.
func (m *Mock) Sockets() ([]model.Socket, error) {
	self := model.SocketProc{PID: os.Getpid(), Name: "mini-net-man"}
	socks := []model.Socket{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Scope: "all", User: "root", Procs: []model.SocketProc{{PID: 812, Name: "sshd"}}},
		{Proto: "tcp6", Addr: "::", Port: 22, Scope: "all", User: "root", Procs: []model.SocketProc{{PID: 812, Name: "sshd"}}},
		{Proto: "udp", Addr: "127.0.0.53", Port: 53, Scope: "local", User: "systemd-resolve", Procs: []model.SocketProc{{PID: 640, Name: "systemd-resolve"}}},
		{Proto: "tcp", Addr: "127.0.0.53", Port: 53, Scope: "local", User: "systemd-resolve", Procs: []model.SocketProc{{PID: 640, Name: "systemd-resolve"}}},
		{Proto: "udp", Addr: "0.0.0.0", Port: 51820, Scope: "all", Kernel: true},
		{Proto: "udp6", Addr: "::", Port: 51820, Scope: "all", Kernel: true},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 8080, Scope: "all", User: "root", Procs: []model.SocketProc{self}},
		{Proto: "tcp", Addr: "10.0.0.1", Port: 8443, Scope: "address", User: "www-data", Procs: []model.SocketProc{{PID: 1201, Name: "nginx"}, {PID: 1202, Name: "nginx"}, {PID: 1203, Name: "nginx"}}},
		{Proto: "udp", Addr: "127.0.0.1", Port: 323, Scope: "local", User: "chrony", Procs: []model.SocketProc{{PID: 701, Name: "chronyd"}}},
	}
	sort.SliceStable(socks, func(i, j int) bool { return socks[i].Port < socks[j].Port })
	return socks, nil
}

func (m *Mock) Watch(ctx context.Context) (<-chan struct{}, error) {
	ch := make(chan struct{}, 1)
	m.mu.Lock()
	m.watchers = append(m.watchers, ch)
	m.mu.Unlock()
	return ch, nil
}
