package kernel

import (
	"context"
	"fmt"
	"sort"
	"sync"

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
	forward  bool
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
	add("wgServer", "wireguard", true, "10.0.0.1/16")
	add("wgBridge0", "wireguard", true, "10.8.0.2/32")
	add("wgBridge1", "wireguard", true, "10.9.0.2/32")
	m.routes = []LiveRoute{
		{Route: model.Route{Dst: "default", Gateway: "192.168.71.1", Dev: "ens192", Table: "main", Metric: 100}, Proto: "static"},
		{Route: model.Route{Dst: "192.168.71.0/24", Dev: "ens192", Table: "main"}, Proto: "kernel"},
		{Route: model.Route{Dst: "10.0.0.0/16", Dev: "wgServer", Table: "main"}, Proto: "kernel"},
	}
	m.rules = []LiveRule{
		{Rule: model.Rule{Priority: 0, Action: "lookup", Table: "local"}},
		{Rule: model.Rule{Priority: 32766, Action: "lookup", Table: "main"}},
		{Rule: model.Rule{Priority: 32767, Action: "lookup", Table: "default"}},
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

func (m *Mock) IPForward() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.forward, nil
}

func (m *Mock) SetIPForward(on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forward = on
	return nil
}

func (m *Mock) Watch(ctx context.Context) (<-chan struct{}, error) {
	ch := make(chan struct{}, 1)
	m.mu.Lock()
	m.watchers = append(m.watchers, ch)
	m.mu.Unlock()
	return ch, nil
}
