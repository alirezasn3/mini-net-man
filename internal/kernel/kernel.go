// Package kernel is the boundary between mini-net-man and the operating
// system. The engine only talks to the Kernel interface, so the web UI can be
// developed against Mock on any OS while Linux uses netlink and nftables.
package kernel

import (
	"context"
	"net/netip"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// Owner is the protocol number stamped on every route and rule we create, so
// we can tell our objects from ones made by hand or by other tools.
const Owner = 201

// Addr is one address (IPv4 or IPv6) on an interface.
type Addr struct {
	Interface string `json:"interface"`
	Address   string `json:"address"` // CIDR with host bits, e.g. 10.0.0.1/16 or fd00::1/64
}

// LiveRoute is a route as it exists in the kernel right now.
type LiveRoute struct {
	model.Route
	Owned bool   `json:"owned"`
	Proto string `json:"proto"` // kernel, static, boot, dhcp, ... or "mini-net-man"
}

// LiveRule is a policy rule as it exists in the kernel right now.
type LiveRule struct {
	model.Rule
	Owned bool `json:"owned"`
}

type Kernel interface {
	Links() ([]model.Link, error)

	// SetLinkUp brings an interface up or down; SetLinkMTU changes its MTU.
	SetLinkUp(name string, up bool) error
	SetLinkMTU(name string, mtu int) error
	// AddBridge creates an (empty, down) bridge. DelBridge removes one, and
	// refuses anything that isn't a bridge. SetBridgeSTP turns spanning tree
	// on or off. SetMaster makes iface a port of bridge, or with "" releases it.
	AddBridge(name string) error
	DelBridge(name string) error
	SetBridgeSTP(name string, on bool) error
	SetMaster(iface, bridge string) error

	ListAddrs() ([]Addr, error)
	AddAddr(iface, cidr string) error
	DelAddr(iface, cidr string) error

	// ListRoutes returns IPv4 and IPv6 routes of every table except "local".
	ListRoutes() ([]LiveRoute, error)
	// ReplaceRoute adds the route or overwrites the one with the same key.
	ReplaceRoute(r model.Route) error
	DelRoute(r model.Route) error

	ListRules() ([]LiveRule, error)
	AddRule(r model.Rule) error
	// DelRule removes a rule matching r, whether or not we own it.
	DelRule(r model.Rule) error

	// ApplyFirewall atomically replaces the mini-net-man nftables table.
	// Only the table named "mini-net-man" is ever touched. It is an `inet`
	// table, so rules without an address match apply to both families.
	ApplyFirewall(fw model.Firewall) error
	// FirewallRuleset dumps the live table as text ("" when absent).
	FirewallRuleset() (string, error)
	// ListDynamic returns the addresses firewall rules have added to address
	// lists (add-src-to-list); DelDynamic removes one and FlushDynamic empties
	// a list's, or every list's when list is "". Applying the firewall keeps them.
	ListDynamic() ([]DynAddr, error)
	DelDynamic(list, address string) error
	FlushDynamic(list string) error
	// AddToList puts addresses in a list's dynamic sets, each living for
	// timeout (an address already there gets the new time). It is how domain
	// entries are filled in. The list's sets must exist, which they do once the
	// firewall has been applied with an entry or rule that names the list.
	AddToList(list string, addrs []netip.Addr, timeout time.Duration) error

	// IPForward and SetIPForward read and write net.ipv4.ip_forward, or
	// net.ipv6.conf.all.forwarding when v6 is true.
	IPForward(v6 bool) (bool, error)
	SetIPForward(v6, on bool) error

	// Conntrack returns the connection tracking table and its limits. When
	// tracking isn't active, Info.Available is false and Conns is empty.
	Conntrack() (model.ConntrackInfo, []model.Conn, error)
	ConntrackAcct() (bool, error)
	SetConntrackAcct(on bool) error

	// Ping sends one ICMP echo to target out of the named interface and waits
	// for the matching reply. The error says why there wasn't one.
	Ping(ctx context.Context, iface, target string, timeout time.Duration) (time.Duration, error)

	// Sysctl reads, and SetSysctl writes, a kernel setting such as
	// "net.ipv4.tcp_mtu_probing". Only keys from the tuning catalogue (or
	// read-only helpers like the list of available congestion controls) are
	// accepted. Errors say in plain words why, e.g. that the kernel lacks it.
	Sysctl(key string) (string, error)
	SetSysctl(key, value string) error

	// Sockets lists listening TCP and bound UDP sockets with the process
	// that owns each, like `ss -tulnp`.
	Sockets() ([]model.Socket, error)

	// Watch emits a value whenever links, addresses or routes change.
	Watch(ctx context.Context) (<-chan struct{}, error)
}
