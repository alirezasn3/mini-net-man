// Package kernel is the boundary between mini-net-man and the operating
// system. The engine only talks to the Kernel interface, so the web UI can be
// developed against Mock on any OS while Linux uses netlink and nftables.
package kernel

import (
	"context"

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

	// IPForward and SetIPForward read and write net.ipv4.ip_forward, or
	// net.ipv6.conf.all.forwarding when v6 is true.
	IPForward(v6 bool) (bool, error)
	SetIPForward(v6, on bool) error

	// Sockets lists listening TCP and bound UDP sockets with the process
	// that owns each, like `ss -tulnp`.
	Sockets() ([]model.Socket, error)

	// Watch emits a value whenever links, addresses or routes change.
	Watch(ctx context.Context) (<-chan struct{}, error)
}
