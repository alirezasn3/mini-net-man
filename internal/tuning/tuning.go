// Package tuning is the catalogue of kernel settings mini-net-man can manage.
//
// It is deliberately a short, curated list rather than a free-form sysctl
// editor: each entry says what it does and why you might want it, accepts only
// values that make sense, and may write several related sysctls together. The
// package has no dependencies so both the config validation and the kernel
// layer can use it.
package tuning

import (
	"fmt"
	"strconv"
)

// Choice is one allowed value of a choice setting.
type Choice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Setting is one tunable. Its ID is what the config file stores.
type Setting struct {
	ID    string   `json:"id"`
	Group string   `json:"group"`
	Label string   `json:"label"`
	Desc  string   `json:"desc"`
	Keys  []string `json:"keys"` // sysctls written (all get the same value)
	Kind  string   `json:"kind"` // "choice" or "int"

	Choices []Choice `json:"choices,omitempty"`
	Min     int64    `json:"min,omitempty"`
	Max     int64    `json:"max,omitempty"`
	Unit    string   `json:"unit,omitempty"`

	// Recommended is a sensible value for a VPN or router gateway; empty
	// when the right value depends on the machine.
	Recommended string `json:"recommended,omitempty"`
}

// Groups in display order.
const (
	GroupThroughput = "Throughput"
	GroupConntrack  = "Connection tracking"
	GroupSecurity   = "Routing and safety"
)

var onOff = []Choice{{"0", "off"}, {"1", "on"}}

// Catalog lists every setting, in display order.
var Catalog = []Setting{
	{
		ID: "tcp_congestion_control", Group: GroupThroughput, Label: "TCP congestion control",
		Keys: []string{"net.ipv4.tcp_congestion_control"}, Kind: "choice", Recommended: "bbr",
		Choices: []Choice{{"bbr", "bbr"}, {"cubic", "cubic (Linux default)"}, {"reno", "reno"}},
		Desc:    "How this machine's own TCP connections speed up and back off. BBR measures bandwidth and delay instead of reacting to packet loss, which keeps throughput up on lossy or long-distance links. It applies to connections that END on this machine (the panel, a proxy running here), not to your clients' traffic merely passing through, whose speed is decided by the two ends. Needs the tcp_bbr kernel module; it is loaded for you if the kernel has it.",
	},
	{
		ID: "default_qdisc", Group: GroupThroughput, Label: "Default queue discipline",
		Keys: []string{"net.core.default_qdisc"}, Kind: "choice", Recommended: "fq",
		Choices: []Choice{{"fq", "fq (pairs with BBR)"}, {"fq_codel", "fq_codel (common default)"}, {"cake", "cake (also shapes bandwidth)"}},
		Desc:    "The queue each network card gets for outgoing packets. fq is the usual partner of BBR; fq_codel keeps latency low under load. Only interfaces that come up AFTER this is set get it: an existing interface keeps its queue until it is brought down and up again or `tc qdisc replace` is run.",
	},
	{
		ID: "socket_buffer_max", Group: GroupThroughput, Label: "Largest socket buffers",
		Keys: []string{"net.core.rmem_max", "net.core.wmem_max"}, Kind: "int", Unit: "bytes", Min: 212992, Max: 1 << 30, Recommended: "16777216",
		Desc: "The most memory one socket may use to buffer incoming and outgoing data. The kernel default (about 200 KB) is too small for a fast link, and WireGuard's UDP socket drops packets when it fills during a burst. 16 MiB is a comfortable ceiling; memory is only used when a connection needs it.",
	},
	{
		ID: "tcp_mtu_probing", Group: GroupThroughput, Label: "TCP MTU probing",
		Keys: []string{"net.ipv4.tcp_mtu_probing"}, Kind: "choice", Recommended: "1",
		Choices: []Choice{{"0", "off"}, {"1", "only after a black hole is detected"}, {"2", "always"}},
		Desc:    "Tunnels shrink the usable packet size, and some networks silently drop the ICMP message that would say so, leaving connections that hang after the handshake. With this on, TCP notices the stall and retries with smaller packets. Mainly helps connections that end on this machine.",
	},
	{
		ID: "tcp_slow_start_after_idle", Group: GroupThroughput, Label: "Slow start after idle",
		Keys: []string{"net.ipv4.tcp_slow_start_after_idle"}, Kind: "choice", Recommended: "0",
		Choices: []Choice{{"1", "on (Linux default)"}, {"0", "off"}},
		Desc:    "By default a connection that sat idle for a moment drops back to its slowest speed and ramps up again. Turning it off keeps long-lived connections (an SSH session, a proxy, an HTTP/2 stream) fast after a pause.",
	},
	{
		ID: "conntrack_max", Group: GroupConntrack, Label: "Connection tracking table size",
		Keys: []string{"net.netfilter.nf_conntrack_max"}, Kind: "int", Unit: "connections", Min: 1024, Max: 1 << 24,
		Desc: "How many connections the kernel can track at once; when the table is full new connections are dropped. Every VPN client and NAT'd connection uses an entry (about 300 bytes of memory). Raise it if the Connections page shows the table close to full. Only exists once connection tracking is active (a NAT or connection-state firewall rule).",
	},
	{
		ID: "conntrack_tcp_established_timeout", Group: GroupConntrack, Label: "Idle TCP connection lifetime",
		Keys: []string{"net.netfilter.nf_conntrack_tcp_timeout_established"}, Kind: "int", Unit: "seconds", Min: 60, Max: 2592000, Recommended: "86400",
		Desc: "How long an established but idle TCP connection stays in the tracking table. The default is 5 days, so abandoned connections (a client that vanished) linger and fill the table. One day is plenty for connections that use keepalives; an idle session with none is dropped after this time.",
	},
	{
		ID: "rp_filter", Group: GroupSecurity, Label: "Reverse-path filtering",
		Keys: []string{"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"}, Kind: "choice", Recommended: "2",
		Choices: []Choice{{"0", "off"}, {"1", "strict"}, {"2", "loose"}},
		Desc:    "Drops packets whose source address couldn't be reached back the way they came, a defence against spoofing. Strict (1) wrongly drops legitimate traffic on a router with policy routing or several exits. Loose (2) only requires that the source has some route, and is the right choice for this kind of gateway. An interface set higher than this on its own still wins.",
	},
	{
		ID: "accept_redirects", Group: GroupSecurity, Label: "Accept ICMP redirects",
		Keys: []string{"net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects", "net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.default.accept_redirects"},
		Kind: "choice", Recommended: "0", Choices: onOff,
		Desc: "Lets a neighbouring router tell this machine \"use me instead\", which changes its routes. On a gateway whose routing you manage deliberately, a forged redirect could quietly divert traffic, so off is safer.",
	},
	{
		ID: "send_redirects", Group: GroupSecurity, Label: "Send ICMP redirects",
		Keys: []string{"net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects"},
		Kind: "choice", Recommended: "0", Choices: onOff,
		Desc: "Makes this machine tell a client \"there is a shorter path, go straight to that router\" when it forwards a packet back out the way it came. With VPN clients and policy routing that advice is usually wrong, so off avoids confusing it.",
	},
	{
		ID: "log_martians", Group: GroupSecurity, Label: "Log impossible packets",
		Keys: []string{"net.ipv4.conf.all.log_martians", "net.ipv4.conf.default.log_martians"},
		Kind: "choice", Choices: onOff,
		Desc: "Writes a kernel log line (see `dmesg`) for every packet dropped for having an impossible source address. Turn it on briefly when something isn't getting through and you suspect reverse-path filtering; leave it off otherwise, as a flood of such packets fills the log.",
	},
}

// Get returns the setting with this id.
func Get(id string) (Setting, bool) {
	for _, s := range Catalog {
		if s.ID == id {
			return s, true
		}
	}
	return Setting{}, false
}

// Validate checks that value is allowed for the setting.
func Validate(id, value string) error {
	s, ok := Get(id)
	if !ok {
		return fmt.Errorf("unknown setting %q", id)
	}
	return s.Check(value)
}

// Check reports whether value is allowed for s.
func (s Setting) Check(value string) error {
	switch s.Kind {
	case "choice":
		for _, c := range s.Choices {
			if c.Value == value {
				return nil
			}
		}
		return fmt.Errorf("%s: %q is not one of the allowed values", s.Label, value)
	case "int":
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("%s: %q is not a whole number", s.Label, value)
		}
		if n < s.Min || n > s.Max {
			return fmt.Errorf("%s: must be between %d and %d %s", s.Label, s.Min, s.Max, s.Unit)
		}
		return nil
	}
	return fmt.Errorf("%s: unsupported kind %q", s.Label, s.Kind)
}
