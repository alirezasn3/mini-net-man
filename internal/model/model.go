// Package model holds the types shared by the config file, the REST API and
// the kernel layer. IPv4 and IPv6 are both supported; an item's family is
// inferred from its addresses (see the V6 methods) or set explicitly.
package model

// Well-known routing table ids.
const (
	TableDefault = 253
	TableMain    = 254
	TableLocal   = 255
)

// Config is the on-disk source of truth (config.yaml).
type Config struct {
	Web           Web           `yaml:"web" json:"web"`
	Sysctl        Sysctl        `yaml:"sysctl" json:"sysctl"`
	Addresses     []Address     `yaml:"addresses" json:"addresses"`
	Routes        []Route       `yaml:"routes" json:"routes"`
	Rules         []Rule        `yaml:"rules" json:"rules"`
	Checks        []Check       `yaml:"checks" json:"checks"`
	Firewall      Firewall      `yaml:"firewall" json:"firewall"`
	ClientRouting ClientRouting `yaml:"client_routing" json:"client_routing"`
	Update        Update        `yaml:"update" json:"update"`
}

// Update configures self-update from GitHub Releases.
type Update struct {
	// Repo is "owner/name"; empty means the project's own repository.
	Repo string `yaml:"repo,omitempty" json:"repo"`
	// NoAutoCheck stops the panel from asking GitHub for the latest version
	// when you log in. Checking by hand still works.
	NoAutoCheck bool `yaml:"no_auto_check,omitempty" json:"no_auto_check"`
}

type Web struct {
	Listen     string   `yaml:"listen" json:"listen"` // e.g. "0.0.0.0"
	Port       int      `yaml:"port" json:"port"`
	AllowedIPs []string `yaml:"allowed_ips" json:"allowed_ips"` // IPs or CIDRs; empty = nobody
	Users      []User   `yaml:"users" json:"users"`
	TLSCert    string   `yaml:"tls_cert,omitempty" json:"tls_cert,omitempty"`
	TLSKey     string   `yaml:"tls_key,omitempty" json:"tls_key,omitempty"`
}

type User struct {
	Name         string `yaml:"name" json:"name"`
	PasswordHash string `yaml:"password_hash" json:"-"`
}

type Sysctl struct {
	// nil leaves the kernel setting alone.
	IPForward   *bool `yaml:"ip_forward,omitempty" json:"ip_forward"`
	IPv6Forward *bool `yaml:"ipv6_forward,omitempty" json:"ipv6_forward"`
	// ConntrackAcct makes the kernel count bytes and packets per tracked
	// connection (net.netfilter.nf_conntrack_acct); the Connections page shows them.
	ConntrackAcct *bool `yaml:"conntrack_acct,omitempty" json:"conntrack_acct"`
	// Tuning maps a setting from the tuning catalogue (internal/tuning) to the
	// value to keep. Only settings listed here are managed; the rest are left
	// as the system has them.
	Tuning map[string]string `yaml:"tuning,omitempty" json:"tuning"`
}

// Address is an extra address (IPv4 or IPv6) added to an interface (like `ip addr add`).
type Address struct {
	ID        string `yaml:"id" json:"id"`
	Interface string `yaml:"interface" json:"interface"`
	Address   string `yaml:"address" json:"address"` // CIDR, e.g. 10.0.0.1/16 or fd00::1/64
	Comment   string `yaml:"comment,omitempty" json:"comment"`
	Disabled  bool   `yaml:"disabled,omitempty" json:"disabled"`
	Source    string `yaml:"-" json:"source,omitempty"` // set on generated items only
}

// Route is an entry in a routing table (like `ip route add`).
type Route struct {
	ID       string `yaml:"id" json:"id"`
	Dst      string `yaml:"dst" json:"dst"`                   // CIDR or "default"
	Gateway  string `yaml:"gateway,omitempty" json:"gateway"` // optional next hop
	Dev      string `yaml:"dev,omitempty" json:"dev"`         // optional output interface
	Table    string `yaml:"table,omitempty" json:"table"`     // number or main/local/default; "" = main
	Metric   int    `yaml:"metric,omitempty" json:"metric"`   // 0 = kernel default
	Type     string `yaml:"type,omitempty" json:"type"`       // unicast (default), blackhole, unreachable, prohibit
	Comment  string `yaml:"comment,omitempty" json:"comment"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled"`
	Source   string `yaml:"-" json:"source,omitempty"`
}

// Rule is a policy routing rule (like `ip rule add`).
type Rule struct {
	ID       string `yaml:"id" json:"id"`
	Priority int    `yaml:"priority" json:"priority"`
	Src      string `yaml:"src,omitempty" json:"src"`
	Dst      string `yaml:"dst,omitempty" json:"dst"`
	Iif      string `yaml:"iif,omitempty" json:"iif"`
	Oif      string `yaml:"oif,omitempty" json:"oif"`
	Fwmark   uint32 `yaml:"fwmark,omitempty" json:"fwmark"`
	Family   string `yaml:"family,omitempty" json:"family"` // "", ipv4 or ipv6; "" infers from src/dst, else IPv4
	Action   string `yaml:"action,omitempty" json:"action"` // lookup (default), blackhole, unreachable, prohibit
	Table    string `yaml:"table,omitempty" json:"table"`   // for action=lookup
	// Check makes the rule conditional: it is in the kernel only while this
	// health check (by id) is not failing. Empty means always.
	Check    string `yaml:"check,omitempty" json:"check"`
	Comment  string `yaml:"comment,omitempty" json:"comment"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled"`
	Source   string `yaml:"-" json:"source,omitempty"`
}

// Firewall describes the single nftables table owned by mini-net-man.
type Firewall struct {
	Policy FirewallPolicy `yaml:"policy" json:"policy"`
	Rules  []FWRule       `yaml:"rules" json:"rules"`
}

// FirewallPolicy is what happens to a packet that no rule in a filter chain
// decided: accept, drop, or reject (drop, but tell the sender). nftables has
// no reject policy, so it is built as a final catch-all reject rule.
type FirewallPolicy struct {
	Input   string `yaml:"input" json:"input"` // accept | drop | reject
	Forward string `yaml:"forward" json:"forward"`
	Output  string `yaml:"output" json:"output"`
}

// ActionClampMSS shrinks the TCP MSS of connections being set up through this
// machine (chain mangle only). MSS 0 means "to fit the outgoing route's MTU".
const ActionClampMSS = "clamp-mss"

// FW chains.
const (
	ChainInput       = "input"
	ChainForward     = "forward"
	ChainOutput      = "output"
	ChainMangle      = "mangle"
	ChainPrerouting  = "dstnat"
	ChainPostrouting = "srcnat"
)

// FWRule is one firewall rule. Rules are evaluated per chain in list order.
type FWRule struct {
	ID        string `yaml:"id" json:"id"`
	Chain     string `yaml:"chain" json:"chain"`   // input|forward|output|mangle|dstnat|srcnat
	Action    string `yaml:"action" json:"action"` // accept|drop|reject|masquerade|dnat|snat|return|clamp-mss
	InIface   string `yaml:"in_iface,omitempty" json:"in_iface"`
	OutIface  string `yaml:"out_iface,omitempty" json:"out_iface"`
	Src       string `yaml:"src,omitempty" json:"src"`
	Dst       string `yaml:"dst,omitempty" json:"dst"`
	Family    string `yaml:"family,omitempty" json:"family"`         // "" = both families, ipv4 or ipv6
	Proto     string `yaml:"proto,omitempty" json:"proto"`           // tcp|udp|icmp|icmpv6 or ""
	SrcPort   string `yaml:"src_port,omitempty" json:"src_port"`     // "80" or "1000-2000"
	DstPort   string `yaml:"dst_port,omitempty" json:"dst_port"`     // "80" or "1000-2000"
	ConnState string `yaml:"conn_state,omitempty" json:"conn_state"` // comma list: new,established,related,invalid
	ToAddr    string `yaml:"to_addr,omitempty" json:"to_addr"`       // dnat/snat target IP
	ToPort    int    `yaml:"to_port,omitempty" json:"to_port"`       // dnat/snat target port
	MSS       int    `yaml:"mss,omitempty" json:"mss"`               // clamp-mss: size to clamp to; 0 = fit the route\'s MTU
	Comment   string `yaml:"comment,omitempty" json:"comment"`
	Disabled  bool   `yaml:"disabled,omitempty" json:"disabled"`
	Source    string `yaml:"-" json:"source,omitempty"`
}

// ClientRouting is the optional convenience feature that sends chosen clients
// out through a chosen interface. It is expanded into plain routes, rules and
// firewall entries (see engine.Expand); nothing else depends on it.
type ClientRouting struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// First routing table number handed out to output interfaces.
	TableBase int `yaml:"table_base,omitempty" json:"table_base"`
	// Priority of the first generated ip rule.
	PriorityBase int `yaml:"priority_base,omitempty" json:"priority_base"`
	// Tables already allocated to output interfaces (stable across edits).
	Exits   []Exit        `yaml:"exits,omitempty" json:"exits"`
	Clients []ClientRoute `yaml:"clients,omitempty" json:"clients"`
}

type Exit struct {
	Interface string `yaml:"interface" json:"interface"`
	Table     int    `yaml:"table" json:"table"`
}

// ClientRoute sends traffic from Src (arriving on In) out through Out.
type ClientRoute struct {
	ID         string `yaml:"id" json:"id"`
	Name       string `yaml:"name,omitempty" json:"name"`
	Src        string `yaml:"src" json:"src"` // client IP or CIDR
	In         string `yaml:"in" json:"in"`   // client-facing interface (e.g. wgServer)
	Out        string `yaml:"out" json:"out"` // exit interface (e.g. wgBridge1)
	KillSwitch bool   `yaml:"kill_switch" json:"kill_switch"`
	Disabled   bool   `yaml:"disabled,omitempty" json:"disabled"`
}

// Link is a live network interface as seen by the kernel.
type Link struct {
	Name    string   `json:"name"`
	Index   int      `json:"index"`
	Type    string   `json:"type"`
	Up      bool     `json:"up"`
	Running bool     `json:"running"`
	MTU     int      `json:"mtu"`
	MAC     string   `json:"mac"`
	Addrs   []string `json:"addrs"` // IPv4 and global IPv6
	RxBytes uint64   `json:"rx_bytes"`
	TxBytes uint64   `json:"tx_bytes"`
}

// Issue reports that one configured item could not be applied.
type Issue struct {
	Kind    string `json:"kind"` // address|route|rule|firewall|sysctl
	ID      string `json:"id"`
	Message string `json:"message"`
}

// Socket is a listening TCP socket or a bound, unconnected UDP socket: one
// line of `ss -tulnp`.
type Socket struct {
	Proto string `json:"proto"` // tcp, tcp6, udp, udp6
	Addr  string `json:"addr"`  // local address the socket is bound to
	Port  int    `json:"port"`
	// Scope says who can reach it: "all" (bound to 0.0.0.0 or ::, so every
	// interface), "local" (loopback only) or "address" (one specific address).
	Scope  string       `json:"scope"`
	Kernel bool         `json:"kernel,omitempty"` // owned by the kernel itself, such as WireGuard's UDP port
	User   string       `json:"user,omitempty"`
	Procs  []SocketProc `json:"procs,omitempty"`
}

// SocketProc is a process holding a socket open.
type SocketProc struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

// Conn is one entry of the kernel's connection tracking table. The first
// address pair is the original direction (who opened the connection), the
// Reply pair is what the kernel expects to come back, which differs when NAT
// rewrote something.
type Conn struct {
	Family       string `json:"family"` // ipv4 | ipv6
	Proto        string `json:"proto"`  // tcp, udp, icmp, ...
	State        string `json:"state,omitempty"`
	Src          string `json:"src"`
	SrcPort      int    `json:"src_port,omitempty"`
	Dst          string `json:"dst"`
	DstPort      int    `json:"dst_port,omitempty"`
	ReplySrc     string `json:"reply_src,omitempty"`
	ReplySrcPort int    `json:"reply_src_port,omitempty"`
	ReplyDst     string `json:"reply_dst,omitempty"`
	ReplyDstPort int    `json:"reply_dst_port,omitempty"`
	Timeout      int    `json:"timeout"` // seconds until the entry expires
	Unreplied    bool   `json:"unreplied,omitempty"`
	Assured      bool   `json:"assured,omitempty"`
	// Byte counters, present only when accounting is on.
	BytesOut uint64 `json:"bytes_out,omitempty"` // original direction
	BytesIn  uint64 `json:"bytes_in,omitempty"`  // reply direction

	// Filled in by the server.
	Kind   string `json:"kind,omitempty"`   // forwarded | incoming | outgoing
	Client string `json:"client,omitempty"` // name of the matching client-routing client
	NAT    string `json:"nat,omitempty"`    // "SNAT 10.8.0.2" / "DNAT 10.0.0.9:443"
	Via    string `json:"via,omitempty"`    // interface that owns the translated source address
}

// ConntrackInfo describes the state of connection tracking itself.
type ConntrackInfo struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"` // why it isn't, when it isn't
	Count     int    `json:"count"`            // entries in the table
	Max       int    `json:"max"`              // table limit
	Acct      bool   `json:"acct"`             // byte counters on
}

// Check is a health check: a ping sent out of one interface. Rules that name
// a check are switched off while it is failing and back on once it recovers.
type Check struct {
	ID        string `yaml:"id" json:"id"`
	Name      string `yaml:"name" json:"name"`
	Target    string `yaml:"target" json:"target"`       // IPv4 or IPv6 address to ping
	Interface string `yaml:"interface" json:"interface"` // the ping leaves through this interface
	// Table is optional. A ping bound to an interface goes out through it
	// even without a route (Linux assumes the target is on that link), which is
	// all a tunnel like WireGuard needs. An exit reached through a gateway
	// needs the real route, which usually lives in a custom table; name that
	// table and the check looks its route up there.
	Table        string `yaml:"table,omitempty" json:"table"`
	IntervalSecs int    `yaml:"interval_secs,omitempty" json:"interval_secs"` // between pings (default 5)
	TimeoutMs    int    `yaml:"timeout_ms,omitempty" json:"timeout_ms"`       // wait for a reply (default 1000)
	FailAfter    int    `yaml:"fail_after,omitempty" json:"fail_after"`       // consecutive misses before "down" (default 3)
	RecoverAfter int    `yaml:"recover_after,omitempty" json:"recover_after"` // consecutive replies before "up" again (default 2)
	Comment      string `yaml:"comment,omitempty" json:"comment"`
}
