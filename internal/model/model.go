// Package model holds the types shared by the config file, the REST API and
// the kernel layer. Everything is IPv4 for now.
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
	Firewall      Firewall      `yaml:"firewall" json:"firewall"`
	ClientRouting ClientRouting `yaml:"client_routing" json:"client_routing"`
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
	IPForward *bool `yaml:"ip_forward,omitempty" json:"ip_forward"`
}

// Address is an extra IPv4 address added to an interface (like `ip addr add`).
type Address struct {
	ID        string `yaml:"id" json:"id"`
	Interface string `yaml:"interface" json:"interface"`
	Address   string `yaml:"address" json:"address"` // CIDR, e.g. 10.0.0.1/16
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
	Action   string `yaml:"action,omitempty" json:"action"` // lookup (default), blackhole, unreachable, prohibit
	Table    string `yaml:"table,omitempty" json:"table"`   // for action=lookup
	Comment  string `yaml:"comment,omitempty" json:"comment"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled"`
	Source   string `yaml:"-" json:"source,omitempty"`
}

// Firewall describes the single nftables table owned by mini-net-man.
type Firewall struct {
	Policy FirewallPolicy `yaml:"policy" json:"policy"`
	Rules  []FWRule       `yaml:"rules" json:"rules"`
}

// FirewallPolicy is the default verdict of each filter base chain.
type FirewallPolicy struct {
	Input   string `yaml:"input" json:"input"` // accept | drop
	Forward string `yaml:"forward" json:"forward"`
	Output  string `yaml:"output" json:"output"`
}

// FW chains.
const (
	ChainInput       = "input"
	ChainForward     = "forward"
	ChainOutput      = "output"
	ChainPrerouting  = "dstnat"
	ChainPostrouting = "srcnat"
)

// FWRule is one firewall rule. Rules are evaluated per chain in list order.
type FWRule struct {
	ID        string `yaml:"id" json:"id"`
	Chain     string `yaml:"chain" json:"chain"`   // input|forward|output|dstnat|srcnat
	Action    string `yaml:"action" json:"action"` // accept|drop|reject|masquerade|dnat|snat|return
	InIface   string `yaml:"in_iface,omitempty" json:"in_iface"`
	OutIface  string `yaml:"out_iface,omitempty" json:"out_iface"`
	Src       string `yaml:"src,omitempty" json:"src"`
	Dst       string `yaml:"dst,omitempty" json:"dst"`
	Proto     string `yaml:"proto,omitempty" json:"proto"`           // tcp|udp|icmp or ""
	SrcPort   string `yaml:"src_port,omitempty" json:"src_port"`     // "80" or "1000-2000"
	DstPort   string `yaml:"dst_port,omitempty" json:"dst_port"`     // "80" or "1000-2000"
	ConnState string `yaml:"conn_state,omitempty" json:"conn_state"` // comma list: new,established,related,invalid
	ToAddr    string `yaml:"to_addr,omitempty" json:"to_addr"`       // dnat/snat target IP
	ToPort    int    `yaml:"to_port,omitempty" json:"to_port"`       // dnat/snat target port
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
	Addrs   []string `json:"addrs"`
	RxBytes uint64   `json:"rx_bytes"`
	TxBytes uint64   `json:"tx_bytes"`
}

// Issue reports that one configured item could not be applied.
type Issue struct {
	Kind    string `json:"kind"` // address|route|rule|firewall|sysctl
	ID      string `json:"id"`
	Message string `json:"message"`
}
