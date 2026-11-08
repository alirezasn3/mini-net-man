package model

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// DNSMasq is the settings of the DHCP and DNS server (dnsmasq) that
// mini-net-man runs for you. DHCP scopes, fixed addresses and DNS records are
// separate lists (Config.DHCPScopes, DHCPHosts, DNSRecords).
type DNSMasq struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// DNS says whether to answer DNS queries (on the interfaces of the DHCP
	// scopes and on Interfaces). With it off the server only does DHCP.
	DNS bool `yaml:"dns" json:"dns"`
	// Interfaces are extra interfaces to serve DNS on, beyond those of the scopes.
	Interfaces []string `yaml:"interfaces,omitempty" json:"interfaces"`
	// Upstreams are the DNS servers queries are forwarded to ("1.1.1.1" or
	// "1.1.1.1#5353"). Empty means the servers in /etc/resolv.conf.
	Upstreams []string `yaml:"upstreams,omitempty" json:"upstreams"`
	// Domain is the local domain: names without a dot are answered locally and
	// clients are told to search it ("lan").
	Domain    string `yaml:"domain,omitempty" json:"domain"`
	CacheSize int    `yaml:"cache_size,omitempty" json:"cache_size"` // 0 means 1000
}

// DHCPScope hands out addresses on one interface.
type DHCPScope struct {
	ID        string `yaml:"id" json:"id"`
	Name      string `yaml:"name,omitempty" json:"name"`
	Interface string `yaml:"interface" json:"interface"`
	Start     string `yaml:"start" json:"start"` // first address handed out, IPv4
	End       string `yaml:"end" json:"end"`     // last address handed out
	// LeaseTime is how long a client keeps an address before asking again:
	// seconds, or 30m, 12h, 2d, or "infinite". Empty means 12h.
	LeaseTime string `yaml:"lease_time,omitempty" json:"lease_time"`
	// Router is the default gateway sent to clients. Empty means this
	// machine's address on the interface; "none" sends no gateway.
	Router string `yaml:"router,omitempty" json:"router"`
	// DNS are the DNS servers sent to clients. Empty means this machine when
	// DNS is on, otherwise none.
	DNS      []string `yaml:"dns,omitempty" json:"dns"`
	Domain   string   `yaml:"domain,omitempty" json:"domain"` // search domain for this scope
	Comment  string   `yaml:"comment,omitempty" json:"comment"`
	Disabled bool     `yaml:"disabled,omitempty" json:"disabled"`
	Source   string   `yaml:"-" json:"source,omitempty"`
}

// DHCPHost always gives the same address to one device.
type DHCPHost struct {
	ID       string `yaml:"id" json:"id"`
	MAC      string `yaml:"mac" json:"mac"`
	IP       string `yaml:"ip" json:"ip"`
	Hostname string `yaml:"hostname,omitempty" json:"hostname"`
	Comment  string `yaml:"comment,omitempty" json:"comment"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled"`
	Source   string `yaml:"-" json:"source,omitempty"`
}

// DNSRecord is a local DNS answer: Name resolves to Address (an IP), or is an
// alias of another name (when Address is a name).
type DNSRecord struct {
	ID       string `yaml:"id" json:"id"`
	Name     string `yaml:"name" json:"name"`
	Address  string `yaml:"address" json:"address"`
	Comment  string `yaml:"comment,omitempty" json:"comment"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled"`
	Source   string `yaml:"-" json:"source,omitempty"`
}

// AccessPoint turns a wireless interface into a Wi-Fi access point (hostapd).
type AccessPoint struct {
	ID        string `yaml:"id" json:"id"`
	Interface string `yaml:"interface" json:"interface"`
	SSID      string `yaml:"ssid" json:"ssid"`
	Hidden    bool   `yaml:"hidden,omitempty" json:"hidden"`
	Band      string `yaml:"band" json:"band"`       // "2.4" or "5"
	Channel   int    `yaml:"channel" json:"channel"` // 0 picks one automatically, if the driver can
	Country   string `yaml:"country,omitempty" json:"country"`
	// Security is open, wpa2, wpa3 or wpa2+wpa3 (WPA3 for the devices that can,
	// WPA2 for the rest).
	Security   string `yaml:"security" json:"security"`
	Passphrase string `yaml:"passphrase,omitempty" json:"passphrase"`
	// Bridge makes hostapd add the interface to this bridge, so Wi-Fi clients
	// are on the same network as the bridge's other ports.
	Bridge     string `yaml:"bridge,omitempty" json:"bridge"`
	Isolate    bool   `yaml:"isolate,omitempty" json:"isolate"`         // clients can't talk to each other
	MaxClients int    `yaml:"max_clients,omitempty" json:"max_clients"` // 0 leaves it to the driver
	N          bool   `yaml:"n,omitempty" json:"n"`                     // 802.11n (Wi-Fi 4)
	AC         bool   `yaml:"ac,omitempty" json:"ac"`                   // 802.11ac (Wi-Fi 5), 5 GHz only
	AX         bool   `yaml:"ax,omitempty" json:"ax"`                   // 802.11ax (Wi-Fi 6)
	Comment    string `yaml:"comment,omitempty" json:"comment"`
	Disabled   bool   `yaml:"disabled,omitempty" json:"disabled"`
	Source     string `yaml:"-" json:"source,omitempty"`
}

// ---- validation -------------------------------------------------------------

var localName = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$`)

// ValidLocalName accepts a host or domain name for the local network: one or
// more labels, so "router" and "nas.lan" are fine (unlike ParseDomain, which
// is for names on the internet).
func ValidLocalName(s string) bool {
	return len(s) > 0 && len(s) <= 253 && localName.MatchString(s)
}

func parseIPv4(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !a.Is4() {
		return netip.Addr{}, fmt.Errorf("%q is not an IPv4 address", s)
	}
	return a, nil
}

var leaseRe = regexp.MustCompile(`^(\d+)([smhd]?)$`)

// LeaseSeconds converts a lease time ("12h", "90m", "2d", "3600") to seconds;
// -1 means infinite. Empty means the default of 12 hours.
func LeaseSeconds(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "":
		return 12 * 3600, nil
	case "infinite":
		return -1, nil
	}
	m := leaseRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("lease time %q: use seconds, or a number with m, h or d (30m, 12h, 2d), or infinite", s)
	}
	n, _ := strconv.Atoi(m[1])
	mul := map[string]int{"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m[2]]
	if n*mul < 120 {
		return 0, fmt.Errorf("lease time must be at least 2 minutes")
	}
	if n*mul > 365*86400 {
		return 0, fmt.Errorf("lease time is longer than a year; use infinite")
	}
	return n * mul, nil
}

// NormalizeMAC returns a MAC address as lower-case aa:bb:cc:dd:ee:ff.
func NormalizeMAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("%q is not a MAC address (aa:bb:cc:dd:ee:ff)", s)
	}
	return strings.ToLower(hw.String()), nil
}

func (d DNSMasq) Validate() error {
	if d.Domain != "" && !ValidLocalName(strings.ToLower(d.Domain)) {
		return fmt.Errorf("invalid domain %q", d.Domain)
	}
	if d.CacheSize < 0 || d.CacheSize > 10000 {
		return fmt.Errorf("cache size must be 0 (the default, 1000) to 10000")
	}
	for _, i := range d.Interfaces {
		if i == "" || !validIface(i) || strings.Contains(i, "*") {
			return fmt.Errorf("invalid interface %q", i)
		}
	}
	for _, u := range d.Upstreams {
		host, port, hasPort := strings.Cut(strings.TrimSpace(u), "#")
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("upstream DNS server %q must be an IP address, optionally with #port", u)
		}
		if hasPort {
			if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("upstream DNS server %q: bad port", u)
			}
		}
	}
	return nil
}

func (s DHCPScope) Validate() error {
	if s.Interface == "" || !validIface(s.Interface) || strings.Contains(s.Interface, "*") {
		return fmt.Errorf("an interface is required")
	}
	a, err := parseIPv4(s.Start)
	if err != nil {
		return fmt.Errorf("first address: %w", err)
	}
	b, err := parseIPv4(s.End)
	if err != nil {
		return fmt.Errorf("last address: %w", err)
	}
	if a.Compare(b) > 0 {
		return fmt.Errorf("the range ends before it starts")
	}
	if _, err := LeaseSeconds(s.LeaseTime); err != nil {
		return err
	}
	if s.Router != "" && s.Router != "none" {
		if _, err := parseIPv4(s.Router); err != nil {
			return fmt.Errorf("router: use an IPv4 address, none, or leave empty for this machine")
		}
	}
	for _, d := range s.DNS {
		if _, err := parseIPv4(d); err != nil {
			return fmt.Errorf("DNS server: %w", err)
		}
	}
	if s.Domain != "" && !ValidLocalName(strings.ToLower(s.Domain)) {
		return fmt.Errorf("invalid domain %q", s.Domain)
	}
	return nil
}

func (h DHCPHost) Validate() error {
	if _, err := NormalizeMAC(h.MAC); err != nil {
		return err
	}
	if _, err := parseIPv4(h.IP); err != nil {
		return err
	}
	if h.Hostname != "" && !ValidLocalName(strings.ToLower(h.Hostname)) {
		return fmt.Errorf("invalid hostname %q", h.Hostname)
	}
	return nil
}

func (r DNSRecord) Validate() error {
	if !ValidLocalName(strings.ToLower(strings.TrimSuffix(r.Name, "."))) {
		return fmt.Errorf("invalid name %q", r.Name)
	}
	if _, err := netip.ParseAddr(strings.TrimSpace(r.Address)); err == nil {
		return nil
	}
	if !ValidLocalName(strings.ToLower(strings.TrimSuffix(r.Address, "."))) {
		return fmt.Errorf("%q is neither an IP address nor a name", r.Address)
	}
	return nil
}

// IsAlias reports whether the record points at another name rather than an IP.
func (r DNSRecord) IsAlias() bool {
	_, err := netip.ParseAddr(strings.TrimSpace(r.Address))
	return err != nil
}

var ch24 = map[int]bool{}
var ch5 = map[int]bool{}

func init() {
	for c := 1; c <= 14; c++ {
		ch24[c] = true
	}
	for _, c := range []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165} {
		ch5[c] = true
	}
}

func (a AccessPoint) Validate() error {
	if a.Interface == "" || !validIface(a.Interface) || strings.Contains(a.Interface, "*") {
		return fmt.Errorf("the wireless interface is required")
	}
	if n := len(a.SSID); n < 1 || n > 32 || !utf8.ValidString(a.SSID) {
		return fmt.Errorf("the network name (SSID) must be 1 to 32 bytes")
	}
	for _, r := range a.SSID {
		if r < ' ' || r == 0x7f {
			return fmt.Errorf("the network name can't contain control characters")
		}
	}
	switch a.Band {
	case "2.4":
		if a.Channel != 0 && !ch24[a.Channel] {
			return fmt.Errorf("channel %d is not a 2.4 GHz channel (1 to 14, or 0 for automatic)", a.Channel)
		}
		if a.AC {
			return fmt.Errorf("802.11ac only exists on 5 GHz")
		}
	case "5":
		if a.Channel != 0 && !ch5[a.Channel] {
			return fmt.Errorf("channel %d is not a 5 GHz channel (36 to 165, or 0 for automatic)", a.Channel)
		}
	default:
		return fmt.Errorf("band must be 2.4 or 5")
	}
	if a.Country != "" && (len(a.Country) != 2 || strings.ToUpper(a.Country) != a.Country || strings.Trim(a.Country, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "") {
		return fmt.Errorf("country is a two-letter code such as DE or US")
	}
	if a.Band == "5" && a.Country == "" {
		return fmt.Errorf("5 GHz needs a country code, because the allowed channels and power depend on it")
	}
	switch a.Security {
	case "open":
	case "wpa2", "wpa3", "wpa2+wpa3":
		p := a.Passphrase
		hex64 := len(p) == 64 && strings.Trim(strings.ToLower(p), "0123456789abcdef") == ""
		if hex64 && a.Security != "wpa2" {
			return fmt.Errorf("a 64-digit key only works with WPA2; WPA3 needs a password of 8 to 63 characters")
		}
		if !hex64 {
			if len(p) < 8 || len(p) > 63 {
				return fmt.Errorf("the password must be 8 to 63 characters")
			}
			for _, r := range p {
				if r < ' ' || r > '~' {
					return fmt.Errorf("the password may only use plain ASCII characters")
				}
			}
		}
	default:
		return fmt.Errorf("security must be open, wpa2, wpa3 or wpa2+wpa3")
	}
	if a.Bridge != "" && (!validIface(a.Bridge) || strings.Contains(a.Bridge, "*")) {
		return fmt.Errorf("invalid bridge name")
	}
	if a.MaxClients < 0 || a.MaxClients > 2007 {
		return fmt.Errorf("max clients must be 0 (the driver's limit) to 2007")
	}
	return nil
}

// validateServices checks the DHCP, DNS and Wi-Fi parts of a config. It is
// called from Config.Validate.
func (c *Config) validateServices(check func(kind, id string) error) error {
	if err := c.DNSMasq.Validate(); err != nil {
		return fmt.Errorf("dnsmasq: %w", err)
	}
	onIface := map[string]string{}
	for _, s := range c.DHCPScopes {
		if err := check("DHCP scope", s.ID); err != nil {
			return err
		}
		if err := s.Validate(); err != nil {
			return fmt.Errorf("DHCP scope on %s: %w", s.Interface, err)
		}
		if s.Disabled {
			continue
		}
		if other, ok := onIface[s.Interface]; ok {
			return fmt.Errorf("two DHCP scopes on %s (%s and %s): keep one per interface", s.Interface, other, s.Start)
		}
		onIface[s.Interface] = s.Start
	}
	macs, ips := map[string]bool{}, map[string]bool{}
	for _, h := range c.DHCPHosts {
		if err := check("fixed address", h.ID); err != nil {
			return err
		}
		if err := h.Validate(); err != nil {
			return fmt.Errorf("fixed address %s: %w", h.MAC, err)
		}
		if h.Disabled {
			continue
		}
		mac, _ := NormalizeMAC(h.MAC)
		ip, _ := parseIPv4(h.IP)
		if macs[mac] {
			return fmt.Errorf("%s already has a fixed address", mac)
		}
		if ips[ip.String()] {
			return fmt.Errorf("%s is already given to another device", ip)
		}
		macs[mac], ips[ip.String()] = true, true
	}
	recs := map[string]bool{}
	for _, r := range c.DNSRecords {
		if err := check("DNS record", r.ID); err != nil {
			return err
		}
		if err := r.Validate(); err != nil {
			return fmt.Errorf("DNS record %s: %w", r.Name, err)
		}
		if r.Disabled {
			continue
		}
		key := strings.ToLower(strings.TrimSuffix(r.Name, ".")) + "|" + strings.ToLower(strings.TrimSpace(r.Address))
		if recs[key] {
			return fmt.Errorf("DNS record %s -> %s is listed twice", r.Name, r.Address)
		}
		recs[key] = true
	}
	inBridge := map[string]string{}
	for _, b := range c.Bridges {
		if !b.Disabled {
			for _, p := range b.Ports {
				inBridge[p] = b.Name
			}
		}
	}
	aps := map[string]bool{}
	for _, a := range c.AccessPoints {
		if err := check("access point", a.ID); err != nil {
			return err
		}
		if err := a.Validate(); err != nil {
			return fmt.Errorf("access point %s: %w", a.Interface, err)
		}
		if a.Disabled {
			continue
		}
		if aps[a.Interface] {
			return fmt.Errorf("%s has two access points; keep one per interface", a.Interface)
		}
		aps[a.Interface] = true
		if br, ok := inBridge[a.Interface]; ok {
			return fmt.Errorf("access point %s is also a port of bridge %s: remove it from the bridge's ports and set the access point's Bridge instead (hostapd joins it)", a.Interface, br)
		}
	}
	return nil
}
