// Package detect reports which firewall tooling is installed and active, which
// programs mini-net-man's pages need and are missing, and which other programs
// would fight with it, so the UI can warn. It gives the same answers on every
// distribution: where one keeps a file or names a package, internal/distro knows.
package detect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/distro"
	"github.com/alirezasn3/mini-net-man/internal/initsys"
)

type Tool struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Path      string `json:"path,omitempty"`
	Purpose   string `json:"purpose"`        // what mini-net-man uses it for
	Hint      string `json:"hint,omitempty"` // how to install it, when it is missing
}

type Report struct {
	Distro           string   `json:"distro"`
	Init             string   `json:"init"` // systemd | openrc | ""
	Tools            []Tool   `json:"tools"`
	UFWActive        bool     `json:"ufw_active"`
	IptablesBackend  string   `json:"iptables_backend,omitempty"` // nf_tables | legacy
	IptablesRules    bool     `json:"iptables_has_rules"`
	PersistentFiles  []string `json:"iptables_persistent_files"`
	PersistentActive bool     `json:"iptables_persistent_active"`
	Warnings         []string `json:"warnings"`
}

// Needs says which optional pages are in use, so that a conflict is only
// reported for what the config actually does.
type Needs struct {
	DHCP bool // DHCP or DNS is configured (runs dnsmasq)
	WiFi bool // an access point is configured (runs hostapd)
}

// tools and what they are for. Only those with a package of their own get an
// install hint.
var tools = []struct{ name, purpose string }{
	{"nft", "shows the live firewall ruleset (rules are applied through the kernel, not this)"},
	{"ip", "optional: mini-net-man talks to the kernel directly"},
	{"iptables", "optional: reading existing iptables rules to import them"},
	{"iptables-save", "optional: reading existing iptables rules to import them"},
	{"ip6tables", "optional: reading existing iptables rules to import them"},
	{"ip6tables-save", "optional: reading existing iptables rules to import them"},
	{"ufw", "optional: importing ufw's rules"},
	{"netfilter-persistent", "optional: Debian and Ubuntu's saved-rules service"},
	{"wg", "optional: WireGuard's own tool"},
	{"dnsmasq", "the DHCP & DNS page"},
	{"hostapd", "the Wi-Fi page"},
}

// hasHint are the tools that are worth telling someone how to install.
var hasHint = map[string]bool{"nft": true, "wg": true, "dnsmasq": true, "hostapd": true, "iptables": true}

// Run looks at this machine.
func Run(n Needs) Report {
	dist, kind := distro.Detect(), initsys.Detect()
	r := Report{Distro: dist.String(), Init: string(kind), Tools: []Tool{}, PersistentFiles: []string{}, Warnings: []string{}}
	for _, t := range tools {
		p, err := exec.LookPath(t.name)
		tool := Tool{Name: t.name, Installed: err == nil, Path: p, Purpose: t.purpose}
		if err != nil && hasHint[t.name] {
			tool.Hint = dist.InstallCmd(t.name)
		}
		r.Tools = append(r.Tools, tool)
	}
	has := func(name string) bool {
		for _, t := range r.Tools {
			if t.Name == name {
				return t.Installed
			}
		}
		return false
	}
	warn := func(s string) { r.Warnings = append(r.Warnings, s) }
	running := runningProcs()

	// ufw, firewalld, awall: front ends that write their own rules.
	if b, err := os.ReadFile("/etc/ufw/ufw.conf"); err == nil {
		r.UFWActive = regexp.MustCompile(`(?m)^ENABLED=yes\s*$`).Match(b)
	}
	if running["firewalld"] {
		warn("firewalld is running. It manages its own nftables rules, which run alongside mini-net-man's table, so a packet must be accepted by both. Stop and disable it (" + kind.DisableCmd("firewalld") + ") once mini-net-man has the rules you need.")
	}
	if ents, _ := os.ReadDir("/etc/awall/enabled"); len(ents) > 0 {
		warn("awall (Alpine's firewall front end) has policies enabled. It generates iptables rules, which keep working next to mini-net-man's table until you disable it (awall disable <policy>; awall activate).")
	}

	// Saved iptables rules, restored at boot.
	var labels []string
	for _, f := range distro.IptablesFiles() {
		r.PersistentFiles = append(r.PersistentFiles, f.Path)
		labels = append(labels, f.Path)
	}
	// Debian and Ubuntu name the service netfilter-persistent; Alpine and Red
	// Hat have one each for IPv4 and IPv6.
	for _, name := range []string{"netfilter-persistent", "iptables", "ip6tables"} {
		if kind.InUse(name) {
			r.PersistentActive = true
		}
	}
	if has("iptables") {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "iptables", "-V").Output(); err == nil {
			switch {
			case strings.Contains(string(out), "nf_tables"):
				r.IptablesBackend = "nf_tables"
			case strings.Contains(string(out), "legacy"):
				r.IptablesBackend = "legacy"
			}
		}
	}

	// A service that loads a ruleset starting with "flush ruleset" empties every
	// table, mini-net-man's included, whenever it runs after mini-net-man.
	if kind.InUse("nftables") {
		for _, f := range []string{"/etc/nftables.conf", "/etc/nftables.nft", "/etc/sysconfig/nftables.conf"} {
			if b, err := os.ReadFile(f); err == nil && regexp.MustCompile(`(?m)^\s*flush\s+ruleset\b`).Match(b) {
				warn("The nftables service loads " + f + ", which starts with \"flush ruleset\". Anything that reloads it empties mini-net-man's firewall table until the next change makes mini-net-man apply it again. Remove that line, or stop the service (" + kind.DisableCmd("nftables") + ").")
				break
			}
		}
	}

	// The system copies of the services mini-net-man runs for itself.
	if n.DHCP && kind.InUse("dnsmasq") {
		warn("The system dnsmasq service is enabled or running. mini-net-man runs its own dnsmasq for the DHCP & DNS page, and two cannot both use port 53 and 67. Turn the system one off (" + kind.DisableCmd("dnsmasq") + ").")
	}
	if n.WiFi && kind.InUse("hostapd") {
		warn("The system hostapd service is enabled or running. mini-net-man runs its own hostapd for each access point, and the system one would take the radio first. Turn it off (" + kind.DisableCmd("hostapd") + ").")
	}

	if !has("nft") {
		msg := "nft is not installed. Firewall rules are applied through the kernel API, but you can't inspect them with the nft command."
		if c := dist.InstallCmd("nft"); c != "" {
			msg += " To get it: " + c + "."
		}
		warn(msg)
	}
	if r.UFWActive {
		warn("ufw is active. Its chains run alongside mini-net-man's table, so a packet must be accepted by both. Import its rules and disable it to avoid surprises.")
	}
	if r.PersistentActive || len(r.PersistentFiles) > 0 {
		msg := "Saved iptables rules are restored at boot"
		if len(labels) > 0 {
			msg += " (" + strings.Join(labels, ", ") + ")"
		}
		warn(msg + ". They keep working next to mini-net-man until you remove them.")
	}
	return r
}

// runningProcs is the set of names of the processes running now.
func runningProcs() map[string]bool {
	out := map[string]bool{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm")); err == nil {
			out[strings.TrimSpace(string(b))] = true
		}
	}
	return out
}
