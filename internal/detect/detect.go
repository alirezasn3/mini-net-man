// Package detect reports which firewall tooling is installed and active so
// the UI can warn about things that will interact with mini-net-man.
package detect

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	goSystemd "github.com/alirezasn3/go-systemd"
)

type Tool struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Path      string `json:"path,omitempty"`
}

type Report struct {
	Tools            []Tool   `json:"tools"`
	UFWActive        bool     `json:"ufw_active"`
	IptablesBackend  string   `json:"iptables_backend,omitempty"` // nf_tables | legacy
	IptablesRules    bool     `json:"iptables_has_rules"`
	PersistentFiles  []string `json:"iptables_persistent_files"`
	PersistentActive bool     `json:"iptables_persistent_active"`
	Warnings         []string `json:"warnings"`
}

var toolNames = []string{"nft", "ip", "iptables", "iptables-save", "ip6tables", "ip6tables-save", "ufw", "netfilter-persistent", "wg"}

func Run() Report {
	r := Report{Tools: []Tool{}, PersistentFiles: []string{}, Warnings: []string{}}
	for _, n := range toolNames {
		p, err := exec.LookPath(n)
		r.Tools = append(r.Tools, Tool{Name: n, Installed: err == nil, Path: p})
	}
	has := func(n string) bool {
		for _, t := range r.Tools {
			if t.Name == n {
				return t.Installed
			}
		}
		return false
	}

	if b, err := os.ReadFile("/etc/ufw/ufw.conf"); err == nil {
		r.UFWActive = regexp.MustCompile(`(?m)^ENABLED=yes\s*$`).Match(b)
	}
	for _, f := range []string{"/etc/iptables/rules.v4", "/etc/iptables/rules.v6"} {
		if _, err := os.Stat(f); err == nil {
			r.PersistentFiles = append(r.PersistentFiles, f)
		}
	}
	if st, err := goSystemd.StatusService("netfilter-persistent"); err == nil && st != nil {
		r.PersistentActive = st.Exists && (st.Active || st.Enabled)
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

	if !has("nft") {
		r.Warnings = append(r.Warnings, "nft is not installed. Firewall rules are applied through the kernel API, but you can't inspect them with the nft command.")
	}
	if r.UFWActive {
		r.Warnings = append(r.Warnings, "ufw is active. Its chains run alongside mini-net-man's table, so a packet must be accepted by both. Import its rules and disable it to avoid surprises.")
	}
	if r.PersistentActive || len(r.PersistentFiles) > 0 {
		r.Warnings = append(r.Warnings, "iptables-persistent restores saved iptables rules at boot. They keep working next to mini-net-man until you remove them.")
	}
	return r
}
