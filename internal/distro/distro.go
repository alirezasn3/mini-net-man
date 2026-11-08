// Package distro knows what the machine's Linux distribution calls things: its
// package manager and packages, and where it saves iptables rules. It is how the
// panel gives the same advice on Ubuntu, Alpine, Fedora and Arch.
package distro

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Info is the distribution this machine runs.
type Info struct {
	ID      string // os-release ID: ubuntu, alpine, fedora, ...
	Name    string // PRETTY_NAME, or the ID
	Manager string // apt, apk, dnf, yum, pacman, zypper; "" when unknown
}

func (i Info) String() string {
	if i.Name != "" {
		return i.Name
	}
	return "Linux"
}

// Detect reads this machine's os-release.
func Detect() Info { return DetectIn("") }

// DetectIn is Detect looking under root, for tests ("" is the real root).
func DetectIn(root string) Info {
	var info Info
	var like []string
	for _, f := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		file, err := os.Open(filepath.Join(root, f))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"'`)
			switch k {
			case "ID":
				info.ID = strings.ToLower(v)
			case "ID_LIKE":
				like = strings.Fields(strings.ToLower(v))
			case "PRETTY_NAME":
				info.Name = v
			}
		}
		file.Close()
		break
	}
	byID := map[string]string{
		"debian": "apt", "ubuntu": "apt", "raspbian": "apt", "linuxmint": "apt", "kali": "apt",
		"alpine": "apk", "postmarketos": "apk",
		"fedora": "dnf", "rhel": "dnf", "centos": "dnf", "rocky": "dnf", "almalinux": "dnf", "amzn": "dnf",
		"arch": "pacman", "manjaro": "pacman", "endeavouros": "pacman",
		"opensuse": "zypper", "opensuse-leap": "zypper", "opensuse-tumbleweed": "zypper", "sles": "zypper",
	}
	for _, id := range append([]string{info.ID}, like...) {
		if m, ok := byID[id]; ok {
			info.Manager = m
			break
		}
	}
	if info.Manager == "" && root == "" { // an unknown distribution: go by what is installed
		for _, m := range []string{"apt-get", "apk", "dnf", "yum", "pacman", "zypper"} {
			if _, err := exec.LookPath(m); err == nil {
				info.Manager = strings.TrimSuffix(m, "-get")
				break
			}
		}
	}
	return info
}

// packages maps a program to the package that provides it, where that is not
// simply the program's own name.
var packages = map[string]map[string]string{
	"dnsmasq":  {"apt": "dnsmasq-base"}, // the system service is not needed
	"ip":       {"dnf": "iproute", "yum": "iproute"},
	"iptables": {"dnf": "iptables-nft", "yum": "iptables-services"},
	"nft":      {"": "nftables"},
	"wg":       {"": "wireguard-tools"},
	"iw":       {"": "iw"},
	"hostapd":  {"": "hostapd"},
}

// Package is the name of the package that provides program here.
func (i Info) Package(program string) string {
	if p, ok := packages[program][i.Manager]; ok {
		return p
	}
	if p, ok := packages[program][""]; ok {
		return p
	}
	switch program {
	case "ip":
		return "iproute2"
	}
	return program
}

// InstallCmd is the command that installs the programs, or "" when the package
// manager is not known.
func (i Info) InstallCmd(programs ...string) string {
	if len(programs) == 0 {
		return ""
	}
	var pkgs []string
	for _, p := range programs {
		pkgs = append(pkgs, i.Package(p))
	}
	list := strings.Join(pkgs, " ")
	switch i.Manager {
	case "apt":
		return "apt install " + list
	case "apk":
		return "apk add " + list
	case "dnf", "yum":
		return i.Manager + " install " + list
	case "pacman":
		return "pacman -S " + list
	case "zypper":
		return "zypper install " + list
	}
	return ""
}

// SavedRules is a file a distribution restores iptables rules from at boot.
type SavedRules struct {
	Path   string
	Family string // ipv4 or ipv6
	Label  string // what to call it when showing a rule that came from it
}

// IptablesFiles lists the saved iptables rule files that exist on this machine:
// Debian and Ubuntu's iptables-persistent, Alpine's iptables service (at the
// path its /etc/conf.d/iptables names) and Red Hat's iptables-services.
func IptablesFiles() []SavedRules { return IptablesFilesIn("") }

// IptablesFilesIn is IptablesFiles looking under root, for tests.
func IptablesFilesIn(root string) []SavedRules {
	alpine4, alpine6 := "/etc/iptables/rules-save", "/etc/iptables/rules6-save"
	if v := confValue(filepath.Join(root, "/etc/conf.d/iptables"), "IPTABLES_SAVE"); v != "" {
		alpine4 = v
	}
	if v := confValue(filepath.Join(root, "/etc/conf.d/ip6tables"), "IP6TABLES_SAVE"); v != "" {
		alpine6 = v
	}
	all := []SavedRules{
		{"/etc/iptables/rules.v4", "ipv4", "iptables-persistent"},
		{"/etc/iptables/rules.v6", "ipv6", "iptables-persistent"},
		{alpine4, "ipv4", "iptables (saved rules)"},
		{alpine6, "ipv6", "iptables (saved rules)"},
		{"/etc/sysconfig/iptables", "ipv4", "iptables (saved rules)"},
		{"/etc/sysconfig/ip6tables", "ipv6", "iptables (saved rules)"},
	}
	var out []SavedRules
	seen := map[string]bool{}
	for _, f := range all {
		if seen[f.Path] {
			continue
		}
		seen[f.Path] = true
		if st, err := os.Stat(filepath.Join(root, f.Path)); err == nil && !st.IsDir() {
			out = append(out, f)
		}
	}
	return out
}

// confValue reads NAME="value" from a shell-style conf.d file.
func confValue(path, name string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	val := ""
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if k, v, ok := strings.Cut(line, "="); ok && k == name {
			val = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return val
}
