package distro

import (
	"os"
	"path/filepath"
	"testing"
)

func put(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectAndInstallCommands(t *testing.T) {
	for _, c := range []struct {
		osrelease, manager, dnsmasq, ip string
	}{
		{"ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n", "apt", "apt install dnsmasq-base", "apt install iproute2"},
		{"ID=alpine\nPRETTY_NAME=\"Alpine Linux v3.20\"\n", "apk", "apk add dnsmasq", "apk add iproute2"},
		{"ID=fedora\n", "dnf", "dnf install dnsmasq", "dnf install iproute"},
		{"ID=pop\nID_LIKE=\"ubuntu debian\"\n", "apt", "apt install dnsmasq-base", "apt install iproute2"},
		{"ID=arch\n", "pacman", "pacman -S dnsmasq", "pacman -S iproute2"},
	} {
		root := t.TempDir()
		put(t, root, "/etc/os-release", c.osrelease)
		i := DetectIn(root)
		if i.Manager != c.manager {
			t.Errorf("%q: manager %q, want %q", c.osrelease, i.Manager, c.manager)
		}
		if got := i.InstallCmd("dnsmasq"); got != c.dnsmasq {
			t.Errorf("dnsmasq: %q, want %q", got, c.dnsmasq)
		}
		if got := i.InstallCmd("ip"); got != c.ip {
			t.Errorf("ip: %q, want %q", got, c.ip)
		}
	}
	root := t.TempDir()
	put(t, root, "/etc/os-release", "ID=alpine\nPRETTY_NAME=\"Alpine Linux v3.20\"\n")
	i := DetectIn(root)
	if i.String() != "Alpine Linux v3.20" {
		t.Error(i.String())
	}
	if got := i.InstallCmd("hostapd", "nft"); got != "apk add hostapd nftables" {
		t.Error(got)
	}
	if (Info{}).InstallCmd("hostapd") != "" {
		t.Error("unknown package manager should give no command")
	}
}

func TestIptablesFiles(t *testing.T) {
	root := t.TempDir()
	if got := IptablesFilesIn(root); len(got) != 0 {
		t.Fatalf("empty machine: %+v", got)
	}
	// Ubuntu
	put(t, root, "/etc/iptables/rules.v4", "*filter\nCOMMIT\n")
	// Alpine, default paths
	put(t, root, "/etc/iptables/rules-save", "*filter\nCOMMIT\n")
	put(t, root, "/etc/iptables/rules6-save", "*filter\nCOMMIT\n")
	got := IptablesFilesIn(root)
	if len(got) != 3 || got[0].Label != "iptables-persistent" || got[1].Path != "/etc/iptables/rules-save" || got[2].Family != "ipv6" {
		t.Fatalf("%+v", got)
	}
	// Alpine with the save file moved by /etc/conf.d/iptables
	put(t, root, "/etc/conf.d/iptables", "# comment\nIPTABLES_SAVE=\"/var/lib/iptables/rules-save\"\n")
	put(t, root, "/var/lib/iptables/rules-save", "*filter\nCOMMIT\n")
	found := false
	for _, f := range IptablesFilesIn(root) {
		if f.Path == "/var/lib/iptables/rules-save" && f.Family == "ipv4" {
			found = true
		}
		if f.Path == "/etc/iptables/rules-save" {
			t.Error("the default path is replaced by the one conf.d names")
		}
	}
	if !found {
		t.Error("conf.d's IPTABLES_SAVE not honoured")
	}
}
