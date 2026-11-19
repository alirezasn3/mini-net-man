package netmgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alirezasn3/mini-net-man/internal/model"
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

func ids(r Report) map[string]Manager {
	out := map[string]Manager{}
	for _, m := range r.Managers {
		out[m.ID] = m
	}
	return out
}

func TestDetectNothing(t *testing.T) {
	h := Host{Root: t.TempDir(), Comm: func() []string { return []string{"sshd", "bash"} }}
	if r := h.Detect(nil); len(r.Managers) != 0 {
		t.Errorf("found %+v on an empty system", r.Managers)
	}
}

func TestDetectUbuntuNetplanNetworkd(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/etc/netplan/50-cloud-init.yaml", "network:\n  version: 2\n  ethernets:\n    ens3:\n      dhcp4: true\n")
	put(t, root, "/run/systemd/network/10-netplan-ens3.network", "[Match]\nName=ens3\n")
	put(t, root, "/run/systemd/netif/links/2", "ADMIN_STATE=configured\nOPER_STATE=routable\n")
	put(t, root, "/run/systemd/netif/links/1", "ADMIN_STATE=unmanaged\n")
	h := Host{Root: root, Comm: func() []string { return []string{"systemd-network"} }}
	r := h.Detect([]model.Link{{Name: "lo", Index: 1}, {Name: "ens3", Index: 2}})
	m := ids(r)
	if !m["networkd"].Running || !m["networkd"].Config || m["netplan"].Detail == "" || m["cloud-init"].Name == "" {
		t.Errorf("managers: %+v", r.Managers)
	}
	if got := r.Links["ens3"]; len(got) != 1 || got[0] != "systemd-networkd" {
		t.Errorf("ens3: %v", got)
	}
	if len(r.Links["lo"]) != 0 {
		t.Errorf("unmanaged lo reported as managed: %v", r.Links["lo"])
	}
	if want := "rendering for systemd-networkd"; !strings.Contains(m["netplan"].Detail, want) {
		t.Errorf("netplan renderer: %q", m["netplan"].Detail)
	}
}

func TestDetectNetworkManager(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/etc/netplan/01.yaml", "network:\n  renderer: NetworkManager\n")
	put(t, root, "/etc/NetworkManager/system-connections/Wired.nmconnection", "[connection]\n")
	h := Host{Root: root,
		Comm: func() []string { return []string{"NetworkManager"} },
		Run: func(name string, args ...string) (string, error) {
			return "ens3:connected\nwlan0:disconnected\nbr0:unmanaged\nlo:unmanaged (externally)\n", nil
		}}
	r := h.Detect([]model.Link{{Name: "ens3", Index: 2}})
	m := ids(r)
	if !m["networkmanager"].Running || !m["networkmanager"].Config || m["networkmanager"].Note == "" {
		t.Errorf("managers: %+v", r.Managers)
	}
	if !strings.Contains(m["netplan"].Detail, "rendering for NetworkManager") {
		t.Errorf("netplan: %q", m["netplan"].Detail)
	}
	if len(r.Links["ens3"]) != 1 || len(r.Links["wlan0"]) != 1 || len(r.Links["br0"]) != 0 || len(r.Links["lo"]) != 0 {
		t.Errorf("links: %v", r.Links)
	}
}

func TestDetectIfupdown(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/etc/network/interfaces", "auto lo\niface lo inet loopback\nsource /etc/network/interfaces.d/*\n")
	if r := (Host{Root: root, Comm: func() []string { return nil }}).Detect(nil); len(r.Managers) != 0 {
		t.Errorf("loopback only should not count: %+v", r.Managers)
	}
	put(t, root, "/etc/network/interfaces.d/eth0", "auto eth0\niface eth0 inet dhcp\n")
	r := Host{Root: root, Comm: func() []string { return nil }}.Detect(nil)
	if m := ids(r)["ifupdown"]; m.Name == "" || !m.Config || m.Running {
		t.Errorf("ifupdown: %+v", r.Managers)
	}
}
