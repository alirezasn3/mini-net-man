// Package netmgr finds out what else configures the network on this machine
// (NetworkManager, systemd-networkd, netplan, ifupdown, ...), so the panel can
// say so, and warn when one of them also manages an interface mini-net-man does.
//
// It only reads files and, for NetworkManager, asks nmcli; it changes nothing.
// On a system without any of them it finds nothing.
package netmgr

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// Manager is one thing that configures the network.
type Manager struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Running bool   `json:"running"` // a daemon is running now
	Config  bool   `json:"config"`  // it has configuration on disk
	Detail  string `json:"detail"`  // what we saw, in plain words
	Note    string `json:"note,omitempty"`
}

// Report is what Detect found.
type Report struct {
	Managers []Manager `json:"managers"`
	// Links maps an interface name to who manages it, for the ones where that
	// can be told ("NetworkManager", "systemd-networkd").
	Links map[string][]string `json:"-"`
}

// Host is where Detect looks. The zero value means this machine.
type Host struct {
	Root string                                            // "/" unless testing
	Comm func() []string                                   // names of running processes
	Run  func(name string, args ...string) (string, error) // runs a command with a short timeout
}

func (h Host) path(p string) string {
	if h.Root == "" {
		return p
	}
	return filepath.Join(h.Root, p)
}

func (h Host) exists(p string) bool { _, err := os.Stat(h.path(p)); return err == nil }

func (h Host) glob(pattern string) []string {
	m, _ := filepath.Glob(h.path(pattern))
	sort.Strings(m)
	return m
}

func (h Host) read(p string) string { b, _ := os.ReadFile(h.path(p)); return string(b) }

func (h Host) comms() map[string]bool {
	out := map[string]bool{}
	if h.Comm != nil {
		for _, c := range h.Comm() {
			out[c] = true
		}
		return out
	}
	ents, _ := os.ReadDir(h.path("/proc"))
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if b, err := os.ReadFile(h.path("/proc/" + e.Name() + "/comm")); err == nil {
			out[strings.TrimSpace(string(b))] = true
		}
	}
	return out
}

func (h Host) run(name string, args ...string) (string, error) {
	if h.Run != nil {
		return h.Run(name, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// Detect looks at this machine.
func Detect(links []model.Link) Report { return Host{}.Detect(links) }

// Detect looks at the host and says what manages each of links.
func (h Host) Detect(links []model.Link) Report {
	comms := h.comms()
	r := Report{Links: map[string][]string{}}
	add := func(m Manager) { r.Managers = append(r.Managers, m) }

	// NetworkManager.
	nmRunning := comms["NetworkManager"]
	nmProfiles := h.glob("/etc/NetworkManager/system-connections/*")
	nmProfiles = append(nmProfiles, h.glob("/run/NetworkManager/system-connections/*")...)
	if nmRunning || len(nmProfiles) > 0 {
		m := Manager{ID: "networkmanager", Name: "NetworkManager", Running: nmRunning, Config: len(nmProfiles) > 0}
		m.Detail = "running"
		if !nmRunning {
			m.Detail = "installed with " + plural(len(nmProfiles), "saved connection", "saved connections") + ", not running"
		} else if len(nmProfiles) > 0 {
			m.Detail += ", " + plural(len(nmProfiles), "saved connection", "saved connections")
		}
		if nmRunning {
			m.Note = "It may undo changes made here to interfaces it manages. Mark an interface unmanaged (nmcli device set <name> managed no) or add it to unmanaged-devices in NetworkManager.conf."
		}
		add(m)
		if nmRunning {
			if out, err := h.run("nmcli", "-t", "-f", "DEVICE,STATE", "device", "status"); err == nil {
				for _, line := range strings.Split(out, "\n") {
					dev, state, ok := strings.Cut(strings.TrimSpace(line), ":")
					if ok && dev != "" && !strings.HasPrefix(state, "unmanaged") {
						r.Links[dev] = append(r.Links[dev], "NetworkManager")
					}
				}
			}
		}
	}

	// systemd-networkd.
	ndRunning := comms["systemd-network"] // the 15-character process name of systemd-networkd
	ndFiles := append(h.glob("/etc/systemd/network/*.network"), h.glob("/run/systemd/network/*.network")...)
	if ndRunning || len(ndFiles) > 0 {
		m := Manager{ID: "networkd", Name: "systemd-networkd", Running: ndRunning, Config: len(ndFiles) > 0}
		m.Detail = "running"
		if !ndRunning {
			m.Detail = plural(len(ndFiles), ".network file", ".network files") + " present, not running"
		} else if len(ndFiles) > 0 {
			m.Detail += ", " + plural(len(ndFiles), ".network file", ".network files")
		}
		if ndRunning {
			m.Note = "It reconfigures interfaces that match a .network file, including their addresses and MTU."
		}
		add(m)
		if ndRunning {
			for _, l := range links {
				var kv = map[string]string{}
				for _, line := range strings.Split(h.read("/run/systemd/netif/links/"+strconv.Itoa(l.Index)), "\n") {
					if k, v, ok := strings.Cut(line, "="); ok {
						kv[k] = v
					}
				}
				if st := kv["ADMIN_STATE"]; st != "" && st != "unmanaged" {
					r.Links[l.Name] = append(r.Links[l.Name], "systemd-networkd")
				}
			}
		}
	}

	// netplan: not a daemon, it writes config for one of the two above.
	if files := h.glob("/etc/netplan/*.yaml"); len(files) > 0 {
		renderer := "systemd-networkd"
		for _, f := range trimRoot(h, files) {
			sc := bufio.NewScanner(strings.NewReader(h.read(f)))
			for sc.Scan() {
				if k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":"); ok && k == "renderer" {
					renderer = strings.TrimSpace(v)
				}
			}
		}
		add(Manager{ID: "netplan", Name: "netplan", Config: true, Detail: plural(len(files), "file", "files") + " in /etc/netplan, rendering for " + renderer,
			Note: "netplan regenerates the " + renderer + " configuration at boot and on `netplan apply`."})
	}

	// ifupdown.
	if txt := h.read("/etc/network/interfaces"); txt != "" || len(h.glob("/etc/network/interfaces.d/*")) > 0 {
		n := 0
		for _, f := range append([]string{"/etc/network/interfaces"}, trimRoot(h, h.glob("/etc/network/interfaces.d/*"))...) {
			for _, line := range strings.Split(h.read(f), "\n") {
				if f := strings.Fields(line); len(f) >= 2 && f[0] == "iface" && f[1] != "lo" {
					n++
				}
			}
		}
		if n > 0 {
			add(Manager{ID: "ifupdown", Name: "ifupdown", Config: true, Detail: plural(n, "interface", "interfaces") + " in /etc/network/interfaces",
				Note: "ifupdown configures these at boot (`ifup`). It doesn't watch them afterwards."})
		}
	}

	for _, d := range []struct{ id, name, proc, dir, note string }{
		{"connman", "ConnMan", "connmand", "/var/lib/connman", ""},
		{"dhcpcd", "dhcpcd", "dhcpcd", "", "A DHCP client: it sets the address and default route of the interfaces it serves."},
		{"wicd", "wicd", "wicd", "/etc/wicd", ""},
		{"netctl", "netctl", "", "/etc/netctl", ""},
	} {
		running := d.proc != "" && comms[d.proc]
		files := 0
		if d.dir != "" {
			files = len(h.glob(d.dir + "/*"))
		}
		if running || files > 0 {
			det := "running"
			if !running {
				det = "configuration found in " + d.dir + ", not running"
			}
			add(Manager{ID: d.id, Name: d.name, Running: running, Config: files > 0, Detail: det, Note: d.note})
		}
	}
	if comms["dhclient"] || comms["udhcpc"] {
		add(Manager{ID: "dhclient", Name: "DHCP client", Running: true, Detail: "running", Note: "It sets the address and default route of the interfaces it serves."})
	}
	if h.exists("/etc/netplan/50-cloud-init.yaml") || h.exists("/etc/network/interfaces.d/50-cloud-init") || len(h.glob("/etc/systemd/network/10-cloud-init-*")) > 0 {
		add(Manager{ID: "cloud-init", Name: "cloud-init", Config: true, Detail: "wrote the network configuration",
			Note: "cloud-init can rewrite the network configuration on boot. To stop it: create /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg containing network: {config: disabled}."})
	}
	return r
}

func trimRoot(h Host, paths []string) []string {
	out := make([]string, 0, len(paths))
	root := strings.TrimSuffix(h.path("/"), "/")
	for _, p := range paths {
		out = append(out, strings.TrimPrefix(p, root))
	}
	return out
}
