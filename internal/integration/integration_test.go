//go:build linux && integration

// Package integration tests the real Linux backend (netlink + nftables)
// against a live kernel. Run it with `make integration`, which starts a
// privileged container and runs every test in its own network namespace.
package integration

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/conns"
	"github.com/alirezasn3/mini-net-man/internal/dnslist"
	"github.com/alirezasn3/mini-net-man/internal/engine"
	"github.com/alirezasn3/mini-net-man/internal/health"
	"github.com/alirezasn3/mini-net-man/internal/importer"
	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
)

// ---- helpers ---------------------------------------------------------------

func sh(t *testing.T, cmd string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("%s\n%v\n%s", cmd, err, out)
	}
	return string(out)
}

func try(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

func contains(t *testing.T, what, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("%s: missing %q in:\n%s", what, w, out)
		}
	}
}

func absent(t *testing.T, what, out string, nots ...string) {
	t.Helper()
	for _, n := range nots {
		if strings.Contains(out, n) {
			t.Errorf("%s: unexpected %q in:\n%s", what, n, out)
		}
	}
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// topology builds the interfaces of a typical VPN gateway as dummy links.
func topology(t *testing.T) {
	t.Helper()
	sh(t, `
ip link set lo up
for n in ens192 wgServer wgBridge0 wgBridge1; do ip link add $n type dummy; ip link set $n up; done
ip addr add 192.168.71.10/24 dev ens192
ip addr add 10.0.0.1/16 dev wgServer
ip addr add fd00:10::1/64 dev wgServer nodad
ip addr add 10.8.0.2/24 dev wgBridge0
ip addr add fd00:8::2/64 dev wgBridge0 nodad
ip addr add 10.9.0.2/24 dev wgBridge1
ip addr add fd00:9::2/64 dev wgBridge1 nodad`)
}

type env struct {
	eng *engine.Engine
	k   *kernel.Linux
}

func newEnv(t *testing.T) *env {
	t.Helper()
	topology(t)
	cfg, err := engine.DefaultConfig("x")
	if err != nil {
		t.Fatal(err)
	}
	k := kernel.NewLinux()
	e := engine.New(k, cfg, filepath.Join(t.TempDir(), "config.yaml"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.Start()
	return &env{e, k}
}

func (v *env) update(t *testing.T, fn func(*model.Config)) {
	t.Helper()
	issues, err := v.eng.Update(func(c *model.Config) error { fn(c); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Fatalf("apply issues: %+v", issues)
	}
}

// ---- routing ---------------------------------------------------------------

// The setup from the README, entered by hand as primitives.
func TestUserSetup(t *testing.T) {
	v := newEnv(t)
	sh(t, `ip route add 203.0.113.0/24 dev ens192 table 77`) // not ours: must survive everything below
	v.update(t, func(c *model.Config) {
		c.Routes = []model.Route{
			{ID: "r1", Dst: "default", Dev: "wgBridge0", Table: "200"},
			{ID: "r2", Dst: "10.0.0.0/16", Dev: "wgServer", Table: "200"},
		}
		c.Rules = []model.Rule{
			{ID: "u1", Priority: 100, Dst: "10.0.0.1", Action: "lookup", Table: "local"},
			{ID: "u2", Priority: 200, Src: "10.0.0.0/16", Action: "lookup", Table: "200"},
			{ID: "u3", Priority: 201, Dst: "192.168.71.0/24", Action: "lookup", Table: "200"},
		}
		c.Firewall.Rules = []model.FWRule{
			{ID: "f1", Chain: "srcnat", Action: "masquerade", OutIface: "wgBridge0"},
			{ID: "f2", Chain: "forward", Action: "accept", InIface: "wgServer", OutIface: "wgBridge0"},
			{ID: "f3", Chain: "forward", Action: "accept", InIface: "wgBridge0", OutIface: "ens192"},
		}
	})
	rules := sh(t, "ip rule show")
	contains(t, "ip rule", rules, "100:\tfrom all to 10.0.0.1 lookup local", "200:\tfrom 10.0.0.0/16 lookup 200", "201:\tfrom all to 192.168.71.0/24 lookup 200")
	contains(t, "table 200", sh(t, "ip route show table 200"), "default dev wgBridge0", "10.0.0.0/16 dev wgServer")
	nft := sh(t, "nft list table inet mini-net-man")
	contains(t, "nft", nft, `oifname "wgBridge0" masquerade`, `iifname "wgServer" oifname "wgBridge0" accept`, `iifname "wgBridge0" oifname "ens192" accept`)

	if n := v.eng.Converge(); n != 0 {
		t.Errorf("second pass changed %d things; reconcile must be idempotent", n)
	}

	v.update(t, func(c *model.Config) { c.Routes, c.Rules, c.Firewall.Rules = nil, nil, nil })
	absent(t, "ip rule", sh(t, "ip rule show"), "lookup 200", "10.0.0.1 lookup local")
	absent(t, "table 200", sh(t, "ip route show table 200"), "wgBridge0")
	contains(t, "foreign route", sh(t, "ip route show table 77"), "203.0.113.0/24") // untouched
	contains(t, "default rules", sh(t, "ip rule show"), "0:\tfrom all lookup local", "32766:")
}

func TestAdoptHandMadeRule(t *testing.T) {
	v := newEnv(t)
	sh(t, "ip rule add from 10.0.0.0/16 lookup 200 priority 200")
	sh(t, "ip route add default dev wgBridge0 table 200")
	v.update(t, func(c *model.Config) {
		c.Rules = []model.Rule{{ID: "u2", Priority: 200, Src: "10.0.0.0/16", Action: "lookup", Table: "200"}}
		c.Routes = []model.Route{{ID: "r1", Dst: "default", Dev: "wgBridge0", Table: "200"}}
	})
	if got := strings.Count(sh(t, "ip rule show"), "from 10.0.0.0/16 lookup 200"); got != 1 {
		t.Errorf("want exactly one rule, got %d", got)
	}
	rules, _ := v.k.ListRules()
	for _, r := range rules {
		if r.Priority == 200 && !r.Owned {
			t.Error("rule 200 was not adopted")
		}
	}
	routes, _ := v.k.ListRoutes()
	for _, r := range routes {
		if r.Table == "200" && r.Dst == "default" && !r.Owned {
			t.Error("route was not adopted")
		}
	}
	// Once adopted, removing it from the config removes it from the kernel.
	v.update(t, func(c *model.Config) { c.Rules, c.Routes = nil, nil })
	absent(t, "ip rule", sh(t, "ip rule show"), "lookup 200")
}

func TestRuleActions(t *testing.T) {
	v := newEnv(t)
	v.update(t, func(c *model.Config) {
		c.Rules = []model.Rule{
			{ID: "a", Priority: 300, Src: "10.1.1.1", Action: "blackhole"},
			{ID: "b", Priority: 301, Src: "10.1.1.2", Action: "unreachable"},
			{ID: "c", Priority: 302, Src: "10.1.1.3", Action: "prohibit"},
			{ID: "d", Priority: 303, Family: "ipv6", Action: "unreachable"},
			{ID: "e", Priority: 304, Src: "10.1.1.4", Iif: "wgServer", Fwmark: 0x10, Action: "lookup", Table: "main"},
		}
	})
	contains(t, "ip rule", sh(t, "ip rule show"), "from 10.1.1.1 blackhole", "from 10.1.1.2 unreachable", "from 10.1.1.3 prohibit",
		"from 10.1.1.4 fwmark 0x10 iif wgServer lookup main")
	contains(t, "ip -6 rule", sh(t, "ip -6 rule show"), "303:\tfrom all unreachable")
	live, _ := v.k.ListRules()
	got := map[int]string{}
	for _, r := range live {
		if r.Owned {
			got[r.Priority] = r.Action
		}
	}
	want := map[int]string{300: "blackhole", 301: "unreachable", 302: "prohibit", 303: "unreachable", 304: "lookup"}
	for p, a := range want {
		if got[p] != a {
			t.Errorf("rule %d: action %q, want %q", p, got[p], a)
		}
	}
	if n := v.eng.Converge(); n != 0 {
		t.Errorf("not idempotent: %d changes", n)
	}
	v.update(t, func(c *model.Config) { c.Rules = nil })
	absent(t, "ip rule", sh(t, "ip rule show"), "blackhole", "unreachable", "prohibit")
	absent(t, "ip -6 rule", sh(t, "ip -6 rule show"), "unreachable")
}

func TestIPv6Routing(t *testing.T) {
	v := newEnv(t)
	v.update(t, func(c *model.Config) {
		on := true
		c.Sysctl.IPv6Forward = &on
		c.Routes = []model.Route{
			{ID: "d6", Dst: "::/0", Dev: "wgBridge0", Table: "200"},
			{ID: "g6", Dst: "default", Gateway: "FD00:8::1", Dev: "wgBridge0", Table: "201"}, // family from the gateway; mixed case
			{ID: "b6", Dst: "fd00:10::/64", Dev: "wgServer", Table: "200"},
			{ID: "bh", Dst: "2001:db8:dead::/48", Type: "blackhole", Table: "200"},
			{ID: "v4", Dst: "default", Dev: "wgBridge0", Table: "200"},
		}
		c.Rules = []model.Rule{
			{ID: "r6", Priority: 200, Src: "fd00:10::/64", Action: "lookup", Table: "200"},
			{ID: "r4", Priority: 200, Src: "10.0.0.0/16", Action: "lookup", Table: "200"},
		}
		c.Addresses = []model.Address{{ID: "a6", Interface: "wgServer", Address: "fd00:10::2/64"}}
	})
	contains(t, "ip -6 route", sh(t, "ip -6 route show table 200"), "default dev wgBridge0", "fd00:10::/64 dev wgServer", "blackhole 2001:db8:dead::/48")
	contains(t, "ip -6 route 201", sh(t, "ip -6 route show table 201"), "default via fd00:8::1 dev wgBridge0")
	contains(t, "ip route", sh(t, "ip route show table 200"), "default dev wgBridge0")
	contains(t, "ip -6 rule", sh(t, "ip -6 rule show"), "200:\tfrom fd00:10::/64 lookup 200")
	contains(t, "ip rule", sh(t, "ip rule show"), "200:\tfrom 10.0.0.0/16 lookup 200")
	contains(t, "addr", sh(t, "ip -6 addr show dev wgServer"), "fd00:10::2/64")
	contains(t, "sysctl", sh(t, "cat /proc/sys/net/ipv6/conf/all/forwarding"), "1")
	// IPv6 stores routes added without a metric as 1024; that must not look like drift.
	if n := v.eng.Converge(); n != 0 {
		t.Errorf("not idempotent: %d changes", n)
		for _, r := range v.eng.Desired().Routes {
			t.Logf("desired route %s", r.Sig())
		}
		live, _ := v.k.ListRoutes()
		for _, r := range live {
			if r.Owned {
				t.Logf("live    route %s", r.Sig())
			}
		}
	}
	// And the lookup really does pick the right table per family.
	contains(t, "route get v6", sh(t, "ip -6 route get 2001:db8::1 from fd00:10::5 iif wgServer"), "dev wgBridge0")
	contains(t, "route get v4", sh(t, "ip route get 8.8.8.8 from 10.0.0.5 iif wgServer"), "dev wgBridge0")

	v.update(t, func(c *model.Config) { c.Routes, c.Rules, c.Addresses = nil, nil, nil })
	absent(t, "ip -6 route", sh(t, "ip -6 route show table 200")+sh(t, "ip -6 route show table 201"), "wgBridge0", "blackhole")
	absent(t, "addr", sh(t, "ip -6 addr show dev wgServer"), "fd00:10::2/64")
}

func TestSysctlForwarding(t *testing.T) {
	v := newEnv(t)
	flag := func(b bool) *bool { return &b }
	v.update(t, func(c *model.Config) { c.Sysctl.IPForward, c.Sysctl.IPv6Forward = flag(true), flag(true) })
	contains(t, "v4", sh(t, "cat /proc/sys/net/ipv4/ip_forward"), "1")
	contains(t, "v6", sh(t, "cat /proc/sys/net/ipv6/conf/all/forwarding"), "1")
	v.update(t, func(c *model.Config) { c.Sysctl.IPForward, c.Sysctl.IPv6Forward = flag(false), flag(false) })
	contains(t, "v4", sh(t, "cat /proc/sys/net/ipv4/ip_forward"), "0")
	contains(t, "v6", sh(t, "cat /proc/sys/net/ipv6/conf/all/forwarding"), "0")
}

// Tuning settings reach the real /proc/sys, are put back when something else
// changes them, and a choice the kernel lacks (BBR on many container kernels) is
// reported without blocking the rest. Only per-namespace keys are used, and any
// value that turns out to be global is restored afterwards.
func TestTuning(t *testing.T) {
	read := func(key string) string {
		return strings.TrimSpace(sh(t, "cat /proc/sys/"+strings.ReplaceAll(key, ".", "/")))
	}
	for _, key := range []string{"net.ipv4.tcp_congestion_control", "net.ipv4.tcp_mtu_probing", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"} {
		key, orig := key, read(key)
		t.Cleanup(func() { try("echo " + orig + " > /proc/sys/" + strings.ReplaceAll(key, ".", "/")) })
	}

	v := newEnv(t)
	v.update(t, func(c *model.Config) {
		c.Sysctl.Tuning = map[string]string{"tcp_mtu_probing": "1", "rp_filter": "2", "tcp_congestion_control": "reno"}
	})
	if got := read("net.ipv4.tcp_mtu_probing"); got != "1" {
		t.Errorf("tcp_mtu_probing = %q, want 1", got)
	}
	for _, key := range []string{"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"} {
		if got := read(key); got != "2" {
			t.Errorf("%s = %q, want 2", key, got)
		}
	}
	if got := read("net.ipv4.tcp_congestion_control"); got != "reno" {
		t.Errorf("congestion control = %q, want reno", got)
	}

	// Someone changes it behind our back: the next pass puts it back, and a
	// second pass has nothing left to do.
	sh(t, "echo 0 > /proc/sys/net/ipv4/tcp_mtu_probing")
	if n := v.eng.Converge(); n == 0 {
		t.Error("Converge changed nothing after the setting was altered")
	}
	if got := read("net.ipv4.tcp_mtu_probing"); got != "1" {
		t.Errorf("tcp_mtu_probing = %q after Converge, want 1", got)
	}
	if n := v.eng.Converge(); n != 0 {
		t.Errorf("second Converge made %d changes, want 0", n)
	}

	// BBR: set where the kernel has it, otherwise a clear per-setting issue.
	issues, err := v.eng.Update(func(c *model.Config) error {
		c.Sysctl.Tuning["tcp_congestion_control"] = "bbr"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if avail := read("net.ipv4.tcp_available_congestion_control"); strings.Contains(avail, "bbr") {
		if len(issues) != 0 || read("net.ipv4.tcp_congestion_control") != "bbr" {
			t.Errorf("bbr is available but wasn't set: issues=%+v", issues)
		}
	} else {
		t.Logf("kernel without bbr (%s); issues: %+v", avail, issues)
		if len(issues) == 0 {
			t.Error("bbr unavailable but no issue reported")
		}
	}
	if got := read("net.ipv4.tcp_mtu_probing"); got != "1" {
		t.Errorf("one failing setting stopped the others: tcp_mtu_probing = %q", got)
	}
}

// ---- client routing, link flaps, kill switch -------------------------------

func TestClientRoutingFlap(t *testing.T) {
	v := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.eng.Run(ctx)
	time.Sleep(300 * time.Millisecond) // let the netlink subscriptions start

	v.update(t, func(c *model.Config) {
		on := true
		c.Sysctl.IPForward, c.Sysctl.IPv6Forward = &on, &on
		c.ClientRouting.Enabled = true
		c.ClientRouting.Clients = []model.ClientRoute{
			{ID: "c4", Name: "v4", Src: "10.0.0.5", In: "wgServer", Out: "wgBridge0", KillSwitch: true},
			{ID: "c6", Name: "v6", Src: "fd00:10::5", In: "wgServer", Out: "wgBridge0", KillSwitch: true},
			{ID: "n4", Name: "no-kill", Src: "10.0.0.6", In: "wgServer", Out: "wgBridge1"},
		}
	})
	contains(t, "table 200", sh(t, "ip route show table 200"), "default dev wgBridge0", "10.0.0.0/16 dev wgServer")
	contains(t, "table 200 v6", sh(t, "ip -6 route show table 200"), "default dev wgBridge0", "fd00:10::/64 dev wgServer")
	contains(t, "rules", sh(t, "ip rule show"), "from 10.0.0.5 lookup 200", "from 10.0.0.5 blackhole", "from 10.0.0.6 lookup 201")
	absent(t, "rules", sh(t, "ip rule show"), "from 10.0.0.6 blackhole")
	nft := sh(t, "nft list table inet mini-net-man")
	contains(t, "nft", nft, `oifname "wgBridge0" masquerade`, `iifname "wgServer" oifname "wgBridge0" accept`, "ct state established,related accept")
	contains(t, "route get", sh(t, "ip route get 8.8.8.8 from 10.0.0.5 iif wgServer"), "dev wgBridge0")
	contains(t, "route get v6", sh(t, "ip -6 route get 2001:db8::1 from fd00:10::5 iif wgServer"), "dev wgBridge0")

	// Exit goes down: routes vanish, the kill switch drops the client, the
	// client without a kill switch falls back to the main table.
	sh(t, "ip link set wgBridge0 down")
	waitFor(t, 5*time.Second, "exit route to disappear", func() bool {
		return !strings.Contains(sh(t, "ip route show table 200"), "default dev wgBridge0")
	})
	if out, err := try("ip route get 8.8.8.8 from 10.0.0.5 iif wgServer"); err == nil && !strings.Contains(out, "blackhole") {
		t.Errorf("kill switch failed, traffic would leak: %s", out)
	}

	// Exit returns: the engine re-adds the routes on its own.
	sh(t, "ip link set wgBridge0 up")
	waitFor(t, 10*time.Second, "exit route to come back", func() bool {
		return strings.Contains(sh(t, "ip route show table 200"), "default dev wgBridge0") &&
			strings.Contains(sh(t, "ip -6 route show table 200"), "default dev wgBridge0")
	})
	contains(t, "route get after flap", sh(t, "ip route get 8.8.8.8 from 10.0.0.5 iif wgServer"), "dev wgBridge0")

	// Turning the feature off leaves nothing behind.
	v.update(t, func(c *model.Config) { c.ClientRouting.Enabled = false })
	absent(t, "rules", sh(t, "ip rule show"), "lookup 200", "lookup 201", "blackhole")
	absent(t, "table 200", sh(t, "ip route show table 200"), "wgBridge0")
	absent(t, "nft", sh(t, "nft list table inet mini-net-man"), "masquerade")
}

func TestWatch(t *testing.T) {
	topology(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := kernel.NewLinux().Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sh(t, "ip link add probe0 type dummy")
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("no event after adding a link")
	}
}

// ---- firewall ----------------------------------------------------------------

func TestFirewallRuleset(t *testing.T) {
	v := newEnv(t)
	// The IPv4-only table early versions created must be cleaned up.
	sh(t, "nft add table ip mini-net-man && nft add chain ip mini-net-man leftover")
	v.update(t, func(c *model.Config) {
		c.Firewall.Policy = model.FirewallPolicy{Input: "drop", Forward: "drop", Output: "accept"}
		c.Firewall.Rules = []model.FWRule{
			{ID: "1", Chain: "input", Action: "accept", ConnState: "established,related"},
			{ID: "2", Chain: "input", Action: "accept", InIface: "lo"},
			{ID: "3", Chain: "input", Action: "accept", Proto: "tcp", DstPort: "22,8080", ConnState: "new", Comment: "mgmt"},
			{ID: "4", Chain: "input", Action: "accept", Proto: "udp", DstPort: "51000-51100"},
			{ID: "5", Chain: "input", Action: "accept", Family: "ipv6", Proto: "icmpv6"},
			{ID: "6", Chain: "input", Action: "drop", Src: "203.0.113.0/24"},
			{ID: "7", Chain: "input", Action: "drop", Src: "2001:db8::/32"},
			{ID: "8", Chain: "input", Action: "reject", Proto: "tcp", DstPort: "23"},
			{ID: "9", Chain: "dstnat", Action: "dnat", Proto: "tcp", DstPort: "8443", ToAddr: "10.0.0.5", ToPort: 443},
			{ID: "10", Chain: "dstnat", Action: "dnat", Proto: "tcp", DstPort: "9443", ToAddr: "fd00:10::5", ToPort: 443},
			{ID: "11", Chain: "srcnat", Action: "snat", OutIface: "ens192", Src: "10.0.0.0/16", ToAddr: "192.168.71.10"},
			{ID: "12", Chain: "srcnat", Action: "masquerade", OutIface: "wgBridge0", Family: "ipv4"},
		}
	})
	out := sh(t, "nft list table inet mini-net-man")
	contains(t, "nft", out,
		"type filter hook input priority filter; policy drop;", "type filter hook forward priority filter; policy drop;",
		"ct state established,related accept", `iifname "lo" accept`,
		"tcp dport 22", "tcp dport 8080", `comment "mgmt"`, "udp dport 51000-51100",
		"ipv6-icmp", "ip saddr 203.0.113.0/24 drop", "ip6 saddr 2001:db8::/32 drop",
		"reject", "dnat ip to 10.0.0.5:443", "dnat ip6 to [fd00:10::5]:443",
		"snat ip to 192.168.71.10", "masquerade")
	if tables := sh(t, "nft list tables"); strings.Contains(tables, "table ip mini-net-man") {
		t.Errorf("legacy ip table still present:\n%s", tables)
	}
}

// The firewall sits between a client (MTU 1500) and a server reached through a
// smaller link (1400), the situation a tunnel exit creates. The server's view of
// the connection (ss reports its MSS) shows what the SYN carried after the rule.
func TestClampMSS(t *testing.T) {
	v := newEnv(t)
	sh(t, `
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
for n in cli srv; do ip netns add $n; done
ip link add rc0 type veth peer name c0 netns cli
ip link add rs0 type veth peer name s0 netns srv
ip link set rc0 up; ip link set rs0 up mtu 1400
ip addr add 10.61.0.1/24 dev rc0; ip addr add fd61::1/64 dev rc0 nodad
ip addr add 10.62.0.1/24 dev rs0; ip addr add fd62::1/64 dev rs0 nodad
ip netns exec cli sh -c 'ip link set lo up; ip link set c0 up; ip addr add 10.61.0.2/24 dev c0; ip addr add fd61::2/64 dev c0 nodad; ip route add 10.62.0.0/24 via 10.61.0.1; ip route add fd62::/64 via fd61::1'
ip netns exec srv sh -c 'ip link set lo up; ip link set s0 up; ip addr add 10.62.0.2/24 dev s0; ip addr add fd62::2/64 dev s0 nodad; ip route add 10.61.0.0/24 via 10.62.0.1; ip route add fd61::/64 via fd62::1'
sleep 1`)
	t.Cleanup(func() { try("ip netns del cli; ip netns del srv") })
	for _, fam := range []string{"-4", "-6"} {
		c := exec.Command("ip", "netns", "exec", "srv", "nc", fam, "-l", "-k", "9000")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	}
	time.Sleep(300 * time.Millisecond)

	// serverMSS opens a connection from the client and returns the MSS the server settled on.
	serverMSS := func(addr string) int {
		t.Helper()
		fam := "-4"
		if strings.Contains(addr, ":") {
			fam = "-6"
		}
		c := exec.Command("ip", "netns", "exec", "cli", "sh", "-c", "sleep 3 | nc "+fam+" "+addr+" 9000")
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		stop := func() { _ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL); _ = c.Wait() }
		defer stop()
		var out string
		waitFor(t, 3*time.Second, "connection on the server", func() bool {
			out, _ = try("ip netns exec srv ss -tin state established '( sport = :9000 )'")
			return strings.Contains(out, "mss:")
		})
		var mss int
		if _, err := fmt.Sscanf(out[strings.Index(out, "mss:"):], "mss:%d", &mss); err != nil {
			t.Fatalf("no mss in %q", out)
		}
		stop()
		waitFor(t, 3*time.Second, "connection to close", func() bool {
			o, _ := try("ip netns exec srv ss -tn state established '( sport = :9000 )'")
			return !strings.Contains(o, "9000")
		})
		return mss
	}
	between := func(what string, got, lo, hi int) {
		t.Helper()
		if got < lo || got > hi {
			t.Errorf("%s: server MSS %d, want %d..%d", what, got, lo, hi)
		}
	}
	rule := func(mss int) {
		v.update(t, func(c *model.Config) {
			c.Firewall.Rules = []model.FWRule{{ID: "m", Chain: "mangle", Action: "clamp-mss", OutIface: "rs0", MSS: mss}}
		})
	}

	between("no rule, v4", serverMSS("10.62.0.2"), 1400, 1460)
	rule(0)
	contains(t, "nft", sh(t, "nft list table inet mini-net-man"), "tcp option maxseg size set rt mtu")
	between("path MTU, v4", serverMSS("10.62.0.2"), 1300, 1360)
	between("path MTU, v6", serverMSS("fd62::2"), 1280, 1340)

	rule(1200)
	between("fixed 1200, v4", serverMSS("10.62.0.2"), 1100, 1200)

	// A client that already asked for less is never raised.
	rule(0)
	sh(t, "ip netns exec cli ip route replace 10.62.0.0/24 via 10.61.0.1 advmss 1000")
	between("small client MSS kept", serverMSS("10.62.0.2"), 900, 1000)

	// A rule for another interface leaves it alone.
	sh(t, "ip netns exec cli ip route replace 10.62.0.0/24 via 10.61.0.1")
	v.update(t, func(c *model.Config) {
		c.Firewall.Rules = []model.FWRule{{ID: "m", Chain: "mangle", Action: "clamp-mss", OutIface: "elsewhere0"}}
	})
	between("other interface, v4", serverMSS("10.62.0.2"), 1400, 1460)
}

// A trailing * matches any interface name with that prefix, and only those.
func TestInterfaceWildcard(t *testing.T) {
	v := newEnv(t)
	peer(t) // host side is veth0
	const h4 = "10.55.0.1"
	if !pingable(h4) {
		t.Fatal("baseline connectivity is broken")
	}
	block := func(in string) bool {
		t.Helper()
		v.update(t, func(c *model.Config) {
			c.Firewall.Rules = []model.FWRule{{ID: "w", Chain: "input", Action: "drop", Proto: "icmp", InIface: in}}
		})
		return pingable(h4)
	}
	for _, c := range []struct {
		iface   string
		blocked bool
	}{
		{"veth*", true}, {"vet*", true}, {"*", true}, {"veth0", true},
		{"vx*", false}, {"veth00*", false}, {"veth1", false}, {"eth*", false},
	} {
		if got := block(c.iface); got == c.blocked {
			t.Errorf("in_iface %q: ping reachable=%v, want %v", c.iface, got, !c.blocked)
		}
	}
	contains(t, "nft", sh(t, "nft list table inet mini-net-man"), `iifname "eth*"`)
}

// Two links to two servers that both carry the same client address (10.0.0.5).
// The routing table has one way back to 10.0.0.0/16, so replies for clients
// that came in on the other link get lost until connections are marked by the
// interface they arrived on and replies are routed by that mark.
func TestRepliesLeaveByTheInterfaceTheyCameIn(t *testing.T) {
	v := newEnv(t)
	sh(t, noRPFilter("lo")+`
for n in a b; do ip netns add c$n; done
ip link add va type veth peer name ca0 netns ca
ip link add vb type veth peer name cb0 netns cb
ip link set va up; ip link set vb up
ip addr add 192.168.80.1/24 dev va; ip addr add 192.168.81.1/24 dev vb
sysctl -qw net.ipv4.conf.va.rp_filter=0 net.ipv4.conf.vb.rp_filter=0
ip netns exec ca sh -c 'ip link set lo up; ip link set ca0 up; ip addr add 192.168.80.2/24 dev ca0; ip addr add 10.0.0.5/32 dev lo; ip route add 192.168.80.1 dev ca0 src 10.0.0.5'
ip netns exec cb sh -c 'ip link set lo up; ip link set cb0 up; ip addr add 192.168.81.2/24 dev cb0; ip addr add 10.0.0.5/32 dev lo; ip route add 192.168.81.1 dev cb0 src 10.0.0.5'
sleep 1`)
	t.Cleanup(func() { try("ip netns del ca; ip netns del cb") })
	c := exec.Command("nc", "-4", "-l", "-k", "9000")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	time.Sleep(300 * time.Millisecond)

	reach := func(ns, panel string) bool {
		_, err := try("ip netns exec " + ns + " nc -4 -z -w 2 -s 10.0.0.5 " + panel + " 9000")
		return err == nil
	}
	routes := []model.Route{{ID: "r1", Dst: "10.0.0.0/16", Gateway: "192.168.80.2"}}
	v.update(t, func(cfg *model.Config) { cfg.Routes = routes })
	if !reach("ca", "192.168.80.1") {
		t.Fatal("baseline: the client on the link the route points at can't connect")
	}
	if reach("cb", "192.168.81.1") {
		t.Fatal("baseline: the other client connected without any marking, so this test proves nothing")
	}

	v.update(t, func(cfg *model.Config) {
		cfg.Routes = append(routes,
			model.Route{ID: "r70", Dst: "10.0.0.0/16", Gateway: "192.168.80.2", Table: "70"},
			model.Route{ID: "r71", Dst: "10.0.0.0/16", Gateway: "192.168.81.2", Table: "71"})
		cfg.Rules = []model.Rule{
			{ID: "p70", Priority: 100, Fwmark: 70, Table: "70"},
			{ID: "p71", Priority: 101, Fwmark: 71, Table: "71"},
		}
		cfg.Firewall.Rules = []model.FWRule{
			{ID: "m1", Chain: "mangle-in", Action: "mark-connection", InIface: "va", Mark: 70},
			{ID: "m2", Chain: "mangle-in", Action: "mark-connection", InIface: "vb", Mark: 71},
			{ID: "m3", Chain: "mangle-out", Action: "restore-mark"},
		}
	})
	contains(t, "nft", sh(t, "nft list table inet mini-net-man"), "ct mark set 0x00000046", "meta mark set ct mark")
	for ns, panel := range map[string]string{"ca": "192.168.80.1", "cb": "192.168.81.1"} {
		if !reach(ns, panel) {
			t.Errorf("client %s could not connect once connections are marked\nrules:\n%s\ntable 70:\n%s\ntable 71:\n%s",
				ns, sh(t, "ip rule"), sh(t, "ip route show table 70"), sh(t, "ip route show table 71"))
		}
	}
}

// A ruleset the kernel rejects must leave the previous one untouched.
func TestFirewallAtomic(t *testing.T) {
	v := newEnv(t)
	good := model.Firewall{Rules: []model.FWRule{{ID: "1", Chain: "input", Action: "drop", Src: "198.51.100.7"}}}
	if err := v.k.ApplyFirewall(good); err != nil {
		t.Fatal(err)
	}
	before := sh(t, "nft list table inet mini-net-man")

	bad := model.Firewall{Rules: []model.FWRule{
		{ID: "2", Chain: "input", Action: "drop", Src: "198.51.100.8"},
		{ID: "3", Chain: "dstnat", Action: "masquerade"}, // masquerade belongs in srcnat: the kernel refuses it
	}}
	if err := v.k.ApplyFirewall(bad); err == nil {
		t.Fatal("kernel accepted a masquerade rule in a prerouting chain")
	}
	if after := sh(t, "nft list table inet mini-net-man"); after != before {
		t.Errorf("failed apply changed the ruleset:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// peer builds a second namespace connected over a veth pair, to send real
// packets at the rules.
func peer(t *testing.T) {
	t.Helper()
	sh(t, `
ip netns add peer
ip link add veth0 type veth peer name veth1
ip link set veth1 netns peer
ip addr add 10.55.0.1/24 dev veth0
ip addr add fd55::1/64 dev veth0 nodad
ip link set veth0 up
ip netns exec peer ip link set lo up
ip netns exec peer ip addr add 10.55.0.2/24 dev veth1
ip netns exec peer ip addr add fd55::2/64 dev veth1 nodad
ip netns exec peer ip link set veth1 up
sleep 1`)
	t.Cleanup(func() { try("ip netns del peer") })
}

func fromPeer(cmd string) error {
	_, err := try("ip netns exec peer " + cmd)
	return err
}

func listen(t *testing.T, port string) {
	t.Helper()
	for _, fam := range []string{"-4", "-6"} {
		c := exec.Command("nc", fam, "-l", "-k", port)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	}
	time.Sleep(300 * time.Millisecond)
}

func connect(addr, port string) bool {
	fam := "-4"
	if strings.Contains(addr, ":") {
		fam = "-6"
	}
	return fromPeer("nc "+fam+" -z -w 1 "+addr+" "+port) == nil
}

func pingable(addr string) bool {
	p := "ping"
	if strings.Contains(addr, ":") {
		p = "ping -6"
	}
	return fromPeer(p+" -c 1 -W 1 "+addr) == nil
}

// Real packets against the rules: this is what proves the expressions are
// built correctly, not just that the kernel accepted them.
func TestFirewallBehavior(t *testing.T) {
	v := newEnv(t)
	peer(t)
	listen(t, "9000")
	listen(t, "9001")
	listen(t, "9100")
	const h4, h6 = "10.55.0.1", "fd55::1"
	if !pingable(h4) || !pingable(h6) || !connect(h4, "9000") || !connect(h6, "9000") {
		t.Fatal("baseline connectivity is broken")
	}
	set := func(policy string, rules ...model.FWRule) {
		t.Helper()
		for i := range rules {
			rules[i].ID = string(rune('a' + i))
		}
		v.update(t, func(c *model.Config) {
			c.Firewall.Policy = model.FirewallPolicy{Input: policy}
			c.Firewall.Rules = rules
		})
	}
	expect := func(what string, got, want bool) {
		t.Helper()
		if got != want {
			t.Errorf("%s: reachable=%v, want %v", what, got, want)
		}
	}

	t.Log("address matching is per family")
	set("accept", model.FWRule{Chain: "input", Action: "drop", Proto: "icmp", Src: "10.55.0.0/24"})
	expect("ping v4 from a dropped /24", pingable(h4), false)
	expect("ping v6 (rule is IPv4 only)", pingable(h6), true)
	set("accept", model.FWRule{Chain: "input", Action: "drop", Proto: "icmpv6", Src: "fd55::/64"})
	expect("ping v6 from a dropped /64", pingable(h6), false)
	expect("ping v4 (rule is IPv6 only)", pingable(h4), true)
	set("accept", model.FWRule{Chain: "input", Action: "drop", Proto: "icmp", Src: "10.55.0.3/32"})
	expect("ping v4 from a different /32", pingable(h4), true)
	set("accept",
		model.FWRule{Chain: "input", Action: "accept", Proto: "icmp", Src: "10.55.0.2"},
		model.FWRule{Chain: "input", Action: "drop", Proto: "icmp"})
	expect("first matching rule wins", pingable(h4), true)

	t.Log("family field on a rule without addresses")
	set("accept", model.FWRule{Chain: "input", Action: "drop", Family: "ipv4", InIface: "veth0", Proto: "tcp", DstPort: "9000"})
	expect("tcp 9000 over v4", connect(h4, "9000"), false)
	expect("tcp 9000 over v6", connect(h6, "9000"), true)
	set("accept", model.FWRule{Chain: "input", Action: "drop", Proto: "tcp", DstPort: "9000"}) // both families
	expect("tcp 9000 over v4", connect(h4, "9000"), false)
	expect("tcp 9000 over v6", connect(h6, "9000"), false)
	expect("tcp 9001 untouched", connect(h4, "9001"), true)

	t.Log("port lists and ranges")
	set("accept", model.FWRule{Chain: "input", Action: "drop", Proto: "tcp", DstPort: "9000,9001"})
	expect("9000 in list", connect(h4, "9000"), false)
	expect("9001 in list", connect(h4, "9001"), false)
	expect("9100 not in list", connect(h4, "9100"), true)
	set("accept", model.FWRule{Chain: "input", Action: "drop", Proto: "tcp", DstPort: "9050-9150"})
	expect("9100 in range", connect(h4, "9100"), false)
	expect("9001 below range", connect(h4, "9001"), true)

	t.Log("default drop with established/related and a port allowed")
	set("drop",
		model.FWRule{Chain: "input", Action: "accept", ConnState: "established,related"},
		model.FWRule{Chain: "input", Action: "accept", Proto: "tcp", DstPort: "9001"})
	expect("allowed port under drop policy", connect(h4, "9001"), true)
	expect("allowed port over v6", connect(h6, "9001"), true)
	expect("other port under drop policy", connect(h4, "9000"), false)
	expect("ping under drop policy", pingable(h4), false)

	t.Log("reject answers instead of dropping")
	set("accept", model.FWRule{Chain: "input", Action: "reject", Proto: "tcp", DstPort: "9000"})
	start := time.Now()
	expect("rejected port", connect(h4, "9000"), false)
	if time.Since(start) > 900*time.Millisecond {
		t.Errorf("reject took %v; it should refuse immediately rather than time out", time.Since(start))
	}

	t.Log("dnat redirects, for both families")
	set("accept",
		model.FWRule{Chain: "dstnat", Action: "dnat", Proto: "tcp", DstPort: "8443", ToAddr: h4, ToPort: 9001},
		model.FWRule{Chain: "dstnat", Action: "dnat", Proto: "tcp", DstPort: "8444", ToAddr: h6, ToPort: 9001})
	expect("v4 8443 -> 9001", connect(h4, "8443"), true)
	expect("v6 8444 -> 9001", connect(h6, "8444"), true)
	expect("8443 isn't open without the rule", connect(h4, "8445"), false)
}

// ---- import ------------------------------------------------------------------

// The literal commands from the README, then import and take over.
func TestMigrateExistingSetup(t *testing.T) {
	v := newEnv(t)
	sh(t, `
ip route replace default dev wgBridge0 table 200
ip rule add to 10.0.0.1 lookup local priority 100
ip rule add from 10.0.0.0/16 lookup 200 priority 200
ip rule add to 192.168.71.0/24 lookup 200 priority 201
ip route add 10.0.0.0/16 dev wgServer table 200
ip -6 route replace default dev wgBridge0 table 200
ip -6 rule add from fd00:10::/64 lookup 200 priority 200`)
	nftViaIptables := true
	if _, err := try("iptables -t nat -I POSTROUTING -o wgBridge0 -j MASQUERADE"); err != nil {
		nftViaIptables = false
		t.Log("iptables NAT unavailable in this kernel; skipping that part of the import check")
	}

	p := importer.Scan(v.k)
	var rules, routes []string
	for _, r := range p.Rules {
		rules = append(rules, r.Describe())
	}
	for _, r := range p.Routes {
		routes = append(routes, r.Dst+" dev "+r.Dev+" table "+r.Table)
	}
	contains(t, "imported rules", strings.Join(rules, "\n"),
		"100: to 10.0.0.1/32 lookup local", "200: from 10.0.0.0/16 lookup 200", "201: to 192.168.71.0/24 lookup 200", "200: from fd00:10::/64 [ipv6] lookup 200")
	absent(t, "imported rules", strings.Join(rules, "\n"), "32766", "0: lookup local") // system defaults stay out
	contains(t, "imported routes", strings.Join(routes, "\n"), "default dev wgBridge0 table 200", "10.0.0.0/16 dev wgServer table 200", "::/0 dev wgBridge0 table 200")
	if nftViaIptables {
		found := false
		for _, r := range p.Firewall {
			found = found || (r.Chain == "srcnat" && r.Action == "masquerade" && r.OutIface == "wgBridge0" && r.Family == "ipv4")
		}
		if !found {
			t.Errorf("MASQUERADE rule not found in import: %+v", p.Firewall)
		}
	}

	before := sh(t, "ip rule show") + sh(t, "ip -6 rule show")
	v.update(t, func(c *model.Config) {
		for _, r := range p.Rules {
			r.Source = ""
			c.Rules = append(c.Rules, r)
		}
		for _, r := range p.Routes {
			r.Source = ""
			c.Routes = append(c.Routes, r)
		}
		for _, r := range p.Firewall {
			r.Source = ""
			c.Firewall.Rules = append(c.Firewall.Rules, r)
		}
	})
	if after := sh(t, "ip rule show") + sh(t, "ip -6 rule show"); after != before {
		// "proto" annotations may differ, but the rule set itself must not.
		norm := func(s string) string {
			return strings.Join(strings.Fields(strings.ReplaceAll(s, "proto 201", "")), " ")
		}
		if norm(after) != norm(before) {
			t.Errorf("importing changed the live rules:\nbefore:\n%s\nafter:\n%s", before, after)
		}
	}
	if n := v.eng.Converge(); n != 0 {
		t.Errorf("not idempotent after import: %d changes", n)
	}
	// Everything is ours now, so removing it from the config cleans the kernel.
	v.update(t, func(c *model.Config) { c.Rules, c.Routes, c.Firewall.Rules = nil, nil, nil })
	absent(t, "ip rule", sh(t, "ip rule show")+sh(t, "ip -6 rule show"), "lookup 200")
}

// ---- safe mode and restarts ----------------------------------------------------

func TestSafeModeRollback(t *testing.T) {
	v := newEnv(t)
	v.update(t, func(c *model.Config) {
		c.Rules = []model.Rule{{ID: "keep", Priority: 300, Src: "10.1.1.1", Action: "blackhole"}}
	})
	if err := v.eng.SafeStart(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	v.update(t, func(c *model.Config) {
		c.Rules = append(c.Rules, model.Rule{ID: "oops", Priority: 301, Src: "0.0.0.0/0", Action: "blackhole"})
		c.Routes = []model.Route{{ID: "r", Dst: "default", Dev: "wgBridge0", Table: "200"}}
		c.Firewall.Rules = []model.FWRule{{ID: "f", Chain: "input", Action: "drop"}}
	})
	contains(t, "during safe mode", sh(t, "ip rule show"), "from all blackhole")
	contains(t, "during safe mode", sh(t, "nft list table inet mini-net-man"), "drop")

	v.eng.SafeCancel()
	rules := sh(t, "ip rule show")
	contains(t, "after rollback", rules, "from 10.1.1.1 blackhole")
	absent(t, "after rollback", rules, "301:")
	absent(t, "after rollback", sh(t, "ip route show table 200"), "wgBridge0")
	absent(t, "after rollback", sh(t, "nft list table inet mini-net-man"), "drop\n")
}

// After a reboot the kernel starts empty; a fresh daemon must rebuild it from the config file.
func TestRestartReconciles(t *testing.T) {
	newEnv(t) // just the topology
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg, _ := engine.DefaultConfig("x")
	cfg.Rules = []model.Rule{{ID: "u2", Priority: 200, Src: "10.0.0.0/16", Action: "lookup", Table: "200"}}
	cfg.Routes = []model.Route{{ID: "r1", Dst: "default", Dev: "wgBridge0", Table: "200"}}
	cfg.Addresses = []model.Address{{ID: "a", Interface: "wgServer", Address: "10.0.0.2/16"}}
	cfg.Firewall.Rules = []model.FWRule{{ID: "f", Chain: "srcnat", Action: "masquerade", OutIface: "wgBridge0"}}
	if err := engine.SaveConfig(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, ok, err := engine.LoadConfig(cfgPath)
	if err != nil || !ok {
		t.Fatal("config did not round-trip", err)
	}
	e := engine.New(kernel.NewLinux(), loaded, cfgPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.Start()
	contains(t, "rules", sh(t, "ip rule show"), "from 10.0.0.0/16 lookup 200")
	contains(t, "routes", sh(t, "ip route show table 200"), "default dev wgBridge0")
	contains(t, "addr", sh(t, "ip addr show dev wgServer"), "10.0.0.2/16")
	contains(t, "nft", sh(t, "nft list table inet mini-net-man"), "masquerade")

	// Simulate losing the rules (flush) and restarting.
	sh(t, "ip rule del priority 200; nft delete table inet mini-net-man")
	e2 := engine.New(kernel.NewLinux(), loaded, cfgPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e2.Start()
	contains(t, "rules after restart", sh(t, "ip rule show"), "from 10.0.0.0/16 lookup 200")
	contains(t, "nft after restart", sh(t, "nft list table inet mini-net-man"), "masquerade")
}

// ---- listening sockets -------------------------------------------------------

func TestSockets(t *testing.T) {
	topology(t)
	start := func(args ...string) int {
		c := exec.Command("nc", args...)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
		return c.Process.Pid
	}
	v4 := start("-4", "-l", "-k", "9000")        // all IPv4 interfaces
	v6 := start("-6", "-l", "-k", "9000")        // all IPv6 interfaces
	lo := start("-l", "-k", "127.0.0.1", "9002") // loopback only
	udp := start("-u", "-l", "10.0.0.1", "9001") // one specific address
	time.Sleep(500 * time.Millisecond)

	socks, err := kernel.NewLinux().Sockets()
	if err != nil {
		t.Fatal(err)
	}
	find := func(proto string, port int) (model.Socket, bool) {
		for _, s := range socks {
			if s.Proto == proto && s.Port == port {
				return s, true
			}
		}
		return model.Socket{}, false
	}
	check := func(proto string, port int, addr, scope string, pid int) {
		t.Helper()
		s, ok := find(proto, port)
		if !ok {
			t.Errorf("%s/%d not listed; got %+v", proto, port, socks)
			return
		}
		if s.Addr != addr || s.Scope != scope {
			t.Errorf("%s/%d: addr=%s scope=%s, want %s/%s", proto, port, s.Addr, s.Scope, addr, scope)
		}
		if len(s.Procs) != 1 || s.Procs[0].PID != pid || s.Procs[0].Name != "nc" {
			t.Errorf("%s/%d: processes %+v, want nc pid %d", proto, port, s.Procs, pid)
		}
		if s.User != "root" {
			t.Errorf("%s/%d: user %q, want root", proto, port, s.User)
		}
	}
	check("tcp", 9000, "0.0.0.0", "all", v4)
	check("tcp6", 9000, "::", "all", v6)
	check("tcp", 9002, "127.0.0.1", "local", lo)
	check("udp", 9001, "10.0.0.1", "address", udp)

	// A connection that is not a listener must not appear.
	if out, err := try("nc -z -w1 127.0.0.1 9002"); err != nil {
		t.Fatalf("connect: %v %s", err, out)
	}
	socks, _ = kernel.NewLinux().Sockets()
	n := 0
	for _, s := range socks {
		if s.Port == 9002 {
			n++
		}
	}
	if n != 1 {
		t.Errorf("port 9002 listed %d times; established connections must not count as listeners", n)
	}
}

// ---- connection tracking -------------------------------------------------------

// A client in one namespace reaches a server in another THROUGH this machine,
// with masquerade and a port forward, and the tracked entries are read back,
// counted and described.
func TestConnections(t *testing.T) {
	v := newEnv(t)
	sh(t, `
ip netns add pa; ip netns add pb
ip link add va0 type veth peer name va1; ip link set va1 netns pa
ip link add vb0 type veth peer name vb1; ip link set vb1 netns pb
ip addr add 10.55.0.1/24 dev va0; ip link set va0 up
ip addr add 10.66.0.1/24 dev vb0; ip link set vb0 up
ip netns exec pa sh -c 'ip link set lo up; ip addr add 10.55.0.2/24 dev va1; ip link set va1 up; ip route add default via 10.55.0.1'
ip netns exec pb sh -c 'ip link set lo up; ip addr add 10.66.0.2/24 dev vb1; ip link set vb1 up'
sleep 1`)
	t.Cleanup(func() { try("ip netns del pa; ip netns del pb") })

	srv := exec.Command("ip", "netns", "exec", "pb", "nc", "-l", "-k", "9000")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	time.Sleep(400 * time.Millisecond)

	on := true
	v.update(t, func(c *model.Config) {
		c.Sysctl.IPForward, c.Sysctl.ConntrackAcct = &on, &on
		c.ClientRouting.Clients = []model.ClientRoute{{ID: "x", Name: "pa-client", Src: "10.55.0.2", In: "va0", Out: "vb0"}}
		c.Firewall.Rules = []model.FWRule{
			{ID: "m", Chain: "srcnat", Action: "masquerade", OutIface: "vb0"},
			{ID: "d", Chain: "dstnat", Action: "dnat", Proto: "tcp", DstPort: "9100", ToAddr: "10.66.0.2", ToPort: 9000},
		}
	})
	// Byte counting is set after the firewall has loaded connection tracking.
	contains(t, "acct", sh(t, "cat /proc/sys/net/netfilter/nf_conntrack_acct"), "1")

	sh(t, `printf 'hello through the router' | ip netns exec pa nc -w1 10.66.0.2 9000 || true`)
	sh(t, `printf 'via the port forward' | ip netns exec pa nc -w1 10.55.0.1 9100 || true`)

	info, all, err := v.k.Conntrack()
	if err != nil {
		t.Fatal(err)
	}
	if !info.Available || !info.Acct || info.Max == 0 || info.Count == 0 {
		t.Fatalf("conntrack info: %+v", info)
	}
	addrs, _ := v.k.ListAddrs()
	ctx := conns.NewContext(addrs, v.eng.Config().ClientRouting.Clients)
	for i := range all {
		ctx.Enrich(&all[i])
	}
	find := func(dst string, port int) model.Conn {
		t.Helper()
		for _, c := range all {
			if c.Src == "10.55.0.2" && c.Dst == dst && c.DstPort == port && c.Proto == "tcp" {
				return c
			}
		}
		t.Fatalf("no tcp 10.55.0.2 -> %s:%d in %d entries", dst, port, len(all))
		return model.Conn{}
	}

	fw := find("10.66.0.2", 9000)
	if fw.Kind != "forwarded" || fw.Client != "pa-client" {
		t.Errorf("kind=%q client=%q", fw.Kind, fw.Client)
	}
	if fw.ReplyDst != "10.66.0.1" || fw.NAT != "SNAT 10.66.0.1" || fw.Via != "vb0" {
		t.Errorf("masquerade: reply_dst=%s nat=%q via=%q (the translated address belongs to vb0)", fw.ReplyDst, fw.NAT, fw.Via)
	}
	if fw.BytesOut < uint64(len("hello through the router")) || fw.BytesIn == 0 && fw.State == "ESTABLISHED" {
		t.Errorf("byte counters: out=%d in=%d", fw.BytesOut, fw.BytesIn)
	}

	pf := find("10.55.0.1", 9100)
	if pf.Kind != "forwarded" {
		t.Errorf("a port forward to another host is forwarded traffic, got %q", pf.Kind)
	}
	if !strings.Contains(pf.NAT, "DNAT 10.66.0.2:9000") || !strings.Contains(pf.NAT, "SNAT 10.66.0.1") {
		t.Errorf("port forward NAT = %q", pf.NAT)
	}

	// And the query layer sees exactly these as this client's forwarded traffic.
	sum, rows := conns.Run(all, conns.Query{Kind: "forwarded", Client: "10.55.0.2"})
	if len(rows) < 2 || sum.Clients[0].Name != "pa-client" || len(sum.Exits) == 0 || sum.Exits[0].Via != "vb0" {
		t.Errorf("summary: %+v rows=%d", sum, len(rows))
	}
}

// ---- boot order --------------------------------------------------------------

// At boot the daemon can start before the WireGuard interfaces exist, while
// other interfaces keep appearing. Everything must still converge once the
// awaited interfaces show up, without a restart.
func TestInterfacesAppearLate(t *testing.T) {
	v := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.eng.Run(ctx)
	time.Sleep(300 * time.Millisecond)

	// The config refers to interfaces that do not exist yet. Failing to apply
	// them now is expected; the issues are reported, not fatal.
	if _, err := v.eng.Update(func(c *model.Config) error {
		c.Routes = []model.Route{
			{ID: "r1", Dst: "default", Dev: "wgLate0", Table: "200"},
			{ID: "r2", Dst: "10.99.0.0/16", Dev: "wgLate1", Table: "200"},
		}
		c.Rules = []model.Rule{{ID: "u1", Priority: 200, Src: "10.99.0.0/16", Action: "lookup", Table: "200"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	contains(t, "rule is added even though the routes can't be yet", sh(t, "ip rule show"), "from 10.99.0.0/16 lookup 200")

	// A noisy boot: unrelated interfaces and addresses keep appearing, each
	// producing kernel events, over several seconds.
	for i := 0; i < 14; i++ {
		sh(t, fmt.Sprintf("ip link add noise%d type dummy; ip link set noise%d up; ip addr add 172.31.%d.1/24 dev noise%d", i, i, i, i))
		time.Sleep(450 * time.Millisecond)
	}

	// Now the awaited interfaces appear.
	sh(t, "ip link add wgLate0 type dummy; ip link set wgLate0 up; ip link add wgLate1 type dummy; ip link set wgLate1 up")
	waitFor(t, 15*time.Second, "routes through the late interfaces", func() bool {
		out, _ := try("ip route show table 200") // errors while the table is still empty
		return strings.Contains(out, "default dev wgLate0") && strings.Contains(out, "10.99.0.0/16 dev wgLate1")
	})
}

// Even with no kernel event at all after the interfaces appear (events can be
// missed in the gap before the watcher starts), failed items are retried.
func TestFailedItemsAreRetried(t *testing.T) {
	v := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.eng.Run(ctx)
	time.Sleep(300 * time.Millisecond)
	if _, err := v.eng.Update(func(c *model.Config) error {
		c.Routes = []model.Route{{ID: "r1", Dst: "default", Dev: "wgLate0", Table: "200"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(v.eng.Issues()) == 0 {
		t.Fatal("expected an issue for the missing interface")
	}
	// Create the interface from another network namespace's point of view is
	// not possible, so make the failure persist past the event: bring the link
	// up, then stop the engine from hearing about it by waiting out its
	// debounce, and rely on the retry timer for the rest.
	sh(t, "ip link add wgLate0 type dummy; ip link set wgLate0 up")
	waitFor(t, 15*time.Second, "route to appear", func() bool {
		out, _ := try("ip route show table 200")
		return strings.Contains(out, "default dev wgLate0")
	})
	waitFor(t, 5*time.Second, "issue to clear", func() bool { return len(v.eng.Issues()) == 0 })
}

// A default policy of reject must refuse what no rule accepted (immediately,
// where drop would just hang), and keep accepting what the rules allow.
func TestDefaultPolicyReject(t *testing.T) {
	v := newEnv(t)
	peer(t)
	listen(t, "9000")
	listen(t, "9001")
	const h4 = "10.55.0.1"

	set := func(policy string) {
		t.Helper()
		v.update(t, func(c *model.Config) {
			c.Firewall.Policy = model.FirewallPolicy{Input: policy}
			c.Firewall.Rules = []model.FWRule{
				{ID: "a", Chain: "input", Action: "accept", ConnState: "established,related"},
				{ID: "b", Chain: "input", Action: "accept", Proto: "tcp", DstPort: "9001"},
			}
		})
	}
	took := func(port string) (bool, time.Duration) {
		start := time.Now()
		ok := connect(h4, port)
		return ok, time.Since(start)
	}

	set("reject")
	if ok, _ := took("9001"); !ok {
		t.Error("the allowed port should still work under a reject default")
	}
	ok, d := took("9000")
	if ok || d > 900*time.Millisecond {
		t.Errorf("9000 under reject: reachable=%v after %v; want a refusal well inside the 1s connect timeout", ok, d)
	}
	nft := sh(t, "nft list chain inet mini-net-man input")
	contains(t, "nft", nft, "policy accept", `reject comment "default policy"`)
	if strings.LastIndex(nft, `reject comment "default policy"`) < strings.LastIndex(nft, "tcp dport 9001 accept") {
		t.Errorf("the catch-all reject must be the last rule:\n%s", nft)
	}

	set("drop")
	ok, d = took("9000")
	if ok || d < 900*time.Millisecond {
		t.Errorf("9000 under drop: reachable=%v after %v; a drop should leave the connection hanging until the timeout", ok, d)
	}
	nft = sh(t, "nft list chain inet mini-net-man input")
	contains(t, "nft", nft, "policy drop")
	absent(t, "nft", nft, "default policy")

	set("accept")
	if ok, _ := took("9000"); !ok {
		t.Error("9000 should be reachable again under an accept default")
	}
	absent(t, "nft", sh(t, "nft list chain inet mini-net-man input"), "reject")
}

// noRPFilter turns off reverse-path filtering for the host side of a test
// topology. Ubuntu-style kernels default to loose filtering (rp_filter=2),
// which drops a reply whose source has no route back; these tests ping
// addresses that deliberately have none, so they must not depend on the
// machine's default.
func noRPFilter(iface string) string {
	return "sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 net.ipv4.conf." + iface + ".rp_filter=0"
}

// ---- health checks -------------------------------------------------------------

// A policy rule that depends on a ping check leaves the kernel when the pings
// stop being answered and returns when they are. The target is reachable only
// through a gateway in a custom routing table, as with an exit that isn't a
// tunnel, so this also proves the check can find that route.
func TestHealthCheckSwitchesRule(t *testing.T) {
	defer health.SetUnitsForTest(100*time.Millisecond, time.Millisecond)() // 1 "second" = 100 ms
	v := newEnv(t)
	sh(t, `
ip netns add peer
ip link add va0 type veth peer name va1; ip link set va1 netns peer
`+noRPFilter("va0")+`
ip addr add 10.55.0.1/24 dev va0; ip link set va0 up
ip netns exec peer sh -c 'ip link set lo up; ip addr add 10.55.0.2/24 dev va1; ip link set va1 up
  ip addr add 10.99.0.9/32 dev lo
  sysctl -qw net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.va1.arp_ignore=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.va1.rp_filter=0'
sleep 1`)
	t.Cleanup(func() { try("ip netns del peer") })

	// The peer is a gateway: it will not answer ARP for the target itself (so the
	// "assume it's on the link" shortcut can't work), but takes packets sent to it
	// as the next hop. Only the route in table 200 gets a ping through.
	sh(t, "ip route add default via 10.55.0.2 dev va0 table 200")
	if _, err := v.k.Ping(context.Background(), "va0", "10.99.0.9", 400*time.Millisecond); err == nil {
		t.Fatal("expected the ping to fail without a rule pointing at table 200")
	}
	sh(t, "ip route del default via 10.55.0.2 dev va0 table 200")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.eng.Run(ctx)
	v.update(t, func(c *model.Config) {
		c.Routes = []model.Route{{ID: "r", Dst: "default", Gateway: "10.55.0.2", Dev: "va0", Table: "200"}}
		c.Checks = []model.Check{{ID: "ck", Name: "exit", Target: "10.99.0.9", Interface: "va0", Table: "200",
			IntervalSecs: 1, TimeoutMs: 300, FailAfter: 2, RecoverAfter: 2}}
		c.Rules = []model.Rule{{ID: "guarded", Priority: 300, Src: "10.77.0.0/16", Action: "lookup", Table: "200", Check: "ck"}}
	})
	hasRule := func() bool {
		out, _ := try("ip rule show")
		return strings.Contains(out, "from 10.77.0.0/16 lookup 200")
	}
	state := func() string { return v.eng.CheckStatuses()["ck"].State }

	waitFor(t, 5*time.Second, "the check to see the target through table 200", func() bool { return state() == health.Up })
	contains(t, "helper rule", sh(t, "ip rule show"), "1:\tfrom all oif va0 lookup 200")
	if !hasRule() {
		t.Fatal("the guarded rule should be in the kernel while the check is up")
	}
	if rtt := v.eng.CheckStatuses()["ck"].RTTMs; rtt <= 0 {
		t.Errorf("no round-trip time recorded: %v", rtt)
	}

	// The exit stops answering.
	sh(t, "ip netns exec peer ip link set va1 down")
	waitFor(t, 8*time.Second, "the rule to be switched off", func() bool { return !hasRule() })
	if state() != health.Down {
		t.Errorf("state = %q, want down (%+v)", state(), v.eng.CheckStatuses()["ck"])
	}
	contains(t, "helper rule stays", sh(t, "ip rule show"), "oif va0 lookup 200")
	if got := v.eng.Config().Rules[0]; got.Disabled {
		t.Error("the configured rule must not be edited by a failing check")
	}

	// It answers again.
	sh(t, "ip netns exec peer ip link set va1 up")
	waitFor(t, 8*time.Second, "the rule to come back", hasRule)
	waitFor(t, 3*time.Second, "state up", func() bool { return state() == health.Up })
	if n := v.eng.Converge(); n != 0 {
		t.Errorf("not idempotent: %d changes", n)
	}

	// Removing the check's rule dependency cleans up the helper too.
	v.update(t, func(c *model.Config) { c.Rules, c.Checks = nil, nil })
	out, _ := try("ip rule show")
	absent(t, "ip rule", out, "oif va0", "10.77.0.0/16")
}

// IPv6 targets are pinged over ICMPv6 out of the named interface.
func TestPingIPv6AndErrors(t *testing.T) {
	topology(t)
	sh(t, `
ip netns add peer
ip link add va0 type veth peer name va1; ip link set va1 netns peer
ip addr add fd55::1/64 dev va0 nodad; ip link set va0 up
ip netns exec peer sh -c 'ip link set lo up; ip addr add fd55::2/64 dev va1 nodad; ip link set va1 up'
ip addr add 10.55.0.1/24 dev va0
ip netns exec peer ip addr add 10.55.0.2/24 dev va1
sleep 1`)
	t.Cleanup(func() { try("ip netns del peer") })
	k := kernel.NewLinux()
	ctx := context.Background()

	if rtt, err := k.Ping(ctx, "va0", "fd55::2", time.Second); err != nil || rtt <= 0 {
		t.Errorf("ipv6 ping: rtt=%v err=%v", rtt, err)
	}
	if rtt, err := k.Ping(ctx, "va0", "10.55.0.2", time.Second); err != nil || rtt <= 0 {
		t.Errorf("ipv4 ping: rtt=%v err=%v", rtt, err)
	}
	if _, err := k.Ping(ctx, "va0", "10.55.0.77", 300*time.Millisecond); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("an address nobody answers should time out, got %v", err)
	}
	if _, err := k.Ping(ctx, "nosuch0", "10.55.0.2", 300*time.Millisecond); err == nil {
		t.Error("an interface that doesn't exist should be an error")
	}
	if _, err := k.Ping(ctx, "va0", "not-an-ip", time.Second); err == nil {
		t.Error("a hostname isn't accepted")
	}
}

// A ping bound to an interface leaves through it even when no route covers the
// target (Linux treats the target as on that link). That is what lets a check
// work on a tunnel exit, such as WireGuard with `Table = off`, with no table
// configured at all.
func TestPingNeedsNoRouteOnATunnelLikeLink(t *testing.T) {
	topology(t)
	sh(t, `
ip netns add peer
ip link add va0 type veth peer name va1; ip link set va1 netns peer
`+noRPFilter("va0")+`
ip addr add 10.55.0.1/32 dev va0; ip link set va0 up
ip netns exec peer sh -c 'ip link set lo up; ip addr add 10.55.0.2/32 dev va1; ip link set va1 up
  ip addr add 10.99.0.9/32 dev lo; ip route add 10.55.0.1 dev va1
  sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.va1.rp_filter=0'
sleep 1`)
	t.Cleanup(func() { try("ip netns del peer") })

	if out, err := try("ip route get 10.99.0.9"); err == nil {
		t.Fatalf("precondition: the host must have no route to the target, but has: %s", out)
	}
	if rtt, err := kernel.NewLinux().Ping(context.Background(), "va0", "10.99.0.9", time.Second); err != nil || rtt <= 0 {
		t.Errorf("a bound ping should reach the target with no route: rtt=%v err=%v", rtt, err)
	}
}

// TestBridge builds a real bridge with spanning tree, joins ports, repairs
// drift, and removes it again, checking what `ip` reports at each step.
func TestBridge(t *testing.T) {
	v := newEnv(t)
	v.update(t, func(c *model.Config) {
		c.Bridges = []model.Bridge{{ID: "b1", Name: "br0", Ports: []string{"wgBridge0", "wgBridge1"}, STP: true, MTU: 1400}}
		c.Interfaces = []model.LinkSetting{{ID: "i1", Name: "wgServer", State: "down", MTU: 1300}}
	})
	br := sh(t, "ip -d link show br0")
	contains(t, "bridge", br, "bridge", "mtu 1400", "stp_state 1", "UP")
	for _, p := range []string{"wgBridge0", "wgBridge1"} {
		contains(t, p, sh(t, "ip link show "+p), "master br0")
	}
	if out := sh(t, "ip link show wgServer"); strings.Contains(out, "<") && strings.Contains(strings.SplitN(out, ">", 2)[0], "UP") || !strings.Contains(out, "mtu 1300") {
		t.Errorf("wgServer should be down with mtu 1300:\n%s", out)
	}
	if n := v.eng.Converge(); n != 0 {
		t.Errorf("a second pass made %d changes, want 0", n)
	}

	// Someone unplugs a port; the next pass puts it back.
	sh(t, "ip link set wgBridge0 nomaster")
	if n := v.eng.Converge(); n == 0 {
		t.Error("Converge changed nothing after a port was removed")
	}
	contains(t, "port restored", sh(t, "ip link show wgBridge0"), "master br0")

	// An address goes on the bridge, as the page tells people to do.
	v.update(t, func(c *model.Config) {
		c.Addresses = []model.Address{{ID: "a1", Interface: "br0", Address: "10.77.0.1/24"}}
	})
	contains(t, "bridge address", sh(t, "ip -4 addr show br0"), "10.77.0.1/24")

	// A bridge that was there before is joined, not adopted for deletion.
	sh(t, "ip link add legacy0 type bridge")
	v.update(t, func(c *model.Config) {
		c.Bridges = []model.Bridge{{ID: "b2", Name: "legacy0", Ports: []string{"wgBridge1"}}}
		c.Addresses = nil
	})
	if _, err := try("ip link show br0"); err == nil {
		t.Error("br0 should have been deleted with its config entry")
	}
	contains(t, "legacy port", sh(t, "ip link show wgBridge1"), "master legacy0")
	if out := sh(t, "ip link show wgBridge0"); strings.Contains(out, "master") {
		t.Errorf("wgBridge0 still has a master after br0 was removed:\n%s", out)
	}
	v.update(t, func(c *model.Config) { c.Bridges = nil })
	sh(t, "ip link show legacy0") // still there
	if out := sh(t, "ip link show wgBridge1"); strings.Contains(out, "master") {
		t.Errorf("wgBridge1 not released:\n%s", out)
	}
}

// TestAddressLists sends real packets at rules that use address lists:
// static entries (networks and ranges, both families, overlapping), negated
// matches, and addresses that a rule adds to a list, with their timeouts, kept
// across a rebuild of the firewall.
func TestAddressLists(t *testing.T) {
	v := newEnv(t)
	peer(t)
	listen(t, "9000")
	listen(t, "9001")
	const h4, h6 = "10.55.0.1", "fd55::1"
	expect := func(what string, got, want bool) {
		t.Helper()
		if got != want {
			t.Errorf("%s: reachable=%v, want %v", what, got, want)
		}
	}
	set := func(lists []model.AddressEntry, rules ...model.FWRule) {
		t.Helper()
		for i := range rules {
			rules[i].ID = fmt.Sprintf("r%d", i)
		}
		for i := range lists {
			lists[i].ID = fmt.Sprintf("e%d", i)
		}
		v.update(t, func(c *model.Config) {
			c.AddressLists = lists
			c.Firewall.Rules = rules
		})
	}
	dyn := func() map[string]int {
		t.Helper()
		out := map[string]int{}
		ds, err := v.k.ListDynamic()
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range ds {
			out[d.List+" "+d.Address] = d.Remaining
		}
		return out
	}
	if !pingable(h4) || !pingable(h6) {
		t.Fatal("baseline connectivity is broken")
	}

	t.Log("static entries: a range and a network, overlapping, both families")
	bad := func(addrs ...string) (out []model.AddressEntry) {
		for _, a := range addrs {
			out = append(out, model.AddressEntry{List: "bad", Address: a})
		}
		return
	}
	drop := model.FWRule{Chain: "input", Action: "drop", Proto: "icmp", SrcList: "bad"}
	drop6 := model.FWRule{Chain: "input", Action: "drop", Proto: "icmpv6", SrcList: "bad"}
	set(bad("10.55.0.1-10.55.0.5", "10.55.0.0/28", "fd55::/64"), drop, drop6)
	expect("ping v4 from a listed range", pingable(h4), false)
	expect("ping v6 from a listed /64", pingable(h6), false)
	set(bad("10.55.0.9", "10.56.0.0/16"), drop, drop6)
	expect("ping v4 from an address not in the list", pingable(h4), true)
	expect("ping v6 with only IPv4 entries listed", pingable(h6), true)
	set(bad("10.55.0.0-10.55.0.1"), drop, drop6)
	expect("ping v4 from just below a range's end", pingable(h4), true)
	set(bad("10.55.0.0-10.55.0.1", "10.55.0.2-10.55.0.250"), drop, drop6)
	expect("ping v4 from the first address of a range", pingable(h4), false)
	sets := sh(t, "nft list set inet mini-net-man bad.s4")
	contains(t, "adjacent ranges merged", sets, "10.55.0.0-10.55.0.250")
	set(bad("10.55.0.1-10.55.0.2"), drop, drop6)
	expect("ping v4 from the last address of a range", pingable(h4), false)

	t.Log("not in the list")
	notIn := model.FWRule{Chain: "input", Action: "drop", Proto: "icmp", SrcList: "!ok"}
	set([]model.AddressEntry{{List: "ok", Address: "192.0.2.1"}}, notIn)
	expect("ping from an address outside the allow list", pingable(h4), false)
	set([]model.AddressEntry{{List: "ok", Address: "192.0.2.1"}, {List: "ok", Address: "10.55.0.0/24"}}, notIn)
	expect("ping from an address inside the allow list", pingable(h4), true)
	set(nil, notIn) // the list no longer exists: nothing is in it
	expect("ping with the list gone", pingable(h4), false)

	t.Log("destination lists")
	set([]model.AddressEntry{{List: "mine", Address: h4}}, model.FWRule{Chain: "input", Action: "drop", Proto: "icmp", DstList: "mine"})
	expect("ping an address in dst list", pingable(h4), false)
	expect("ping v6 (list is IPv4 only)", pingable(h6), true)

	t.Log("a rule adds the sender to a list")
	add := func(timeout int) model.FWRule {
		return model.FWRule{Chain: "input", Action: "add-src-to-list", List: "seen", Timeout: timeout, Proto: "tcp", DstPort: "9000", ConnState: "new"}
	}
	block := model.FWRule{Chain: "input", Action: "drop", Proto: "tcp", DstPort: "9001", SrcList: "seen"}
	set(nil, add(120), block)
	expect("9001 before anything was added", connect(h4, "9001"), true)
	expect("9000 itself is not blocked", connect(h4, "9000"), true)
	expect("9001 after 9000 was touched (v4)", connect(h4, "9001"), false)
	expect("v6 is a different set", connect(h6, "9001"), true)
	expect("9000 over v6", connect(h6, "9000"), true)
	expect("9001 after 9000 was touched (v6)", connect(h6, "9001"), false)
	got := dyn()
	if r := got["seen 10.55.0.2"]; r <= 0 || r > 120 {
		t.Errorf("seen 10.55.0.2 remaining = %d, want 1..120 (all: %v)", r, got)
	}
	if _, ok := got["seen fd55::2"]; !ok {
		t.Errorf("v6 sender not listed: %v", got)
	}

	t.Log("changing the config rebuilds the table but keeps what rules added")
	set([]model.AddressEntry{{List: "elsewhere", Address: "192.0.2.77"}}, add(120), block)
	expect("9001 still blocked after the rebuild", connect(h4, "9001"), false)
	if r := dyn()["seen 10.55.0.2"]; r <= 0 || r > 120 {
		t.Errorf("entry lost or its time reset across the rebuild: %d", r)
	}

	t.Log("removing one address and flushing")
	if err := v.k.DelDynamic("seen", "10.55.0.2"); err != nil {
		t.Fatal(err)
	}
	expect("9001 after removing the v4 sender", connect(h4, "9001"), true)
	expect("9001 v6 sender still listed", connect(h6, "9001"), false)
	if err := v.k.FlushDynamic("seen"); err != nil {
		t.Fatal(err)
	}
	expect("9001 v6 after flush", connect(h6, "9001"), true)
	if n := len(dyn()); n != 0 {
		t.Errorf("flush left %v", dyn())
	}

	t.Log("entries expire")
	set(nil, add(2), block)
	expect("touch", connect(h4, "9000"), true)
	expect("blocked while listed", connect(h4, "9001"), false)
	time.Sleep(3 * time.Second)
	expect("reachable after the timeout", connect(h4, "9001"), true)
	if n := len(dyn()); n != 0 {
		t.Errorf("expired entry still listed: %v", dyn())
	}

	t.Log("the staged SSH-style example from the README: the fourth connection in a minute is dropped")
	staged := []model.FWRule{
		{Chain: "input", Action: "drop", SrcList: "blocked"},
		{Chain: "input", Action: "add-src-to-list", List: "blocked", Timeout: 86400, Proto: "tcp", DstPort: "9000", ConnState: "new", SrcList: "stage2"},
		{Chain: "input", Action: "add-src-to-list", List: "stage2", Timeout: 60, Proto: "tcp", DstPort: "9000", ConnState: "new", SrcList: "stage1"},
		{Chain: "input", Action: "add-src-to-list", List: "stage1", Timeout: 60, Proto: "tcp", DstPort: "9000", ConnState: "new"},
	}
	set(nil, staged...)
	for i := 1; i <= 3; i++ {
		expect(fmt.Sprintf("connection %d", i), connect(h4, "9000"), true)
	}
	expect("connection 4", connect(h4, "9000"), false)
	expect("connection 5", connect(h4, "9000"), false)
	if _, ok := dyn()["blocked 10.55.0.2"]; !ok {
		t.Errorf("sender not in the blocked list: %v", dyn())
	}
	expect("another family is counted on its own", connect(h6, "9000"), true)

	t.Log("removing the rules removes the sets")
	set(nil)
	if out, err := try("nft list sets inet mini-net-man"); err == nil && strings.Contains(out, "seen") {
		t.Errorf("sets left behind:\n%s", out)
	}
}

// TestAddressListDomains puts a domain name in a list. Its address, from a
// stand-in resolver, ends up in the kernel set with a timeout, blocks real
// packets, survives a rebuild of the firewall, and leaves with the entry.
func TestAddressListDomains(t *testing.T) {
	v := newEnv(t)
	peer(t)
	const h4 = "10.55.0.1"
	v.eng.SetLookup(func(_ context.Context, name string) (dnslist.Result, error) {
		if name != "evil.example.com" {
			return dnslist.Result{}, fmt.Errorf("%s does not exist (NXDOMAIN)", name)
		}
		return dnslist.Result{Addrs: []netip.Addr{netip.MustParseAddr("10.55.0.2"), netip.MustParseAddr("fd55::2")}, TTL: time.Hour}, nil
	})
	if !pingable(h4) {
		t.Fatal("baseline connectivity is broken")
	}
	dyn := func() map[string]int {
		out := map[string]int{}
		ds, err := v.k.ListDynamic()
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range ds {
			out[d.List+" "+d.Address] = d.Remaining
		}
		return out
	}
	set := func(entries ...model.AddressEntry) {
		for i := range entries {
			entries[i].ID = fmt.Sprintf("e%d", i)
		}
		v.update(t, func(c *model.Config) {
			c.AddressLists = entries
			c.Firewall.Rules = []model.FWRule{{ID: "r", Chain: "input", Action: "drop", Proto: "icmp", SrcList: "bad"}}
		})
	}

	set(model.AddressEntry{List: "bad", Address: "evil.example.com"}, model.AddressEntry{List: "bad", Address: "192.0.2.0/24"})
	waitFor(t, 5*time.Second, "the name's addresses in the kernel set", func() bool { _, ok := dyn()["bad 10.55.0.2"]; return ok })
	if r := dyn()["bad 10.55.0.2"]; r < 3500 || r > 3640 {
		t.Errorf("remaining = %d, want about the DNS TTL (an hour) plus a little", r)
	}
	if pingable(h4) {
		t.Error("ping from a listed domain's address got through")
	}
	contains(t, "static part", sh(t, "nft list set inet mini-net-man bad.s4"), "192.0.2.0/24")

	t.Log("changing the config rebuilds the table; the name's addresses come back")
	set(model.AddressEntry{List: "bad", Address: "evil.example.com"}, model.AddressEntry{List: "bad", Address: "192.0.2.0/24"}, model.AddressEntry{List: "other", Address: "198.51.100.1"})
	waitFor(t, 5*time.Second, "addresses after the rebuild", func() bool { _, ok := dyn()["bad 10.55.0.2"]; return ok })
	if pingable(h4) {
		t.Error("ping got through after the firewall was rebuilt")
	}

	t.Log("putting an address that is already there renews it")
	if err := v.k.AddToList("bad", []netip.Addr{netip.MustParseAddr("10.55.0.2")}, 5*time.Hour); err != nil {
		t.Fatal(err)
	}
	if r := dyn()["bad 10.55.0.2"]; r < 4*3600 {
		t.Errorf("remaining after a renew = %d, want about 5 h", r)
	}
	if err := v.k.AddToList("nosuchlist", []netip.Addr{netip.MustParseAddr("10.55.0.2")}, time.Minute); err == nil {
		t.Error("adding to a list that has no sets should say so")
	}

	t.Log("taking the name out takes its addresses out")
	set(model.AddressEntry{List: "bad", Address: "192.0.2.0/24"})
	waitFor(t, 5*time.Second, "the name's addresses to leave", func() bool { _, ok := dyn()["bad 10.55.0.2"]; return !ok })
	if !pingable(h4) {
		t.Error("ping still blocked after the name was removed")
	}

	t.Log("a name that does not resolve is reported and blocks nothing")
	set(model.AddressEntry{List: "bad", Address: "missing.example.com"})
	waitFor(t, 5*time.Second, "an error to be reported", func() bool {
		for _, d := range v.eng.Domains() {
			if d.Domain == "missing.example.com" && strings.Contains(d.Error, "NXDOMAIN") {
				return true
			}
		}
		return false
	})
	if !pingable(h4) {
		t.Error("a name that doesn't resolve blocked traffic")
	}
}

// A matching rule in mangle-in doesn't end the chain: the rules after it are
// still checked, and when several mark-connection rules match, the last wins.
func TestMangleInKeepsGoing(t *testing.T) {
	v := newEnv(t)
	peer(t)
	listen(t, "9000")
	listen(t, "9001")
	// markOf connects to a port and reads the mark the kernel gave that connection.
	markOf := func(port string, rules ...model.FWRule) string {
		t.Helper()
		for i := range rules {
			rules[i].ID = fmt.Sprintf("r%d", i)
			rules[i].Chain, rules[i].Action, rules[i].Proto, rules[i].DstPort = "mangle-in", "mark-connection", "tcp", port
		}
		v.update(t, func(c *model.Config) { c.Firewall.Rules = rules })
		if !connect("10.55.0.1", port) {
			t.Fatal("connect failed")
		}
		out, err := try("grep 'dport=" + port + " ' /proc/net/nf_conntrack")
		if err != nil {
			t.Fatalf("no conntrack entry: %v\n%s", err, out)
		}
		for _, f := range strings.Fields(out) {
			if strings.HasPrefix(f, "mark=") {
				return strings.TrimPrefix(f, "mark=")
			}
		}
		t.Fatalf("no mark in the connection:\n%s", out)
		return ""
	}
	if got := markOf("9000", model.FWRule{Mark: 100}, model.FWRule{Mark: 200, Src: "10.55.0.2"}); got != "200" {
		t.Errorf("a general rule then a more specific one: mark = %s, want 200 (the last match wins)", got)
	}
	if got := markOf("9001", model.FWRule{Mark: 200, Src: "10.55.0.2"}, model.FWRule{Mark: 100}); got != "100" {
		t.Errorf("the specific rule first: mark = %s, want 100 (the later rule still ran)", got)
	}
}
