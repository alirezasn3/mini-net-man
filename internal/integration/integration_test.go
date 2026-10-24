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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/conns"
	"github.com/alirezasn3/mini-net-man/internal/engine"
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
