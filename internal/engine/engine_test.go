package engine

import (
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
)

func newTest(t *testing.T) (*Engine, *kernel.Mock) {
	t.Helper()
	k := kernel.NewMock()
	cfg, _ := DefaultConfig("x")
	e := New(k, cfg, filepath.Join(t.TempDir(), "config.yaml"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.Start()
	return e, k
}

func mustUpdate(t *testing.T, e *Engine, fn func(*model.Config) error) []model.Issue {
	t.Helper()
	is, err := e.Update(fn)
	if err != nil {
		t.Fatal(err)
	}
	return is
}

// The exact setup from the README, built by hand with primitives only.
func TestManualSetup(t *testing.T) {
	e, k := newTest(t)
	is := mustUpdate(t, e, func(c *model.Config) error {
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
		return nil
	})
	if len(is) != 0 {
		t.Fatalf("issues: %+v", is)
	}
	rules, _ := k.ListRules()
	if len(rules) != 8 {
		t.Fatalf("want 8 rules, got %d", len(rules))
	}
	text, _ := k.FirewallRuleset()
	for _, want := range []string{`oifname "wgBridge0" masquerade`, `iifname "wgServer" oifname "wgBridge0" accept`} {
		if !strings.Contains(text, want) {
			t.Errorf("ruleset missing %q:\n%s", want, text)
		}
	}
	// Removing items from the config removes them from the kernel.
	mustUpdate(t, e, func(c *model.Config) error { c.Rules = c.Rules[:1]; c.Routes = nil; return nil })
	rules, _ = k.ListRules()
	routes, _ := k.ListRoutes()
	if len(rules) != 6 {
		t.Errorf("want 6 rules after delete, got %d", len(rules))
	}
	for _, r := range routes {
		if r.Owned {
			t.Errorf("owned route left behind: %+v", r)
		}
	}
}

func TestIssueForMissingInterface(t *testing.T) {
	e, _ := newTest(t)
	is := mustUpdate(t, e, func(c *model.Config) error {
		c.Routes = []model.Route{{ID: "r1", Dst: "default", Dev: "nope0", Table: "200"}}
		return nil
	})
	if len(is) != 1 || is[0].ID != "r1" {
		t.Fatalf("want one issue for r1, got %+v", is)
	}
}

func TestClientRouting(t *testing.T) {
	e, k := newTest(t)
	mustUpdate(t, e, func(c *model.Config) error {
		c.ClientRouting.Enabled = true
		c.ClientRouting.Clients = []model.ClientRoute{
			{ID: "c1", Name: "alice", Src: "10.0.0.5", In: "wgServer", Out: "wgBridge0", KillSwitch: true},
			{ID: "c2", Name: "bob", Src: "10.0.0.6", In: "wgServer", Out: "wgBridge1"},
		}
		return nil
	})
	rules, _ := k.ListRules()
	var owned []string
	for _, r := range rules {
		if r.Owned {
			owned = append(owned, r.Describe())
		}
	}
	want := []string{"10000: from 10.0.0.5 lookup 200", "10001: from 10.0.0.5 blackhole", "10002: from 10.0.0.6 lookup 201"}
	if strings.Join(owned, ";") != strings.Join(want, ";") {
		t.Errorf("rules = %v, want %v", owned, want)
	}
	routes, _ := k.ListRoutes()
	n := 0
	for _, r := range routes {
		if r.Owned {
			n++
		}
	}
	if n != 4 { // 2 defaults + 2 return paths
		t.Errorf("want 4 owned routes, got %d", n)
	}
	text, _ := k.FirewallRuleset()
	if !strings.Contains(text, "ct state established,related accept") {
		t.Errorf("no established rule:\n%s", text)
	}

	// Taking the exit interface down removes its route; coming back up and
	// reconciling restores it.
	_ = k.SetLinkUp("wgBridge0", false)
	_ = k.SetLinkUp("wgBridge0", true)
	e.Reapply()
	routes, _ = k.ListRoutes()
	found := false
	for _, r := range routes {
		if r.Owned && r.Dev == "wgBridge0" && r.Dst == "default" {
			found = true
		}
	}
	if !found {
		t.Error("exit route not restored after link flap")
	}

	// Disabling the feature leaves no trace.
	mustUpdate(t, e, func(c *model.Config) error { c.ClientRouting.Enabled = false; return nil })
	rules, _ = k.ListRules()
	for _, r := range rules {
		if r.Owned {
			t.Errorf("owned rule left: %s", r.Describe())
		}
	}
}

func TestAdoptForeignRule(t *testing.T) {
	e, k := newTest(t)
	k.AddForeignRule(model.Rule{Priority: 200, Src: "10.0.0.0/16", Action: "lookup", Table: "200"})
	mustUpdate(t, e, func(c *model.Config) error {
		c.Rules = []model.Rule{{ID: "u", Priority: 200, Src: "10.0.0.0/16", Action: "lookup", Table: "200"}}
		return nil
	})
	owned := 0
	rules, _ := k.ListRules()
	for _, r := range rules {
		if r.Priority == 200 {
			if !r.Owned {
				t.Error("rule not adopted")
			}
			owned++
		}
	}
	if owned != 1 {
		t.Errorf("want exactly one rule at 200, got %d", owned)
	}
}

func TestSafeModeRollback(t *testing.T) {
	e, k := newTest(t)
	mustUpdate(t, e, func(c *model.Config) error {
		c.Rules = []model.Rule{{ID: "keep", Priority: 300, Src: "1.1.1.1", Action: "blackhole"}}
		return nil
	})
	if err := e.SafeStart(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	mustUpdate(t, e, func(c *model.Config) error {
		c.Rules = append(c.Rules, model.Rule{ID: "bad", Priority: 301, Src: "0.0.0.0/0", Action: "blackhole"})
		return nil
	})
	if r, _ := k.ListRules(); len(r) != 7 {
		t.Fatalf("want 7 rules during safe mode, got %d", len(r))
	}
	e.SafeCancel()
	if r, _ := k.ListRules(); len(r) != 6 {
		t.Fatalf("want 6 rules after rollback, got %d", len(r))
	}
	if got := e.Config().Rules; len(got) != 1 || got[0].ID != "keep" {
		t.Fatalf("config not restored: %+v", got)
	}

	// Confirm keeps changes.
	_ = e.SafeStart(5 * time.Second)
	mustUpdate(t, e, func(c *model.Config) error { c.Rules = nil; return nil })
	e.SafeConfirm()
	if e.SafeStatus().Active || len(e.Config().Rules) != 0 {
		t.Fatal("confirm should keep the change")
	}
}

func reconcileChanges(e *Engine) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.applyLocked(false)
}

func TestIPv6(t *testing.T) {
	e, k := newTest(t)
	is := mustUpdate(t, e, func(c *model.Config) error {
		c.Routes = []model.Route{
			{ID: "d6", Dst: "::/0", Dev: "wgBridge0", Table: "200"},
			{ID: "g6", Dst: "default", Gateway: "FD00:8::1", Dev: "wgBridge0", Table: "201"}, // family from the gateway
			{ID: "b6", Dst: "fd00:10::/64", Dev: "wgServer", Table: "200"},
			{ID: "v4", Dst: "default", Dev: "wgBridge0", Table: "200"},
		}
		c.Rules = []model.Rule{
			{ID: "r6", Priority: 200, Src: "fd00:10::/64", Action: "lookup", Table: "200"},
			{ID: "r4", Priority: 200, Src: "10.0.0.0/16", Action: "lookup", Table: "200"}, // same priority, other family
			{ID: "k6", Priority: 300, Family: "ipv6", Action: "unreachable"},              // no src/dst: family is explicit
		}
		c.Firewall.Rules = []model.FWRule{
			{ID: "f1", Chain: "forward", Action: "accept", Src: "fd00:10::/64", OutIface: "wgBridge0"},
			{ID: "f2", Chain: "input", Action: "accept", Family: "ipv6", Proto: "icmpv6"},
			{ID: "f3", Chain: "dstnat", Action: "dnat", Proto: "tcp", DstPort: "443", ToAddr: "fd00:10::5", ToPort: 8443},
		}
		c.Sysctl.IPv6Forward = new(bool)
		*c.Sysctl.IPv6Forward = true
		return nil
	})
	if len(is) != 0 {
		t.Fatalf("issues: %+v", is)
	}
	if on, _ := k.IPForward(true); !on {
		t.Error("ipv6 forwarding not enabled")
	}
	if on, _ := k.IPForward(false); on {
		t.Error("ipv4 forwarding should be untouched")
	}
	rules, _ := k.ListRules()
	v6 := 0
	for _, r := range rules {
		if r.Owned && r.V6() {
			v6++
		}
	}
	if v6 != 2 {
		t.Errorf("want 2 owned ipv6 rules, got %d", v6)
	}
	text, _ := k.FirewallRuleset()
	for _, want := range []string{"ip6 saddr fd00:10::/64", "meta nfproto ipv6 meta l4proto ipv6-icmp accept", "dnat ip6 to [fd00:10::5]:8443"} {
		if !strings.Contains(text, want) {
			t.Errorf("ruleset missing %q:\n%s", want, text)
		}
	}
	// A second pass must find nothing to do (mixed-case gateway, implicit v6 metric...).
	if n := reconcileChanges(e); n != 0 {
		t.Errorf("reconcile is not idempotent: %d changes on the second pass", n)
	}
}

func TestClientRoutingIPv6(t *testing.T) {
	e, k := newTest(t)
	mustUpdate(t, e, func(c *model.Config) error {
		c.ClientRouting.Enabled = true
		c.ClientRouting.Clients = []model.ClientRoute{
			{ID: "c4", Name: "v4", Src: "10.0.0.5", In: "wgServer", Out: "wgBridge0", KillSwitch: true},
			{ID: "c6", Name: "v6", Src: "fd00:10::5", In: "wgServer", Out: "wgBridge0", KillSwitch: true},
		}
		return nil
	})
	routes, _ := k.ListRoutes()
	var got []string
	for _, r := range routes {
		if r.Owned {
			got = append(got, r.Dst+" dev "+r.Dev+" table "+r.Table)
		}
	}
	want := map[string]bool{
		"default dev wgBridge0 table 200":     true, // IPv4 exit
		"::/0 dev wgBridge0 table 200":        true, // IPv6 exit
		"10.0.0.0/16 dev wgServer table 200":  true,
		"fd00:10::/64 dev wgServer table 200": true,
	}
	for _, g := range got {
		delete(want, g)
	}
	if len(want) != 0 || len(got) != 4 {
		t.Errorf("routes = %v, missing %v", got, want)
	}
	text, _ := k.FirewallRuleset()
	for _, w := range []string{"meta nfproto ipv4 oifname \"wgBridge0\" masquerade", "meta nfproto ipv6 oifname \"wgBridge0\" masquerade"} {
		if !strings.Contains(text, w) {
			t.Errorf("missing %q in\n%s", w, text)
		}
	}
	if n := reconcileChanges(e); n != 0 {
		t.Errorf("not idempotent: %d", n)
	}
}
