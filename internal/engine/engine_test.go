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
	if len(rules) != 6 {
		t.Fatalf("want 6 rules, got %d", len(rules))
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
	if len(rules) != 4 {
		t.Errorf("want 4 rules after delete, got %d", len(rules))
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
	if r, _ := k.ListRules(); len(r) != 5 {
		t.Fatalf("want 5 rules during safe mode, got %d", len(r))
	}
	e.SafeCancel()
	if r, _ := k.ListRules(); len(r) != 4 {
		t.Fatalf("want 4 rules after rollback, got %d", len(r))
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
