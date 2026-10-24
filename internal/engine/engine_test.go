package engine

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/health"
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

// fast shortens the loop timing for a test and restores it afterwards.
func fast(t *testing.T) {
	t.Helper()
	d, r, m, tk, w, p := debounceDelay, retryMin, retryMax, tickEvery, stormWindow, stormPause
	debounceDelay, retryMin, retryMax, tickEvery, stormWindow, stormPause =
		10*time.Millisecond, 30*time.Millisecond, 200*time.Millisecond, 10*time.Millisecond, time.Second, time.Second
	t.Cleanup(func() { debounceDelay, retryMin, retryMax, tickEvery, stormWindow, stormPause = d, r, m, tk, w, p })
}

// runEngine starts the reconcile loop and, at the end of the test, stops it and
// waits until it has, so the next test can change the loop's timing safely.
func runEngine(t *testing.T, e *Engine) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func routeApplied(k *kernel.Mock, dev string) bool {
	routes, _ := k.ListRoutes()
	for _, r := range routes {
		if r.Owned && r.Dev == dev {
			return true
		}
	}
	return false
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The daemon can start before an interface it was told about exists. If the
// kernel event for it is missed, the failed route must still be retried.
func TestFailedRoutesAreRetriedWithoutEvents(t *testing.T) {
	fast(t)
	e, k := newTest(t)
	runEngine(t, e)

	is := mustUpdate(t, e, func(c *model.Config) error {
		c.Routes = []model.Route{{ID: "r", Dst: "default", Dev: "wgLate0", Table: "200"}}
		return nil
	})
	if len(is) != 1 {
		t.Fatalf("want one issue for the missing interface, got %+v", is)
	}
	k.AddLink("wgLate0", false) // appears; nobody is told
	eventually(t, "the retry to apply the route", func() bool { return routeApplied(k, "wgLate0") })
	eventually(t, "the issue to clear", func() bool { return len(e.Issues()) == 0 })
}

// During boot unrelated interfaces and addresses keep generating events while
// a route still can't be applied. That must not look like a runaway loop and
// freeze reconciling: the awaited interface appearing later still has to work.
func TestEventBurstWithFailingRouteDoesNotStopReconciling(t *testing.T) {
	fast(t)
	e, k := newTest(t)
	runEngine(t, e)
	mustUpdate(t, e, func(c *model.Config) error {
		c.Routes = []model.Route{{ID: "r", Dst: "default", Dev: "wgLate0", Table: "200"}}
		return nil
	})
	for i := 0; i < 30; i++ { // well past the old limit of 6 per window
		k.Poke()
		time.Sleep(25 * time.Millisecond)
	}
	k.AddLink("wgLate0", true)
	eventually(t, "the route after the burst", func() bool { return routeApplied(k, "wgLate0") })
}

func ownedRuleAt(k *kernel.Mock, priority int) bool {
	rules, _ := k.ListRules()
	for _, r := range rules {
		if r.Owned && r.Priority == priority {
			return true
		}
	}
	return false
}

// A policy rule that depends on a health check is in the kernel while the
// check passes, leaves when pings start timing out, and returns on recovery.
func TestConditionalRuleFollowsItsCheck(t *testing.T) {
	defer health.SetUnitsForTest(10*time.Millisecond, 100*time.Microsecond)()
	e, k := newTest(t)
	mustUpdate(t, e, func(c *model.Config) error {
		c.Checks = []model.Check{{ID: "ck", Name: "germany exit", Target: "1.1.1.1", Interface: "wgBridge0", Table: "200",
			IntervalSecs: 1, TimeoutMs: 1000, FailAfter: 2, RecoverAfter: 2}}
		c.Rules = []model.Rule{
			{ID: "guarded", Priority: 300, Src: "10.0.0.0/16", Action: "lookup", Table: "200", Check: "ck"},
			{ID: "always", Priority: 400, Src: "10.9.0.0/16", Action: "lookup", Table: "main"},
		}
		return nil
	})
	if !ownedRuleAt(k, 300) {
		t.Fatal("a check that has not been measured yet must not switch its rule off")
	}
	eventually(t, "the check to be up", func() bool { return e.CheckStatuses()["ck"].State == health.Up })
	if !ownedRuleAt(k, 1) {
		t.Error("the helper rule that lets the ping reach table 200 is missing")
	}

	k.SetPingFail("wgBridge0", true)
	eventually(t, "the rule to leave the kernel", func() bool { return !ownedRuleAt(k, 300) })
	if st := e.CheckStatuses()["ck"]; st.State != health.Down {
		t.Errorf("status = %+v", st)
	}
	if !ownedRuleAt(k, 400) {
		t.Error("an unconditional rule must be unaffected")
	}
	if !ownedRuleAt(k, 1) {
		t.Error("the helper rule has to stay so the check can notice the recovery")
	}
	if got := e.Config().Rules[0]; got.Disabled || got.Check != "ck" {
		t.Errorf("a failing check must not edit the configured rule: %+v", got)
	}

	k.SetPingFail("wgBridge0", false)
	eventually(t, "the rule to come back", func() bool { return ownedRuleAt(k, 300) })
	if n := e.Converge(); n != 0 {
		t.Errorf("not idempotent after the switch back: %d changes", n)
	}
}

func TestRuleCannotDependOnMissingCheck(t *testing.T) {
	e, _ := newTest(t)
	if _, err := e.Update(func(c *model.Config) error {
		c.Rules = []model.Rule{{ID: "r", Priority: 300, Src: "10.0.0.0/16", Action: "lookup", Table: "200", Check: "nope"}}
		return nil
	}); err == nil {
		t.Fatal("a rule that names a check that does not exist should be rejected")
	}
	mustUpdate(t, e, func(c *model.Config) error {
		c.Checks = []model.Check{{ID: "ck", Name: "x", Target: "1.1.1.1", Interface: "wgBridge0"}}
		c.Rules = []model.Rule{{ID: "r", Priority: 300, Src: "10.0.0.0/16", Action: "lookup", Table: "200", Check: "ck"}}
		return nil
	})
	if _, err := e.Update(func(c *model.Config) error { c.Checks = nil; return nil }); err == nil {
		t.Error("deleting a check that a rule still uses should be rejected")
	}
}

func TestCheckValidation(t *testing.T) {
	bad := []model.Check{
		{ID: "1", Name: "", Target: "1.1.1.1", Interface: "wg0"},
		{ID: "2", Name: "x", Target: "example.com", Interface: "wg0"},
		{ID: "3", Name: "x", Target: "1.1.1.1"},
		{ID: "4", Name: "x", Target: "1.1.1.1", Interface: "wg0", IntervalSecs: 1, TimeoutMs: 5000},
		{ID: "5", Name: "x", Target: "1.1.1.1", Interface: "wg0", Table: "nope"},
		{ID: "6", Name: "x", Target: "1.1.1.1", Interface: "wg0", FailAfter: 500},
	}
	for _, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("check %+v should be rejected", c)
		}
	}
	ok := model.Check{ID: "ok", Name: "x", Target: "2606:4700:4700::1111", Interface: "wg0", Table: "200"}
	if err := ok.Validate(); err != nil || !ok.V6() || ok.Interval() != 5 || ok.Fails() != 3 || ok.Recovers() != 2 || ok.Timeout() != 1000 {
		t.Errorf("defaults/validate: %v %+v", err, ok)
	}
}

func TestCheckHelperRuleFamilyAndDedupe(t *testing.T) {
	e, k := newTest(t)
	mustUpdate(t, e, func(c *model.Config) error {
		c.Checks = []model.Check{
			{ID: "a", Name: "a", Target: "1.1.1.1", Interface: "wgBridge0", Table: "200"},
			{ID: "b", Name: "b", Target: "8.8.8.8", Interface: "wgBridge0", Table: "200"},              // same interface+table+family: one helper
			{ID: "c", Name: "c", Target: "2606:4700:4700::1111", Interface: "wgBridge0", Table: "200"}, // IPv6: its own helper
			{ID: "d", Name: "d", Target: "9.9.9.9", Interface: "wgBridge1"},                            // no table: no helper
		}
		return nil
	})
	rules, _ := k.ListRules()
	v4, v6 := 0, 0
	for _, r := range rules {
		if r.Owned && r.Priority == 1 && r.Oif == "wgBridge0" {
			if r.V6() {
				v6++
			} else {
				v4++
			}
		}
	}
	if v4 != 1 || v6 != 1 {
		t.Errorf("helper rules: %d IPv4, %d IPv6; want one of each", v4, v6)
	}
	for _, r := range rules {
		if r.Owned && r.Oif == "wgBridge1" {
			t.Errorf("a check without a table must not create a helper rule: %+v", r)
		}
	}
}

func sysctl(t *testing.T, k *kernel.Mock, key string) string {
	t.Helper()
	v, err := k.Sysctl(key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTuningIsAppliedAndKept(t *testing.T) {
	e, k := newTest(t)
	is := mustUpdate(t, e, func(c *model.Config) error {
		c.Sysctl.Tuning = map[string]string{
			"tcp_congestion_control": "bbr",
			"socket_buffer_max":      "16777216", // one setting, two sysctls
			"rp_filter":              "2",
			"tcp_mtu_probing":        "1",
		}
		return nil
	})
	if len(is) != 0 {
		t.Fatalf("issues: %+v", is)
	}
	for key, want := range map[string]string{
		"net.ipv4.tcp_congestion_control":    "bbr",
		"net.core.rmem_max":                  "16777216",
		"net.core.wmem_max":                  "16777216",
		"net.ipv4.conf.all.rp_filter":        "2",
		"net.ipv4.conf.default.rp_filter":    "2",
		"net.ipv4.tcp_mtu_probing":           "1",
		"net.ipv4.tcp_slow_start_after_idle": "1", // not managed: untouched
	} {
		if got := sysctl(t, k, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if n := e.Converge(); n != 0 {
		t.Errorf("not idempotent: %d changes on the second pass", n)
	}

	// Something else changes a managed setting behind our back: the next
	// reconcile puts it back, as for forwarding.
	_ = k.SetSysctl("net.ipv4.tcp_mtu_probing", "0")
	if n := e.Converge(); n != 1 {
		t.Errorf("drift not corrected: %d changes", n)
	}
	if got := sysctl(t, k, "net.ipv4.tcp_mtu_probing"); got != "1" {
		t.Errorf("tcp_mtu_probing = %q after reconcile", got)
	}

	// Stop managing one: it is left as it is, not reverted.
	mustUpdate(t, e, func(c *model.Config) error { delete(c.Sysctl.Tuning, "tcp_mtu_probing"); return nil })
	_ = k.SetSysctl("net.ipv4.tcp_mtu_probing", "2")
	e.Converge()
	if got := sysctl(t, k, "net.ipv4.tcp_mtu_probing"); got != "2" {
		t.Errorf("an unmanaged setting was touched: %q", got)
	}
}

func TestTuningRejectsBadValuesAndUnknownSettings(t *testing.T) {
	e, _ := newTest(t)
	for _, bad := range []map[string]string{
		{"tcp_congestion_control": "westwood"},
		{"tcp_mtu_probing": "7"},
		{"socket_buffer_max": "5"},
		{"not_a_setting": "1"},
	} {
		if _, err := e.Update(func(c *model.Config) error { c.Sysctl.Tuning = bad; return nil }); err == nil {
			t.Errorf("%v should be rejected", bad)
		}
	}
	if len(e.Config().Sysctl.Tuning) != 0 {
		t.Error("a rejected change must not be saved")
	}
}

// BBR missing from the kernel, and a setting the kernel doesn't have at all,
// show up as issues with the reason, without blocking the other settings.
func TestTuningFailuresAreReportedPerSetting(t *testing.T) {
	e, k := newTest(t)
	k.SetBBRAvailable(false)
	k.SetKernelWithout("net.core.default_qdisc")
	is := mustUpdate(t, e, func(c *model.Config) error {
		c.Sysctl.Tuning = map[string]string{"tcp_congestion_control": "bbr", "default_qdisc": "fq", "tcp_mtu_probing": "1"}
		return nil
	})
	byID := map[string]string{}
	for _, i := range is {
		byID[i.ID] = i.Message
	}
	if !strings.Contains(byID["tcp_congestion_control"], "bbr isn't available in this kernel") {
		t.Errorf("bbr issue = %q", byID["tcp_congestion_control"])
	}
	if !strings.Contains(byID["default_qdisc"], "this kernel doesn't have net.core.default_qdisc") {
		t.Errorf("qdisc issue = %q", byID["default_qdisc"])
	}
	if len(is) != 2 {
		t.Errorf("want exactly the two failures, got %+v", is)
	}
	if got := sysctl(t, k, "net.ipv4.tcp_mtu_probing"); got != "1" {
		t.Errorf("a working setting must still apply: %q", got)
	}

	// Once the kernel can do it, the retry loop picks it up without a restart.
	k.SetBBRAvailable(true)
	e.Converge()
	if got := sysctl(t, k, "net.ipv4.tcp_congestion_control"); got != "bbr" {
		t.Errorf("bbr not applied after it became available: %q", got)
	}
}

func TestKernelRefusesUnlistedSysctls(t *testing.T) {
	k := kernel.NewMock()
	for _, key := range []string{"kernel.core_pattern", "net.ipv4.ip_forward", "../etc/passwd", "net.ipv4.tcp_mtu_probing; reboot", ""} {
		if err := k.SetSysctl(key, "1"); err == nil {
			t.Errorf("writing %q must be refused", key)
		}
	}
}
