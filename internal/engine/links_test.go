package engine

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/dnslist"

	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
)

func link(t *testing.T, k *kernel.Mock, name string) model.Link {
	t.Helper()
	ls, _ := k.Links()
	for _, l := range ls {
		if l.Name == name {
			return l
		}
	}
	t.Fatalf("no link %s", name)
	return model.Link{}
}

func hasLink(k *kernel.Mock, name string) bool {
	ls, _ := k.Links()
	for _, l := range ls {
		if l.Name == name {
			return true
		}
	}
	return false
}

func TestBridgeLifecycle(t *testing.T) {
	e, k := newTest(t)
	if err := k.SetLinkUp("wgBridge1", false); err != nil {
		t.Fatal(err)
	}
	is := mustUpdate(t, e, func(c *model.Config) error {
		c.Bridges = []model.Bridge{{ID: "b1", Name: "br0", Ports: []string{"wgBridge0", "wgBridge1"}, STP: true, MTU: 1400}}
		return nil
	})
	if len(is) != 0 {
		t.Fatalf("issues: %v", is)
	}
	br := link(t, k, "br0")
	if br.Type != "bridge" || !br.Up || br.MTU != 1400 || !k.BridgeSTP("br0") {
		t.Errorf("bridge not set up: %+v stp=%v", br, k.BridgeSTP("br0"))
	}
	for _, p := range []string{"wgBridge0", "wgBridge1"} {
		if l := link(t, k, p); l.Master != "br0" || !l.Up {
			t.Errorf("port %s: master=%q up=%v", p, l.Master, l.Up)
		}
	}

	// Dropping a port releases it; the other stays.
	mustUpdate(t, e, func(c *model.Config) error { c.Bridges[0].Ports = []string{"wgBridge0"}; return nil })
	if link(t, k, "wgBridge1").Master != "" || link(t, k, "wgBridge0").Master != "br0" {
		t.Error("port not released, or wrong one released")
	}

	// A port someone else joined to the bridge isn't ours to release.
	if err := k.SetMaster("wgServer", "br0"); err != nil {
		t.Fatal(err)
	}
	e.Reapply()
	if link(t, k, "wgServer").Master != "br0" {
		t.Error("released a port mini-net-man never joined")
	}

	// Drift is repaired: someone unplugs a port.
	_ = k.SetMaster("wgBridge0", "")
	e.Reapply()
	if link(t, k, "wgBridge0").Master != "br0" {
		t.Error("port not put back")
	}

	// Removing the bridge from the config removes the bridge we created.
	mustUpdate(t, e, func(c *model.Config) error { c.Bridges = nil; return nil })
	if hasLink(k, "br0") {
		t.Error("bridge we created is still there")
	}
	if link(t, k, "wgBridge0").Master != "" {
		t.Error("port still points at the removed bridge")
	}
}

func TestBridgeAdoptedIsNotDeleted(t *testing.T) {
	e, k := newTest(t)
	if err := k.AddBridge("docker0"); err != nil {
		t.Fatal(err)
	}
	mustUpdate(t, e, func(c *model.Config) error {
		c.Bridges = []model.Bridge{{ID: "b1", Name: "docker0", Ports: []string{"wgBridge0"}}}
		return nil
	})
	if link(t, k, "wgBridge0").Master != "docker0" {
		t.Fatal("port not joined to the existing bridge")
	}
	mustUpdate(t, e, func(c *model.Config) error { c.Bridges = nil; return nil })
	if !hasLink(k, "docker0") {
		t.Error("deleted a bridge that existed before mini-net-man managed it")
	}
	if link(t, k, "wgBridge0").Master != "" {
		t.Error("port we joined was not released")
	}
}

func TestBridgeProblemsAreIssues(t *testing.T) {
	e, _ := newTest(t)
	is := mustUpdate(t, e, func(c *model.Config) error {
		c.Bridges = []model.Bridge{
			{ID: "b1", Name: "wgServer"},                             // exists, not a bridge
			{ID: "b2", Name: "br1", Ports: []string{"nonexistent0"}}, // port missing
		}
		return nil
	})
	var got = map[string]bool{}
	for _, i := range is {
		got[i.ID] = true
	}
	if !got["b1"] || !got["b2"] {
		t.Errorf("expected issues for b1 and b2, got %v", is)
	}
}

func TestInterfaceSettings(t *testing.T) {
	e, k := newTest(t)
	mustUpdate(t, e, func(c *model.Config) error {
		c.Interfaces = []model.LinkSetting{{ID: "i1", Name: "wgBridge1", State: "down", MTU: 1300}}
		return nil
	})
	if l := link(t, k, "wgBridge1"); l.Up || l.MTU != 1300 {
		t.Errorf("settings not applied: %+v", l)
	}
	// It stays down even if something brings it up.
	_ = k.SetLinkUp("wgBridge1", true)
	e.Reapply()
	if link(t, k, "wgBridge1").Up {
		t.Error("interface not kept down")
	}
	// A bridge port that is explicitly down is not raised by the bridge.
	mustUpdate(t, e, func(c *model.Config) error {
		c.Bridges = []model.Bridge{{ID: "b1", Name: "br0", Ports: []string{"wgBridge1"}}}
		return nil
	})
	if l := link(t, k, "wgBridge1"); l.Up || l.Master != "br0" {
		t.Errorf("down port: %+v", l)
	}
	// Dropping the entry stops managing; it doesn't undo.
	mustUpdate(t, e, func(c *model.Config) error { c.Interfaces = nil; return nil })
	_ = k.SetLinkUp("wgBridge1", true)
	e.Reapply()
	if !link(t, k, "wgBridge1").Up {
		t.Error("still forcing the interface down after the entry was removed")
	}
}

func TestBridgeStateSurvivesRestart(t *testing.T) {
	e, k := newTest(t)
	mustUpdate(t, e, func(c *model.Config) error {
		c.Bridges = []model.Bridge{{ID: "b1", Name: "br0", Ports: []string{"wgBridge0"}}}
		return nil
	})
	// A new engine on the same config and state file knows it created br0.
	e2 := New(k, e.Config(), e.path, e.log)
	e2.Start()
	mustUpdate(t, e2, func(c *model.Config) error { c.Bridges = nil; return nil })
	if hasLink(k, "br0") {
		t.Error("restart forgot that mini-net-man created the bridge")
	}
}

func TestBridgeValidation(t *testing.T) {
	bad := map[string]model.Config{
		"no name":      {Bridges: []model.Bridge{{ID: "a"}}},
		"long name":    {Bridges: []model.Bridge{{ID: "a", Name: "averyveryverylongname"}}},
		"wildcard":     {Bridges: []model.Bridge{{ID: "a", Name: "br*"}}},
		"own port":     {Bridges: []model.Bridge{{ID: "a", Name: "br0", Ports: []string{"br0"}}}},
		"dup port":     {Bridges: []model.Bridge{{ID: "a", Name: "br0", Ports: []string{"e0", "e0"}}}},
		"two bridges":  {Bridges: []model.Bridge{{ID: "a", Name: "br0", Ports: []string{"e0"}}, {ID: "b", Name: "br1", Ports: []string{"e0"}}}},
		"same name":    {Bridges: []model.Bridge{{ID: "a", Name: "br0"}, {ID: "b", Name: "br0"}}},
		"bridge port":  {Bridges: []model.Bridge{{ID: "a", Name: "br0"}, {ID: "b", Name: "br1", Ports: []string{"br0"}}}},
		"mtu":          {Bridges: []model.Bridge{{ID: "a", Name: "br0", MTU: 10}}},
		"lo port":      {Bridges: []model.Bridge{{ID: "a", Name: "br0", Ports: []string{"lo"}}}},
		"lo down":      {Interfaces: []model.LinkSetting{{ID: "a", Name: "lo", State: "down"}}},
		"bad state":    {Interfaces: []model.LinkSetting{{ID: "a", Name: "e0", State: "sideways"}}},
		"does nothing": {Interfaces: []model.LinkSetting{{ID: "a", Name: "e0"}}},
		"two entries":  {Interfaces: []model.LinkSetting{{ID: "a", Name: "e0", State: "up"}, {ID: "b", Name: "e0", MTU: 1400}}},
	}
	for name, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := model.Config{
		Bridges:    []model.Bridge{{ID: "a", Name: "br0", Ports: []string{"e0", "e1"}, STP: true, MTU: 1500}, {ID: "b", Name: "br1", Disabled: true, Ports: []string{"e0"}}},
		Interfaces: []model.LinkSetting{{ID: "c", Name: "e2", State: "down"}, {ID: "d", Name: "e3", MTU: 9000}},
	}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestPortMovesBetweenBridges(t *testing.T) {
	e, k := newTest(t)
	mustUpdate(t, e, func(c *model.Config) error {
		c.Bridges = []model.Bridge{{ID: "b1", Name: "br0", Ports: []string{"wgBridge0"}}}
		return nil
	})
	// br0 is replaced by br1 in one change: the port must end up in br1, not released.
	mustUpdate(t, e, func(c *model.Config) error {
		c.Bridges = []model.Bridge{{ID: "b2", Name: "br1", Ports: []string{"wgBridge0"}}}
		return nil
	})
	if got := link(t, k, "wgBridge0").Master; got != "br1" {
		t.Errorf("port master = %q, want br1", got)
	}
	if hasLink(k, "br0") {
		t.Error("br0 should be gone")
	}
}

func TestAddressListValidation(t *testing.T) {
	list := func(name, addr string) model.Config {
		return model.Config{AddressLists: []model.AddressEntry{{ID: "a", List: name, Address: addr}}}
	}
	for name, c := range map[string]model.Config{
		"no list":             list("", "10.0.0.1"),
		"digit first":         list("1bad", "10.0.0.1"),
		"space":               list("my list", "10.0.0.1"),
		"too long":            list("abcdefghijklmnopqrstuvwxyz", "10.0.0.1"),
		"junk address":        list("l", "not-an-ip"),
		"backwards":           list("l", "10.0.0.9-10.0.0.1"),
		"mixed families":      list("l", "10.0.0.1-fd00::1"),
		"bad prefix":          list("l", "10.0.0.0/33"),
		"mapped":              list("l", "::ffff:10.0.0.1"),
		"duplicate":           {AddressLists: []model.AddressEntry{{ID: "a", List: "l", Address: "10.0.0.0/24"}, {ID: "b", List: "l", Address: "10.0.0.0-10.0.0.255"}}},
		"unknown action list": {Firewall: model.Firewall{Rules: []model.FWRule{{ID: "r", Chain: "input", Action: "add-src-to-list"}}}},
		"negative timeout":    {Firewall: model.Firewall{Rules: []model.FWRule{{ID: "r", Chain: "input", Action: "add-src-to-list", List: "x", Timeout: -1}}}},
		"bad src_list":        {Firewall: model.Firewall{Rules: []model.FWRule{{ID: "r", Chain: "input", Action: "drop", SrcList: "!"}}}},
		"mangle":              {Firewall: model.Firewall{Rules: []model.FWRule{{ID: "r", Chain: "mangle", Action: "add-src-to-list", List: "x"}}}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := model.Config{
		AddressLists: []model.AddressEntry{
			{ID: "a", List: "blocklist", Address: "203.0.113.0/24"}, {ID: "b", List: "blocklist", Address: "198.51.100.5-198.51.100.9"},
			{ID: "c", List: "blocklist", Address: "2001:db8::/32"}, {ID: "d", List: "blocklist", Address: "10.0.0.0/24", Disabled: true},
			{ID: "e", List: "blocklist", Address: "10.0.0.0-10.0.0.255"}, // the disabled twin doesn't count
		},
		Firewall: model.Firewall{Rules: []model.FWRule{
			{ID: "r1", Chain: "input", Action: "drop", SrcList: "blocklist"},
			{ID: "r2", Chain: "forward", Action: "drop", DstList: "!allowed"},
			{ID: "r3", Chain: "input", Action: "add-src-to-list", List: "seen", Timeout: 600, Proto: "tcp", DstPort: "22"},
			{ID: "r4", Chain: "mangle-in", Action: "add-dst-to-list", List: "touched"},
		}},
	}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestAddressListsReachTheKernelLayer(t *testing.T) {
	e, k := newTest(t)
	mustUpdate(t, e, func(c *model.Config) error {
		c.AddressLists = []model.AddressEntry{{ID: "a", List: "bad", Address: "203.0.113.0/24"}, {ID: "b", List: "bad", Address: "10.9.9.9", Disabled: true}}
		c.Firewall.Rules = []model.FWRule{{ID: "r", Chain: "input", Action: "drop", SrcList: "bad"}}
		return nil
	})
	live, _ := k.FirewallRuleset()
	_ = live
	d := e.Desired()
	if len(d.Firewall.Lists) != 1 || d.Firewall.Lists[0].Address != "203.0.113.0/24" {
		t.Errorf("lists in desired firewall: %+v", d.Firewall.Lists)
	}
}

func TestDomainEntryValidation(t *testing.T) {
	one := func(addr string) error {
		c := model.Config{AddressLists: []model.AddressEntry{{ID: "a", List: "l", Address: addr}}}
		return c.Validate()
	}
	for _, ok := range []string{"example.com", "Example.COM.", "a-b.example.co.uk", "xn--bcher-kva.example", "_dmarc.example.com", "cdn1.example.com"} {
		if err := one(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for bad, want := range map[string]string{
		"example":        "not an IP address",
		"exa mple.com":   "not an IP address",
		"-bad.example":   "not an IP address",
		"bücher.example": "punycode",
		"*.example.com":  "not an IP address",
		"1.2.3":          "not an IP address", // looks like an address, isn't a name
		"example..com":   "not an IP address",
		"http://a.com/x": "not an IP address",
	} {
		if err := one(bad); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want an error mentioning %q", bad, err, want)
		}
	}
	// The same name in another spelling is a duplicate; in another list it is not.
	dup := model.Config{AddressLists: []model.AddressEntry{{ID: "a", List: "l", Address: "example.com"}, {ID: "b", List: "l", Address: "EXAMPLE.com."}}}
	if dup.Validate() == nil {
		t.Error("duplicate name accepted")
	}
	other := model.Config{AddressLists: []model.AddressEntry{{ID: "a", List: "l", Address: "example.com"}, {ID: "b", List: "m", Address: "example.com"}}}
	if err := other.Validate(); err != nil {
		t.Errorf("same name in two lists: %v", err)
	}
}

func TestDomainEntriesFillTheList(t *testing.T) {
	e, k := newTest(t)
	var mu sync.Mutex
	answer := []string{"203.0.113.7", "2001:db8::7"}
	e.SetLookup(func(_ context.Context, name string) (dnslist.Result, error) {
		mu.Lock()
		defer mu.Unlock()
		if name != "example.com" {
			return dnslist.Result{}, errors.New(name + " does not exist (NXDOMAIN)")
		}
		var r dnslist.Result
		r.TTL = time.Hour
		for _, a := range answer {
			r.Addrs = append(r.Addrs, netip.MustParseAddr(a))
		}
		return r, nil
	})
	mustUpdate(t, e, func(c *model.Config) error {
		c.AddressLists = []model.AddressEntry{
			{ID: "a", List: "cdn", Address: "example.com"},
			{ID: "b", List: "cdn", Address: "192.0.2.0/24"},
			{ID: "c", List: "cdn", Address: "nope.example.org"},
		}
		c.Firewall.Rules = []model.FWRule{{ID: "r", Chain: "forward", Action: "drop", DstList: "cdn"}}
		return nil
	})
	has := func(list, addr string) bool {
		ds, _ := k.ListDynamic()
		for _, d := range ds {
			if d.List == list && d.Address == addr {
				return true
			}
		}
		return false
	}
	deadline := time.Now().Add(3 * time.Second)
	for !(has("cdn", "203.0.113.7") && has("cdn", "2001:db8::7")) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !has("cdn", "203.0.113.7") || !has("cdn", "2001:db8::7") {
		ds, _ := k.ListDynamic()
		t.Fatalf("resolved addresses not in the list: %+v", ds)
	}
	labels := e.DomainLabels()
	if labels["cdn|203.0.113.7"] != "example.com" {
		t.Errorf("labels: %v", labels)
	}
	var failing bool
	for _, d := range e.Domains() {
		if d.Domain == "nope.example.org" && strings.Contains(d.Error, "NXDOMAIN") {
			failing = true
		}
	}
	if !failing {
		t.Errorf("a name that doesn't resolve should say why: %+v", e.Domains())
	}

	// Taking the entry out takes its addresses out.
	mustUpdate(t, e, func(c *model.Config) error { c.AddressLists = c.AddressLists[1:2]; return nil })
	if has("cdn", "203.0.113.7") {
		t.Error("addresses of a removed name are still in the list")
	}
	if len(e.Domains()) != 0 {
		t.Errorf("still following: %+v", e.Domains())
	}
}
