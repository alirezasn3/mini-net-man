package kernel

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

func entries(list string, addrs ...string) []model.AddressEntry {
	var out []model.AddressEntry
	for _, a := range addrs {
		out = append(out, model.AddressEntry{ID: list + a, List: list, Address: a})
	}
	return out
}

func TestListRangesMerge(t *testing.T) {
	got := listRanges(entries("bl",
		"10.0.0.0/24", "10.0.0.128/25", // inside the first
		"10.0.1.0/24",                                          // touches it: one range
		"10.0.3.5", "10.0.3.9-10.0.3.20", "10.0.3.6-10.0.3.10", // overlap each other
		"2001:db8::/32", "2001:db8:1::5",
		"255.255.255.0/24",
	))
	want := map[string]string{
		"bl.s4": "10.0.0.0-10.0.1.255 10.0.3.5-10.0.3.20 255.255.255.0-255.255.255.255",
		"bl.s6": "2001:db8::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
	}
	for set, w := range want {
		var parts []string
		for _, r := range got[set] {
			p := r.first.String()
			if r.first != r.last {
				p += "-" + r.last.String()
			}
			parts = append(parts, p)
		}
		if g := strings.Join(parts, " "); g != w {
			t.Errorf("%s = %s\nwant %s", set, g, w)
		}
	}
}

func TestMergeRangesTouchingAtTheTop(t *testing.T) {
	a := netip.MustParseAddr("255.255.255.255")
	rs := mergeRanges([]rng{{a, a}, {a, a}})
	if len(rs) != 1 {
		t.Errorf("merged %v", rs)
	}
}

func TestRenderAddressLists(t *testing.T) {
	fw := model.Firewall{
		Lists: append(entries("bad", "203.0.113.0/24", "198.51.100.5-198.51.100.9", "2001:db8::/32"), entries("ok", "192.0.2.1")...),
		Rules: []model.FWRule{
			{ID: "1", Chain: "input", Action: "drop", SrcList: "bad"},
			{ID: "2", Chain: "input", Action: "drop", SrcList: "!ok", Family: "ipv4", Proto: "tcp", DstPort: "22"},
			{ID: "3", Chain: "input", Action: model.ActionAddSrcToList, List: "seen", Timeout: 600, Proto: "tcp", DstPort: "22", ConnState: "new"},
			{ID: "4", Chain: "forward", Action: "accept", DstList: "ok", Family: "ipv6"},
		},
	}
	out := RenderNFT(fw)
	for _, want := range []string{
		"set bad.s4 {", "elements = { 198.51.100.5-198.51.100.9, 203.0.113.0-203.0.113.255 }",
		"set bad.s6 {", "elements = { 2001:db8::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff }",
		"set bad.d4 {", "flags dynamic,timeout", "set seen.d6 {",
		// positive match: either the written entries or the added ones, per family
		"ip saddr @bad.s4 drop", "ip saddr @bad.d4 drop", "ip6 saddr @bad.s6 drop", "ip6 saddr @bad.d6 drop",
		// negative: not in either, one rule
		"ip saddr != @ok.s4 ip saddr != @ok.d4 tcp dport 22 drop",
		"update @seen.d4 { ip saddr timeout 600s }", "update @seen.d6 { ip6 saddr timeout 600s }",
		"ip6 daddr @ok.s6 accept", "ip6 daddr @ok.d6 accept",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ip6 saddr != @ok") || strings.Contains(out, "ip daddr @ok") {
		t.Errorf("a family-pinned rule leaked into the other family:\n%s", out)
	}
	// Only the rules that were asked for, not four of everything.
	if n := strings.Count(out, "drop"); n != 5 {
		t.Errorf("%d drop rules, want 5 (4 for the first rule, 1 for the second):\n%s", n, out)
	}
}

func TestRenderNoListsNoSets(t *testing.T) {
	out := RenderNFT(model.Firewall{Rules: []model.FWRule{{ID: "1", Chain: "input", Action: "accept"}}})
	if strings.Contains(out, "set ") {
		t.Errorf("sets without lists:\n%s", out)
	}
}
