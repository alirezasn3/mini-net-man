package kernel

import (
	"strings"
	"testing"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

func TestRenderNFT(t *testing.T) {
	out := RenderNFT(model.Firewall{
		Policy: model.FirewallPolicy{Input: "drop"},
		Rules: []model.FWRule{
			{Chain: "input", Action: "accept", Proto: "tcp", DstPort: "22,8080", ConnState: "new"},
			{Chain: "srcnat", Action: "masquerade", OutIface: "wgBridge0"},
			{Chain: "dstnat", Action: "dnat", InIface: "ens192", Proto: "tcp", DstPort: "8443", ToAddr: "10.0.0.5", ToPort: 443},
			{Chain: "forward", Action: "accept", Src: "fd00::/8", OutIface: "wgBridge0"},
			{Chain: "forward", Action: "accept", Family: "ipv4", InIface: "wgServer"},
			{Chain: "forward", Action: "drop", Src: "10.0.0.5/32", Disabled: true},
		},
	})
	for _, want := range []string{
		"policy drop;",
		"tcp dport 22 ct state new accept",
		"tcp dport 8080 ct state new accept",
		`oifname "wgBridge0" masquerade`,
		`iifname "ens192" tcp dport 8443 dnat ip to 10.0.0.5:443`,
		"table inet mini-net-man",
		`oifname "wgBridge0" ip6 saddr fd00::/8 accept`,
		`meta nfproto ipv4 iifname "wgServer" accept`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "10.0.0.5 drop") {
		t.Error("disabled rule was rendered")
	}
}

func TestRenderRejectPolicy(t *testing.T) {
	out := RenderNFT(model.Firewall{
		Policy: model.FirewallPolicy{Input: "reject", Forward: "drop", Output: "accept"},
		Rules:  []model.FWRule{{Chain: "input", Action: "accept", Proto: "tcp", DstPort: "22"}},
	})
	// nftables has no reject policy: the chain accepts by policy and ends in a reject rule.
	inInput := out[strings.Index(out, "chain input"):strings.Index(out, "chain forward")]
	if !strings.Contains(inInput, "policy accept;") || !strings.HasSuffix(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(inInput), "}")), `reject comment "default policy"`) {
		t.Errorf("input chain:\n%s", inInput)
	}
	if strings.Index(inInput, "tcp dport 22 accept") > strings.Index(inInput, "reject comment") {
		t.Errorf("the catch-all must come after the rules:\n%s", inInput)
	}
	if !strings.Contains(out, "type filter hook forward priority 0; policy drop;") {
		t.Errorf("drop policies stay real policies:\n%s", out)
	}
	if strings.Count(out, `comment "default policy"`) != 1 {
		t.Errorf("only the reject chain gets a catch-all:\n%s", out)
	}
}

func TestRenderClampMSS(t *testing.T) {
	out := RenderNFT(model.Firewall{Rules: []model.FWRule{
		{Chain: "mangle", Action: "clamp-mss", OutIface: "wgBridge0"},
		{Chain: "mangle", Action: "clamp-mss", OutIface: "ppp0", MSS: 1300, Family: "ipv4"},
	}})
	for _, want := range []string{
		"type filter hook forward priority -150; policy accept;",
		`oifname "wgBridge0" meta l4proto tcp tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu`,
		`meta nfproto ipv4 oifname "ppp0" meta l4proto tcp tcp flags & (syn | rst) == syn tcp option maxseg size > 1300 tcp option maxseg size set 1300`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
