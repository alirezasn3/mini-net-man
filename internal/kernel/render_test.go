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
			{Chain: "forward", Action: "drop", Src: "10.0.0.5/32", Disabled: true},
		},
	})
	for _, want := range []string{
		"policy drop;",
		"tcp dport { 22, 8080 } ct state new accept",
		`oifname "wgBridge0" masquerade`,
		`iifname "ens192" tcp dport 8443 dnat to 10.0.0.5:443`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "10.0.0.5 drop") {
		t.Error("disabled rule was rendered")
	}
}
