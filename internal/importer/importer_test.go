package importer

import (
	"testing"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

func TestParseUFW(t *testing.T) {
	user := `*filter
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT
### tuple ### allow any 51820 0.0.0.0/0 any 0.0.0.0/0 in ## wireguard
### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_wgServer!out_wgBridge0
### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_wgBridge0!out_ens192
### tuple ### limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in
COMMIT`
	var p Proposal
	defaults := "DEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n"
	ParseUFW(user, defaults, "ipv4", &p)
	if p.Policy == nil || p.Policy.Input != "drop" || p.Policy.Output != "accept" {
		t.Fatalf("policy: %+v", p.Policy)
	}
	var fwd, in int
	for _, r := range p.Firewall {
		if r.Comment != "" && r.Source == "ufw" && r.Chain == model.ChainForward && r.InIface == "wgServer" && r.OutIface == "wgBridge0" {
			t.Errorf("unexpected comment on route rule")
		}
		if r.Chain == model.ChainForward && r.InIface == "wgServer" && r.OutIface == "wgBridge0" && r.Action == "accept" {
			fwd++
		}
		if r.Chain == model.ChainInput && r.DstPort == "22" && r.Proto == "tcp" {
			in++
		}
	}
	if fwd != 1 || in != 1 {
		t.Errorf("fwd=%d in=%d rules=%+v", fwd, in, p.Firewall)
	}
	udp := 0
	for _, r := range p.Firewall {
		if r.DstPort == "51820" {
			udp++
		}
	}
	if udp != 2 { // portful rule without protocol -> tcp + udp
		t.Errorf("want tcp+udp for 51820, got %d", udp)
	}
}

func TestParseIptablesSave(t *testing.T) {
	in := `*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o wgBridge0 -j MASQUERADE
-A PREROUTING -i ens192 -p tcp -m tcp --dport 8443 -j DNAT --to-destination 10.0.0.5:443
COMMIT
*filter
:INPUT DROP [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -j ufw-before-input
-A FORWARD -i wgServer -o wgBridge0 -j ACCEPT
-A INPUT ! -s 10.0.0.0/8 -j DROP
COMMIT`
	var p Proposal
	ParseIptablesSave(in, "iptables (live)", "ipv4", &p)
	if len(p.Firewall) != 4 {
		t.Fatalf("want 4 rules, got %d: %+v", len(p.Firewall), p.Firewall)
	}
	m := p.Firewall[0]
	if m.Chain != "srcnat" || m.Action != "masquerade" || m.OutIface != "wgBridge0" {
		t.Errorf("masquerade: %+v", m)
	}
	d := p.Firewall[1]
	if d.Action != "dnat" || d.ToAddr != "10.0.0.5" || d.ToPort != 443 || d.DstPort != "8443" {
		t.Errorf("dnat: %+v", d)
	}
	if p.Firewall[2].ConnState != "related,established" {
		t.Errorf("state: %+v", p.Firewall[2])
	}
	if len(p.Notes) < 2 {
		t.Errorf("expected notes about skipped rules and DROP policy: %v", p.Notes)
	}
}

func TestImportIPv6(t *testing.T) {
	var p Proposal
	ParseUFW(`### tuple ### allow tcp 22 ::/0 any ::/0 in
### tuple ### route:allow any any ::/0 any ::/0 in_wgServer!out_wgBridge0
### tuple ### allow tcp 443 fd00::/8 any ::/0 in`, "", "ipv6", &p)
	if len(p.Firewall) != 3 {
		t.Fatalf("want 3 rules, got %+v", p.Firewall)
	}
	for _, r := range p.Firewall {
		if r.Family != "ipv6" {
			t.Errorf("rule not pinned to ipv6: %+v", r)
		}
	}
	if p.Firewall[2].Dst != "fd00::/8" {
		t.Errorf("v6 dst lost: %+v", p.Firewall[2])
	}

	var q Proposal
	ParseIptablesSave(`*filter
-A INPUT -p ipv6-icmp -j ACCEPT
-A FORWARD -s fd00:10::/64 -o wgBridge0 -j ACCEPT
COMMIT`, "ip6tables (live)", "ipv6", &q)
	if len(q.Firewall) != 2 || q.Firewall[0].Proto != "icmpv6" || q.Firewall[1].Src != "fd00:10::/64" {
		t.Errorf("ip6tables parse: %+v", q.Firewall)
	}
}
