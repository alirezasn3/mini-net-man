package importer

import (
	"strings"
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
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "DROP") {
		t.Errorf("expected the DROP policy note only: %v", p.Notes)
	}
	if len(p.Skipped) != 2 {
		t.Fatalf("want 2 skipped rules, got %+v", p.Skipped)
	}
	if !strings.Contains(p.Skipped[0].Reason, "jumps to another chain (ufw-before-input)") || p.Skipped[0].Text != "-A INPUT -j ufw-before-input" || p.Skipped[0].Source != "iptables (live)" {
		t.Errorf("skipped[0] = %+v", p.Skipped[0])
	}
	if !strings.Contains(p.Skipped[1].Reason, "negates a match") {
		t.Errorf("skipped[1] = %+v", p.Skipped[1])
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

func TestSkippedReasons(t *testing.T) {
	in := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -m multiport --dports 80,443 -m comment --comment "web for everyone" -j ACCEPT
-A INPUT -m limit --limit 5/min -j ACCEPT
-A INPUT -m recent --name ssh --update -j DROP
-A INPUT -p tcp --dport 22 -j LOG --log-prefix x
-A INPUT -m set --match-set blocked src -j DROP
-A INPUT -p tcp
-A DOCKER-USER -j RETURN
-A ufw-user-input -p tcp --dport 22 -j ACCEPT
-A ufw6-before-input -i lo -j ACCEPT
COMMIT
*mangle
-A PREROUTING -p tcp -j MARK --set-mark 1
COMMIT
*nat
-A OUTPUT -d 1.2.3.4 -j DNAT --to-destination 5.6.7.8
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT`
	var p Proposal
	ParseIptablesSave(in, "iptables (live)", "ipv4", &p)

	// multiport and a comment with spaces are understood now.
	if len(p.Firewall) != 2 {
		t.Fatalf("want the multiport rule and the masquerade imported, got %+v", p.Firewall)
	}
	w := p.Firewall[0]
	if w.DstPort != "80,443" || w.Comment != "web for everyone" || w.Proto != "tcp" || w.Action != "accept" {
		t.Errorf("multiport rule: %+v", w)
	}

	want := map[string]string{
		"-A INPUT -m limit --limit 5/min -j ACCEPT":        `"limit" match module`,
		"-A INPUT -m recent --name ssh --update -j DROP":   `"recent" match module`,
		"-A INPUT -p tcp --dport 22 -j LOG --log-prefix x": "logging (-j LOG)",
		"-A INPUT -m set --match-set blocked src -j DROP":  `"set" match module`,
		"-A INPUT -p tcp":                                       "no target",
		"-A DOCKER-USER -j RETURN":                              "user-defined chain DOCKER-USER",
		"-A PREROUTING -p tcp -j MARK --set-mark 1":             "mangle table",
		"-A OUTPUT -d 1.2.3.4 -j DNAT --to-destination 5.6.7.8": "OUTPUT chain of the nat table",
	}
	got := map[string]string{}
	for _, s := range p.Skipped {
		got[s.Text] = s.Reason
	}
	for text, frag := range want {
		if r, ok := got[text]; !ok || !strings.Contains(r, frag) {
			t.Errorf("%q: reason %q, want it to mention %q", text, r, frag)
		}
	}
	if len(p.Skipped) != len(want) {
		t.Errorf("want %d skipped, got %d: %+v", len(want), len(p.Skipped), p.Skipped)
	}
	// ufw's internal chains are summarised, not listed rule by rule.
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "2 rule(s) in ufw's own chains") {
		t.Errorf("notes: %v", p.Notes)
	}
}

func TestUFWSkippedAreListed(t *testing.T) {
	var p Proposal
	ParseUFW(`### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow_log tcp 443 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### broken`, "", "ipv4", &p)
	if len(p.Firewall) != 1 || p.Firewall[0].DstPort != "80" {
		t.Errorf("imported: %+v", p.Firewall)
	}
	byText := map[string]Skipped{}
	for _, s := range p.Skipped {
		byText[s.Text] = s
	}
	if s := byText["### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"]; s.Source != "ufw" || !strings.Contains(s.Reason, "rate limiting") {
		t.Errorf("limit: %+v", s)
	}
	if s := byText["### tuple ### allow_log tcp 443 0.0.0.0/0 any 0.0.0.0/0 in"]; !strings.Contains(s.Reason, "allow_log") {
		t.Errorf("allow_log: %+v", s)
	}
	if s := byText["### tuple ### broken"]; !strings.Contains(s.Reason, "unrecognised") {
		t.Errorf("broken: %+v", s)
	}
	if len(p.Skipped) != 3 {
		t.Errorf("want 3 skipped, got %+v", p.Skipped)
	}
}

func TestUFWRejectPolicy(t *testing.T) {
	var p Proposal
	ParseUFW("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", "DEFAULT_INPUT_POLICY=\"REJECT\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n", "ipv4", &p)
	if p.Policy == nil || p.Policy.Input != "reject" || p.Policy.Forward != "drop" || p.Policy.Output != "accept" {
		t.Errorf("policy: %+v", p.Policy)
	}
}
