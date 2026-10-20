package kernel

import (
	"fmt"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// TableName is the nftables table mini-net-man owns.
const TableName = "mini-net-man"

type chainDef struct {
	name, ctype, hook string
	prio              int32
	policy            func(model.FirewallPolicy) string
}

// Chains lists the base chains in the order they are created.
var chainDefs = []chainDef{
	{model.ChainPrerouting, "nat", "prerouting", -100, nil},
	{model.ChainInput, "filter", "input", 0, func(p model.FirewallPolicy) string { return p.Input }},
	{model.ChainForward, "filter", "forward", 0, func(p model.FirewallPolicy) string { return p.Forward }},
	{model.ChainOutput, "filter", "output", 0, func(p model.FirewallPolicy) string { return p.Output }},
	{model.ChainPostrouting, "nat", "postrouting", 100, nil},
}

func policyOr(s string) string {
	if s == "" {
		return "accept"
	}
	return s
}

// RenderNFT writes the firewall as nft syntax. It is what the UI shows as the
// preview; the Linux backend builds the same ruleset natively.
func RenderNFT(fw model.Firewall) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table ip %s {\n", TableName)
	for _, c := range chainDefs {
		pol := "accept"
		if c.policy != nil {
			pol = policyOr(c.policy(fw.Policy))
		}
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype %s hook %s priority %d; policy %s;\n", c.name, c.ctype, c.hook, c.prio, pol)
		for _, r := range fw.Rules {
			if r.Disabled || r.Chain != c.name {
				continue
			}
			fmt.Fprintf(&b, "\t\t%s\n", renderRule(r))
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func renderRule(r model.FWRule) string {
	var p []string
	if r.InIface != "" {
		p = append(p, fmt.Sprintf("iifname %q", r.InIface))
	}
	if r.OutIface != "" {
		p = append(p, fmt.Sprintf("oifname %q", r.OutIface))
	}
	if r.Src != "" {
		p = append(p, "ip saddr "+normNet(r.Src))
	}
	if r.Dst != "" {
		p = append(p, "ip daddr "+normNet(r.Dst))
	}
	switch r.Proto {
	case "tcp", "udp":
		if r.SrcPort != "" {
			p = append(p, fmt.Sprintf("%s sport %s", r.Proto, portSet(r.SrcPort)))
		}
		if r.DstPort != "" {
			p = append(p, fmt.Sprintf("%s dport %s", r.Proto, portSet(r.DstPort)))
		}
		if r.SrcPort == "" && r.DstPort == "" {
			p = append(p, "meta l4proto "+r.Proto)
		}
	case "icmp":
		p = append(p, "meta l4proto icmp")
	}
	if r.ConnState != "" {
		p = append(p, "ct state "+strings.ReplaceAll(strings.ReplaceAll(r.ConnState, " ", ""), ",", ","))
	}
	switch r.Action {
	case "masquerade":
		p = append(p, "masquerade")
	case "dnat", "snat":
		t := r.ToAddr
		if r.ToPort != 0 {
			t = fmt.Sprintf("%s:%d", t, r.ToPort)
		}
		p = append(p, r.Action+" to "+t)
	default:
		p = append(p, r.Action)
	}
	if r.Comment != "" {
		p = append(p, fmt.Sprintf("comment %q", r.Comment))
	}
	return strings.Join(p, " ")
}

func portSet(s string) string {
	if strings.Contains(s, ",") {
		return "{ " + strings.ReplaceAll(s, ",", ", ") + " }"
	}
	return s
}

func normNet(s string) string {
	if n, err := model.ParseCIDR(s, false); err == nil {
		if ones, _ := n.Mask.Size(); ones == 32 {
			return n.IP.String()
		}
		return n.String()
	}
	return s
}
