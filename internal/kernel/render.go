package kernel

import (
	"fmt"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// TableName is the nftables table mini-net-man owns. It lives in the dual
// stack `inet` family; an IPv4-only `ip` table of the same name, which early
// versions created, is removed whenever the firewall is applied.
const TableName = "mini-net-man"

type chainDef struct {
	name, ctype, hook string
	prio              int32
	policy            func(model.FirewallPolicy) string
}

// chainDefs lists the base chains in the order they are created.
var chainDefs = []chainDef{
	{model.ChainMangle, "filter", "forward", -150, nil},
	{model.ChainMangleIn, "filter", "prerouting", -150, nil},
	{model.ChainMangleOut, "route", "output", -150, nil},
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

// chainPolicy returns the nftables policy of a chain and whether it also needs
// a final catch-all reject rule (nftables policies are only accept or drop).
func chainPolicy(c chainDef, fw model.Firewall) (policy string, finalReject bool) {
	if c.policy == nil {
		return "accept", false
	}
	switch p := policyOr(c.policy(fw.Policy)); p {
	case "reject":
		return "accept", true
	default:
		return p, false
	}
}

// RenderNFT writes the firewall as nft syntax. It is what the UI shows as the
// preview; the Linux backend builds the same ruleset natively.
func RenderNFT(fw model.Firewall) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	renderSets(&b, fw)
	for _, c := range chainDefs {
		pol, finalReject := chainPolicy(c, fw)
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype %s hook %s priority %d; policy %s;\n", c.name, c.ctype, c.hook, c.prio, pol)
		for _, r := range fw.Rules {
			if r.Disabled || r.Chain != c.name {
				continue
			}
			// Port lists become one rule per alternative, as in the kernel.
			for _, line := range renderRule(r) {
				fmt.Fprintf(&b, "\t\t%s\n", line)
			}
		}
		if finalReject {
			b.WriteString("\t\treject comment \"default policy\"\n")
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// renderSets writes the sets behind the address lists.
func renderSets(b *strings.Builder, fw model.Firewall) {
	ranges := listRanges(fw.Lists)
	for _, name := range listNames(fw) {
		for _, v6 := range []bool{false, true} {
			typ := "ipv4_addr"
			if v6 {
				typ = "ipv6_addr"
			}
			static := SetName(name, v6, false)
			fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n", static, typ)
			if rs := ranges[static]; len(rs) > 0 {
				items := make([]string, len(rs))
				for i, r := range rs {
					items[i] = r.first.String()
					if r.first != r.last {
						items[i] += "-" + r.last.String()
					}
				}
				fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(items, ", "))
			}
			b.WriteString("\t}\n")
			fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n\t\tsize %d\n\t\tflags dynamic,timeout\n\t}\n", SetName(name, v6, true), typ, DynSetSize)
		}
	}
}

func splitPorts(s string) []string {
	if s == "" {
		return []string{""}
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func renderRule(r model.FWRule) []string {
	if r.Action == model.ActionClampMSS {
		r.Proto = "tcp"
	}
	var out []string
	for _, v := range ruleVariants(r) {
		out = append(out, renderVariant(r, v)...)
	}
	return out
}

func renderVariant(r model.FWRule, v ruleVariant) []string {
	var head []string
	fam := v.fam
	// An address match already pins the family in nft syntax; otherwise say it.
	if fam != "" && r.Src == "" && r.Dst == "" && r.ToAddr == "" && len(v.src) == 0 && len(v.dst) == 0 && v.add == "" {
		head = append(head, "meta nfproto "+fam)
	}
	ipw := map[string]string{"ipv4": "ip", "ipv6": "ip6"}[fam]
	if r.InIface != "" && r.InIface != "*" {
		head = append(head, fmt.Sprintf("iifname %q", r.InIface))
	}
	if r.OutIface != "" && r.OutIface != "*" {
		head = append(head, fmt.Sprintf("oifname %q", r.OutIface))
	}
	if r.Src != "" {
		head = append(head, ipw+" saddr "+normNet(r.Src))
	}
	if r.Dst != "" {
		head = append(head, ipw+" daddr "+normNet(r.Dst))
	}
	for _, l := range v.src {
		head = append(head, ipw+" saddr "+neq(l.not)+"@"+l.name)
	}
	for _, l := range v.dst {
		head = append(head, ipw+" daddr "+neq(l.not)+"@"+l.name)
	}
	hasPorts := (r.Proto == "tcp" || r.Proto == "udp") && (r.SrcPort != "" || r.DstPort != "")
	switch r.Proto {
	case "tcp", "udp":
		if !hasPorts {
			head = append(head, "meta l4proto "+r.Proto)
		}
	case "icmp":
		head = append(head, "meta l4proto icmp")
	case "icmpv6":
		head = append(head, "meta l4proto ipv6-icmp")
	}
	var tail []string
	if r.ConnState != "" {
		tail = append(tail, "ct state "+strings.ReplaceAll(r.ConnState, " ", ""))
	}
	switch r.Action {
	case model.ActionClampMSS:
		tail = append(tail, "tcp flags & (syn | rst) == syn")
		if r.MSS == 0 {
			tail = append(tail, "tcp option maxseg size set rt mtu")
		} else {
			tail = append(tail, fmt.Sprintf("tcp option maxseg size > %d tcp option maxseg size set %d", r.MSS, r.MSS))
		}
	case model.ActionMarkConnection:
		tail = append(tail, fmt.Sprintf("ct mark set %d meta mark set %d", r.Mark, r.Mark))
	case model.ActionRestoreMark:
		tail = append(tail, "ct mark != 0 meta mark set ct mark")
	case model.ActionAddSrcToList, model.ActionAddDstToList:
		field := ipw + " saddr"
		if r.Action == model.ActionAddDstToList {
			field = ipw + " daddr"
		}
		if r.Timeout > 0 {
			field += fmt.Sprintf(" timeout %ds", r.Timeout)
		}
		tail = append(tail, fmt.Sprintf("update @%s { %s }", v.add, field))
	case "masquerade":
		tail = append(tail, "masquerade")
	case "dnat", "snat":
		t := r.ToAddr
		if r.ToPort != 0 {
			if fam == "ipv6" {
				t = fmt.Sprintf("[%s]:%d", t, r.ToPort)
			} else {
				t = fmt.Sprintf("%s:%d", t, r.ToPort)
			}
		}
		tail = append(tail, fmt.Sprintf("%s %s to %s", r.Action, ipw, t))
	default:
		tail = append(tail, r.Action)
	}
	if r.Comment != "" {
		tail = append(tail, fmt.Sprintf("comment %q", r.Comment))
	}

	var out []string
	for _, sp := range splitPorts(r.SrcPort) {
		for _, dp := range splitPorts(r.DstPort) {
			parts := append([]string{}, head...)
			if hasPorts {
				if sp != "" {
					parts = append(parts, fmt.Sprintf("%s sport %s", r.Proto, sp))
				}
				if dp != "" {
					parts = append(parts, fmt.Sprintf("%s dport %s", r.Proto, dp))
				}
			}
			out = append(out, strings.Join(append(parts, tail...), " "))
		}
	}
	return out
}

func neq(not bool) string {
	if not {
		return "!= "
	}
	return ""
}

func normNet(s string) string {
	if n, err := model.ParseCIDR(s, false); err == nil {
		if ones, bits := n.Mask.Size(); ones == bits {
			return n.IP.String()
		}
		return n.String()
	}
	return s
}
