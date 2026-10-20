// Package importer reads existing networking state (ip rule/route, iptables,
// ufw, iptables-persistent) and turns it into config items to adopt.
package importer

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/engine"
	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
)

// Proposal is everything found. Item IDs are fresh, and apply picks by ID.
type Proposal struct {
	Routes   []model.Route  `json:"routes"`
	Rules    []model.Rule   `json:"rules"`
	Firewall []model.FWRule `json:"firewall"`
	// Policy is set when a source runs a default-drop policy.
	Policy *model.FirewallPolicy `json:"policy,omitempty"`
	Notes  []string              `json:"notes"`
}

const (
	UFWUserRules    = "/etc/ufw/user.rules"
	UFWUserRules6   = "/etc/ufw/user6.rules"
	UFWDefaults     = "/etc/default/ufw"
	PersistentRule  = "/etc/iptables/rules.v4"
	PersistentRule6 = "/etc/iptables/rules.v6"
)

// Scan collects proposals from every source that exists on this machine.
func Scan(k kernel.Kernel) Proposal {
	var p Proposal
	scanIP(k, &p)
	def, _ := os.ReadFile(UFWDefaults)
	for _, f := range []struct{ path, family string }{{UFWUserRules, "ipv4"}, {UFWUserRules6, "ipv6"}} {
		if b, err := os.ReadFile(f.path); err == nil {
			ParseUFW(string(b), string(def), f.family, &p)
		}
	}
	for _, f := range []struct{ path, family string }{{PersistentRule, "ipv4"}, {PersistentRule6, "ipv6"}} {
		if b, err := os.ReadFile(f.path); err == nil {
			ParseIptablesSave(string(b), "iptables-persistent", f.family, &p)
		}
	}
	for _, f := range []struct{ tool, family, label string }{
		{"iptables-save", "ipv4", "iptables (live)"}, {"ip6tables-save", "ipv6", "ip6tables (live)"},
	} {
		if path, err := exec.LookPath(f.tool); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if out, err := exec.CommandContext(ctx, path).Output(); err == nil {
				ParseIptablesSave(string(out), f.label, f.family, &p)
			}
			cancel()
		}
	}
	return p
}

// ---- ip rule / ip route --------------------------------------------------

func scanIP(k kernel.Kernel, p *Proposal) {
	rules, err := k.ListRules()
	if err != nil {
		p.Notes = append(p.Notes, "ip rule: "+err.Error())
	}
	for _, r := range rules {
		if r.Owned || (r.Priority == 0 && r.Table == "local") || (r.Priority == 32766 && r.Table == "main") || (r.Priority == 32767 && r.Table == "default") {
			continue
		}
		r.Rule.ID, r.Rule.Source = engine.NewID(), "ip rule"
		p.Rules = append(p.Rules, r.Rule)
	}
	routes, err := k.ListRoutes()
	if err != nil {
		p.Notes = append(p.Notes, "ip route: "+err.Error())
	}
	for _, r := range routes {
		// Main-table routes belong to the OS network config; only extra
		// tables (policy routing) are worth adopting.
		if r.Owned || r.Table == "main" || r.Table == "default" || r.Proto == "kernel" {
			continue
		}
		r.Route.ID, r.Route.Source = engine.NewID(), "ip route"
		p.Routes = append(p.Routes, r.Route)
	}
}

// ---- iptables-save ---------------------------------------------------------

var (
	policyRe = regexp.MustCompile(`^:(INPUT|FORWARD|OUTPUT)\s+(ACCEPT|DROP)`)
	chainMap = map[string]map[string]string{
		"filter": {"INPUT": model.ChainInput, "FORWARD": model.ChainForward, "OUTPUT": model.ChainOutput},
		"nat":    {"PREROUTING": model.ChainPrerouting, "POSTROUTING": model.ChainPostrouting},
	}
)

// ParseIptablesSave understands the common subset of iptables-save: plain
// matches on interface, address, protocol, ports and conntrack state with
// ACCEPT/DROP/REJECT/MASQUERADE/DNAT/SNAT targets. Anything else (including
// jumps into user chains such as ufw-*) is reported in Notes, not guessed at.
func ParseIptablesSave(text, source, family string, p *Proposal) {
	table := ""
	skipped := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "*"):
			table = line[1:]
		case policyRe.MatchString(line):
			m := policyRe.FindStringSubmatch(line)
			if table == "filter" && m[2] == "DROP" && !strings.HasPrefix(source, "ufw") {
				p.Notes = append(p.Notes, fmt.Sprintf("%s: default policy of %s is DROP; not imported automatically", source, m[1]))
			}
		case strings.HasPrefix(line, "-A "):
			chains, ok := chainMap[table]
			if !ok {
				skipped++
				continue
			}
			r, ok := parseIptRule(line, chains)
			if !ok {
				skipped++
				continue
			}
			// iptables rules only ever saw one family; keep them that way.
			r.ID, r.Source, r.Family = engine.NewID(), source, family
			if r.Validate() != nil {
				skipped++
				continue
			}
			p.Firewall = append(p.Firewall, r)
		}
	}
	if skipped > 0 {
		p.Notes = append(p.Notes, fmt.Sprintf("%s: %d rule(s) use options that can't be imported (user chains, modules, ...) and were skipped", source, skipped))
	}
}

func parseIptRule(line string, chains map[string]string) (model.FWRule, bool) {
	f := strings.Fields(line)
	var r model.FWRule
	chain, ok := chains[f[1]]
	if !ok {
		return r, false
	}
	r.Chain = chain
	neg := false
	for i := 2; i < len(f); i++ {
		arg := func() string {
			if i+1 < len(f) {
				i++
				return strings.Trim(f[i], `"`)
			}
			return ""
		}
		switch f[i] {
		case "!":
			neg = true
			continue
		case "-i":
			r.InIface = arg()
		case "-o":
			r.OutIface = arg()
		case "-s":
			r.Src = zeroToEmpty(arg())
		case "-d":
			r.Dst = zeroToEmpty(arg())
		case "-p":
			r.Proto = arg()
		case "-m":
			arg() // module name; its options are matched below
		case "--dport", "--destination-port":
			r.DstPort = strings.ReplaceAll(arg(), ":", "-")
		case "--sport", "--source-port":
			r.SrcPort = strings.ReplaceAll(arg(), ":", "-")
		case "--state", "--ctstate":
			r.ConnState = strings.ToLower(arg())
		case "--comment":
			r.Comment = arg()
		case "-j":
			switch t := arg(); t {
			case "ACCEPT", "DROP", "REJECT", "RETURN", "MASQUERADE":
				r.Action = strings.ToLower(t)
			case "DNAT", "SNAT":
				r.Action = strings.ToLower(t)
			default:
				return r, false // jump into a user chain or an unknown target
			}
		case "--to-destination", "--to-source":
			addr, port, _ := strings.Cut(arg(), ":")
			r.ToAddr = addr
			r.ToPort, _ = strconv.Atoi(port)
		case "--to-ports":
			arg()
		default:
			return r, false
		}
		if neg {
			return r, false // negated matches have no equivalent here
		}
	}
	if r.Action == "" {
		return r, false
	}
	switch r.Proto {
	case "all":
		r.Proto = ""
	case "ipv6-icmp", "icmp6":
		r.Proto = "icmpv6"
	}
	return r, r.Validate() == nil
}

func zeroToEmpty(s string) string {
	if s == "0.0.0.0/0" || s == "::/0" {
		return ""
	}
	return s
}

// ---- ufw -------------------------------------------------------------------

// ParseUFW reads the machine-readable "### tuple ###" comments ufw writes to
// user.rules (family ipv4) or user6.rules (ipv6). defaults is the content of
// /etc/default/ufw.
//
//	### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
//	### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_wgServer!out_wgBridge0
func ParseUFW(text, defaults, family string, p *Proposal) {
	skipped := 0
	var out []model.FWRule
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "### tuple ### ") {
			continue
		}
		line, comment, _ := strings.Cut(strings.TrimPrefix(line, "### tuple ### "), " ## ")
		f := strings.Fields(line)
		if len(f) < 7 {
			skipped++
			continue
		}
		act, proto, dport, dst, sport, src, dir := f[0], f[1], f[2], f[3], f[4], f[5], f[6]
		r := model.FWRule{ID: engine.NewID(), Source: "ufw", Family: family, Proto: proto, DstPort: portSpec(dport), SrcPort: portSpec(sport),
			Dst: zeroToEmpty(dst), Src: zeroToEmpty(src), Comment: comment}
		if proto == "any" {
			r.Proto = ""
		}
		route := strings.HasPrefix(act, "route:")
		act = strings.TrimPrefix(act, "route:")
		switch act {
		case "allow":
			r.Action = "accept"
		case "deny":
			r.Action = "drop"
		case "reject":
			r.Action = "reject"
		default: // limit, logging variants
			skipped++
			continue
		}
		in, outIf, hasIn, hasOut := splitDir(dir)
		switch {
		case route:
			r.Chain, r.InIface, r.OutIface = model.ChainForward, in, outIf
		case hasOut && !hasIn:
			r.Chain, r.OutIface = model.ChainOutput, outIf
		default:
			r.Chain, r.InIface = model.ChainInput, in
		}
		// ufw lets a rule with a port but no protocol mean tcp+udp.
		if (r.DstPort != "" || r.SrcPort != "") && r.Proto == "" {
			t, u := r, r
			t.Proto, u.Proto, u.ID = "tcp", "udp", engine.NewID()
			if r.Validate() != nil {
				out = append(out, t, u)
				continue
			}
		}
		if r.Validate() != nil {
			skipped++
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 && skipped == 0 {
		return
	}

	pol := ufwPolicies(defaults)
	// The policy and ufw's implicit rules are shared by both families, so
	// they're added once (by whichever file is scanned first).
	if p.Policy == nil && (pol.Input == "drop" || pol.Forward == "drop" || pol.Output == "drop") {
		p.Policy = &pol
		// ufw's before.rules provides these implicitly under a drop policy.
		boiler := []model.FWRule{
			{Chain: model.ChainInput, Action: "accept", InIface: "lo", Comment: "ufw: loopback"},
			{Chain: model.ChainInput, Action: "accept", ConnState: "established,related", Comment: "ufw: replies"},
			{Chain: model.ChainOutput, Action: "accept", OutIface: "lo", Comment: "ufw: loopback"},
			{Chain: model.ChainForward, Action: "accept", ConnState: "established,related", Comment: "ufw: replies"},
		}
		for i := range boiler {
			boiler[i].ID, boiler[i].Source = engine.NewID(), "ufw"
		}
		out = append(boiler, out...)
		p.Notes = append(p.Notes, "ufw uses a default-drop policy; the proposal includes ufw's implicit loopback/established rules and the same policy.")
	}
	p.Firewall = append(p.Firewall, out...)
	if skipped > 0 {
		p.Notes = append(p.Notes, fmt.Sprintf("ufw: %d rule(s) (limit, IPv6 or unsupported forms) were skipped", skipped))
	}
}

func portSpec(s string) string {
	if s == "any" {
		return ""
	}
	return strings.ReplaceAll(s, ":", "-")
}

// splitDir parses "in", "out", "in_eth0", "in_wgServer!out_wgBridge0".
func splitDir(d string) (in, out string, hasIn, hasOut bool) {
	for _, part := range strings.Split(d, "!") {
		switch {
		case part == "in":
			hasIn = true
		case part == "out":
			hasOut = true
		case strings.HasPrefix(part, "in_"):
			in, hasIn = part[3:], true
		case strings.HasPrefix(part, "out_"):
			out, hasOut = part[4:], true
		}
	}
	return
}

var ufwPolRe = regexp.MustCompile(`(?m)^DEFAULT_(INPUT|OUTPUT|FORWARD)_POLICY="?(\w+)"?`)

func ufwPolicies(defaults string) model.FirewallPolicy {
	p := model.FirewallPolicy{Input: "accept", Forward: "accept", Output: "accept"}
	for _, m := range ufwPolRe.FindAllStringSubmatch(defaults, -1) {
		v := "accept"
		if m[2] == "DROP" || m[2] == "REJECT" {
			v = "drop"
		}
		switch m[1] {
		case "INPUT":
			p.Input = v
		case "FORWARD":
			p.Forward = v
		case "OUTPUT":
			p.Output = v
		}
	}
	return p
}
