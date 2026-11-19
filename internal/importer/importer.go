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
	// Skipped lists what was found but cannot be imported, each with the
	// reason, so nothing is silently left behind.
	Skipped []Skipped `json:"skipped"`
}

// Skipped is one rule that has no equivalent in mini-net-man.
type Skipped struct {
	Source string `json:"source"` // where it was found: ufw, iptables (live), ...
	Text   string `json:"text"`   // the rule as it was written there
	Reason string `json:"reason"`
}

func (p *Proposal) skip(source, text, reason string) {
	p.Skipped = append(p.Skipped, Skipped{Source: source, Text: text, Reason: reason})
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
	ufwInternal := 0
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
			f := tokens(line)
			if len(f) > 1 && (strings.HasPrefix(f[1], "ufw-") || strings.HasPrefix(f[1], "ufw6-")) {
				ufwInternal++ // ufw's own plumbing; its rules come from user.rules
				continue
			}
			chains, ok := chainMap[table]
			if !ok {
				p.skip(source, line, fmt.Sprintf("the %s table isn't imported (only filter and nat)", table))
				continue
			}
			r, reason := parseIptRule(f, chains, table)
			if reason != "" {
				p.skip(source, line, reason)
				continue
			}
			// iptables rules only ever saw one family; keep them that way.
			r.ID, r.Source, r.Family = engine.NewID(), source, family
			if err := r.Validate(); err != nil {
				p.skip(source, line, "not valid once converted: "+err.Error())
				continue
			}
			p.Firewall = append(p.Firewall, r)
		}
	}
	if ufwInternal > 0 {
		p.Notes = append(p.Notes, fmt.Sprintf("%s: %d rule(s) in ufw's own chains were not listed; ufw's rules are imported from its rule files instead", source, ufwInternal))
	}
}

// tokens splits a rule into words, keeping "quoted text" together (iptables
// writes comments that way) and dropping the quotes.
func tokens(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote, have := false, false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote, have = !inQuote, true
		case (r == ' ' || r == '\t') && !inQuote:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

// Modules whose options parseIptRule understands.
var knownModules = map[string]bool{"tcp": true, "udp": true, "state": true, "conntrack": true, "comment": true, "multiport": true, "icmp": true, "icmp6": true}

// parseIptRule converts one iptables rule. When it can't, the returned reason
// says why in plain words.
func parseIptRule(f []string, chains map[string]string, table string) (model.FWRule, string) {
	var r model.FWRule
	if len(f) < 2 {
		return r, "not a rule"
	}
	chain, ok := chains[f[1]]
	if !ok {
		if _, builtin := map[string]bool{"INPUT": true, "FORWARD": true, "OUTPUT": true, "PREROUTING": true, "POSTROUTING": true}[f[1]]; builtin {
			return r, fmt.Sprintf("the %s chain of the %s table isn't imported", f[1], table)
		}
		return r, fmt.Sprintf("it is in the user-defined chain %s", f[1])
	}
	r.Chain = chain
	neg, module := false, ""
	for i := 2; i < len(f); i++ {
		opt := f[i]
		arg := func() string {
			if i+1 < len(f) {
				i++
				return f[i]
			}
			return ""
		}
		switch opt {
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
			module = arg()
			if !knownModules[module] {
				return r, fmt.Sprintf("it uses the %q match module, which has no equivalent", module)
			}
		case "--dport", "--destination-port", "--dports":
			r.DstPort = strings.ReplaceAll(arg(), ":", "-")
		case "--sport", "--source-port", "--sports":
			r.SrcPort = strings.ReplaceAll(arg(), ":", "-")
		case "--state", "--ctstate":
			r.ConnState = strings.ToLower(arg())
		case "--comment":
			r.Comment = arg()
		case "-j", "-g":
			switch t := arg(); t {
			case "ACCEPT", "DROP", "REJECT", "RETURN", "MASQUERADE", "DNAT", "SNAT":
				r.Action = strings.ToLower(t)
			case "LOG", "ULOG", "NFLOG":
				return r, "logging (-j " + t + ") has no equivalent"
			case "REDIRECT", "TPROXY", "TCPMSS", "MARK", "CONNMARK", "TOS", "DSCP", "CT", "NOTRACK", "SET", "NFQUEUE":
				return r, "the " + t + " target has no equivalent"
			default:
				return r, "it jumps to another chain (" + t + ")"
			}
		case "--to-destination", "--to-source":
			addr, port, _ := strings.Cut(arg(), ":")
			r.ToAddr = addr
			r.ToPort, _ = strconv.Atoi(port)
		case "--to-ports":
			arg()
		default:
			if module != "" && !knownModules[module] {
				return r, fmt.Sprintf("it uses the %q module", module)
			}
			if strings.HasPrefix(opt, "-") {
				return r, fmt.Sprintf("the %s option has no equivalent", opt)
			}
			return r, fmt.Sprintf("unexpected %q", opt)
		}
		if neg {
			return r, "it negates a match (!), which has no equivalent"
		}
	}
	if r.Action == "" {
		return r, "it has no target (-j), so it only counts packets"
	}
	switch r.Proto {
	case "all":
		r.Proto = ""
	case "ipv6-icmp", "icmp6":
		r.Proto = "icmpv6"
	}
	if err := r.Validate(); err != nil {
		return r, "not valid once converted: " + err.Error()
	}
	return r, ""
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
	skip := func(text, reason string) {
		skipped++
		p.skip("ufw", text, reason)
	}
	var out []model.FWRule
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "### tuple ### ") {
			continue
		}
		orig := line
		line, comment, _ := strings.Cut(strings.TrimPrefix(line, "### tuple ### "), " ## ")
		f := strings.Fields(line)
		if len(f) < 7 {
			skip(orig, "unrecognised ufw rule format")
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
		default:
			if act == "limit" {
				skip(orig, "ufw's rate limiting (limit) has no equivalent; add a plain accept rule instead")
			} else {
				skip(orig, fmt.Sprintf("the ufw action %q has no equivalent", act))
			}
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
		if err := r.Validate(); err != nil {
			skip(orig, "not valid once converted: "+err.Error())
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
		switch m[2] {
		case "DROP":
			v = "drop"
		case "REJECT":
			v = "reject"
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
