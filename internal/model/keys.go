package model

import (
	"fmt"
	"strings"
)

func canonNet(s string, allowDefault bool) string {
	if s == "" {
		return ""
	}
	n, err := ParseCIDR(s, allowDefault)
	if err != nil {
		return s
	}
	return n.String()
}

func canonTable(s string) int {
	n, err := ParseTable(s)
	if err != nil {
		return -1
	}
	return n
}

// Key identifies a route the way the kernel does (table, destination, metric).
func (r Route) Key() string {
	return fmt.Sprintf("%d|%s|%d", canonTable(r.Table), canonNet(r.Dst, true), r.Metric)
}

// Sig covers every field that can change without changing the key.
func (r Route) Sig() string {
	t := r.Type
	if t == "" {
		t = "unicast"
	}
	return fmt.Sprintf("%s|%s|%s|%s", r.Key(), r.Gateway, r.Dev, t)
}

// Key is the full identity of a rule: two rules with the same key are the same rule.
func (r Rule) Key() string {
	a := r.Action
	t := 0
	if a == "" || a == "lookup" {
		a = "lookup"
		t = canonTable(r.Table)
	}
	return fmt.Sprintf("%d|%s|%s|%s|%s|%d|%s|%d", r.Priority, canonNet(r.Src, false), canonNet(r.Dst, false), r.Iif, r.Oif, r.Fwmark, a, t)
}

func (a Address) Key() string {
	n, err := ParseAddr(a.Address)
	if err != nil {
		return a.Interface + "|" + a.Address
	}
	return a.Interface + "|" + n.String()
}

// Describe renders a rule like `ip rule` would, for logs and the UI.
func (r Rule) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d:", r.Priority)
	if r.Src != "" {
		b.WriteString(" from " + r.Src)
	}
	if r.Dst != "" {
		b.WriteString(" to " + r.Dst)
	}
	if r.Iif != "" {
		b.WriteString(" iif " + r.Iif)
	}
	if r.Oif != "" {
		b.WriteString(" oif " + r.Oif)
	}
	if r.Fwmark != 0 {
		fmt.Fprintf(&b, " fwmark 0x%x", r.Fwmark)
	}
	if r.Action == "" || r.Action == "lookup" {
		b.WriteString(" lookup " + r.Table)
	} else {
		b.WriteString(" " + r.Action)
	}
	return b.String()
}
