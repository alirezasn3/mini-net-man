package engine

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// NewID returns a short random id for a config item.
func NewID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Desired is everything the kernel should look like: the enabled items from
// the config, plus the helper rules health checks generate.
type Desired struct {
	Bridges    []model.Bridge
	Interfaces []model.LinkSetting
	Addresses  []model.Address
	Routes     []model.Route
	Rules      []model.Rule
	Firewall   model.Firewall
}

// Expand turns the configuration into what the kernel should look like: the
// enabled manual items plus the helper rules health checks need.
//
// down reports whether a health check is failing (nil means none are); rules
// that depend on a failing check are left out, which removes them from the
// kernel until the check recovers.
func Expand(cfg model.Config, down func(checkID string) bool) Desired {
	var d Desired
	for _, b := range cfg.Bridges {
		if !b.Disabled {
			d.Bridges = append(d.Bridges, b)
		}
	}
	for _, l := range cfg.Interfaces {
		if !l.Disabled {
			d.Interfaces = append(d.Interfaces, l)
		}
	}
	for _, a := range cfg.Addresses {
		if !a.Disabled {
			d.Addresses = append(d.Addresses, a)
		}
	}
	for _, r := range cfg.Routes {
		if !r.Disabled {
			d.Routes = append(d.Routes, r)
		}
	}
	for _, r := range cfg.Rules {
		if r.Disabled || (r.Check != "" && down != nil && down(r.Check)) {
			continue
		}
		d.Rules = append(d.Rules, r)
	}
	d.Rules = append(d.Rules, checkRoutes(cfg.Checks)...)
	d.Firewall.Policy = cfg.Firewall.Policy
	for _, e := range cfg.AddressLists {
		if !e.Disabled {
			d.Firewall.Lists = append(d.Firewall.Lists, e)
		}
	}
	for _, r := range cfg.Firewall.Rules {
		if !r.Disabled {
			d.Firewall.Rules = append(d.Firewall.Rules, r)
		}
	}
	return d
}

// checkHelperPriority puts the helper rules right after the system's own
// "local" rule, so nothing else gets a say first.
const checkHelperPriority = 1

// checkRoutes lets a health check use the route of the exit it watches. A ping
// bound to an interface only considers routes through that interface; with no
// route found Linux assumes the target is directly on the link, which is right
// for a tunnel but wrong for an exit reached through a gateway whose route
// lives in a custom table. A check that names a table gets the rule
// `oif <interface> lookup <table>`. It matches only packets sent from a socket
// bound to that interface, which is to say the check's own pings, and affects
// nothing else.
func checkRoutes(checks []model.Check) []model.Rule {
	var out []model.Rule
	seen := map[string]bool{}
	for _, c := range checks {
		if c.Table == "" || c.Disabled {
			continue
		}
		fam := "ipv4"
		if c.V6() {
			fam = "ipv6"
		}
		key := c.Interface + "|" + c.Table + "|" + fam
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, model.Rule{ID: "gen-check-" + c.ID, Priority: checkHelperPriority, Oif: c.Interface, Family: fam,
			Action: "lookup", Table: c.Table, Comment: "route for health check " + c.Name, Source: "health check"})
	}
	return out
}
