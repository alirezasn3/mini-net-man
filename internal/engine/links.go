package engine

import (
	"fmt"
	"slices"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// applyLinksLocked makes bridges, bridge ports and interface settings match
// the config. It runs before addresses so a bridge exists by the time an
// address is put on it.
//
// What it won't do: touch a bridge it didn't create unless the config names
// it, delete a bridge it didn't create, or release a port it didn't join.
func (e *Engine) applyLinksLocked(d Desired, add func(kind, id string, err error), do func(kind, id string, err error)) {
	links, err := e.k.Links()
	if err != nil {
		add("interface", "", err)
		return
	}
	byName := map[string]model.Link{}
	refresh := func() {
		byName = map[string]model.Link{}
		if ls, err := e.k.Links(); err == nil {
			for _, l := range ls {
				byName[l.Name] = l
			}
		}
	}
	for _, l := range links {
		byName[l.Name] = l
	}

	// An explicit "down" wins over the automatic "up" a bridge port gets.
	keepDown := map[string]bool{}
	for _, s := range d.Interfaces {
		if s.State == "down" {
			keepDown[s.Name] = true
		}
	}

	prev := e.lastBridges
	next := map[string]bridgeState{}
	wanted := map[string]bool{}

	for _, b := range d.Bridges {
		wanted[b.Name] = true
		st := prev[b.Name]
		cur, exists := byName[b.Name]
		switch {
		case !exists:
			if err := e.k.AddBridge(b.Name); err != nil {
				add("bridge", b.ID, err)
				continue
			}
			do("bridge", b.ID, nil)
			st.Created, st.STP = true, nil
			refresh()
			cur = byName[b.Name]
		case cur.Type != "bridge":
			add("bridge", b.ID, fmt.Errorf("%s already exists and is a %s interface, not a bridge", b.Name, cur.Type))
			continue
		}
		if st.STP == nil || *st.STP != b.STP {
			if err := e.k.SetBridgeSTP(b.Name, b.STP); err != nil {
				add("bridge", b.ID, err)
			} else {
				v := b.STP
				st.STP = &v
				do("bridge", b.ID, nil)
			}
		}
		if b.MTU > 0 && cur.MTU != b.MTU {
			do("bridge", b.ID, e.k.SetLinkMTU(b.Name, b.MTU))
		}
		if !cur.Up && !keepDown[b.Name] {
			do("bridge", b.ID, e.k.SetLinkUp(b.Name, true))
		}

		// Ports: join the ones listed, release the ones we joined that aren't.
		var joined []string
		for _, p := range b.Ports {
			pl, ok := byName[p]
			if !ok {
				add("bridge", b.ID, fmt.Errorf("port %s doesn't exist (yet)", p))
				if slices.Contains(st.Ports, p) {
					joined = append(joined, p) // keep owning it for when it returns
				}
				continue
			}
			if pl.Master != b.Name {
				if err := e.k.SetMaster(p, b.Name); err != nil {
					add("bridge", b.ID, fmt.Errorf("port %s: %w", p, err))
					continue
				}
				do("bridge", b.ID, nil)
			}
			joined = append(joined, p)
			if !pl.Up && !keepDown[p] {
				do("bridge", b.ID, e.k.SetLinkUp(p, true))
			}
		}
		for _, p := range st.Ports {
			if !slices.Contains(b.Ports, p) && byName[p].Master == b.Name {
				do("bridge", b.ID, e.k.SetMaster(p, ""))
			}
		}
		st.Ports = joined
		next[b.Name] = st
	}

	// Bridges that were in the config and no longer are. Look again first: a
	// port may just have moved from one of them to a bridge above.
	refresh()
	for name, st := range prev {
		if wanted[name] {
			continue
		}
		for _, p := range st.Ports {
			if byName[p].Master == name {
				do("bridge", "", e.k.SetMaster(p, ""))
			}
		}
		if cur, ok := byName[name]; ok && cur.Type == "bridge" && st.Created {
			do("bridge", "", e.k.DelBridge(name))
		}
	}
	e.lastBridges = next

	refresh()
	for _, s := range d.Interfaces {
		l, ok := byName[s.Name]
		if !ok {
			add("interface", s.ID, fmt.Errorf("interface %s doesn't exist (yet)", s.Name))
			continue
		}
		if s.MTU > 0 && l.MTU != s.MTU {
			do("interface", s.ID, e.k.SetLinkMTU(s.Name, s.MTU))
		}
		if s.State != "" && l.Up != (s.State == "up") {
			do("interface", s.ID, e.k.SetLinkUp(s.Name, s.State == "up"))
		}
	}
}
