package kernel

import (
	"net/netip"
	"sort"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// Address lists become nftables sets in the mini-net-man table. A list called
// "block" is four sets, because a set holds one address family and a rule can
// only change a set at run time if it is a hash set:
//
//	block.s4, block.s6   the entries you wrote: ranges and networks (interval sets)
//	block.d4, block.d6   what add-src-to-list / add-dst-to-list put there (with timeouts)
//
// A rule that matches a list matches either set of the right family.

// DynSetSize caps a dynamic set, so a flood of new addresses can't use up
// memory. When it is full, new addresses are simply not added.
const DynSetSize = 131072

// SetName is the nftables set holding a list's entries for one family.
func SetName(list string, v6, dynamic bool) string {
	n := list + "."
	if dynamic {
		n += "d"
	} else {
		n += "s"
	}
	if v6 {
		return n + "6"
	}
	return n + "4"
}

// DynAddr is an address a firewall rule added to a list.
type DynAddr struct {
	List    string `json:"list"`
	Address string `json:"address"`
	// Remaining is the seconds until it expires, or 0 when it has no expiry.
	Remaining int `json:"remaining"`
}

type rng struct{ first, last netip.Addr }

// listNames are all the address lists the firewall mentions, entries or rules.
func listNames(fw model.Firewall) []string {
	seen := map[string]bool{}
	for _, e := range fw.Lists {
		seen[e.List] = true
	}
	for _, r := range fw.Rules {
		if r.Disabled {
			continue
		}
		for _, ref := range []string{r.SrcList, r.DstList} {
			if n, _ := model.SplitListRef(ref); n != "" {
				seen[n] = true
			}
		}
		if r.Action == model.ActionAddSrcToList || r.Action == model.ActionAddDstToList {
			seen[r.List] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// listRanges returns each list's entries as sorted, merged ranges per family.
// The kernel refuses overlapping intervals, so overlaps are merged here (the
// nft command line does the same).
func listRanges(entries []model.AddressEntry) map[string][]rng {
	by := map[string][]rng{}
	for _, e := range entries {
		if e.Disabled {
			continue
		}
		a, b, err := model.ParseListAddress(e.Address)
		if err != nil {
			continue
		}
		k := SetName(e.List, a.Is6(), false)
		by[k] = append(by[k], rng{a, b})
	}
	for k, rs := range by {
		by[k] = mergeRanges(rs)
	}
	return by
}

func mergeRanges(rs []rng) []rng {
	sort.Slice(rs, func(i, j int) bool { return rs[i].first.Compare(rs[j].first) < 0 })
	var out []rng
	for _, r := range rs {
		if n := len(out); n > 0 {
			prev := &out[n-1]
			// Overlapping, or touching (the next address after prev.last).
			if next := prev.last.Next(); r.first.Compare(prev.last) <= 0 || next.IsValid() && r.first.Compare(next) == 0 {
				if r.last.Compare(prev.last) > 0 {
					prev.last = r.last
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// setRef is one set a rule looks an address up in.
type setRef struct {
	name string
	not  bool
}

// ruleVariant is one concrete form of a rule. A rule that mentions an address
// list needs one per address family, and for a positive match one per set
// (static or dynamic), because nftables can't ask "in this set or that one" in
// one comparison. All forms have the same action, so the first match wins just
// as it would for a single rule.
type ruleVariant struct {
	fam      string   // "", "ipv4" or "ipv6"
	src, dst []setRef // lookups to AND together
	add      string   // set to add the address to, for add-src/dst-to-list
}

func usesLists(r model.FWRule) bool {
	return r.SrcList != "" || r.DstList != "" || r.Action == model.ActionAddSrcToList || r.Action == model.ActionAddDstToList
}

func listAlternatives(ref string, v6 bool) [][]setRef {
	name, not := model.SplitListRef(ref)
	if name == "" {
		return [][]setRef{nil}
	}
	s, d := setRef{SetName(name, v6, false), not}, setRef{SetName(name, v6, true), not}
	if not {
		return [][]setRef{{s, d}} // not in either
	}
	return [][]setRef{{s}, {d}}
}

func ruleVariants(r model.FWRule) []ruleVariant {
	fam := r.EffFamily()
	if !usesLists(r) {
		return []ruleVariant{{fam: fam}}
	}
	fams := []string{fam}
	if fam == "" {
		fams = []string{"ipv4", "ipv6"}
	}
	var out []ruleVariant
	for _, f := range fams {
		v6 := f == "ipv6"
		for _, s := range listAlternatives(r.SrcList, v6) {
			for _, d := range listAlternatives(r.DstList, v6) {
				v := ruleVariant{fam: f, src: s, dst: d}
				if r.Action == model.ActionAddSrcToList || r.Action == model.ActionAddDstToList {
					v.add = SetName(r.List, v6, true)
				}
				out = append(out, v)
			}
		}
	}
	return out
}

func timeoutOf(r model.FWRule) time.Duration { return time.Duration(r.Timeout) * time.Second }
