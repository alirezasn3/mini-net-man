//go:build linux

package kernel

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"
	"time"
)

// ApplyFirewall replaces the whole mini-net-man table in one nftables
// transaction: either every rule is in place or nothing changed.
func (Linux) ApplyFirewall(fw model.Firewall) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	defer c.CloseLasting()

	// Addresses that rules added to lists since the last apply live only in the
	// kernel. Read them now so the rebuilt table starts with them.
	keep := dynamicElements(c)

	// add + delete is the idiom for "remove this table if it exists" inside
	// a transaction. The first one clears the IPv4-only table early versions
	// used; the second one clears the current table before it is rebuilt.
	legacy := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName}
	c.AddTable(legacy)
	c.DelTable(legacy)

	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	c.AddTable(tbl)
	c.DelTable(tbl)
	tbl = c.AddTable(tbl)

	sets, err := addListSets(c, tbl, fw, keep)
	if err != nil {
		return err
	}

	chains := map[string]*nftables.Chain{}
	for _, d := range chainDefs {
		ch := &nftables.Chain{
			Name: d.name, Table: tbl,
			Type:     nftables.ChainType(d.ctype),
			Hooknum:  hookOf(d.hook),
			Priority: nftables.ChainPriorityRef(nftables.ChainPriority(d.prio)),
		}
		pol := nftables.ChainPolicyAccept
		if p, _ := chainPolicy(d, fw); p == "drop" {
			pol = nftables.ChainPolicyDrop
		}
		ch.Policy = &pol
		chains[d.name] = c.AddChain(ch)
	}

	for _, r := range fw.Rules {
		if r.Disabled {
			continue
		}
		variants, err := buildRule(r, sets)
		if err != nil {
			return fmt.Errorf("rule %s: %w", r.ID, err)
		}
		for _, exprs := range variants {
			nr := &nftables.Rule{Table: tbl, Chain: chains[r.Chain], Exprs: exprs}
			if r.Comment != "" {
				nr.UserData = userdata.AppendString(nil, userdata.TypeComment, r.Comment)
			}
			c.AddRule(nr)
		}
	}
	// A "reject" default is a catch-all rule at the very end of the chain.
	for _, d := range chainDefs {
		if _, final := chainPolicy(d, fw); final {
			exprs, err := action(model.FWRule{Action: "reject"})
			if err != nil {
				return err
			}
			c.AddRule(&nftables.Rule{Table: tbl, Chain: chains[d.name], Exprs: exprs,
				UserData: userdata.AppendString(nil, userdata.TypeComment, "default policy")})
		}
	}
	return c.Flush()
}

// addListSets creates the sets behind the address lists, with the static
// entries merged into intervals and the dynamic ones carried over.
func addListSets(c *nftables.Conn, tbl *nftables.Table, fw model.Firewall, keep map[string][]nftables.SetElement) (map[string]*nftables.Set, error) {
	sets := map[string]*nftables.Set{}
	ranges := listRanges(fw.Lists)
	for _, name := range listNames(fw) {
		for _, v6 := range []bool{false, true} {
			kt := nftables.TypeIPAddr
			if v6 {
				kt = nftables.TypeIP6Addr
			}
			st := &nftables.Set{Table: tbl, Name: SetName(name, v6, false), KeyType: kt, Interval: true}
			var elems []nftables.SetElement
			for _, r := range ranges[st.Name] {
				elems = append(elems, nftables.SetElement{Key: r.first.AsSlice()})
				if end := r.last.Next(); end.IsValid() {
					elems = append(elems, nftables.SetElement{Key: end.AsSlice(), IntervalEnd: true})
				}
			}
			if err := c.AddSet(st, elems); err != nil {
				return nil, fmt.Errorf("address list %s: %w", name, err)
			}
			sets[st.Name] = st
			dy := &nftables.Set{Table: tbl, Name: SetName(name, v6, true), KeyType: kt, HasTimeout: true, Dynamic: true, Size: DynSetSize}
			if err := c.AddSet(dy, keep[dy.Name]); err != nil {
				return nil, fmt.Errorf("address list %s: %w", name, err)
			}
			sets[dy.Name] = dy
		}
	}
	return sets, nil
}

// dynamicSets returns the live sets that rules add addresses to.
func dynamicSets(c *nftables.Conn) []*nftables.Set {
	all, err := c.GetSets(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
	if err != nil {
		return nil // no table yet
	}
	var out []*nftables.Set
	for _, s := range all {
		if s.Dynamic && (strings.HasSuffix(s.Name, ".d4") || strings.HasSuffix(s.Name, ".d6")) {
			out = append(out, s)
		}
	}
	return out
}

// dynamicElements reads the live dynamic sets, keeping each entry's remaining
// time as its new timeout.
func dynamicElements(c *nftables.Conn) map[string][]nftables.SetElement {
	out := map[string][]nftables.SetElement{}
	for _, s := range dynamicSets(c) {
		els, err := c.GetSetElements(s)
		if err != nil {
			continue
		}
		for _, e := range els {
			ne := nftables.SetElement{Key: e.Key}
			if e.Timeout > 0 {
				if e.Expires <= 0 {
					continue
				}
				ne.Timeout = e.Expires
			}
			out[s.Name] = append(out[s.Name], ne)
		}
	}
	return out
}

func listOfSet(name string) string { return name[:len(name)-3] }

// ListDynamic returns the addresses rules have added to lists, with the time
// each has left.
func (Linux) ListDynamic() ([]DynAddr, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	defer c.CloseLasting()
	out := []DynAddr{}
	for _, s := range dynamicSets(c) {
		els, err := c.GetSetElements(s)
		if err != nil {
			return nil, err
		}
		for _, e := range els {
			a, ok := netip.AddrFromSlice(e.Key)
			if !ok {
				continue
			}
			d := DynAddr{List: listOfSet(s.Name), Address: a.String()}
			if e.Timeout > 0 {
				d.Remaining = int((e.Expires + time.Second - 1) / time.Second)
			}
			out = append(out, d)
		}
	}
	return out, nil
}

// AddToList puts addresses in a list's dynamic sets with a timeout. An address
// that is already there is replaced, which is how its time is renewed.
func (Linux) AddToList(list string, addrs []netip.Addr, timeout time.Duration) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	sets := map[string]*nftables.Set{}
	for _, s := range dynamicSets(c) {
		sets[s.Name] = s
	}
	byFam := map[bool][]netip.Addr{}
	for _, a := range addrs {
		byFam[a.Is6()] = append(byFam[a.Is6()], a.Unmap())
	}
	for v6, as := range byFam {
		set := sets[SetName(list, v6, true)]
		if set == nil {
			return fmt.Errorf("list %s has no sets yet; the firewall hasn't been applied with it", list)
		}
		have := map[netip.Addr]bool{}
		if els, err := c.GetSetElements(set); err == nil {
			for _, e := range els {
				if a, ok := netip.AddrFromSlice(e.Key); ok {
					have[a] = true
				}
			}
		}
		var del, add []nftables.SetElement
		for _, a := range as {
			if have[a] {
				del = append(del, nftables.SetElement{Key: a.AsSlice()})
			}
			add = append(add, nftables.SetElement{Key: a.AsSlice(), Timeout: timeout})
		}
		if len(del) > 0 {
			if err := c.SetDeleteElements(set, del); err != nil {
				return err
			}
		}
		if err := c.SetAddElements(set, add); err != nil {
			return err
		}
	}
	return c.Flush()
}

// DelDynamic removes one address a rule added to a list.
func (Linux) DelDynamic(list, address string) error {
	a, err := netip.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("%q is not an IP address", address)
	}
	c, err := nftables.New()
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	for _, s := range dynamicSets(c) {
		if s.Name == SetName(list, a.Is6(), true) {
			if err := c.SetDeleteElements(s, []nftables.SetElement{{Key: a.AsSlice()}}); err != nil {
				return err
			}
			return c.Flush()
		}
	}
	return fmt.Errorf("%s is not in list %s", address, list)
}

// FlushDynamic empties the dynamic part of one list, or of every list when list is "".
func (Linux) FlushDynamic(list string) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	for _, s := range dynamicSets(c) {
		if list == "" || listOfSet(s.Name) == list {
			c.FlushSet(s)
		}
	}
	return c.Flush()
}

func hookOf(h string) *nftables.ChainHook {
	switch h {
	case "prerouting":
		return nftables.ChainHookPrerouting
	case "input":
		return nftables.ChainHookInput
	case "forward":
		return nftables.ChainHookForward
	case "output":
		return nftables.ChainHookOutput
	}
	return nftables.ChainHookPostrouting
}

func ifname(s string) []byte { return []byte(s + "\x00") }

// matchIface compares an interface name. A trailing * makes it a prefix match:
// the name is compared without its terminating NUL and only that many bytes
// are looked at, which is how nft encodes "wg*". A bare * matches everything.
func matchIface(key expr.MetaKey, name string) []expr.Any {
	if name == "" || name == "*" {
		return nil
	}
	data := ifname(name)
	if prefix, ok := strings.CutSuffix(name, "*"); ok {
		data = []byte(prefix)
	}
	return []expr.Any{&expr.Meta{Key: key, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data}}
}

// matchAddr compares the source or destination address in the IP header.
// The caller has already restricted the rule to the address's family, so the
// payload offsets below are safe to read.
func matchAddr(src bool, cidr string) ([]expr.Any, error) {
	n, err := model.ParseCIDR(cidr, false)
	if err != nil {
		return nil, err
	}
	var offset, size uint32
	ip, mask := []byte(n.IP), []byte(n.Mask)
	if model.IsV6(n) {
		offset, size = 24, 16 // daddr
		if src {
			offset = 8
		}
	} else {
		offset, size = 16, 4
		if src {
			offset = 12
		}
		ip = n.IP.To4()
	}
	out := []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: size}}
	if ones, bits := net.IPMask(mask).Size(); ones < bits {
		out = append(out, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: size, Mask: mask, Xor: make([]byte, size)})
	}
	return append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip}), nil
}

// loadAddr puts the source or destination address of the family into register 1.
func loadAddr(src, v6 bool) *expr.Payload {
	offset, size := uint32(16), uint32(4)
	switch {
	case v6 && src:
		offset, size = 8, 16
	case v6:
		offset, size = 24, 16
	case src:
		offset = 12
	}
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: size}
}

// lookupAddr matches the address against a set, or against not being in it.
func lookupAddr(src, v6 bool, ref setRef, sets map[string]*nftables.Set) ([]expr.Any, error) {
	set := sets[ref.name]
	if set == nil {
		return nil, fmt.Errorf("no set %s", ref.name)
	}
	return []expr.Any{loadAddr(src, v6), &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID, Invert: ref.not}}, nil
}

// portExprs matches a transport-header port (offset 0 = source, 2 = dest)
// against one port or a lo-hi range.
func portExprs(offset uint32, spec string) ([]expr.Any, error) {
	lo, hi, isRange := strings.Cut(spec, "-")
	a, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return nil, fmt.Errorf("bad port %q", spec)
	}
	b := a
	if isRange {
		if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
			return nil, fmt.Errorf("bad port %q", spec)
		}
	}
	out := []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2}}
	be := func(p int) []byte { return binaryutil.BigEndian.PutUint16(uint16(p)) }
	if a == b {
		return append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be(a)}), nil
	}
	return append(out,
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: be(a)},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: be(b)}), nil
}

func splitList(s string) []string {
	if s == "" {
		return []string{""}
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// buildRule returns one expression list per form of the rule: per source and
// destination port alternative ("80,443" is two rules) and, for rules that use
// address lists, per family and per set.
func buildRule(r model.FWRule, sets map[string]*nftables.Set) ([][]expr.Any, error) {
	if r.Action == model.ActionClampMSS {
		r.Proto = "tcp"
	}
	var out [][]expr.Any
	for _, v := range ruleVariants(r) {
		part, err := buildVariant(r, v, sets)
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
	}
	return out, nil
}

func buildVariant(r model.FWRule, v ruleVariant, sets map[string]*nftables.Set) ([][]expr.Any, error) {
	var head []expr.Any
	// In an inet table nothing narrows a rule to one family unless we say so.
	switch v.fam {
	case "ipv4":
		head = append(head, &expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}})
	case "ipv6":
		head = append(head, &expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}})
	}
	head = append(head, matchIface(expr.MetaKeyIIFNAME, r.InIface)...)
	head = append(head, matchIface(expr.MetaKeyOIFNAME, r.OutIface)...)
	if r.Src != "" {
		e, err := matchAddr(true, r.Src)
		if err != nil {
			return nil, err
		}
		head = append(head, e...)
	}
	if r.Dst != "" {
		e, err := matchAddr(false, r.Dst)
		if err != nil {
			return nil, err
		}
		head = append(head, e...)
	}
	for _, side := range []struct {
		src  bool
		refs []setRef
	}{{true, v.src}, {false, v.dst}} {
		for _, ref := range side.refs {
			e, err := lookupAddr(side.src, v.fam == "ipv6", ref, sets)
			if err != nil {
				return nil, err
			}
			head = append(head, e...)
		}
	}
	protos := map[string]byte{"tcp": unix.IPPROTO_TCP, "udp": unix.IPPROTO_UDP, "icmp": unix.IPPROTO_ICMP, "icmpv6": unix.IPPROTO_ICMPV6}
	if p, ok := protos[r.Proto]; ok {
		head = append(head, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{p}})
	}
	if r.ConnState != "" {
		bits := uint32(0)
		for _, s := range strings.Split(r.ConnState, ",") {
			switch strings.TrimSpace(s) {
			case "invalid":
				bits |= 1
			case "established":
				bits |= 2
			case "related":
				bits |= 4
			case "new":
				bits |= 8
			case "untracked":
				bits |= 64
			}
		}
		head = append(head,
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(bits), Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}})
	}

	var tail []expr.Any
	if v.add == "" {
		var err error
		if tail, err = action(r); err != nil {
			return nil, err
		}
	} else {
		set := sets[v.add]
		if set == nil {
			return nil, fmt.Errorf("no set %s", v.add)
		}
		tail = []expr.Any{loadAddr(r.Action == model.ActionAddSrcToList, v.fam == "ipv6"),
			&expr.Dynset{SrcRegKey: 1, SetName: set.Name, SetID: set.ID, Operation: unix.NFT_DYNSET_OP_UPDATE, Timeout: timeoutOf(r)}}
	}

	var out [][]expr.Any
	for _, sp := range splitList(r.SrcPort) {
		for _, dp := range splitList(r.DstPort) {
			e := append([]expr.Any{}, head...)
			if sp != "" {
				p, err := portExprs(0, sp)
				if err != nil {
					return nil, err
				}
				e = append(e, p...)
			}
			if dp != "" {
				p, err := portExprs(2, dp)
				if err != nil {
					return nil, err
				}
				e = append(e, p...)
			}
			out = append(out, append(e, tail...))
		}
	}
	return out, nil
}

func action(r model.FWRule) ([]expr.Any, error) {
	switch r.Action {
	case "accept":
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}, nil
	case "drop":
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}, nil
	case "return":
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictReturn}}, nil
	case "reject":
		// icmpx works for both families.
		return []expr.Any{&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH}}, nil
	case model.ActionClampMSS:
		return clampMSS(r.MSS), nil
	case model.ActionMarkConnection:
		return []expr.Any{
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(r.Mark)},
			&expr.Ct{Key: expr.CtKeyMARK, Register: 1, SourceRegister: true},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
		}, nil
	case model.ActionRestoreMark:
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
		}, nil
	case "masquerade":
		return []expr.Any{&expr.Masq{}}, nil
	case "dnat", "snat":
		to := net.ParseIP(r.ToAddr)
		if to == nil {
			return nil, fmt.Errorf("bad to_addr %q", r.ToAddr)
		}
		nat := &expr.NAT{Type: expr.NATTypeDestNAT, RegAddrMin: 1}
		if r.Action == "snat" {
			nat.Type = expr.NATTypeSourceNAT
		}
		data := []byte(to.To4())
		nat.Family = unix.NFPROTO_IPV4
		if data == nil {
			data, nat.Family = []byte(to.To16()), unix.NFPROTO_IPV6
		}
		out := []expr.Any{&expr.Immediate{Register: 1, Data: data}}
		if r.ToPort != 0 {
			out = append(out, &expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(uint16(r.ToPort))})
			nat.RegProtoMin = 2
		}
		return append(out, nat), nil
	}
	return nil, fmt.Errorf("unknown action %q", r.Action)
}

// clampMSS matches connection setup (SYN or SYN-ACK, not RST) and rewrites the
// MSS option; a packet without one is left alone, because loading the option
// breaks the rule. Size 0 uses the kernel's own figure for the outgoing route
// (its MTU minus the headers); otherwise the MSS is only ever lowered to size.
func clampMSS(size int) []expr.Any {
	const synRst, syn = 0x06, 0x02
	out := []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{synRst}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syn}},
	}
	opt := func() *expr.Exthdr {
		return &expr.Exthdr{Type: unix.TCPOPT_MAXSEG, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt}
	}
	if size == 0 {
		out = append(out,
			&expr.Rt{Register: 1, Key: expr.RtTCPMSS},
			&expr.Byteorder{SourceRegister: 1, DestRegister: 1, Op: expr.ByteorderHton, Len: 2, Size: 2})
	} else {
		be := binaryutil.BigEndian.PutUint16(uint16(size))
		load := opt()
		load.DestRegister = 1
		out = append(out, load,
			&expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: be},
			&expr.Immediate{Register: 1, Data: be})
	}
	set := opt()
	set.SourceRegister = 1
	return append(out, set)
}
