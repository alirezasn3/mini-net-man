//go:build linux

package kernel

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"
)

// ApplyFirewall replaces the whole mini-net-man table in one nftables
// transaction: either every rule is in place or nothing changed.
func (Linux) ApplyFirewall(fw model.Firewall) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	defer c.CloseLasting()

	// add + delete + add is the idiom for "replace this table atomically",
	// and works whether or not the table exists yet.
	tbl := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName}
	c.AddTable(tbl)
	c.DelTable(tbl)
	tbl = c.AddTable(tbl)

	chains := map[string]*nftables.Chain{}
	for _, d := range chainDefs {
		ch := &nftables.Chain{
			Name: d.name, Table: tbl,
			Type:     nftables.ChainType(d.ctype),
			Hooknum:  hookOf(d.hook),
			Priority: nftables.ChainPriorityRef(nftables.ChainPriority(d.prio)),
		}
		pol := nftables.ChainPolicyAccept
		if d.policy != nil && policyOr(d.policy(fw.Policy)) == "drop" {
			pol = nftables.ChainPolicyDrop
		}
		ch.Policy = &pol
		chains[d.name] = c.AddChain(ch)
	}

	for _, r := range fw.Rules {
		if r.Disabled {
			continue
		}
		variants, err := buildRule(r)
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

func ipOf(s string) ([]byte, []byte, error) {
	n, err := model.ParseCIDR(s, false)
	if err != nil {
		return nil, nil, err
	}
	return n.IP.To4(), n.Mask, nil
}

func matchAddr(offset uint32, cidr string) ([]expr.Any, error) {
	ip, mask, err := ipOf(cidr)
	if err != nil {
		return nil, err
	}
	out := []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4}}
	if ones, _ := net.IPMask(mask).Size(); ones < 32 {
		out = append(out, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}})
	}
	return append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip}), nil
}

type maskLen struct{ m []byte }

func (m *maskLen) size() (int, int) {
	n := 0
	for _, b := range m.m {
		for ; b != 0; b <<= 1 {
			n++
		}
	}
	return n, len(m.m) * 8
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

// buildRule returns one expression list per source/destination port
// alternative ("80,443" becomes two rules).
func buildRule(r model.FWRule) ([][]expr.Any, error) {
	var head []expr.Any
	if r.InIface != "" {
		head = append(head, &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(r.InIface)})
	}
	if r.OutIface != "" {
		head = append(head, &expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(r.OutIface)})
	}
	if r.Src != "" {
		e, err := matchAddr(12, r.Src)
		if err != nil {
			return nil, err
		}
		head = append(head, e...)
	}
	if r.Dst != "" {
		e, err := matchAddr(16, r.Dst)
		if err != nil {
			return nil, err
		}
		head = append(head, e...)
	}
	switch r.Proto {
	case "tcp":
		head = append(head, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}})
	case "udp":
		head = append(head, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}})
	case "icmp":
		head = append(head, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMP}})
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

	tail, err := action(r)
	if err != nil {
		return nil, err
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
		return []expr.Any{&expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH}}, nil
	case "masquerade":
		return []expr.Any{&expr.Masq{}}, nil
	case "dnat", "snat":
		ip, _, err := ipOf(r.ToAddr)
		if err != nil {
			return nil, err
		}
		nat := &expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1}
		if r.Action == "snat" {
			nat.Type = expr.NATTypeSourceNAT
		}
		out := []expr.Any{&expr.Immediate{Register: 1, Data: ip}}
		if r.ToPort != 0 {
			out = append(out, &expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(uint16(r.ToPort))})
			nat.RegProtoMin = 2
		}
		return append(out, nat), nil
	}
	return nil, fmt.Errorf("unknown action %q", r.Action)
}
