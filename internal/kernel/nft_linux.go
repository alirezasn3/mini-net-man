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
	if r.Action == model.ActionClampMSS {
		r.Proto = "tcp"
	}
	var head []expr.Any
	// In an inet table nothing narrows a rule to one family unless we say so.
	switch r.EffFamily() {
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
		// icmpx works for both families.
		return []expr.Any{&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH}}, nil
	case model.ActionClampMSS:
		return clampMSS(r.MSS), nil
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
