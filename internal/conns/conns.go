// Package conns turns the raw connection-tracking table into something to
// look at: each entry is classified (forwarded, incoming, outgoing, local),
// NAT is spelled out, the exit interface and client are named, and the list
// can be filtered, sorted and summarised.
package conns

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
)

// Context is what enrichment needs to know about this machine.
type Context struct {
	local   map[netip.Addr]bool   // addresses owned by this machine
	owner   map[netip.Addr]string // address -> interface that has it
	clients []clientNet
}

type clientNet struct {
	net  netip.Prefix
	name string
}

// NewContext builds a Context from the interface addresses and the
// client-routing clients (used to put names on source addresses).
func NewContext(addrs []kernel.Addr, clients []model.ClientRoute) *Context {
	c := &Context{local: map[netip.Addr]bool{}, owner: map[netip.Addr]string{}}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.Address); err == nil {
			c.local[p.Addr()] = true
			c.owner[p.Addr()] = a.Interface
		}
	}
	for _, cl := range clients {
		n, err := model.ParseCIDR(cl.Src, false)
		if err != nil {
			continue
		}
		ones, _ := n.Mask.Size()
		if ip, ok := netip.AddrFromSlice(n.IP); ok {
			name := cl.Name
			if name == "" {
				name = cl.Src
			}
			c.clients = append(c.clients, clientNet{netip.PrefixFrom(ip.Unmap(), ones), name})
		}
	}
	return c
}

func (c *Context) isLocal(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return a.IsLoopback() || c.local[a]
}

func hostPort(ip string, port int) string {
	if port == 0 {
		return ip
	}
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port)
}

// Enrich fills in Kind, NAT, Via and Client.
func (c *Context) Enrich(cn *model.Conn) {
	// Where the packets really end up is the reply tuple's source, which
	// differs from the original destination when DNAT redirected them.
	end := cn.Dst
	if cn.ReplySrc != "" {
		end = cn.ReplySrc
	}
	srcLocal, dstLocal := c.isLocal(cn.Src), c.isLocal(end)
	switch {
	case srcLocal && dstLocal:
		cn.Kind = "local"
	case dstLocal:
		cn.Kind = "incoming"
	case srcLocal:
		cn.Kind = "outgoing"
	default:
		cn.Kind = "forwarded"
	}

	var nat []string
	if cn.ReplyDst != "" && (cn.ReplyDst != cn.Src || (cn.ReplyDstPort != cn.SrcPort && cn.SrcPort != 0)) {
		nat = append(nat, "SNAT "+hostPort(cn.ReplyDst, portIfChanged(cn.ReplyDstPort, cn.SrcPort)))
		if a, err := netip.ParseAddr(cn.ReplyDst); err == nil {
			cn.Via = c.owner[a]
		}
	}
	if cn.ReplySrc != "" && (cn.ReplySrc != cn.Dst || (cn.ReplySrcPort != cn.DstPort && cn.DstPort != 0)) {
		nat = append(nat, "DNAT "+hostPort(cn.ReplySrc, cn.ReplySrcPort))
	}
	cn.NAT = strings.Join(nat, "; ")

	if a, err := netip.ParseAddr(cn.Src); err == nil {
		for _, cl := range c.clients {
			if cl.net.Contains(a.Unmap()) {
				cn.Client = cl.name
				break
			}
		}
	}
}

func portIfChanged(reply, orig int) int {
	if reply != orig {
		return reply
	}
	return 0
}

// ---- querying ----------------------------------------------------------------

type Query struct {
	Text   string
	Proto  string // tcp, udp, icmp, ...; "" for all
	Kind   string // forwarded, incoming, outgoing, local; "" for all
	State  string
	Client string // exact original source address
	Sort   string // client (default), data, expiry, dest
	Limit  int
}

type ClientCount struct {
	Key   string `json:"key"` // the source address
	Name  string `json:"name,omitempty"`
	Count int    `json:"count"`
}

type ExitCount struct {
	Via   string `json:"via"`
	Count int    `json:"count"`
}

type Summary struct {
	Total    int            `json:"total"`    // entries in the table
	Matching int            `json:"matching"` // entries passing every filter
	Shown    int            `json:"shown"`    // entries returned (the limit may cut it)
	ByState  map[string]int `json:"by_state"`
	Clients  []ClientCount  `json:"clients"`
	Exits    []ExitCount    `json:"exits"`
	BytesOut uint64         `json:"bytes_out"`
	BytesIn  uint64         `json:"bytes_in"`
}

const (
	DefaultLimit = 500
	MaxLimit     = 5000
)

// match applies the query, optionally ignoring one filter so that summaries
// can show the alternatives to what is currently selected.
func match(c *model.Conn, q Query, skip string) bool {
	if skip != "proto" && q.Proto != "" && c.Proto != q.Proto {
		return false
	}
	if skip != "kind" && q.Kind != "" && c.Kind != q.Kind {
		return false
	}
	if skip != "state" && q.State != "" && c.State != q.State {
		return false
	}
	if skip != "client" && q.Client != "" && c.Src != q.Client {
		return false
	}
	if t := strings.ToLower(strings.TrimSpace(q.Text)); t != "" {
		hay := strings.ToLower(strings.Join([]string{c.Src, c.Dst, c.ReplyDst, c.Client, c.Via, c.NAT, c.Proto, c.State, c.Kind,
			strconv.Itoa(c.SrcPort), strconv.Itoa(c.DstPort)}, " "))
		if !strings.Contains(hay, t) {
			return false
		}
	}
	return true
}

func addrLess(a, b string) bool {
	x, e1 := netip.ParseAddr(a)
	y, e2 := netip.ParseAddr(b)
	if e1 != nil || e2 != nil {
		return a < b
	}
	return x.Less(y)
}

// Run filters, sorts and summarises the table. The conns must already be enriched.
func Run(all []model.Conn, q Query) (Summary, []model.Conn) {
	if q.Limit <= 0 {
		q.Limit = DefaultLimit
	}
	if q.Limit > MaxLimit {
		q.Limit = MaxLimit
	}
	sum := Summary{Total: len(all), ByState: map[string]int{}}
	clients := map[string]*ClientCount{}
	exits := map[string]int{}
	var out []model.Conn

	for i := range all {
		c := &all[i]
		// Counts per state ignore the state filter itself, so you can see
		// what else is there to switch to.
		if c.State != "" && match(c, q, "state") {
			sum.ByState[c.State]++
		}
		if match(c, q, "client") {
			cc := clients[c.Src]
			if cc == nil {
				cc = &ClientCount{Key: c.Src, Name: c.Client}
				clients[c.Src] = cc
			}
			cc.Count++
		}
		if !match(c, q, "") {
			continue
		}
		sum.Matching++
		sum.BytesOut += c.BytesOut
		sum.BytesIn += c.BytesIn
		if c.Via != "" {
			exits[c.Via]++
		}
		out = append(out, *c)
	}

	for _, cc := range clients {
		sum.Clients = append(sum.Clients, *cc)
	}
	sort.Slice(sum.Clients, func(i, j int) bool {
		if sum.Clients[i].Count != sum.Clients[j].Count {
			return sum.Clients[i].Count > sum.Clients[j].Count
		}
		return addrLess(sum.Clients[i].Key, sum.Clients[j].Key)
	})
	if len(sum.Clients) > 12 {
		sum.Clients = sum.Clients[:12]
	}
	for v, n := range exits {
		sum.Exits = append(sum.Exits, ExitCount{v, n})
	}
	sort.Slice(sum.Exits, func(i, j int) bool { return sum.Exits[i].Count > sum.Exits[j].Count })

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch q.Sort {
		case "data":
			if x, y := a.BytesOut+a.BytesIn, b.BytesOut+b.BytesIn; x != y {
				return x > y
			}
		case "expiry":
			if a.Timeout != b.Timeout {
				return a.Timeout < b.Timeout
			}
		case "dest":
			if a.Dst != b.Dst {
				return addrLess(a.Dst, b.Dst)
			}
			return a.DstPort < b.DstPort
		}
		if a.Src != b.Src {
			return addrLess(a.Src, b.Src)
		}
		if a.Dst != b.Dst {
			return addrLess(a.Dst, b.Dst)
		}
		return a.DstPort < b.DstPort
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	sum.Shown = len(out)
	return sum, out
}
