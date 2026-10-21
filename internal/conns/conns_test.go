package conns

import (
	"testing"

	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
)

func testContext() *Context {
	return NewContext(
		[]kernel.Addr{
			{Interface: "lo", Address: "127.0.0.1/8"},
			{Interface: "ens192", Address: "192.168.71.10/24"},
			{Interface: "wgServer", Address: "10.0.0.1/16"},
			{Interface: "wgBridge0", Address: "10.8.0.2/32"},
			{Interface: "wgBridge1", Address: "10.9.0.2/32"},
			{Interface: "wgBridge0", Address: "fd00:8::2/128"},
		},
		[]model.ClientRoute{
			{ID: "1", Name: "alice", Src: "10.0.0.5", In: "wgServer", Out: "wgBridge1"},
			{ID: "2", Name: "lan", Src: "10.0.1.0/24", In: "wgServer", Out: "wgBridge0"},
		})
}

func enrich(c model.Conn) model.Conn { testContext().Enrich(&c); return c }

func TestEnrichForwardedMasquerade(t *testing.T) {
	c := enrich(model.Conn{Proto: "tcp", Src: "10.0.0.5", SrcPort: 50001, Dst: "142.250.74.78", DstPort: 443,
		ReplySrc: "142.250.74.78", ReplySrcPort: 443, ReplyDst: "10.9.0.2", ReplyDstPort: 50001})
	if c.Kind != "forwarded" {
		t.Errorf("kind = %q", c.Kind)
	}
	if c.NAT != "SNAT 10.9.0.2" || c.Via != "wgBridge1" {
		t.Errorf("nat=%q via=%q; the masqueraded address belongs to wgBridge1", c.NAT, c.Via)
	}
	if c.Client != "alice" {
		t.Errorf("client = %q", c.Client)
	}
}

func TestEnrichClientNetworkAndIPv6(t *testing.T) {
	c := enrich(model.Conn{Proto: "udp", Src: "10.0.1.77", Dst: "8.8.8.8", DstPort: 53, SrcPort: 4000,
		ReplySrc: "8.8.8.8", ReplySrcPort: 53, ReplyDst: "10.8.0.2", ReplyDstPort: 4000})
	if c.Client != "lan" || c.Via != "wgBridge0" {
		t.Errorf("a client given as a /24 should name every address in it: %+v", c)
	}
	v6 := enrich(model.Conn{Proto: "tcp", Src: "fd00:10::5", SrcPort: 43210, Dst: "2606:4700::6810:84e5", DstPort: 443,
		ReplySrc: "2606:4700::6810:84e5", ReplySrcPort: 443, ReplyDst: "fd00:8::2", ReplyDstPort: 43210})
	if v6.Kind != "forwarded" || v6.Via != "wgBridge0" || v6.NAT != "SNAT fd00:8::2" {
		t.Errorf("ipv6: %+v", v6)
	}
}

func TestEnrichKinds(t *testing.T) {
	cases := []struct {
		name string
		c    model.Conn
		kind string
		nat  string
	}{
		{"ssh to this machine", model.Conn{Src: "203.0.113.7", Dst: "192.168.71.10", DstPort: 22, SrcPort: 51822,
			ReplySrc: "192.168.71.10", ReplySrcPort: 22, ReplyDst: "203.0.113.7", ReplyDstPort: 51822}, "incoming", ""},
		{"this machine fetching a page", model.Conn{Src: "192.168.71.10", SrcPort: 40000, Dst: "1.1.1.1", DstPort: 443,
			ReplySrc: "1.1.1.1", ReplySrcPort: 443, ReplyDst: "192.168.71.10", ReplyDstPort: 40000}, "outgoing", ""},
		{"loopback", model.Conn{Src: "127.0.0.1", SrcPort: 38000, Dst: "127.0.0.1", DstPort: 8080,
			ReplySrc: "127.0.0.1", ReplySrcPort: 8080, ReplyDst: "127.0.0.1", ReplyDstPort: 38000}, "local", ""},
		// A port forward: aimed at this machine's address, but delivered to 10.0.0.20.
		{"port forward", model.Conn{Src: "203.0.113.50", SrcPort: 60022, Dst: "192.168.71.10", DstPort: 8443,
			ReplySrc: "10.0.0.20", ReplySrcPort: 443, ReplyDst: "203.0.113.50", ReplyDstPort: 60022}, "forwarded", "DNAT 10.0.0.20:443"},
	}
	for _, tc := range cases {
		got := enrich(tc.c)
		if got.Kind != tc.kind || got.NAT != tc.nat {
			t.Errorf("%s: kind=%q nat=%q, want %q / %q", tc.name, got.Kind, got.NAT, tc.kind, tc.nat)
		}
	}
}

func sample() []model.Conn {
	ctx := testContext()
	mk := func(src, dst string, dport int, state string, to string, out, in uint64, timeout int) model.Conn {
		c := model.Conn{Proto: "tcp", State: state, Src: src, SrcPort: 50000, Dst: dst, DstPort: dport, Timeout: timeout,
			ReplySrc: dst, ReplySrcPort: dport, ReplyDst: to, ReplyDstPort: 50000, BytesOut: out, BytesIn: in}
		ctx.Enrich(&c)
		return c
	}
	return []model.Conn{
		mk("10.0.0.5", "9.9.9.9", 443, "ESTABLISHED", "10.9.0.2", 100, 9000, 400),
		mk("10.0.0.5", "1.1.1.1", 443, "TIME_WAIT", "10.9.0.2", 50, 60, 100),
		mk("10.0.0.6", "9.9.9.9", 443, "ESTABLISHED", "10.8.0.2", 5000, 900000, 300),
		mk("10.0.0.10", "8.8.4.4", 53, "ESTABLISHED", "10.8.0.2", 1, 1, 200),
		mk("203.0.113.7", "192.168.71.10", 22, "ESTABLISHED", "203.0.113.7", 10, 10, 500),
	}
}

func TestRunFilters(t *testing.T) {
	all := sample()
	sum, rows := Run(all, Query{})
	if sum.Total != 5 || sum.Matching != 5 || len(rows) != 5 {
		t.Fatalf("no filter: %+v", sum)
	}
	sum, rows = Run(all, Query{Kind: "forwarded"})
	if sum.Matching != 4 {
		t.Errorf("forwarded: %+v", sum)
	}
	if len(sum.Exits) != 2 || sum.Exits[0].Via != "wgBridge1" && sum.Exits[0].Via != "wgBridge0" {
		t.Errorf("exits: %+v", sum.Exits)
	}
	_, rows = Run(all, Query{Client: "10.0.0.5"})
	if len(rows) != 2 {
		t.Errorf("client filter: %d rows", len(rows))
	}
	// The client list ignores the client filter, so the alternatives stay visible.
	sum, _ = Run(all, Query{Client: "10.0.0.5", Kind: "forwarded"})
	if len(sum.Clients) != 3 || sum.Clients[0].Key != "10.0.0.5" || sum.Clients[0].Count != 2 || sum.Clients[0].Name != "alice" {
		t.Errorf("clients: %+v", sum.Clients)
	}
	// Likewise the state counts ignore the state filter.
	sum, rows = Run(all, Query{State: "TIME_WAIT"})
	if len(rows) != 1 || sum.ByState["ESTABLISHED"] != 4 || sum.ByState["TIME_WAIT"] != 1 {
		t.Errorf("state: rows=%d by=%v", len(rows), sum.ByState)
	}
	_, rows = Run(all, Query{Text: "alice"})
	if len(rows) != 2 {
		t.Errorf("text search by client name: %d rows", len(rows))
	}
	_, rows = Run(all, Query{Text: "wgbridge0"})
	if len(rows) != 2 {
		t.Errorf("text search by exit: %d rows", len(rows))
	}
	_, rows = Run(all, Query{Text: "no-such-thing"})
	if len(rows) != 0 {
		t.Errorf("no match: %d rows", len(rows))
	}
}

func TestRunSortAndLimit(t *testing.T) {
	all := sample()
	_, rows := Run(all, Query{Sort: "data"})
	if rows[0].Src != "10.0.0.6" { // 905,000 bytes, the most
		t.Errorf("data sort: first is %s", rows[0].Src)
	}
	_, rows = Run(all, Query{Sort: "expiry"})
	if rows[0].Timeout != 100 {
		t.Errorf("expiry sort: first has %ds", rows[0].Timeout)
	}
	// Default order sorts addresses numerically: 10.0.0.5 before 10.0.0.10.
	_, rows = Run(all, Query{})
	if rows[0].Src != "10.0.0.5" || rows[2].Src != "10.0.0.6" || rows[3].Src != "10.0.0.10" {
		t.Errorf("default order: %s %s %s", rows[0].Src, rows[2].Src, rows[3].Src)
	}
	sum, rows := Run(all, Query{Limit: 2})
	if len(rows) != 2 || sum.Shown != 2 || sum.Matching != 5 {
		t.Errorf("limit: shown=%d matching=%d rows=%d", sum.Shown, sum.Matching, len(rows))
	}
	if sum.BytesOut == 0 || sum.BytesIn != 9000+60+900000+1+10 {
		t.Errorf("byte totals: out=%d in=%d", sum.BytesOut, sum.BytesIn)
	}
}
