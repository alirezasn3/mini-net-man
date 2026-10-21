package kernel

import (
	"strings"
	"testing"
)

// Lines copied from a real kernel (7.0), with and without accounting.
const ctSample = `ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=142.250.74.78 sport=50001 dport=443 packets=9 bytes=1200 src=142.250.74.78 dst=10.9.0.2 sport=443 dport=50001 packets=7 bytes=9000 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 119 TIME_WAIT src=127.0.0.1 dst=127.0.0.1 sport=47462 dport=9000 src=127.0.0.1 dst=127.0.0.1 sport=9000 dport=47462 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 25 src=10.0.0.5 dst=8.8.8.8 sport=41000 dport=53 [UNREPLIED] src=8.8.8.8 dst=10.0.0.5 sport=53 dport=41000 mark=0 zone=0 use=2
ipv4     2 icmp     1 29 src=127.0.0.1 dst=127.0.0.1 type=8 code=0 id=19 src=127.0.0.1 dst=127.0.0.1 type=0 code=0 id=19 mark=0 zone=0 use=2
ipv6     10 tcp      6 431900 ESTABLISHED src=fd00:10::5 dst=2606:4700::6810:84e5 sport=43210 dport=443 src=2606:4700::6810:84e5 dst=fd00:8::2 sport=443 dport=43210 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431990 ESTABLISHED src=203.0.113.50 dst=192.168.71.10 sport=60022 dport=8443 src=10.0.0.20 dst=203.0.113.50 sport=443 dport=60022 [OFFLOAD] mark=0 zone=0 use=3
garbage line
ipv4     2 gre      47 29 src=10.0.0.9 dst=1.1.1.1 srckey=0x0 dstkey=0x1 src=1.1.1.1 dst=10.0.0.9 srckey=0x1 dstkey=0x0 mark=0 zone=0 use=2
`

func TestParseConntrack(t *testing.T) {
	got, err := ParseConntrack(strings.NewReader(ctSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 { // the garbage line is skipped
		t.Fatalf("want 7 entries, got %d: %+v", len(got), got)
	}

	c := got[0]
	if c.Family != "ipv4" || c.Proto != "tcp" || c.State != "ESTABLISHED" || c.Timeout != 431999 || !c.Assured {
		t.Errorf("entry 0 header: %+v", c)
	}
	if c.Src != "10.0.0.5" || c.SrcPort != 50001 || c.Dst != "142.250.74.78" || c.DstPort != 443 {
		t.Errorf("entry 0 original tuple: %+v", c)
	}
	// Masquerade shows up as the reply tuple's destination.
	if c.ReplySrc != "142.250.74.78" || c.ReplyDst != "10.9.0.2" || c.ReplyDstPort != 50001 {
		t.Errorf("entry 0 reply tuple: %+v", c)
	}
	if c.BytesOut != 1200 || c.BytesIn != 9000 {
		t.Errorf("entry 0 counters: out=%d in=%d", c.BytesOut, c.BytesIn)
	}

	if u := got[2]; !u.Unreplied || u.State != "" || u.Proto != "udp" || u.BytesOut != 0 {
		t.Errorf("udp: %+v", u)
	}
	if i := got[3]; i.Proto != "icmp" || i.SrcPort != 0 || i.Src != "127.0.0.1" || i.ReplyDst != "127.0.0.1" {
		t.Errorf("icmp: %+v", i)
	}
	if v6 := got[4]; v6.Family != "ipv6" || v6.Src != "fd00:10::5" || v6.ReplyDst != "fd00:8::2" {
		t.Errorf("ipv6: %+v", v6)
	}
	// DNAT: the reply source differs from the original destination.
	if d := got[5]; d.Dst != "192.168.71.10" || d.ReplySrc != "10.0.0.20" || d.ReplySrcPort != 443 || d.State != "ESTABLISHED" {
		t.Errorf("dnat/offload: %+v", d)
	}
	if g := got[6]; g.Proto != "gre" || g.Src != "10.0.0.9" || g.ReplyDst != "10.0.0.9" {
		t.Errorf("gre: %+v", g)
	}
}
