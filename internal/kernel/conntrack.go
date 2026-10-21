package kernel

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// tuple is one direction of a tracked connection while parsing.
type tuple struct {
	src, dst       string
	sport, dport   int
	packets, bytes uint64
	hasSrc         bool
}

// ParseConntrack reads /proc/net/nf_conntrack. A line looks like
//
//	ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=1.2.3.4 sport=5555 dport=443 \
//	  packets=9 bytes=1200 src=1.2.3.4 dst=10.8.0.2 sport=443 dport=5555 packets=7 bytes=9000 [ASSURED] mark=0 ...
//
// The first tuple is the original direction, the second the reply. Counters
// appear only when accounting is enabled. Unrecognised fields are ignored.
func ParseConntrack(r io.Reader) ([]model.Conn, error) {
	var out []model.Conn
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		c := model.Conn{Family: f[0], Proto: f[2]}
		c.Timeout, _ = strconv.Atoi(f[4])

		var orig, reply tuple
		cur := &orig
		seenFirst := false
		for _, tok := range f[5:] {
			switch {
			case strings.HasPrefix(tok, "["):
				switch tok {
				case "[UNREPLIED]":
					c.Unreplied = true
				case "[ASSURED]":
					c.Assured = true
				}
			case !strings.Contains(tok, "="):
				c.State = tok // TCP state, e.g. ESTABLISHED or TIME_WAIT
			default:
				k, v, _ := strings.Cut(tok, "=")
				if k == "src" {
					if seenFirst {
						cur = &reply // the second src= starts the reply tuple
					}
					seenFirst = true
				}
				switch k {
				case "src":
					cur.src = v
				case "dst":
					cur.dst = v
				case "sport":
					cur.sport, _ = strconv.Atoi(v)
				case "dport":
					cur.dport, _ = strconv.Atoi(v)
				case "packets":
					cur.packets, _ = strconv.ParseUint(v, 10, 64)
				case "bytes":
					cur.bytes, _ = strconv.ParseUint(v, 10, 64)
				}
			}
		}
		if orig.src == "" || orig.dst == "" {
			continue
		}
		c.Src, c.SrcPort, c.Dst, c.DstPort = orig.src, orig.sport, orig.dst, orig.dport
		c.ReplySrc, c.ReplySrcPort, c.ReplyDst, c.ReplyDstPort = reply.src, reply.sport, reply.dst, reply.dport
		c.BytesOut, c.BytesIn = orig.bytes, reply.bytes
		out = append(out, c)
	}
	return out, sc.Err()
}
