//go:build linux

package kernel

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	ctCount = "/proc/sys/net/netfilter/nf_conntrack_count"
	ctMax   = "/proc/sys/net/netfilter/nf_conntrack_max"
	ctAcct  = "/proc/sys/net/netfilter/nf_conntrack_acct"
)

func readInt(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

var ctProtoNames = map[uint8]string{1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmpv6", 132: "sctp", 136: "udplite"}

var ctTCPStates = map[uint8]string{1: "SYN_SENT", 2: "SYN_RECV", 3: "ESTABLISHED", 4: "FIN_WAIT", 5: "CLOSE_WAIT",
	6: "LAST_ACK", 7: "TIME_WAIT", 8: "CLOSE", 9: "SYN_SENT2"}

const ctOff = "Connection tracking is not active. The kernel loads it as soon as a firewall rule uses NAT or connection state; add one (for example a masquerade rule, or `ct state established,related accept`) and it starts."

// Conntrack dumps the connection tracking table over ctnetlink, the
// supported interface (/proc/net/nf_conntrack is an optional, deprecated
// kernel feature that many distributions leave out).
func (Linux) Conntrack() (model.ConntrackInfo, []model.Conn, error) {
	if _, err := os.Stat(ctMax); err != nil {
		return model.ConntrackInfo{Reason: ctOff}, nil, nil
	}
	info := model.ConntrackInfo{Available: true, Count: readInt(ctCount), Max: readInt(ctMax), Acct: readInt(ctAcct) == 1}

	var out []model.Conn
	for _, fam := range []netlink.InetFamily{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, fam)
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EPROTONOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) {
				if fam == netlink.FAMILY_V4 {
					return model.ConntrackInfo{Reason: ctOff}, nil, nil
				}
				continue // no IPv6 tracking
			}
			return info, nil, err
		}
		for _, f := range flows {
			out = append(out, flowToConn(f, info.Acct))
		}
	}
	return info, out, nil
}

func flowToConn(f *netlink.ConntrackFlow, acct bool) model.Conn {
	c := model.Conn{
		Family: "ipv4", Proto: strconv.Itoa(int(f.Forward.Protocol)),
		Src: f.Forward.SrcIP.String(), SrcPort: int(f.Forward.SrcPort), Dst: f.Forward.DstIP.String(), DstPort: int(f.Forward.DstPort),
		ReplySrc: f.Reverse.SrcIP.String(), ReplySrcPort: int(f.Reverse.SrcPort), ReplyDst: f.Reverse.DstIP.String(), ReplyDstPort: int(f.Reverse.DstPort),
		Timeout: int(f.TimeOut), BytesOut: f.Forward.Bytes, BytesIn: f.Reverse.Bytes,
	}
	if f.FamilyType == unix.AF_INET6 {
		c.Family = "ipv6"
	}
	if name, ok := ctProtoNames[f.Forward.Protocol]; ok {
		c.Proto = name
	}
	if tcp, ok := f.ProtoInfo.(*netlink.ProtoInfoTCP); ok {
		c.State = ctTCPStates[tcp.State]
	}
	// With counters on, "nothing came back yet" is knowable for any protocol.
	c.Unreplied = acct && f.Reverse.Packets == 0
	return c
}

func (Linux) ConntrackAcct() (bool, error) {
	if _, err := os.Stat(ctAcct); err != nil {
		return false, err
	}
	return readInt(ctAcct) == 1, nil
}

func (Linux) SetConntrackAcct(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return os.WriteFile(ctAcct, []byte(v), 0o644)
}
