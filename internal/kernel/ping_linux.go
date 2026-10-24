//go:build linux

package kernel

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// Ping sends one ICMP echo out of iface and waits for its reply. The socket is
// bound to the interface, so the packet leaves through it (and is routed by
// the rules that apply to traffic from that interface) rather than wherever
// the main routing table would send it. That is what makes it a test of that
// interface's path. Needs CAP_NET_RAW, which the daemon has as root.
func (Linux) Ping(ctx context.Context, iface, target string, timeout time.Duration) (time.Duration, error) {
	ip := net.ParseIP(target)
	if ip == nil {
		return 0, fmt.Errorf("%q is not an IP address", target)
	}
	v6 := ip.To4() == nil
	network, bind := "ip4:icmp", "0.0.0.0"
	reqType, replyType, proto := icmp.Type(ipv4.ICMPTypeEcho), icmp.Type(ipv4.ICMPTypeEchoReply), 1
	if v6 {
		network, bind = "ip6:ipv6-icmp", "::"
		reqType, replyType, proto = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, 58
	}

	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(ctx, network, bind)
	if err != nil {
		return 0, fmt.Errorf("opening a socket on %s: %w", iface, err)
	}
	defer pc.Close()

	id, seq := rand.Intn(0xffff)+1, rand.Intn(0xffff)+1
	msg := icmp.Message{Type: reqType, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("mini-net-man")}}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	deadline := time.Now().Add(timeout)
	if err := pc.SetDeadline(deadline); err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err := pc.WriteTo(wire, &net.IPAddr{IP: ip}); err != nil {
		return 0, fmt.Errorf("sending: %w", err) // e.g. network unreachable: no route out of that interface
	}

	buf := make([]byte, 1500)
	for {
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return 0, errors.New("timed out")
			}
			return 0, err
		}
		data := buf[:n]
		if !v6 && n > 0 { // IPv4 raw sockets hand back the IP header too
			if hl := int(data[0]&0x0f) * 4; hl <= n {
				data = data[hl:]
			}
		}
		if pa, ok := peer.(*net.IPAddr); ok && !pa.IP.Equal(ip) {
			continue
		}
		m, err := icmp.ParseMessage(proto, data)
		if err != nil || m.Type != replyType {
			continue // someone else's ICMP, or an error message
		}
		if echo, ok := m.Body.(*icmp.Echo); ok && echo.ID == id && echo.Seq == seq {
			return time.Since(start), nil
		}
	}
}
