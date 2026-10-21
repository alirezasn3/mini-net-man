package kernel

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// rawSock is one parsed line of /proc/net/{tcp,tcp6,udp,udp6}.
type rawSock struct {
	proto string
	ip    net.IP
	port  int
	state string
	uid   int
	inode uint64
}

// Socket states in /proc/net: a listening TCP socket is 0A, a UDP socket
// that is bound but not connected shows as 07 (TCP_CLOSE).
const (
	stateTCPListen = "0A"
	stateUDPBound  = "07"
)

// parseProcNet reads the text of one /proc/net file. Only sockets that are
// accepting connections or receiving datagrams are returned.
func parseProcNet(r io.Reader, proto string) ([]rawSock, error) {
	want := stateTCPListen
	if strings.HasPrefix(proto, "udp") {
		want = stateUDPBound
	}
	var out []rawSock
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		state := strings.ToUpper(f[3])
		if state != want {
			continue
		}
		ip, port, err := parseProcAddr(f[1])
		if err != nil {
			return nil, err
		}
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, rawSock{proto: proto, ip: ip, port: port, state: state, uid: uid, inode: inode})
	}
	return out, sc.Err()
}

// parseProcAddr decodes "0100007F:0035". The kernel prints addresses as
// native-endian 32-bit words, so on little-endian machines each word is
// reversed; the port is plain big-endian hex.
func parseProcAddr(s string) (net.IP, int, error) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.LittleEndian.PutUint32(ip[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("bad port in %q", s)
	}
	return ip, int(port), nil
}

func scopeOf(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "all"
	case ip.IsLoopback():
		return "local"
	}
	return "address"
}

// buildSockets turns parsed sockets into API objects. procs maps a socket
// inode to the processes holding it; userName resolves a uid.
func buildSockets(raw []rawSock, procs map[uint64][]model.SocketProc, userName func(uid int) string) []model.Socket {
	out := make([]model.Socket, 0, len(raw))
	for _, r := range raw {
		s := model.Socket{Proto: r.proto, Addr: r.ip.String(), Port: r.port, Scope: scopeOf(r.ip), User: userName(r.uid)}
		if r.inode != 0 {
			s.Procs = procs[r.inode]
		} else {
			s.Kernel = true // no inode: the kernel opened it (WireGuard's UDP port, NFS, ...)
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}
