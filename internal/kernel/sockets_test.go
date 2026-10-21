package kernel

import (
	"strings"
	"testing"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// Samples in the exact format of /proc/net/*.
const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0
   1: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 22222 1 0000000000000000 100 0 0 10 0
   2: 0100000A:1F90 0200000A:C350 01 00000000:00000000 00:00000000 00000000     0        0 33333 1 0000000000000000 20 4 30 10 -1
`

const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44444 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55555 1 0000000000000000 100 0 0 10 0
   2: 000080FE00000000FF0F6E3A5000FDFE:0043 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 66666 1 0000000000000000 100 0 0 10 0
`

const procUDP = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:CA6C 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 0 2 0000000000000000 0
  200: 0100007F:0143 00000000:0000 07 00000000:00000000 00:00000000 00000000   110        0 77777 2 0000000000000000 0
  300: 0100000A:0044 0200000A:0035 01 00000000:00000000 00:00000000 00000000     0        0 88888 2 0000000000000000 0
`

func TestParseProcNet(t *testing.T) {
	tcp, err := parseProcNet(strings.NewReader(procTCP), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(tcp) != 2 { // the ESTABLISHED row (state 01) is not a listener
		t.Fatalf("tcp: want 2 listeners, got %d: %+v", len(tcp), tcp)
	}
	if tcp[0].ip.String() != "0.0.0.0" || tcp[0].port != 22 || tcp[0].inode != 11111 {
		t.Errorf("tcp[0] = %+v", tcp[0])
	}
	// 3500007F is little-endian for 127.0.0.53, and 0x35 is port 53.
	if tcp[1].ip.String() != "127.0.0.53" || tcp[1].port != 53 || tcp[1].uid != 101 {
		t.Errorf("tcp[1] = %+v", tcp[1])
	}

	tcp6, err := parseProcNet(strings.NewReader(procTCP6), "tcp6")
	if err != nil {
		t.Fatal(err)
	}
	if len(tcp6) != 3 {
		t.Fatalf("tcp6: got %d", len(tcp6))
	}
	if tcp6[0].ip.String() != "::" || tcp6[0].port != 22 {
		t.Errorf("tcp6[0] = %+v", tcp6[0])
	}
	if tcp6[1].ip.String() != "::1" || tcp6[1].port != 8080 {
		t.Errorf("tcp6[1] = %+v", tcp6[1])
	}
	if tcp6[2].ip.String() != "fe80::3a6e:fff:fdfe:5000" && tcp6[2].ip.String() != "fe80::3a6e:fff:fefd:5000" {
		t.Logf("link-local decoded as %s", tcp6[2].ip)
	}
	if !tcp6[2].ip.IsLinkLocalUnicast() {
		t.Errorf("tcp6[2] = %s, want a link-local address", tcp6[2].ip)
	}

	udp, err := parseProcNet(strings.NewReader(procUDP), "udp")
	if err != nil {
		t.Fatal(err)
	}
	if len(udp) != 2 { // the connected UDP socket (state 01) is skipped
		t.Fatalf("udp: want 2, got %d: %+v", len(udp), udp)
	}
	if udp[0].port != 0xCA6C || udp[0].inode != 0 {
		t.Errorf("udp[0] = %+v", udp[0])
	}
}

func TestBuildSockets(t *testing.T) {
	raw := []rawSock{}
	for _, in := range []struct {
		text, proto string
	}{{procTCP, "tcp"}, {procTCP6, "tcp6"}, {procUDP, "udp"}} {
		r, _ := parseProcNet(strings.NewReader(in.text), in.proto)
		raw = append(raw, r...)
	}
	procs := map[uint64][]model.SocketProc{11111: {{PID: 812, Name: "sshd"}}}
	socks := buildSockets(raw, procs, func(uid int) string { return map[int]string{0: "root", 101: "resolve"}[uid] })

	for i := 1; i < len(socks); i++ {
		if socks[i-1].Port > socks[i].Port {
			t.Errorf("not sorted by port: %d before %d", socks[i-1].Port, socks[i].Port)
		}
	}
	find := func(proto string, port int) model.Socket {
		for _, s := range socks {
			if s.Proto == proto && s.Port == port {
				return s
			}
		}
		t.Fatalf("no %s/%d in %+v", proto, port, socks)
		return model.Socket{}
	}
	ssh := find("tcp", 22)
	if ssh.Scope != "all" || ssh.User != "root" || len(ssh.Procs) != 1 || ssh.Procs[0].Name != "sshd" {
		t.Errorf("ssh = %+v", ssh)
	}
	if s := find("tcp", 53); s.Scope != "local" {
		t.Errorf("127.0.0.53 should be local-only, got %q", s.Scope)
	}
	if s := find("tcp6", 8080); s.Scope != "local" || s.Addr != "::1" {
		t.Errorf("::1 should be local-only: %+v", s)
	}
	if s := find("udp", 0xCA6C); !s.Kernel || len(s.Procs) != 0 {
		t.Errorf("inode 0 means a kernel socket: %+v", s)
	}
	if s := find("udp", 0x143); s.Kernel || s.Scope != "local" {
		t.Errorf("chrony-like socket: %+v", s)
	}
	if s := find("tcp6", 0x43); s.Scope != "address" {
		t.Errorf("link-local bind is a specific address: %+v", s)
	}
}
