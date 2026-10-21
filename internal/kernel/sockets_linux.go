//go:build linux

package kernel

import (
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// Sockets reads /proc/net for listening sockets and /proc/<pid>/fd to find
// which process holds each one. Seeing other users' processes needs root,
// which the daemon has; without it the Procs lists simply come back empty.
func (Linux) Sockets() ([]model.Socket, error) {
	var raw []rawSock
	for _, p := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open("/proc/net/" + p)
		if err != nil {
			continue // e.g. no IPv6
		}
		socks, err := parseProcNet(f, p)
		f.Close()
		if err != nil {
			return nil, err
		}
		raw = append(raw, socks...)
	}

	want := map[uint64]bool{}
	for _, r := range raw {
		if r.inode != 0 {
			want[r.inode] = true
		}
	}
	return buildSockets(raw, procsByInode(want), userNamer()), nil
}

// procsByInode walks /proc/*/fd once and returns the processes that hold
// each wanted socket inode.
func procsByInode(want map[uint64]bool) map[uint64][]model.SocketProc {
	out := map[uint64][]model.SocketProc{}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(d + "/fd")
		if err != nil {
			continue
		}
		var name string
		seen := map[uint64]bool{}
		for _, fd := range fds {
			link, err := os.Readlink(d + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err != nil || !want[inode] || seen[inode] {
				continue
			}
			seen[inode] = true
			if name == "" {
				b, _ := os.ReadFile(d + "/comm")
				name = strings.TrimSpace(string(b))
			}
			out[inode] = append(out[inode], model.SocketProc{PID: pid, Name: name})
		}
	}
	for _, ps := range out {
		sort.Slice(ps, func(i, j int) bool { return ps[i].PID < ps[j].PID })
	}
	return out
}

func userNamer() func(int) string {
	cache := map[int]string{}
	return func(uid int) string {
		if n, ok := cache[uid]; ok {
			return n
		}
		n := strconv.Itoa(uid)
		if u, err := user.LookupId(n); err == nil {
			n = u.Username
		}
		cache[uid] = n
		return n
	}
}
