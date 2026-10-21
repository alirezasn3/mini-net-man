//go:build linux

package kernel

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

const (
	ctTable = "/proc/net/nf_conntrack"
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

func (Linux) Conntrack() (model.ConntrackInfo, []model.Conn, error) {
	f, err := os.Open(ctTable)
	if errors.Is(err, os.ErrNotExist) {
		return model.ConntrackInfo{Reason: "Connection tracking is not active. The kernel loads it as soon as a firewall rule uses NAT or connection state; add one (for example a masquerade rule, or `ct state established,related accept`) and it starts."}, nil, nil
	}
	if err != nil {
		return model.ConntrackInfo{}, nil, err
	}
	defer f.Close()
	conns, err := ParseConntrack(f)
	if err != nil {
		return model.ConntrackInfo{}, nil, err
	}
	return model.ConntrackInfo{Available: true, Count: readInt(ctCount), Max: readInt(ctMax), Acct: readInt(ctAcct) == 1}, conns, nil
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
