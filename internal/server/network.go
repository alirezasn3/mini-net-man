package server

import (
	"sort"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/alirezasn3/mini-net-man/internal/netmgr"
)

// netmgr returns what manages the network, looked up at most every few seconds
// (it reads /proc and may run nmcli). The mock kernel reports a fixed example.
func (s *Server) netmgr(links []model.Link) netmgr.Report {
	s.nmMu.Lock()
	defer s.nmMu.Unlock()
	if time.Since(s.nmAt) < 5*time.Second && s.nmCache.Links != nil {
		return s.nmCache
	}
	if s.mock {
		s.nmCache = mockNetmgr()
	} else {
		s.nmCache = netmgr.Detect(links)
	}
	s.nmAt = time.Now()
	return s.nmCache
}

// links is the kernel's interfaces, each labelled with what manages it:
// NetworkManager or systemd-networkd where they claim it, and mini-net-man
// where the config names it as a bridge, a bridge port or an interface setting.
func (s *Server) links() ([]model.Link, error) {
	ls, err := s.eng.Kernel().Links()
	if err != nil {
		return nil, err
	}
	rep := s.netmgr(ls)
	cfg := s.eng.Config()
	ours := map[string]bool{}
	for _, b := range cfg.Bridges {
		if b.Disabled {
			continue
		}
		ours[b.Name] = true
		for _, p := range b.Ports {
			ours[p] = true
		}
	}
	for _, i := range cfg.Interfaces {
		if !i.Disabled {
			ours[i.Name] = true
		}
	}
	for i := range ls {
		by := append([]string(nil), rep.Links[ls[i].Name]...)
		if ours[ls[i].Name] {
			by = append(by, "mini-net-man")
		}
		sort.Strings(by)
		ls[i].ManagedBy = by
	}
	return ls, nil
}

func mockNetmgr() netmgr.Report {
	return netmgr.Report{
		Managers: []netmgr.Manager{
			{ID: "networkmanager", Name: "NetworkManager", Running: true, Config: true, Detail: "running, 1 saved connection",
				Note: "It may undo changes made here to interfaces it manages. Mark an interface unmanaged (nmcli device set <name> managed no) or add it to unmanaged-devices in NetworkManager.conf."},
			{ID: "netplan", Name: "netplan", Config: true, Detail: "1 file in /etc/netplan, rendering for NetworkManager",
				Note: "netplan regenerates the NetworkManager configuration at boot and on `netplan apply`."},
		},
		Links: map[string][]string{"ens192": {"NetworkManager"}},
	}
}
