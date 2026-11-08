package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/dnsmasq"
	"github.com/alirezasn3/mini-net-man/internal/engine"
	"github.com/alirezasn3/mini-net-man/internal/hostapd"
	"github.com/alirezasn3/mini-net-man/internal/model"
)

// ---- DHCP and DNS (dnsmasq) ------------------------------------------------------

func (s *Server) dnsmasqGet(w http.ResponseWriter, r *http.Request) {
	d := s.eng.Config().DNSMasq
	d.Interfaces, d.Upstreams = orEmpty(d.Interfaces), orEmpty(d.Upstreams)
	writeJSON(w, d)
}

func (s *Server) dnsmasqPut(w http.ResponseWriter, r *http.Request) {
	var in model.DNSMasq
	if !decode(w, r, &in) {
		return
	}
	s.mutate(w, func(c *model.Config) error { c.DNSMasq = in; return nil })
}

// serviceState is what the panel shows about one helper program.
type serviceState struct {
	Installed bool      `json:"installed"`
	Path      string    `json:"path,omitempty"`
	Version   string    `json:"version,omitempty"`
	Problem   string    `json:"problem,omitempty"` // why it can't be started, when it can't
	Wanted    bool      `json:"wanted"`            // the config asks for it to run
	Running   bool      `json:"running"`
	Since     time.Time `json:"since"`
	Restarts  int       `json:"restarts"`
	LastError string    `json:"last_error,omitempty"`
	Log       []string  `json:"log"`
}

func (s *Server) stateOf(name, binary string, wanted bool) (serviceState, int) {
	st := serviceState{Wanted: wanted, Log: []string{}}
	path, err := s.eng.Binary(binary)
	if err != nil {
		st.Problem = err.Error()
	} else {
		st.Installed, st.Path = true, path
		if !s.mock {
			st.Version = dnsmasqVersion(binary, path)
		}
	}
	pid := 0
	if ps, ok := s.eng.ServiceStatus(name); ok {
		st.Running, st.Since, st.Restarts, st.LastError = ps.Running, ps.Since, ps.Restarts, ps.LastError
		st.Log, pid = orEmpty(ps.Log), ps.PID
	}
	return st, pid
}

func dnsmasqVersion(binary, path string) string {
	if binary == "dnsmasq" {
		return dnsmasq.Version(path)
	}
	return ""
}

func (s *Server) dnsmasqStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.eng.Config()
	in := engine.DNSMasqInput(cfg, s.eng.ServicesDir())
	st, pid := s.stateOf("dnsmasq", "dnsmasq", in.Enabled())
	out := struct {
		serviceState
		Conflicts []string `json:"conflicts"`
	}{st, []string{}}
	// Something else already answering DNS or DHCP on this machine makes dnsmasq
	// fail with "address in use".
	if in.Enabled() && !s.mock {
		socks, _ := s.eng.Kernel().Sockets()
		for _, k := range socks {
			if k.Scope == "local" || (k.Port != 53 && k.Port != 67) || k.Addr == "127.0.0.53" || k.Addr == "127.0.0.54" {
				continue
			}
			if k.Port == 67 && !strings.HasPrefix(k.Proto, "udp") {
				continue
			}
			for _, p := range k.Procs {
				if p.PID != pid {
					out.Conflicts = append(out.Conflicts, fmt.Sprintf("%s (pid %d) already listens on %s port %d (%s)", p.Name, p.PID, k.Addr, k.Port, k.Proto))
				}
			}
		}
	}
	writeJSON(w, out)
}

// lease is a dnsmasq lease with what the panel adds to it.
type lease struct {
	dnsmasq.Lease
	Remaining int  `json:"remaining"` // seconds left; 0 with no expiry
	Static    bool `json:"static"`    // it is one of your fixed addresses
}

func (s *Server) dhcpLeases(w http.ResponseWriter, r *http.Request) {
	var ls []dnsmasq.Lease
	var err error
	if s.mock {
		now := time.Now().Unix()
		ls = []dnsmasq.Lease{
			{Expires: now + 40000, MAC: "3c:22:fb:10:aa:01", IP: "192.168.50.101", Hostname: "alis-iphone"},
			{Expires: now + 9000, MAC: "a4:83:e7:55:12:90", IP: "192.168.50.102", Hostname: "macbook"},
			{Expires: now + 31000, MAC: "b8:27:eb:00:00:07", IP: "192.168.50.10", Hostname: "nas"},
			{Expires: 0, MAC: "00:11:32:aa:bb:cc", IP: "192.168.50.11"},
		}
	} else if ls, err = dnsmasq.Leases(dnsmasq.LeasePath(s.eng.ServicesDir())); err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	fixed := map[string]bool{}
	for _, h := range s.eng.Config().DHCPHosts {
		if !h.Disabled {
			m, _ := model.NormalizeMAC(h.MAC)
			fixed[m] = true
		}
	}
	out := make([]lease, 0, len(ls))
	for _, l := range ls {
		x := lease{Lease: l, Static: fixed[l.MAC]}
		if l.Expires > 0 {
			if x.Remaining = int(l.Expires - time.Now().Unix()); x.Remaining <= 0 {
				continue // expired but not yet cleaned out of the file
			}
		}
		out = append(out, x)
	}
	writeJSON(w, out)
}

// serviceConfigs shows the generated files, with Wi-Fi passwords hidden.
func (s *Server) serviceConfigs(w http.ResponseWriter, r *http.Request) {
	cfg, dir := s.eng.Config(), s.eng.ServicesDir()
	out := struct {
		Dnsmasq string            `json:"dnsmasq"`
		Hostapd map[string]string `json:"hostapd"`
	}{Hostapd: map[string]string{}}
	if in := engine.DNSMasqInput(cfg, dir); in.Enabled() {
		out.Dnsmasq = dnsmasq.Render(in)
	}
	for _, ap := range cfg.AccessPoints {
		if ap.Disabled {
			continue
		}
		text := hostapd.Render(ap, dir)
		if ap.Passphrase != "" {
			text = strings.ReplaceAll(strings.ReplaceAll(text, ap.Passphrase, "********"), strings.ToLower(ap.Passphrase), "********")
		}
		out.Hostapd[ap.Interface] = text
	}
	writeJSON(w, out)
}

// ---- Wi-Fi access points (hostapd) -----------------------------------------------

// apView is an access point as the API shows it: never with its password.
type apView struct {
	model.AccessPoint
	HasPassphrase bool `json:"has_passphrase"`
}

func viewAP(a model.AccessPoint) apView {
	v := apView{AccessPoint: a, HasPassphrase: a.Passphrase != ""}
	v.Passphrase = ""
	return v
}

func (s *Server) apList(w http.ResponseWriter, r *http.Request) {
	out := []apView{}
	for _, a := range s.eng.Config().AccessPoints {
		out = append(out, viewAP(a))
	}
	writeJSON(w, out)
}

func (s *Server) apAdd(w http.ResponseWriter, r *http.Request) {
	var in model.AccessPoint
	if !decode(w, r, &in) {
		return
	}
	in.ID = engine.NewID()
	s.mutateWith(w, map[string]any{"id": in.ID}, func(c *model.Config) error {
		c.AccessPoints = append(c.AccessPoints, in)
		return nil
	})
}

// apReplace replaces an access point. Leaving the password empty keeps the
// one already stored, since it is never sent to the browser.
func (s *Server) apReplace(w http.ResponseWriter, r *http.Request) {
	var in model.AccessPoint
	if !decode(w, r, &in) {
		return
	}
	want := r.PathValue("id")
	in.ID = want
	s.mutate(w, func(c *model.Config) error {
		for i := range c.AccessPoints {
			if c.AccessPoints[i].ID != want {
				continue
			}
			if in.Passphrase == "" && in.Security != "open" {
				in.Passphrase = c.AccessPoints[i].Passphrase
			}
			if in.Security == "open" {
				in.Passphrase = ""
			}
			c.AccessPoints[i] = in
			return nil
		}
		return errNotFound
	})
}

func (s *Server) apDelete(w http.ResponseWriter, r *http.Request) {
	s.apRemove(w, []string{r.PathValue("id")})
}

func (s *Server) apDeleteMany(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.IDs) == 0 {
		httpErr(w, http.StatusBadRequest, errors.New("no ids given"))
		return
	}
	s.apRemove(w, in.IDs)
}

func (s *Server) apRemove(w http.ResponseWriter, ids []string) {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	removed := 0
	s.mutateWith(w, nil, func(c *model.Config) error {
		kept := make([]model.AccessPoint, 0, len(c.AccessPoints))
		removed = 0
		for _, a := range c.AccessPoints {
			if drop[a.ID] {
				removed++
			} else {
				kept = append(kept, a)
			}
		}
		if removed == 0 {
			return errNotFound
		}
		c.AccessPoints = kept
		return nil
	}, func(out map[string]any) { out["removed"] = removed })
}

// apState is one access point's status.
type apState struct {
	ID        string            `json:"id"`
	Interface string            `json:"interface"`
	Exists    bool              `json:"exists"`   // the interface is there
	Wireless  bool              `json:"wireless"` // and is a Wi-Fi interface
	ManagedBy []string          `json:"managed_by,omitempty"`
	Process   serviceState      `json:"process"`
	Radio     *hostapd.Status   `json:"radio,omitempty"`
	Stations  []hostapd.Station `json:"stations"`
	Error     string            `json:"error,omitempty"`
}

func (s *Server) apStatus(w http.ResponseWriter, r *http.Request) {
	links, _ := s.links()
	byName := map[string]model.Link{}
	for _, l := range links {
		byName[l.Name] = l
	}
	ctl := hostapd.Control{Dir: hostapd.CtrlDir(s.eng.ServicesDir())}
	out := []apState{}
	for _, ap := range s.eng.Config().AccessPoints {
		st := apState{ID: ap.ID, Interface: ap.Interface, Stations: []hostapd.Station{}}
		l, ok := byName[ap.Interface]
		st.Exists, st.Wireless, st.ManagedBy = ok, l.Wireless, otherManagers(l.ManagedBy)
		st.Process, _ = s.stateOf(hostapd.Name(ap.Interface), "hostapd", !ap.Disabled)
		if st.Process.Running {
			if s.mock {
				st.Radio = &hostapd.Status{State: "ENABLED", Channel: ap.Channel, Freq: 2437, Clients: 2}
				st.Stations = mockStations()
			} else if radio, err := ctl.Status(ap.Interface); err != nil {
				st.Error = err.Error()
			} else {
				st.Radio = &radio
				if stations, err := ctl.Stations(ap.Interface); err == nil {
					st.Stations = stations
				}
			}
		}
		out = append(out, st)
	}
	writeJSON(w, out)
}

func otherManagers(by []string) []string {
	var out []string
	for _, m := range by {
		if m != "mini-net-man" {
			out = append(out, m)
		}
	}
	return out
}

func mockStations() []hostapd.Station {
	return []hostapd.Station{
		{MAC: "3c:22:fb:10:aa:01", Flags: "[AUTH][ASSOC][AUTHORIZED][WMM][HT]", Signal: -48, ConnectedSecs: 5400, InactiveMs: 300, RxBytes: 48_000_000, TxBytes: 910_000_000, RxPackets: 120000, TxPackets: 740000},
		{MAC: "a4:83:e7:55:12:90", Flags: "[AUTH][ASSOC][AUTHORIZED][WMM]", Signal: -67, ConnectedSecs: 320, InactiveMs: 2100, RxBytes: 1_200_000, TxBytes: 9_000_000, RxPackets: 3100, TxPackets: 6900},
	}
}

func (s *Server) apKick(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MAC string `json:"mac"`
	}
	if !decode(w, r, &in) {
		return
	}
	var iface string
	for _, ap := range s.eng.Config().AccessPoints {
		if ap.ID == r.PathValue("id") {
			iface = ap.Interface
		}
	}
	if iface == "" {
		httpErr(w, http.StatusNotFound, errNotFound)
		return
	}
	if !s.mock {
		if err := (hostapd.Control{Dir: hostapd.CtrlDir(s.eng.ServicesDir())}).Kick(iface, in.MAC); err != nil {
			httpErr(w, http.StatusBadGateway, err)
			return
		}
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// wifiConfigured reports whether any access point is switched on.
func wifiConfigured(cfg model.Config) bool {
	for _, ap := range cfg.AccessPoints {
		if !ap.Disabled {
			return true
		}
	}
	return false
}
