package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/alirezasn3/mini-net-man/internal/tuning"
)

// tuningItem is one catalogue entry plus what this machine says about it.
type tuningItem struct {
	tuning.Setting
	Current   string   `json:"current"`             // value in the kernel now
	Supported bool     `json:"supported"`           // false when the kernel lacks it
	Why       string   `json:"why,omitempty"`       // reason, when not supported
	Managed   string   `json:"managed"`             // value mini-net-man keeps, "" if unmanaged
	Error     string   `json:"error,omitempty"`     // why the managed value couldn't be applied
	Available []string `json:"available,omitempty"` // values the kernel offers right now (congestion control, qdisc)
}

// available lists what the kernel offers for settings whose values are loadable.
func (s *Server) available(id string) []string {
	key := map[string]string{
		"tcp_congestion_control": "net.ipv4.tcp_available_congestion_control",
		"default_qdisc":          "net.core.available_qdisc",
	}[id]
	if key == "" {
		return nil
	}
	v, err := s.eng.Kernel().Sysctl(key)
	if err != nil {
		return nil
	}
	return strings.Fields(v)
}

func (s *Server) tuningList(w http.ResponseWriter, r *http.Request) {
	cfg := s.eng.Config()
	issues := map[string]string{}
	for _, is := range s.eng.Issues() {
		if is.Kind == "sysctl" {
			issues[is.ID] = is.Message
		}
	}
	out := make([]tuningItem, 0, len(tuning.Catalog))
	for _, st := range tuning.Catalog {
		it := tuningItem{Setting: st, Managed: cfg.Sysctl.Tuning[st.ID], Error: issues[st.ID], Available: s.available(st.ID)}
		cur, err := s.eng.Kernel().Sysctl(st.Keys[0])
		if err == nil {
			it.Current, it.Supported = cur, true
		} else {
			it.Why = err.Error()
			if strings.HasPrefix(st.Keys[0], "net.netfilter.") {
				it.Why = "Connection tracking isn't active yet. It starts as soon as a firewall rule uses NAT or connection state."
			}
		}
		out = append(out, it)
	}
	writeJSON(w, out)
}

// tuningSet manages (or, with an empty value, stops managing) one setting.
func (s *Server) tuningSet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := tuning.Get(id); !ok {
		httpErr(w, http.StatusNotFound, errors.New("no such setting"))
		return
	}
	var in struct {
		Value string `json:"value"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mutate(w, func(c *model.Config) error {
		if in.Value == "" {
			delete(c.Sysctl.Tuning, id)
			return nil
		}
		if c.Sysctl.Tuning == nil {
			c.Sysctl.Tuning = map[string]string{}
		}
		c.Sysctl.Tuning[id] = in.Value
		return nil
	})
}
