package tuning

import (
	"strings"
	"testing"
)

// The catalogue is data, but data can be wrong in ways the compiler can't see.
func TestCatalogIsConsistent(t *testing.T) {
	ids, keys := map[string]bool{}, map[string]string{}
	for _, s := range Catalog {
		if s.ID == "" || s.Label == "" || s.Desc == "" || s.Group == "" || len(s.Keys) == 0 {
			t.Errorf("incomplete entry: %+v", s)
		}
		if ids[s.ID] {
			t.Errorf("duplicate id %q", s.ID)
		}
		ids[s.ID] = true
		for _, k := range s.Keys {
			if !strings.HasPrefix(k, "net.") || strings.ContainsAny(k, "/ \t") {
				t.Errorf("%s: suspicious sysctl key %q", s.ID, k)
			}
			if other, dup := keys[k]; dup {
				t.Errorf("sysctl %s is written by both %s and %s", k, other, s.ID)
			}
			keys[k] = s.ID
		}
		switch s.Kind {
		case "choice":
			if len(s.Choices) < 2 {
				t.Errorf("%s: a choice needs at least two options", s.ID)
			}
		case "int":
			if s.Min >= s.Max || s.Unit == "" {
				t.Errorf("%s: bad range or no unit: %+v", s.ID, s)
			}
		default:
			t.Errorf("%s: unknown kind %q", s.ID, s.Kind)
		}
		// A recommendation must itself be allowed.
		if s.Recommended != "" {
			if err := s.Check(s.Recommended); err != nil {
				t.Errorf("%s: recommended value rejected: %v", s.ID, err)
			}
		}
	}
}

func TestValidate(t *testing.T) {
	good := [][2]string{{"tcp_congestion_control", "bbr"}, {"tcp_mtu_probing", "2"}, {"socket_buffer_max", "16777216"}, {"rp_filter", "0"}, {"conntrack_max", "1024"}}
	for _, g := range good {
		if err := Validate(g[0], g[1]); err != nil {
			t.Errorf("%s=%s should be allowed: %v", g[0], g[1], err)
		}
	}
	bad := [][2]string{
		{"tcp_congestion_control", "westwood; rm -rf /"}, // not in the list
		{"tcp_mtu_probing", "3"},
		{"socket_buffer_max", "10"},          // below the minimum
		{"socket_buffer_max", "99999999999"}, // above the maximum
		{"socket_buffer_max", "lots"},
		{"conntrack_max", ""},
		{"no_such_setting", "1"},
	}
	for _, b := range bad {
		if err := Validate(b[0], b[1]); err == nil {
			t.Errorf("%s=%q should be rejected", b[0], b[1])
		}
	}
}
