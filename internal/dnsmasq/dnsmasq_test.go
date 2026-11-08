package dnsmasq

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

func lines(s string) map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		m[l] = true
	}
	return m
}

func TestRender(t *testing.T) {
	in := Input{
		Dir:      "/etc/mnm/services",
		Settings: model.DNSMasq{Enabled: true, DNS: true, Upstreams: []string{"1.1.1.1", "9.9.9.9#5353"}, Domain: "LAN", CacheSize: 500, Interfaces: []string{"br1"}},
		Scopes: []model.DHCPScope{
			{ID: "aa", Interface: "br0", Start: "192.168.50.100", End: "192.168.50.200", LeaseTime: "12h", Comment: "x\nconf-file=/etc/shadow"},
			{ID: "bb", Interface: "wlan0", Start: "10.9.0.10", End: "10.9.0.50", LeaseTime: "90m", Router: "none", DNS: []string{"10.9.0.1", "8.8.8.8"}, Domain: "guest.lan"},
			{ID: "cc", Interface: "eth9", Start: "10.1.0.2", End: "10.1.0.9", Disabled: true},
		},
		Hosts: []model.DHCPHost{
			{ID: "h1", MAC: "AA:BB:CC:00:11:22", IP: "192.168.50.10", Hostname: "NAS", Comment: "evil\nport=1"},
			{ID: "h2", MAC: "aa-bb-cc-00-11-33", IP: "192.168.50.11"},
			{ID: "h3", MAC: "aa:bb:cc:00:11:44", IP: "192.168.50.12", Disabled: true},
		},
		Records: []model.DNSRecord{
			{ID: "r1", Name: "Router.lan", Address: "192.168.50.1"},
			{ID: "r2", Name: "files.lan", Address: "nas.lan"},
			{ID: "r3", Name: "v6.lan", Address: "fd00::5"},
			{ID: "r4", Name: "off.lan", Address: "1.2.3.4", Disabled: true},
		},
	}
	out := Render(in)
	got := lines(out)
	for _, want := range []string{
		"keep-in-foreground", "log-facility=-", "bind-dynamic", "domain-needed", "bogus-priv", "dhcp-authoritative",
		"pid-file=/etc/mnm/services/dnsmasq.pid", "dhcp-leasefile=/etc/mnm/services/dnsmasq.leases",
		"interface=br0", "interface=br1", "interface=wlan0", "no-resolv", "server=1.1.1.1", "server=9.9.9.9#5353",
		"cache-size=500", "domain=lan", "local=/lan/", "expand-hosts",
		"host-record=router.lan,192.168.50.1", "cname=files.lan,nas.lan", "host-record=v6.lan,fd00::5",
		"dhcp-range=tag:br0,set:s_aa,192.168.50.100,192.168.50.200,12h",
		"dhcp-range=tag:wlan0,set:s_bb,10.9.0.10,10.9.0.50,90m",
		"dhcp-option=tag:s_bb,3", "dhcp-option=tag:s_bb,6,10.9.0.1,8.8.8.8", "dhcp-option=tag:s_bb,15,guest.lan",
		"dhcp-host=aa:bb:cc:00:11:22,192.168.50.10,nas", "dhcp-host=aa:bb:cc:00:11:33,192.168.50.11",
	} {
		if !got[want] {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, bad := range []string{"eth9", "off.lan", "00:11:44", "conf-file", "port=", "evil", "shadow"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q should not appear:\n%s", bad, out)
		}
	}
	if strings.Contains(out, "dhcp-option=tag:s_aa") {
		t.Errorf("a scope with default router and DNS needs no options:\n%s", out)
	}
	if got := in.Interfaces(); strings.Join(got, ",") != "br0,br1,wlan0" {
		t.Errorf("interfaces %v", got)
	}
}

func TestRenderDHCPOnly(t *testing.T) {
	in := Input{Dir: "/d", Settings: model.DNSMasq{Enabled: true, Domain: "lan"},
		Scopes:  []model.DHCPScope{{ID: "aa", Interface: "br0", Start: "10.0.0.2", End: "10.0.0.9", LeaseTime: "infinite"}},
		Records: []model.DNSRecord{{ID: "r", Name: "a.lan", Address: "10.0.0.2"}}}
	out := Render(in)
	got := lines(out)
	if !in.Enabled() || in.ServesDNS() {
		t.Fatal("DHCP only")
	}
	for _, want := range []string{"port=0", "dhcp-range=tag:br0,set:s_aa,10.0.0.2,10.0.0.9,infinite", "dhcp-option=tag:s_aa,6", "domain=lan"} {
		if !got[want] {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "host-record") || strings.Contains(out, "cache-size") || strings.Contains(out, "local=") {
		t.Errorf("DNS settings leaked into a DHCP-only config:\n%s", out)
	}
}

func TestEnabled(t *testing.T) {
	if (Input{}).Enabled() {
		t.Error("empty is not enabled")
	}
	if (Input{Settings: model.DNSMasq{Enabled: true}}).Enabled() {
		t.Error("enabled with nothing to serve")
	}
	if !(Input{Settings: model.DNSMasq{Enabled: true, DNS: true, Interfaces: []string{"br0"}}}).Enabled() {
		t.Error("DNS on an interface should enable it")
	}
	if (Input{Settings: model.DNSMasq{DNS: true, Interfaces: []string{"br0"}}}).Enabled() {
		t.Error("the master switch is off")
	}
}

func TestLeases(t *testing.T) {
	p := filepath.Join(t.TempDir(), "leases")
	if ls, err := Leases(p); err != nil || len(ls) != 0 {
		t.Fatalf("missing file: %v %v", ls, err)
	}
	os.WriteFile(p, []byte("duid 00:01:00:01:aa\n1893456000 AA:bb:cc:00:11:22 192.168.50.101 phone 01:aa:bb:cc:00:11:22\n0 aa:bb:cc:00:11:33 192.168.50.20 * *\n1893456000 aa:bb:cc:00:11:44 192.168.50.9 laptop *\ngarbage\n"), 0o644)
	ls, err := Leases(p)
	if err != nil || len(ls) != 3 {
		t.Fatalf("%v %v", ls, err)
	}
	if ls[0].IP != "192.168.50.9" || ls[1].Hostname != "" || ls[1].Expires != 0 || ls[2].MAC != "aa:bb:cc:00:11:22" || ls[2].ClientID == "" {
		t.Errorf("parsed: %+v", ls)
	}
}
