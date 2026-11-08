package engine

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/alirezasn3/mini-net-man/internal/svc"
)

func newSvcTest(t *testing.T) (*Engine, *kernel.Mock) {
	t.Helper()
	e, k := newTest(t)
	e.SetMockServices(svc.NewFake(slog.New(slog.NewTextHandler(io.Discard, nil))))
	return e, k
}

func hasIssue(is []model.Issue, kind, contains string) bool {
	for _, i := range is {
		if i.Kind == kind && strings.Contains(i.Message, contains) {
			return true
		}
	}
	return false
}

func dhcpConfig(c *model.Config) error {
	c.DNSMasq = model.DNSMasq{Enabled: true, DNS: true, Domain: "lan"}
	c.DHCPScopes = []model.DHCPScope{{ID: "s1", Interface: "wgServer", Start: "10.0.5.10", End: "10.0.5.50"}}
	c.DHCPHosts = []model.DHCPHost{{ID: "h1", MAC: "aa:bb:cc:00:11:22", IP: "10.0.5.5", Hostname: "nas"}}
	return nil
}

func TestDnsmasqIsStartedAndStopped(t *testing.T) {
	e, _ := newSvcTest(t)
	if _, ok := e.ServiceStatus("dnsmasq"); ok {
		t.Fatal("running with nothing configured")
	}
	if is := mustUpdate(t, e, dhcpConfig); len(is) != 0 {
		t.Fatalf("issues: %v", is)
	}
	if st, ok := e.ServiceStatus("dnsmasq"); !ok || !st.Running {
		t.Fatalf("not running: %+v %v", st, ok)
	}
	// The master switch stops it.
	mustUpdate(t, e, func(c *model.Config) error { c.DNSMasq.Enabled = false; return nil })
	if _, ok := e.ServiceStatus("dnsmasq"); ok {
		t.Error("still running after it was switched off")
	}
	// So does removing the only thing it had to do.
	mustUpdate(t, e, func(c *model.Config) error { dhcpConfig(c); c.DNSMasq.DNS = false; return nil })
	if _, ok := e.ServiceStatus("dnsmasq"); !ok {
		t.Fatal("DHCP only should run")
	}
	mustUpdate(t, e, func(c *model.Config) error { c.DHCPScopes = nil; return nil })
	if _, ok := e.ServiceStatus("dnsmasq"); ok {
		t.Error("running with no scope and no DNS")
	}
}

func TestDnsmasqProblemsAreIssues(t *testing.T) {
	e, _ := newSvcTest(t)
	e.svc.findDnsmasq = func() (string, error) { return "", errors.New("dnsmasq is not installed") }
	is := mustUpdate(t, e, dhcpConfig)
	if !hasIssue(is, "dnsmasq", "not installed") {
		t.Errorf("a missing program should be an issue: %v", is)
	}
	if _, ok := e.ServiceStatus("dnsmasq"); ok {
		t.Error("started without a binary")
	}

	// It gets going once the program is there.
	e.svc.findDnsmasq = func() (string, error) { return "/usr/sbin/dnsmasq", nil }
	if is := e.Reapply(); hasIssue(is, "dnsmasq", "") {
		t.Fatalf("still an issue: %v", is)
	}
	if _, ok := e.ServiceStatus("dnsmasq"); !ok {
		t.Fatal("not started once installed")
	}

	// A config dnsmasq refuses is reported, and the working one keeps running.
	before, _ := e.ServiceStatus("dnsmasq")
	e.svc.checkDnsmasq = func(bin, conf string) error { return errors.New("dnsmasq rejects the config: bad option at line 7") }
	is = mustUpdate(t, e, func(c *model.Config) error { c.DHCPScopes[0].End = "10.0.5.60"; return nil })
	if !hasIssue(is, "dnsmasq", "rejects the config") {
		t.Errorf("a refused config should be an issue: %v", is)
	}
	if after, ok := e.ServiceStatus("dnsmasq"); !ok || !after.Running || after.Since != before.Since {
		t.Errorf("the working dnsmasq was disturbed: %+v -> %+v", before, after)
	}
}

func TestDhcpOpensTheFirewall(t *testing.T) {
	e, _ := newSvcTest(t)
	mustUpdate(t, e, func(c *model.Config) error {
		dhcpConfig(c)
		c.DNSMasq.Interfaces = []string{"wgBridge0"}
		c.Firewall.Policy.Input = "drop"
		c.Firewall.Rules = []model.FWRule{{ID: "ssh", Chain: "input", Action: "accept", Proto: "tcp", DstPort: "22"}}
		return nil
	})
	d := e.Desired()
	got := map[string]model.FWRule{}
	for _, r := range d.Firewall.Rules {
		if r.Source == "dnsmasq" {
			got[r.ID] = r
		}
	}
	for id, want := range map[string]string{
		"gen-dhcp-wgServer": "udp 67 wgServer", "gen-dns-udp-wgServer": "udp 53 wgServer", "gen-dns-tcp-wgServer": "tcp 53 wgServer",
		"gen-dns-udp-wgBridge0": "udp 53 wgBridge0", "gen-dns-tcp-wgBridge0": "tcp 53 wgBridge0",
	} {
		r, ok := got[id]
		if !ok || r.Chain != "input" || r.Action != "accept" || r.Proto+" "+r.DstPort+" "+r.InIface != want {
			t.Errorf("%s: %+v (want %s)", id, r, want)
		}
	}
	if len(got) != 5 {
		t.Errorf("%d generated rules: %v", len(got), got)
	}
	if d.Firewall.Rules[0].Source != "dnsmasq" {
		t.Errorf("generated rules should come before yours: first is %+v", d.Firewall.Rules[0])
	}
	mustUpdate(t, e, func(c *model.Config) error { c.DNSMasq.Enabled = false; return nil })
	for _, r := range e.Desired().Firewall.Rules {
		if r.Source == "dnsmasq" {
			t.Errorf("rule left behind after switching off: %+v", r)
		}
	}
}

func TestAccessPoints(t *testing.T) {
	e, _ := newSvcTest(t)
	ap := model.AccessPoint{ID: "a1", Interface: "wlan0", SSID: "Home", Band: "2.4", Channel: 6, Security: "wpa2", Passphrase: "correct horse"}
	if is := mustUpdate(t, e, func(c *model.Config) error { c.AccessPoints = []model.AccessPoint{ap}; return nil }); len(is) != 0 {
		t.Fatalf("issues: %v", is)
	}
	if st, ok := e.ServiceStatus("hostapd-wlan0"); !ok || !st.Running {
		t.Fatalf("hostapd not running: %+v %v", st, ok)
	}
	// An interface that isn't there is an issue, not a crash loop.
	bad := ap
	bad.ID, bad.Interface = "a2", "wlan9"
	is := mustUpdate(t, e, func(c *model.Config) error { c.AccessPoints = []model.AccessPoint{ap, bad}; return nil })
	if !hasIssue(is, "access point", "wlan9 doesn't exist") {
		t.Errorf("missing interface: %v", is)
	}
	if _, ok := e.ServiceStatus("hostapd-wlan9"); ok {
		t.Error("started on a missing interface")
	}
	// No hostapd installed.
	e.svc.findHostapd = func() (string, error) { return "", errors.New("hostapd is not installed") }
	if is := e.Reapply(); !hasIssue(is, "access point", "not installed") {
		t.Errorf("missing hostapd: %v", is)
	}
	e.svc.findHostapd = func() (string, error) { return "/usr/sbin/hostapd", nil }
	// Disabling or deleting stops it.
	mustUpdate(t, e, func(c *model.Config) error {
		c.AccessPoints[0].Disabled = true
		c.AccessPoints = c.AccessPoints[:1]
		return nil
	})
	if _, ok := e.ServiceStatus("hostapd-wlan0"); ok {
		t.Error("a disabled access point is still running")
	}
}
