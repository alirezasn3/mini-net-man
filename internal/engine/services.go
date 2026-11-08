package engine

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/alirezasn3/mini-net-man/internal/dnsmasq"
	"github.com/alirezasn3/mini-net-man/internal/hostapd"
	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/alirezasn3/mini-net-man/internal/svc"
)

// services are the helper programs the engine keeps running: one dnsmasq for
// DHCP and DNS, and one hostapd per access point.
type services struct {
	sup *svc.Supervisor

	findDnsmasq  func() (string, error)
	findHostapd  func() (string, error)
	checkDnsmasq func(bin, conf string) error

	dnsmasqOK   string    // the last dnsmasq config that passed the check
	dnsmasqSpec *svc.Spec // what runs now, kept if a new config is refused
}

func newServices(sup *svc.Supervisor) *services {
	return &services{sup: sup, findDnsmasq: dnsmasq.Find, findHostapd: hostapd.Find, checkDnsmasq: dnsmasq.Check}
}

// ServicesDir is where the generated configs, dnsmasq's leases and hostapd's
// control sockets live: next to config.yaml.
func (e *Engine) ServicesDir() string { return filepath.Join(filepath.Dir(e.path), "services") }

// ServiceStatus reports one helper program ("dnsmasq" or "hostapd-wlan0").
func (e *Engine) ServiceStatus(name string) (svc.Status, bool) { return e.svc.sup.Status(name) }

// DNSMasqInput is the DHCP and DNS part of a config as dnsmasq's input.
func DNSMasqInput(cfg model.Config, dir string) dnsmasq.Input {
	return dnsmasq.Input{Settings: cfg.DNSMasq, Scopes: cfg.DHCPScopes, Hosts: cfg.DHCPHosts, Records: cfg.DNSRecords, Dir: dir}
}

// Binary reports where a helper program is installed, or why it isn't.
func (e *Engine) Binary(name string) (string, error) {
	switch name {
	case "dnsmasq":
		return e.svc.findDnsmasq()
	case "hostapd":
		return e.svc.findHostapd()
	}
	return "", fmt.Errorf("unknown program %q", name)
}

// SetMockServices swaps the real programs for stand-ins that only pretend to
// run, for the -mock server.
func (e *Engine) SetMockServices(sup *svc.Supervisor) {
	e.svc.sup.Close()
	e.svc = newServices(sup)
	e.svc.findDnsmasq = func() (string, error) { return "/usr/sbin/dnsmasq", nil }
	e.svc.findHostapd = func() (string, error) { return "/usr/sbin/hostapd", nil }
	e.svc.checkDnsmasq = func(string, string) error { return nil }
}

// applyServicesLocked starts, restarts and stops the helper programs to match
// the config. Anything that stops it from starting becomes an issue.
func (e *Engine) applyServicesLocked(d Desired, add func(kind, id string, err error)) {
	s, dir := e.svc, e.ServicesDir()
	var specs []svc.Spec

	if in := d.DHCP; in.Enabled() {
		in.Dir = dir
		conf := dnsmasq.Render(in)
		bin, err := s.findDnsmasq()
		switch {
		case err != nil:
			add("dnsmasq", "", err)
		case conf == s.dnsmasqOK && s.dnsmasqSpec != nil:
			specs = append(specs, *s.dnsmasqSpec)
		default:
			// Check a new config before it replaces the working one.
			path := dnsmasq.ConfPath(dir)
			check := path + ".check"
			err := os.MkdirAll(dir, 0o755)
			if err == nil {
				err = os.WriteFile(check, []byte(conf), 0o644)
			}
			if err == nil {
				err = s.checkDnsmasq(bin, check)
				_ = os.Remove(check)
			}
			if err != nil {
				add("dnsmasq", "", err)
				if s.dnsmasqSpec != nil {
					specs = append(specs, *s.dnsmasqSpec) // keep what works
				}
				break
			}
			sp := svc.Spec{Name: "dnsmasq", Binary: bin, Args: []string{"--conf-file=" + path},
				Files: []svc.File{{Path: path, Data: []byte(conf), Mode: 0o644}}}
			s.dnsmasqOK, s.dnsmasqSpec = conf, &sp
			specs = append(specs, sp)
		}
	} else {
		s.dnsmasqOK, s.dnsmasqSpec = "", nil
	}

	var links map[string]bool
	for _, ap := range e.cfg.AccessPoints {
		if ap.Disabled {
			continue
		}
		bin, err := s.findHostapd()
		if err != nil {
			add("access point", ap.ID, err)
			continue
		}
		if links == nil {
			links = map[string]bool{}
			if ls, err := e.k.Links(); err == nil {
				for _, l := range ls {
					links[l.Name] = true
				}
			}
		}
		if !links[ap.Interface] {
			add("access point", ap.ID, fmt.Errorf("interface %s doesn't exist (yet)", ap.Interface))
			continue
		}
		path := hostapd.ConfPath(dir, ap.Interface)
		specs = append(specs, svc.Spec{Name: hostapd.Name(ap.Interface), Binary: bin, Args: []string{path},
			Files: []svc.File{{Path: path, Data: []byte(hostapd.Render(ap, dir)), Mode: 0o600, RemoveOnStop: true}}})
	}
	s.sup.Set(specs)
}
