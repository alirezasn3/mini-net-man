package model

import (
	"strings"
	"testing"
)

func TestLeaseSeconds(t *testing.T) {
	for in, want := range map[string]int{"": 43200, "12h": 43200, "90m": 5400, "2d": 172800, "3600": 3600, "120s": 120, "INFINITE": -1} {
		if got, err := LeaseSeconds(in); err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"1m", "60", "abc", "12 h", "-5", "1w", "400d"} {
		if _, err := LeaseSeconds(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDHCPAndDNSValidation(t *testing.T) {
	ok := func(c Config) error { return c.Validate() }
	scope := DHCPScope{ID: "s", Interface: "br0", Start: "192.168.1.10", End: "192.168.1.20"}
	good := Config{
		DNSMasq:    DNSMasq{Enabled: true, DNS: true, Upstreams: []string{"1.1.1.1", "9.9.9.9#5353", "2606:4700:4700::1111"}, Domain: "lan", CacheSize: 1000},
		DHCPScopes: []DHCPScope{scope},
		DHCPHosts:  []DHCPHost{{ID: "h", MAC: "AA:BB:CC:00:11:22", IP: "192.168.1.5", Hostname: "nas"}},
		DNSRecords: []DNSRecord{{ID: "r1", Name: "router.lan", Address: "192.168.1.1"}, {ID: "r2", Name: "files", Address: "nas.lan"}},
	}
	if err := ok(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := func(what, want string, edit func(*Config)) {
		t.Helper()
		c := good
		c.DHCPScopes = append([]DHCPScope{}, good.DHCPScopes...)
		c.DHCPHosts = append([]DHCPHost{}, good.DHCPHosts...)
		c.DNSRecords = append([]DNSRecord{}, good.DNSRecords...)
		edit(&c)
		if err := ok(c); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v (want an error with %q)", what, err, want)
		}
	}
	bad("range backwards", "ends before", func(c *Config) { c.DHCPScopes[0].End = "192.168.1.5" })
	bad("ipv6 range", "IPv4", func(c *Config) { c.DHCPScopes[0].Start = "fd00::1" })
	bad("no interface", "interface", func(c *Config) { c.DHCPScopes[0].Interface = "" })
	bad("short lease", "2 minutes", func(c *Config) { c.DHCPScopes[0].LeaseTime = "30s" })
	bad("bad router", "router", func(c *Config) { c.DHCPScopes[0].Router = "gateway" })
	bad("bad dns", "DNS server", func(c *Config) { c.DHCPScopes[0].DNS = []string{"fd00::1"} })
	bad("two scopes on one interface", "two DHCP scopes", func(c *Config) {
		c.DHCPScopes = append(c.DHCPScopes, DHCPScope{ID: "s2", Interface: "br0", Start: "10.0.0.1", End: "10.0.0.9"})
	})
	bad("bad mac", "MAC", func(c *Config) { c.DHCPHosts[0].MAC = "aa:bb" })
	bad("duplicate mac", "already has a fixed address", func(c *Config) {
		c.DHCPHosts = append(c.DHCPHosts, DHCPHost{ID: "h2", MAC: "aa-bb-cc-00-11-22", IP: "192.168.1.6"})
	})
	bad("duplicate ip", "already given", func(c *Config) {
		c.DHCPHosts = append(c.DHCPHosts, DHCPHost{ID: "h2", MAC: "aa:bb:cc:00:11:33", IP: "192.168.1.5"})
	})
	bad("bad hostname", "hostname", func(c *Config) { c.DHCPHosts[0].Hostname = "my nas" })
	bad("bad record name", "invalid name", func(c *Config) { c.DNSRecords[0].Name = "a b.lan" })
	bad("record to junk", "neither an IP", func(c *Config) { c.DNSRecords[0].Address = "not an address" })
	bad("duplicate record", "twice", func(c *Config) {
		c.DNSRecords = append(c.DNSRecords, DNSRecord{ID: "r3", Name: "Router.lan.", Address: "192.168.1.1"})
	})
	bad("bad upstream", "upstream", func(c *Config) { c.DNSMasq.Upstreams = []string{"dns.google"} })
	bad("bad upstream port", "port", func(c *Config) { c.DNSMasq.Upstreams = []string{"1.1.1.1#99999"} })
	bad("bad domain", "domain", func(c *Config) { c.DNSMasq.Domain = "my lan" })
	bad("huge cache", "cache", func(c *Config) { c.DNSMasq.CacheSize = 100000 })

	// A disabled item doesn't clash with the one that replaces it.
	c := good
	c.DHCPScopes = []DHCPScope{scope, {ID: "s2", Interface: "br0", Start: "10.0.0.1", End: "10.0.0.9", Disabled: true}}
	if err := c.Validate(); err != nil {
		t.Errorf("a disabled twin was counted: %v", err)
	}
}

func TestAccessPointValidation(t *testing.T) {
	good := AccessPoint{ID: "a", Interface: "wlan0", SSID: "Home", Band: "5", Channel: 36, Country: "DE", Security: "wpa2+wpa3", Passphrase: "correct horse", N: true, AC: true}
	check := func(c Config) error { return c.Validate() }
	if err := check(Config{AccessPoints: []AccessPoint{good}}); err != nil {
		t.Fatalf("valid access point rejected: %v", err)
	}
	bad := func(what, want string, edit func(*AccessPoint)) {
		t.Helper()
		a := good
		edit(&a)
		if err := check(Config{AccessPoints: []AccessPoint{a}}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v (want an error with %q)", what, err, want)
		}
	}
	bad("no interface", "interface", func(a *AccessPoint) { a.Interface = "" })
	bad("empty ssid", "SSID", func(a *AccessPoint) { a.SSID = "" })
	bad("long ssid", "SSID", func(a *AccessPoint) { a.SSID = strings.Repeat("x", 33) })
	bad("control in ssid", "control", func(a *AccessPoint) { a.SSID = "a\nb" })
	bad("bad band", "band", func(a *AccessPoint) { a.Band = "6" })
	bad("5 GHz channel on 2.4", "2.4 GHz channel", func(a *AccessPoint) { a.Band, a.AC, a.Channel = "2.4", false, 36 })
	bad("2.4 channel on 5", "5 GHz channel", func(a *AccessPoint) { a.Channel = 6 })
	bad("ac on 2.4", "ac only exists", func(a *AccessPoint) { a.Band, a.Channel = "2.4", 6 })
	bad("5 GHz without a country", "country", func(a *AccessPoint) { a.Country = "" })
	bad("lower-case country", "country", func(a *AccessPoint) { a.Country = "de" })
	bad("short password", "8 to 63", func(a *AccessPoint) { a.Passphrase = "short" })
	bad("non-ascii password", "ASCII", func(a *AccessPoint) { a.Passphrase = "pässword123" })
	bad("hex key with wpa3", "WPA2", func(a *AccessPoint) { a.Passphrase = strings.Repeat("ab", 32) })
	bad("bad security", "security", func(a *AccessPoint) { a.Security = "wep" })
	bad("too many clients", "max clients", func(a *AccessPoint) { a.MaxClients = 5000 })

	// A raw key is fine for WPA2, a password isn't needed when open, automatic channel is fine.
	for what, edit := range map[string]func(*AccessPoint){
		"hex wpa2": func(a *AccessPoint) { a.Security, a.Passphrase = "wpa2", strings.Repeat("AB", 32) },
		"open":     func(a *AccessPoint) { a.Security, a.Passphrase = "open", "" },
		"auto":     func(a *AccessPoint) { a.Channel = 0 },
		"2.4":      func(a *AccessPoint) { a.Band, a.AC, a.Channel, a.Country = "2.4", false, 11, "" },
	} {
		a := good
		edit(&a)
		if err := check(Config{AccessPoints: []AccessPoint{a}}); err != nil {
			t.Errorf("%s rejected: %v", what, err)
		}
	}

	two := Config{AccessPoints: []AccessPoint{good, {ID: "b", Interface: "wlan0", SSID: "x", Band: "2.4", Channel: 1, Security: "open"}}}
	if err := two.Validate(); err == nil || !strings.Contains(err.Error(), "two access points") {
		t.Errorf("two on one interface: %v", err)
	}
	inBridge := Config{AccessPoints: []AccessPoint{good}, Bridges: []Bridge{{ID: "br", Name: "br0", Ports: []string{"eth1", "wlan0"}}}}
	if err := inBridge.Validate(); err == nil || !strings.Contains(err.Error(), "Bridge instead") {
		t.Errorf("access point also a bridge port: %v", err)
	}
	inBridge.Bridges[0].Disabled = true
	if err := inBridge.Validate(); err != nil {
		t.Errorf("a disabled bridge counted: %v", err)
	}
}
