package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/engine"
	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/svc"
)

type apiClient struct {
	t       *testing.T
	url     string
	cookies []*http.Cookie
}

func (a *apiClient) do(method, p, body string) (int, string) {
	a.t.Helper()
	req, _ := http.NewRequest(method, a.url+p, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range a.cookies {
		req.AddCookie(c)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func newAPI(t *testing.T) (*apiClient, *engine.Engine) {
	t.Helper()
	cfg, _ := engine.DefaultConfig("correct horse")
	cfg.Web.AllowedIPs = []string{"127.0.0.1"}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := engine.New(kernel.NewMock(), cfg, filepath.Join(t.TempDir(), "config.yaml"), quiet)
	eng.SetMockServices(svc.NewFake(quiet))
	ts := httptest.NewServer(New(eng, nil, "", true, "test", quiet).Handler())
	t.Cleanup(ts.Close)
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(`{"username":"admin","password":"correct horse"}`))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return &apiClient{t: t, url: ts.URL, cookies: res.Cookies()}, eng
}

func TestDHCPAndDNSAPI(t *testing.T) {
	a, eng := newAPI(t)
	if code, out := a.do("PUT", "/api/dnsmasq", `{"enabled":true,"dns":true,"upstreams":["1.1.1.1"],"domain":"lan"}`); code != 200 {
		t.Fatalf("settings: %d %s", code, out)
	}
	if code, _ := a.do("PUT", "/api/dnsmasq", `{"enabled":true,"upstreams":["not-an-ip"]}`); code != 400 {
		t.Errorf("bad upstream: %d", code)
	}
	code, out := a.do("GET", "/api/dnsmasq", "")
	if code != 200 || !strings.Contains(out, `"interfaces":[]`) || !strings.Contains(out, `"1.1.1.1"`) {
		t.Errorf("get settings: %d %s", code, out)
	}
	if code, out := a.do("POST", "/api/dhcp/scopes", `{"interface":"wgServer","start":"10.0.5.10","end":"10.0.5.50"}`); code != 200 || !strings.Contains(out, `"id"`) {
		t.Fatalf("scope: %d %s", code, out)
	}
	if code, _ := a.do("POST", "/api/dhcp/scopes", `{"interface":"wgServer","start":"10.0.6.10","end":"10.0.6.50"}`); code != 400 {
		t.Errorf("a second scope on one interface: %d", code)
	}
	if code, _ := a.do("POST", "/api/dhcp/scopes", `{"interface":"eth1","start":"10.0.9.50","end":"10.0.9.10"}`); code != 400 {
		t.Errorf("backwards range: %d", code)
	}
	if code, out := a.do("POST", "/api/dhcp/hosts", `{"mac":"B8-27-EB-00-00-07","ip":"192.168.50.10","hostname":"nas"}`); code != 200 {
		t.Fatalf("host: %d %s", code, out)
	}
	if code, out := a.do("POST", "/api/dns/records", `{"name":"router.lan","address":"10.0.5.1"}`); code != 200 {
		t.Fatalf("record: %d %s", code, out)
	}

	code, out = a.do("GET", "/api/dnsmasq/status", "")
	var st struct {
		Installed, Wanted, Running bool
		Conflicts                  []string
		Log                        []string
	}
	_ = json.Unmarshal([]byte(out), &st)
	if code != 200 || !st.Installed || !st.Wanted || !st.Running || st.Conflicts == nil || len(st.Log) == 0 {
		t.Errorf("status: %d %s", code, out)
	}

	code, out = a.do("GET", "/api/dhcp/leases", "")
	var ls []struct {
		MAC       string
		Static    bool
		Remaining int
	}
	_ = json.Unmarshal([]byte(out), &ls)
	var fixedSeen bool
	for _, l := range ls {
		if l.MAC == "b8:27:eb:00:00:07" && l.Static {
			fixedSeen = true
		}
	}
	if code != 200 || len(ls) < 3 || !fixedSeen {
		t.Errorf("leases: %d %s", code, out)
	}

	_, out = a.do("GET", "/api/services/config", "")
	for _, want := range []string{"dhcp-range=tag:wgServer", "dhcp-host=b8:27:eb:00:00:07,192.168.50.10,nas", "host-record=router.lan,10.0.5.1", "server=1.1.1.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("config preview misses %q: %s", want, out)
		}
	}
	// The firewall opens for it by itself.
	var found bool
	for _, r := range eng.Desired().Firewall.Rules {
		found = found || (r.Source == "dnsmasq" && r.DstPort == "67")
	}
	if !found {
		t.Error("no generated DHCP firewall rule")
	}
}

func TestAccessPointAPIHidesThePassword(t *testing.T) {
	a, eng := newAPI(t)
	if code, out := a.do("POST", "/api/access-points", `{"interface":"wlan0","ssid":"Home","band":"2.4","channel":6,"security":"wpa2","passphrase":"short"}`); code != 400 {
		t.Errorf("a short password: %d %s", code, out)
	}
	code, out := a.do("POST", "/api/access-points", `{"interface":"wlan0","ssid":"Home","band":"2.4","channel":6,"security":"wpa2+wpa3","passphrase":"correct horse battery","n":true}`)
	var made struct{ ID string }
	_ = json.Unmarshal([]byte(out), &made)
	if code != 200 || made.ID == "" {
		t.Fatalf("add: %d %s", code, out)
	}
	for _, p := range []string{"/api/access-points", "/api/services/config"} {
		if _, out := a.do("GET", p, ""); strings.Contains(out, "correct horse battery") {
			t.Errorf("GET %s leaks the password: %s", p, out)
		}
	}
	_, out = a.do("GET", "/api/access-points", "")
	if !strings.Contains(out, `"has_passphrase":true`) {
		t.Errorf("the list should say a password is set: %s", out)
	}
	if _, out := a.do("GET", "/api/services/config", ""); !strings.Contains(out, "wpa_passphrase=********") {
		t.Errorf("config preview: %s", out)
	}

	// Saving without a password keeps the one stored.
	if code, out := a.do("PUT", "/api/access-points/"+made.ID, `{"interface":"wlan0","ssid":"Home 2","band":"2.4","channel":11,"security":"wpa2+wpa3","passphrase":""}`); code != 200 {
		t.Fatalf("edit: %d %s", code, out)
	}
	if got := eng.Config().AccessPoints[0]; got.SSID != "Home 2" || got.Passphrase != "correct horse battery" {
		t.Errorf("after an edit without a password: %+v", got)
	}
	// A new one replaces it; open drops it.
	a.do("PUT", "/api/access-points/"+made.ID, `{"interface":"wlan0","ssid":"Home 2","band":"2.4","channel":11,"security":"wpa2","passphrase":"another password"}`)
	if got := eng.Config().AccessPoints[0].Passphrase; got != "another password" {
		t.Errorf("new password: %q", got)
	}
	a.do("PUT", "/api/access-points/"+made.ID, `{"interface":"wlan0","ssid":"Guests","band":"2.4","channel":11,"security":"open"}`)
	if got := eng.Config().AccessPoints[0]; got.Passphrase != "" || got.Security != "open" {
		t.Errorf("open network keeps a password: %+v", got)
	}
	if code, _ := a.do("PUT", "/api/access-points/nosuch", `{"interface":"wlan0","ssid":"x","band":"2.4","channel":1,"security":"open"}`); code != 404 {
		t.Errorf("edit of a missing one: %d", code)
	}

	// Status, with the fake process running; kick a device.
	var states []struct {
		ID       string
		Exists   bool
		Wireless bool
		Process  struct{ Running bool }
		Stations []struct{ MAC string }
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, out = a.do("GET", "/api/access-points/status", "")
		states = nil
		_ = json.Unmarshal([]byte(out), &states)
		if len(states) == 1 && states[0].Process.Running || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(states) != 1 || !states[0].Exists || !states[0].Wireless || !states[0].Process.Running || len(states[0].Stations) == 0 {
		t.Fatalf("status: %s", out)
	}
	if code, _ := a.do("POST", "/api/access-points/"+made.ID+"/kick", `{"mac":"3c:22:fb:10:aa:01"}`); code != 200 {
		t.Errorf("kick: %d", code)
	}
	if code, _ := a.do("POST", "/api/access-points/nosuch/kick", `{"mac":"3c:22:fb:10:aa:01"}`); code != 404 {
		t.Errorf("kick on a missing one: %d", code)
	}
	if code, out := a.do("POST", "/api/access-points/delete", `{"ids":["`+made.ID+`"]}`); code != 200 || !strings.Contains(out, `"removed":1`) {
		t.Errorf("delete: %d %s", code, out)
	}
	if n := len(eng.Config().AccessPoints); n != 0 {
		t.Errorf("%d left", n)
	}
}
