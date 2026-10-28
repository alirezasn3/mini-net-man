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

	"github.com/alirezasn3/mini-net-man/internal/engine"
	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
)

func TestBridgesAPIAndLinkOwners(t *testing.T) {
	cfg, _ := engine.DefaultConfig("correct horse")
	cfg.Web.AllowedIPs = []string{"127.0.0.1"}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := engine.New(kernel.NewMock(), cfg, filepath.Join(t.TempDir(), "config.yaml"), quiet)
	ts := httptest.NewServer(New(eng, nil, "", true, "test", quiet).Handler())
	defer ts.Close()
	call := func(method, p, body string, cookies []*http.Cookie) (*http.Response, string) {
		req, _ := http.NewRequest(method, ts.URL+p, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res, string(b)
	}
	res, _ := call("POST", "/api/login", `{"username":"admin","password":"correct horse"}`, nil)
	cookies := res.Cookies()

	if res, _ := call("POST", "/api/bridges", `{"name":"br0","ports":["wgBridge0","wgBridge0"]}`, cookies); res.StatusCode != 400 {
		t.Errorf("duplicate port accepted: %d", res.StatusCode)
	}
	if res, out := call("POST", "/api/bridges", `{"name":"br0","ports":["wgBridge0"]}`, cookies); res.StatusCode != 200 {
		t.Fatalf("add bridge: %d %s", res.StatusCode, out)
	}
	if res, _ := call("POST", "/api/interfaces", `{"name":"ens192"}`, cookies); res.StatusCode != 400 {
		t.Errorf("a setting that does nothing was accepted: %d", res.StatusCode)
	}

	_, out := call("GET", "/api/links", "", cookies)
	var links []model.Link
	if err := json.Unmarshal([]byte(out), &links); err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Link{}
	for _, l := range links {
		by[l.Name] = l
	}
	if l := by["br0"]; l.Type != "bridge" || strings.Join(l.ManagedBy, ",") != "mini-net-man" {
		t.Errorf("br0: %+v", l)
	}
	if l := by["wgBridge0"]; l.Master != "br0" || len(l.ManagedBy) != 1 {
		t.Errorf("wgBridge0: %+v", l)
	}
	if l := by["ens192"]; strings.Join(l.ManagedBy, ",") != "NetworkManager" {
		t.Errorf("ens192 should show the mock's NetworkManager: %+v", l)
	}
	_, out = call("GET", "/api/network/managers", "", cookies)
	if !strings.Contains(out, "NetworkManager") {
		t.Errorf("managers: %s", out)
	}
}
