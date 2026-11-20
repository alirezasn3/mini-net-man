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

// The panel's Disable button PUTs the whole item with disabled flipped. For a
// health check that used to vanish silently: the field wasn't part of the
// model, so the check kept running and never showed as disabled.
func TestHealthCheckCanBeDisabled(t *testing.T) {
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

	res, out := call("POST", "/api/checks", `{"name":"exit","target":"1.1.1.1","interface":"wgBridge0"}`, cookies)
	if res.StatusCode != 200 {
		t.Fatalf("add check: %d %s", res.StatusCode, out)
	}
	var made struct{ ID string }
	if err := json.Unmarshal([]byte(out), &made); err != nil || made.ID == "" {
		t.Fatalf("no id in %q (%v)", out, err)
	}
	get := func() model.Check {
		t.Helper()
		_, out := call("GET", "/api/checks", "", cookies)
		var list []model.Check
		if err := json.Unmarshal([]byte(out), &list); err != nil || len(list) != 1 {
			t.Fatalf("checks = %q (%v)", out, err)
		}
		return list[0]
	}

	item := get()
	item.Disabled = true
	body, _ := json.Marshal(item)
	if res, out := call("PUT", "/api/checks/"+made.ID, string(body), cookies); res.StatusCode != 200 {
		t.Fatalf("disable: %d %s", res.StatusCode, out)
	}
	if !get().Disabled {
		t.Error("the check is not disabled after the PUT the panel's Disable button sends")
	}
	if _, out := call("GET", "/api/checks/status", "", cookies); strings.Contains(out, made.ID) {
		t.Errorf("a disabled check is still being measured: %s", out)
	}

	item.Disabled = false
	body, _ = json.Marshal(item)
	call("PUT", "/api/checks/"+made.ID, string(body), cookies)
	if get().Disabled {
		t.Error("the check is still disabled after Enable")
	}

	// The removed feature is gone from the API.
	if res, _ := call("GET", "/api/client-routing", "", cookies); res.StatusCode != 404 {
		t.Errorf("GET /api/client-routing = %d, want 404", res.StatusCode)
	}
}
