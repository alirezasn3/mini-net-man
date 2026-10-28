package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alirezasn3/mini-net-man/internal/engine"
	"github.com/alirezasn3/mini-net-man/internal/kernel"
)

func TestAPIToken(t *testing.T) {
	cfg, err := engine.DefaultConfig("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Web.AllowedIPs = []string{"127.0.0.1"}
	path := filepath.Join(t.TempDir(), "config.yaml")
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := engine.New(kernel.NewMock(), cfg, path, quiet)
	ts := httptest.NewServer(New(eng, nil, "", true, "test", quiet).Handler())
	defer ts.Close()

	do := func(method, p, body, auth string, cookies []*http.Cookie) (int, string) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, ts.URL+p, rd)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(`{"username":"admin","password":"correct horse"}`))
	req.Header.Set("Content-Type", "application/json")
	res, _ := http.DefaultClient.Do(req)
	cookies := res.Cookies()

	create := func(body string) (int, string, string) {
		code, out := do("POST", "/api/tokens", body, "", cookies)
		var got struct{ Token string }
		_ = json.Unmarshal([]byte(out), &got)
		return code, out, got.Token
	}

	if code, _, _ := create(`{"name":"x","password":"nope"}`); code != 403 {
		t.Errorf("wrong password: %d", code)
	}
	if code, _, _ := create(`{"name":"  ","password":"correct horse"}`); code != 400 {
		t.Errorf("empty name: %d", code)
	}
	code, out, full := create(`{"name":"grafana","password":"correct horse"}`)
	if code != 200 || !strings.HasPrefix(full, "mnm_") {
		t.Fatalf("create: %d %s", code, out)
	}
	if code, _, _ := create(`{"name":"GRAFANA","password":"correct horse"}`); code != 400 {
		t.Errorf("duplicate name: %d", code)
	}
	_, out, ro := create(`{"name":"monitor","read_only":true,"password":"correct horse"}`)
	if ro == "" {
		t.Fatalf("read-only create: %s", out)
	}

	// The secret is not stored or listed: only its hash.
	code, list := do("GET", "/api/tokens", "", "", cookies)
	if code != 200 || strings.Contains(list, full) || !strings.Contains(list, "grafana") {
		t.Errorf("list: %d %s", code, list)
	}
	if b, _ := io.ReadAll(mustOpen(t, path)); strings.Contains(string(b), full) {
		t.Error("the token secret was written to the config")
	}

	bearer := "Bearer " + full
	if code, _ := do("GET", "/api/routes", "", bearer, nil); code != 200 {
		t.Errorf("token read: %d", code)
	}
	// No JSON content type needed: a token can't be sent cross-site by a browser.
	if code, out := do("POST", "/api/routes", `{"dst":"10.9.0.0/24","dev":"lo"}`, bearer, nil); code != 200 {
		t.Errorf("token write: %d %s", code, out)
	}
	if code, out := do("GET", "/api/routes", "", bearer, nil); !strings.Contains(out, "10.9.0.0/24") {
		t.Errorf("route not created: %d %s", code, out)
	}

	// A read-only token reads but never writes.
	if code, _ := do("GET", "/api/routes", "", "Bearer "+ro, nil); code != 200 {
		t.Errorf("read-only read: %d", code)
	}
	if code, _ := do("POST", "/api/routes", `{"dst":"10.8.0.0/24","dev":"lo"}`, "Bearer "+ro, nil); code != 403 {
		t.Errorf("read-only write: %d", code)
	}
	if code, _ := do("POST", "/api/reapply", `{}`, "Bearer "+ro, nil); code != 403 {
		t.Errorf("read-only reapply: %d", code)
	}

	// Account and token management stays with a logged-in person.
	for _, c := range []struct{ m, p, b string }{
		{"POST", "/api/tokens", `{"name":"y","password":"correct horse"}`},
		{"GET", "/api/tokens", ""},
		{"POST", "/api/password", `{"old":"correct horse","new":"another one!"}`},
		{"POST", "/api/username", `{"password":"correct horse","new":"root"}`},
		{"PUT", "/api/settings/web", `{"listen":"0.0.0.0","port":8080,"allowed_ips":[]}`},
		{"POST", "/api/update/install", `{}`},
	} {
		if code, _ := do(c.m, c.p, c.b, bearer, nil); code != 403 {
			t.Errorf("token reached %s %s: %d", c.m, c.p, code)
		}
	}

	// Bad tokens are refused and, like bad passwords, lock the address out.
	for _, h := range []string{"Bearer mnm_nonsense", "Bearer", "Basic abc", "Bearer " + full + "x", "Bearer mnm_" + strings.Repeat("0", 64)} {
		if code, _ := do("GET", "/api/routes", "", h, nil); code != 401 && code != 429 {
			t.Errorf("%q: %d", h, code)
		}
	}
	if code, _ := do("GET", "/api/routes", "", bearer, nil); code != 429 {
		t.Errorf("address not locked out after repeated bad tokens: %d", code)
	}
}

func TestAPITokenRevoke(t *testing.T) {
	cfg, _ := engine.DefaultConfig("correct horse")
	cfg.Web.AllowedIPs = []string{"127.0.0.1"}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := engine.New(kernel.NewMock(), cfg, filepath.Join(t.TempDir(), "config.yaml"), quiet)
	ts := httptest.NewServer(New(eng, nil, "", true, "test", quiet).Handler())
	defer ts.Close()
	call := func(method, p, body string, hdr map[string]string, cookies []*http.Cookie) (int, string) {
		req, _ := http.NewRequest(method, ts.URL+p, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(`{"username":"admin","password":"correct horse"}`))
	req.Header.Set("Content-Type", "application/json")
	res, _ := http.DefaultClient.Do(req)
	cookies := res.Cookies()

	_, out := call("POST", "/api/tokens", `{"name":"app","password":"correct horse"}`, nil, cookies)
	var tok struct{ ID, Token string }
	_ = json.Unmarshal([]byte(out), &tok)
	h := map[string]string{"Authorization": "Bearer " + tok.Token}
	if code, _ := call("GET", "/api/me", "", h, nil); code != 200 {
		t.Fatalf("token should work: %d", code)
	}
	if code, _ := call("DELETE", "/api/tokens/"+tok.ID, "", nil, cookies); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := call("GET", "/api/me", "", h, nil); code != 401 {
		t.Errorf("deleted token still works: %d", code)
	}
	if code, _ := call("DELETE", "/api/tokens/"+tok.ID, "", nil, cookies); code != 404 {
		t.Errorf("deleting twice: %d", code)
	}
}

func mustOpen(t *testing.T, path string) io.Reader {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
