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
)

func TestChangeUsername(t *testing.T) {
	cfg, err := engine.DefaultConfig("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Web.AllowedIPs = []string{"127.0.0.1"}
	eng := engine.New(kernel.NewMock(), cfg, filepath.Join(t.TempDir(), "config.yaml"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(New(eng, nil, "", true, "test", slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer ts.Close()

	post := func(cookies []*http.Cookie, path, body string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(body))
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
	res, _ := post(nil, "/api/login", `{"username":"admin","password":"correct horse"}`)
	if res.StatusCode != 200 {
		t.Fatalf("login: %d", res.StatusCode)
	}
	cookies := res.Cookies()

	for name, body := range map[string]string{
		"wrong password": `{"password":"nope","new":"boss"}`,
		"empty":          `{"password":"correct horse","new":"  "}`,
		"has a space":    `{"password":"correct horse","new":"my name"}`,
		"too long":       `{"password":"correct horse","new":"` + strings.Repeat("a", 33) + `"}`,
	} {
		if res, _ := post(cookies, "/api/username", body); res.StatusCode < 400 {
			t.Errorf("%s: accepted (%d)", name, res.StatusCode)
		}
	}

	res, out := post(cookies, "/api/username", `{"password":"correct horse","new":"boss"}`)
	if res.StatusCode != 200 {
		t.Fatalf("rename: %d %s", res.StatusCode, out)
	}
	var got struct{ User string }
	_ = json.Unmarshal([]byte(out), &got)
	if got.User != "boss" {
		t.Errorf("response user = %q", got.User)
	}

	// The open session carries on under the new name; the old name is gone.
	req, _ := http.NewRequest("GET", ts.URL+"/api/me", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	me, _ := http.DefaultClient.Do(req)
	b, _ := io.ReadAll(me.Body)
	if me.StatusCode != 200 || !strings.Contains(string(b), "boss") {
		t.Errorf("session after rename: %d %s", me.StatusCode, b)
	}
	if res, _ := post(nil, "/api/login", `{"username":"admin","password":"correct horse"}`); res.StatusCode != 401 {
		t.Errorf("old username still logs in: %d", res.StatusCode)
	}
	if res, _ := post(nil, "/api/login", `{"username":"boss","password":"correct horse"}`); res.StatusCode != 200 {
		t.Errorf("new username doesn't log in: %d", res.StatusCode)
	}
}
