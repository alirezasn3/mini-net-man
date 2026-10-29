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

func TestAddressListAPI(t *testing.T) {
	cfg, _ := engine.DefaultConfig("correct horse")
	cfg.Web.AllowedIPs = []string{"127.0.0.1"}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	k := kernel.NewMock()
	eng := engine.New(k, cfg, filepath.Join(t.TempDir(), "config.yaml"), quiet)
	ts := httptest.NewServer(New(eng, nil, "", true, "test", quiet).Handler())
	defer ts.Close()
	call := func(method, p, body string, cookies []*http.Cookie) (int, string) {
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
		return res.StatusCode, string(b)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(`{"username":"admin","password":"correct horse"}`))
	req.Header.Set("Content-Type", "application/json")
	res, _ := http.DefaultClient.Do(req)
	c := res.Cookies()

	if code, _ := call("POST", "/api/address-lists", `{"list":"1bad","address":"10.0.0.1"}`, c); code != 400 {
		t.Errorf("bad list name: %d", code)
	}
	code, out := call("POST", "/api/address-lists", `{"list":"bl","address":"10.0.0.0/24","comment":"office"}`, c)
	var made struct{ ID string }
	_ = json.Unmarshal([]byte(out), &made)
	if code != 200 || made.ID == "" {
		t.Fatalf("add: %d %s", code, out)
	}
	if code, _ := call("POST", "/api/address-lists", `{"list":"bl","address":"10.0.0.0-10.0.0.255"}`, c); code != 400 {
		t.Errorf("the same range under another spelling was accepted: %d", code)
	}

	// Bulk: comments, blank lines, mixed separators, duplicates of what exists.
	code, out = call("POST", "/api/address-lists/bulk", `{"list":"bl","addresses":"# my blocklist\n10.0.0.0/24 ; already there\n192.0.2.1, 192.0.2.2\n\n198.51.100.0-198.51.100.9\n2001:db8::/32\n192.0.2.1"}`, c)
	var bulk struct{ Added, Skipped int }
	_ = json.Unmarshal([]byte(out), &bulk)
	if code != 200 || bulk.Added != 4 || bulk.Skipped != 2 {
		t.Errorf("bulk: %d %s (added %d, skipped %d; want 4 and 2)", code, out, bulk.Added, bulk.Skipped)
	}
	// All or nothing.
	before := len(eng.Config().AddressLists)
	code, out = call("POST", "/api/address-lists/bulk", `{"list":"bl","addresses":["203.0.113.1","nonsense","300.1.1.1"]}`, c)
	if code != 400 || !strings.Contains(out, "nonsense") || len(eng.Config().AddressLists) != before {
		t.Errorf("invalid bulk: %d %s, entries %d -> %d", code, out, before, len(eng.Config().AddressLists))
	}
	// Replace swaps the list's entries and leaves other lists alone.
	call("POST", "/api/address-lists", `{"list":"other","address":"10.9.9.9"}`, c)
	code, out = call("POST", "/api/address-lists/bulk", `{"list":"bl","addresses":["192.0.2.50"],"replace":true}`, c)
	n, other := 0, 0
	for _, e := range eng.Config().AddressLists {
		switch e.List {
		case "bl":
			n++
		case "other":
			other++
		}
	}
	if code != 200 || n != 1 || other != 1 {
		t.Errorf("replace: %d %s: bl has %d, other has %d", code, out, n, other)
	}

	// Entries a rule would add are listed and can be removed.
	code, out = call("GET", "/api/address-lists/dynamic", "", c)
	var dyn []kernel.DynAddr
	_ = json.Unmarshal([]byte(out), &dyn)
	if code != 200 || len(dyn) != 3 {
		t.Fatalf("dynamic: %d %s", code, out)
	}
	if code, _ := call("DELETE", "/api/address-lists/dynamic?address=203.0.113.50", "", c); code != 400 {
		t.Errorf("address without a list: %d", code)
	}
	if code, _ := call("DELETE", "/api/address-lists/dynamic?list=ssh-stage1&address=203.0.113.50", "", c); code != 200 {
		t.Errorf("delete one: %d", code)
	}
	if code, _ := call("DELETE", "/api/address-lists/dynamic?list=ssh-blocked", "", c); code != 200 {
		t.Errorf("flush one list: %d", code)
	}
	_, out = call("GET", "/api/address-lists/dynamic", "", c)
	if strings.TrimSpace(out) != "[]" {
		t.Errorf("dynamic after removing everything: %s", out)
	}

	// The entry list is an ordinary list: edit and delete work.
	if code, _ := call("DELETE", "/api/address-lists/"+made.ID, "", c); code != 404 {
		t.Errorf("replace should have removed the first entry: %d", code)
	}

	// A firewall rule can use the list from the API too.
	if code, out := call("POST", "/api/firewall/rules", `{"chain":"input","action":"drop","src_list":"bl"}`, c); code != 200 {
		t.Errorf("rule with src_list: %d %s", code, out)
	}
}
