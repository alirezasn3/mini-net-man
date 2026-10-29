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

	"github.com/alirezasn3/mini-net-man/internal/dnslist"
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

func TestAddressListDomains(t *testing.T) {
	cfg, _ := engine.DefaultConfig("correct horse")
	cfg.Web.AllowedIPs = []string{"127.0.0.1"}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := engine.New(kernel.NewMock(), cfg, filepath.Join(t.TempDir(), "config.yaml"), quiet)
	eng.SetLookup(dnslist.DemoLookup)
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

	if code, out := call("POST", "/api/address-lists", `{"list":"cdn","address":"Example.com"}`, c); code != 200 {
		t.Fatalf("add a domain: %d %s", code, out)
	}
	if code, _ := call("POST", "/api/address-lists", `{"list":"cdn","address":"example.COM."}`, c); code != 400 {
		t.Errorf("the same name spelled differently: %d", code)
	}
	if code, out := call("POST", "/api/address-lists", `{"list":"cdn","address":"not_a domain"}`, c); code != 400 {
		t.Errorf("junk accepted: %d %s", code, out)
	}
	code, out := call("POST", "/api/address-lists/bulk", `{"list":"cdn","addresses":"example.com\nother.example.net # cdn\n10.1.0.0/16"}`, c)
	var bulk struct{ Added, Skipped int }
	_ = json.Unmarshal([]byte(out), &bulk)
	if code != 200 || bulk.Added != 2 || bulk.Skipped != 1 {
		t.Errorf("bulk with names: %d %s", code, out)
	}
	if code, out := call("POST", "/api/address-lists/bulk", `{"list":"cdn","addresses":"fine.example.com\nbad name"}`, c); code != 400 || !strings.Contains(out, "bad") {
		t.Errorf("bulk with a bad name: %d %s", code, out)
	}

	var doms []struct {
		List, Domain string
		Addresses    []string
		Error        string
	}
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		_, out = call("GET", "/api/address-lists/domains", "", c)
		doms = nil
		_ = json.Unmarshal([]byte(out), &doms)
		if len(doms) == 2 && len(doms[0].Addresses) > 0 && len(doms[1].Addresses) > 0 {
			break
		}
	}
	if len(doms) != 2 || doms[0].Domain != "example.com" || doms[1].Domain != "other.example.net" || len(doms[0].Addresses) != 2 {
		t.Fatalf("domains: %s", out)
	}
	_, out = call("GET", "/api/address-lists/dynamic", "", c)
	if !strings.Contains(out, `"domain":"example.com"`) {
		t.Errorf("resolved addresses should say where they came from: %s", out)
	}
}

func TestDeleteSeveralAtOnce(t *testing.T) {
	cfg, _ := engine.DefaultConfig("correct horse")
	cfg.Web.AllowedIPs = []string{"127.0.0.1"}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := engine.New(kernel.NewMock(), cfg, filepath.Join(t.TempDir(), "config.yaml"), quiet)
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

	call("POST", "/api/address-lists/bulk", `{"list":"bl","addresses":"10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5"}`, c)
	var all []struct{ ID, Address string }
	_, out := call("GET", "/api/address-lists", "", c)
	_ = json.Unmarshal([]byte(out), &all)
	if len(all) != 5 {
		t.Fatalf("setup: %s", out)
	}
	ids := `["` + all[0].ID + `","` + all[2].ID + `","` + all[3].ID + `","nosuchid"]`
	code, out := call("POST", "/api/address-lists/delete", `{"ids":`+ids+`}`, c)
	var got struct {
		Removed int
		Issues  []any
	}
	_ = json.Unmarshal([]byte(out), &got)
	if code != 200 || got.Removed != 3 || got.Issues == nil {
		t.Errorf("delete: %d %s", code, out)
	}
	if left := eng.Config().AddressLists; len(left) != 2 || left[0].ID != all[1].ID || left[1].ID != all[4].ID {
		t.Errorf("wrong entries left, or order changed: %+v", left)
	}
	if code, _ := call("POST", "/api/address-lists/delete", `{"ids":["nosuchid"]}`, c); code != 404 {
		t.Errorf("only unknown ids: %d", code)
	}
	if code, _ := call("POST", "/api/address-lists/delete", `{"ids":[]}`, c); code != 400 {
		t.Errorf("no ids: %d", code)
	}
	// Every list has it.
	call("POST", "/api/routes", `{"dst":"10.9.0.0/24","dev":"lo"}`, c)
	call("POST", "/api/routes", `{"dst":"10.9.1.0/24","dev":"lo"}`, c)
	var routes []struct{ ID string }
	_, out = call("GET", "/api/routes", "", c)
	_ = json.Unmarshal([]byte(out), &routes)
	if code, out := call("POST", "/api/routes/delete", `{"ids":["`+routes[0].ID+`","`+routes[1].ID+`"]}`, c); code != 200 || !strings.Contains(out, `"removed":2`) {
		t.Errorf("routes: %d %s", code, out)
	}
	if n := len(eng.Config().Routes); n != 0 {
		t.Errorf("%d routes left", n)
	}
}
