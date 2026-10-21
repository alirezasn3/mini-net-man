package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		cur, cand string
		want      bool
	}{
		{"v1.2.3", "v1.2.4", true},
		{"v1.2.3", "v1.3.0", true},
		{"v1.2.3", "v2.0.0", true},
		{"v1.2.3", "v1.2.3", false},
		{"v1.2.3", "v1.2.2", false},
		{"v1.9.0", "v1.10.0", true}, // numeric, not lexical
		{"v1.0.0-rc1", "v1.0.0", true},
		{"v1.0.0", "v1.0.0-rc1", false},
		{"v1.0.0-rc1", "v1.0.0-rc2", true},
	}
	for _, c := range cases {
		got, err := Newer(c.cur, c.cand)
		if err != nil || got != c.want {
			t.Errorf("Newer(%q, %q) = %v, %v; want %v", c.cur, c.cand, got, err, c.want)
		}
	}
	for _, bad := range []string{"dev", "219a233", "1234567", "1.0.0", "", "v1.x.3", "v"} {
		if _, err := Newer(bad, "v1.0.0"); err == nil {
			t.Errorf("Newer(%q, ...) should refuse a non-release version", bad)
		}
		if Comparable(bad) {
			t.Errorf("Comparable(%q) = true", bad)
		}
	}
}

// fakeGitHub serves one release whose binary is a shell script that prints
// `reported` for `version`.
func fakeGitHub(t *testing.T, tag, reported string, corrupt bool) *Client {
	t.Helper()
	script := fmt.Sprintf("#!/bin/sh\necho %s\n", reported)
	sum := sha256.Sum256([]byte(script))
	sumLine := fmt.Sprintf("%s  %s\n%s  other-file\n", hex.EncodeToString(sum[:]), AssetName(), strings.Repeat("0", 64))
	if corrupt {
		sumLine = fmt.Sprintf("%s  %s\n", strings.Repeat("a", 64), AssetName())
	}
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/repos/o/r/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":%q,"html_url":"https://example/rel","body":"notes","assets":[
			{"name":%q,"browser_download_url":%q,"size":1},
			{"name":"checksums.txt","browser_download_url":%q,"size":1}]}`,
			tag, AssetName(), srv.URL+"/bin", srv.URL+"/sums")
	})
	mux.HandleFunc("/bin", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, script) })
	mux.HandleFunc("/sums", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, sumLine) })
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &Client{Repo: "o/r", APIBase: srv.URL, HTTP: srv.Client()}
}

func installedBinary(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "mini-net-man")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho v1.0.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return exe
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallAndRollback(t *testing.T) {
	c := fakeGitHub(t, "v1.1.0", "v1.1.0", false)
	exe := installedBinary(t)
	rel, err := c.Latest(context.Background())
	if err != nil || rel.Tag != "v1.1.0" {
		t.Fatalf("latest: %v %+v", err, rel)
	}
	if _, err := c.Install(context.Background(), rel, exe); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, exe), "v1.1.0") {
		t.Error("binary not replaced")
	}
	if !strings.Contains(read(t, exe+".old"), "v1.0.0") {
		t.Error("previous binary not kept")
	}
	if st, _ := os.Stat(exe); st.Mode()&0o111 == 0 {
		t.Error("installed binary is not executable")
	}
	if _, err := os.Stat(exe + ".new"); err == nil {
		t.Error("temporary file left behind")
	}

	if err := Rollback(exe); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, exe), "v1.0.0") || !strings.Contains(read(t, exe+".old"), "v1.1.0") {
		t.Error("rollback did not swap the binaries")
	}
}

func TestInstallRefusesBadDownloads(t *testing.T) {
	for _, tc := range []struct {
		name            string
		tag, reported   string
		corrupt         bool
		wantErrContains string
	}{
		{"checksum mismatch", "v1.1.0", "v1.1.0", true, "checksum mismatch"},
		{"binary reports another version", "v1.1.0", "v9.9.9", false, "reports version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fakeGitHub(t, tc.tag, tc.reported, tc.corrupt)
			exe := installedBinary(t)
			rel, _ := c.Latest(context.Background())
			_, err := c.Install(context.Background(), rel, exe)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErrContains)
			}
			if !strings.Contains(read(t, exe), "v1.0.0") {
				t.Error("the installed binary was touched despite the failure")
			}
			if _, err := os.Stat(exe + ".new"); err == nil {
				t.Error("rejected download left behind")
			}
		})
	}
}

func TestInstallNeedsChecksums(t *testing.T) {
	c := &Client{Repo: "o/r", HTTP: http.DefaultClient}
	rel := &Release{Tag: "v1.1.0", Assets: []Asset{{Name: AssetName(), URL: "http://unused"}}}
	if _, err := c.Install(context.Background(), rel, installedBinary(t)); err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Errorf("want a refusal to install without checksums, got %v", err)
	}
	rel = &Release{Tag: "v1.1.0"}
	if _, err := c.Install(context.Background(), rel, installedBinary(t)); err == nil || !strings.Contains(err.Error(), AssetName()) {
		t.Errorf("want a missing-asset error naming %s, got %v", AssetName(), err)
	}
}

func TestLatestErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer srv.Close()
	c := &Client{Repo: "o/r", APIBase: srv.URL, HTTP: srv.Client()}
	if _, err := c.Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "no such release") {
		t.Errorf("got %v", err)
	}
}

func TestReinstallSameVersionKeepsBackup(t *testing.T) {
	c := fakeGitHub(t, "v1.0.0", "v1.0.0", false)
	exe := installedBinary(t) // already reports v1.0.0
	if err := os.WriteFile(exe+".old", []byte("#!/bin/sh\necho v0.9.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rel, _ := c.Latest(context.Background())
	done, err := c.Install(context.Background(), rel, exe)
	if err != nil {
		t.Fatal(err)
	}
	if done.Previous != "" {
		t.Errorf("a same-version reinstall should not rotate the backup, got %q", done.Previous)
	}
	if !strings.Contains(read(t, exe+".old"), "v0.9.0") {
		t.Error("the older backup was overwritten")
	}
}
