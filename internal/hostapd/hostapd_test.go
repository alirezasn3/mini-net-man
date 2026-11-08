package hostapd

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

func has(t *testing.T, out string, wants ...string) {
	t.Helper()
	lines := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		lines[l] = true
	}
	for _, w := range wants {
		if !lines[w] {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

func TestRender(t *testing.T) {
	ap := model.AccessPoint{ID: "a", Interface: "wlan0", SSID: "Home Wi-Fi", Band: "5", Channel: 36, Country: "DE", Security: "wpa2+wpa3",
		Passphrase: "correct horse #1", Bridge: "br0", Isolate: true, MaxClients: 20, N: true, AC: true, AX: true, Hidden: true, Comment: "x\nbad=1"}
	out := Render(ap, "/etc/mnm/services")
	has(t, out, "interface=wlan0", "driver=nl80211", "ctrl_interface=/etc/mnm/services/hostapd-ctrl", "ssid=Home Wi-Fi",
		"country_code=DE", "ieee80211d=1", "ieee80211h=1", "hw_mode=a", "channel=36", "ieee80211n=1", "ieee80211ac=1", "ieee80211ax=1",
		"ignore_broadcast_ssid=1", "ap_isolate=1", "max_num_sta=20", "bridge=br0", "wpa=2", "rsn_pairwise=CCMP",
		"wpa_key_mgmt=WPA-PSK SAE", "ieee80211w=1", "sae_require_mfp=1", "wpa_passphrase=correct horse #1")
	if strings.Contains(out, "bad=1") {
		t.Errorf("a comment got into the config:\n%s", out)
	}

	g := Render(model.AccessPoint{Interface: "wlan1", SSID: "g", Band: "2.4", Channel: 0, Security: "open"}, "/d")
	has(t, g, "hw_mode=g", "channel=0", "auth_algs=1")
	for _, no := range []string{"wpa", "ieee80211n", "ieee80211ac", "country", "bridge", "ignore_broadcast", "max_num_sta"} {
		if strings.Contains(g, no) {
			t.Errorf("%q in an open 2.4 GHz access point:\n%s", no, g)
		}
	}
	w3 := Render(model.AccessPoint{Interface: "w", SSID: "s", Band: "2.4", Channel: 6, Security: "wpa3", Passphrase: "password1", AC: true}, "/d")
	has(t, w3, "wpa_key_mgmt=SAE", "ieee80211w=2", "wpa_passphrase=password1", "ieee80211n=1")
	if strings.Contains(w3, "ieee80211ac") {
		t.Errorf("802.11ac on 2.4 GHz:\n%s", w3)
	}
	psk := Render(model.AccessPoint{Interface: "w", SSID: "s", Band: "2.4", Channel: 1, Security: "wpa2", Passphrase: strings.Repeat("AB", 32)}, "/d")
	has(t, psk, "wpa_psk="+strings.Repeat("ab", 32))
	if strings.Contains(psk, "wpa_passphrase") {
		t.Errorf("a raw key sent as a passphrase:\n%s", psk)
	}
}

// fakeHostapd answers on a unix datagram socket the way hostapd does.
func fakeHostapd(t *testing.T, iface string, answer func(cmd string) string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hapd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	pc, err := net.ListenPacket("unixgram", filepath.Join(dir, iface))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo([]byte(answer(string(buf[:n]))), from)
		}
	}()
	return dir
}

func TestControl(t *testing.T) {
	var mu sync.Mutex
	var kicked []string
	dir := fakeHostapd(t, "wlan0", func(cmd string) string {
		switch {
		case cmd == "STATUS":
			return "state=ENABLED\nphy=phy0\nfreq=5180\nchannel=36\nnum_sta[0]=2\nnum_sta[1]=0\nssid[0]=Home\n"
		case cmd == "STA-FIRST":
			return "aa:bb:cc:00:11:22\nflags=[AUTH][ASSOC][AUTHORIZED][WMM]\naid=1\nrx_packets=100\ntx_packets=200\nrx_bytes=1000\ntx_bytes=2000\ninactive_msec=120\nsignal=-47\nconnected_time=3600\n"
		case cmd == "STA-NEXT aa:bb:cc:00:11:22":
			return "AA:BB:CC:00:11:33\nflags=[AUTH][ASSOC]\nconnected_time=5\n"
		case strings.HasPrefix(cmd, "STA-NEXT"):
			return ""
		case strings.HasPrefix(cmd, "DEAUTHENTICATE "):
			mu.Lock()
			kicked = append(kicked, strings.TrimPrefix(cmd, "DEAUTHENTICATE "))
			mu.Unlock()
			return "OK\n"
		}
		return "UNKNOWN COMMAND\n"
	})
	c := Control{Dir: dir}
	st, err := c.Status("wlan0")
	if err != nil || st.State != "ENABLED" || st.Channel != 36 || st.Freq != 5180 || st.Clients != 2 {
		t.Errorf("status: %+v %v", st, err)
	}
	sts, err := c.Stations("wlan0")
	if err != nil || len(sts) != 2 {
		t.Fatalf("stations: %+v %v", sts, err)
	}
	if s := sts[0]; s.MAC != "aa:bb:cc:00:11:22" || s.Signal != -47 || s.ConnectedSecs != 3600 || s.RxBytes != 1000 || s.TxPackets != 200 || s.InactiveMs != 120 || !strings.Contains(s.Flags, "AUTHORIZED") {
		t.Errorf("first station: %+v", s)
	}
	if sts[1].MAC != "aa:bb:cc:00:11:33" {
		t.Errorf("second station: %+v", sts[1])
	}
	err = c.Kick("wlan0", "AA-BB-CC-00-11-22")
	mu.Lock()
	got := append([]string{}, kicked...)
	mu.Unlock()
	if err != nil || len(got) != 1 || got[0] != "aa:bb:cc:00:11:22" {
		t.Errorf("kick: %v %v", err, got)
	}
	if err := c.Kick("wlan0", "nonsense"); err == nil {
		t.Error("a bad MAC was sent to hostapd")
	}
	if _, err := c.Status("wlan9"); err == nil || !strings.Contains(err.Error(), "wlan9") {
		t.Errorf("no such socket: %v", err)
	}
}
