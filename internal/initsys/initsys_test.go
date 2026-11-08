package initsys

import (
	"strings"
	"testing"
)

func TestHints(t *testing.T) {
	if got := Systemd.RestartCmd("x"); got != "systemctl restart x" {
		t.Fatal(got)
	}
	if got := OpenRC.RestartCmd("x"); got != "rc-service x restart" {
		t.Fatal(got)
	}
	if !strings.Contains(Systemd.LogsHint("x"), "journalctl -u x") {
		t.Fatal(Systemd.LogsHint("x"))
	}
	if !strings.Contains(OpenRC.LogsHint("x"), "/var/log/x.log") {
		t.Fatal(OpenRC.LogsHint("x"))
	}
}

func TestSupervised(t *testing.T) {
	t.Setenv("INVOCATION_ID", "")
	t.Setenv("RC_SVCNAME", "")
	if Systemd.Supervised() || OpenRC.Supervised() || None.Supervised() {
		t.Fatal("nothing set, nothing supervised")
	}
	t.Setenv("INVOCATION_ID", "abc")
	if !Systemd.Supervised() || OpenRC.Supervised() {
		t.Fatal("INVOCATION_ID means systemd")
	}
	t.Setenv("INVOCATION_ID", "")
	t.Setenv("RC_SVCNAME", "mini-net-man")
	if !OpenRC.Supervised() || Systemd.Supervised() {
		t.Fatal("RC_SVCNAME means OpenRC")
	}
}

func TestNoInitSystem(t *testing.T) {
	if err := None.Create(Spec{Name: "x", ExecStart: "/bin/true"}); err != ErrNone {
		t.Fatal(err)
	}
	if err := None.Delete("x"); err != ErrNone {
		t.Fatal(err)
	}
	if _, err := None.Status("x"); err != ErrNone {
		t.Fatal(err)
	}
	if err := None.Restart("x", false); err != ErrNone {
		t.Fatal(err)
	}
}
