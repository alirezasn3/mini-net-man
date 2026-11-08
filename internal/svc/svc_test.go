package svc

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func fast(t *testing.T) {
	t.Helper()
	a, b, c, d := backoffMin, backoffMax, stableAfter, stopGrace
	backoffMin, backoffMax, stableAfter, stopGrace = 30*time.Millisecond, 120*time.Millisecond, time.Hour, time.Second
	t.Cleanup(func() { backoffMin, backoffMax, stableAfter, stopGrace = a, b, c, d })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func sh(name, script string, files ...File) Spec {
	return Spec{Name: name, Binary: "/bin/sh", Args: []string{"-c", script}, Files: files}
}

func pidAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func TestStartsLogsAndStops(t *testing.T) {
	fast(t)
	dir := t.TempDir()
	conf := filepath.Join(dir, "sub", "x.conf")
	s := New(quiet())
	defer s.Close()
	s.Set([]Spec{sh("a", "echo started; echo oops >&2; cat "+conf+"; sleep 60", File{Path: conf, Data: []byte("hello\n"), Mode: 0o600, RemoveOnStop: true})})
	waitFor(t, "output", func() bool {
		st, _ := s.Status("a")
		return st.Running && strings.Join(st.Log, ",") == "started,oops,hello"
	})
	if fi, err := os.Stat(conf); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("config file: %v %v", fi, err)
	}
	st, _ := s.Status("a")
	if st.PID == 0 || !pidAlive(st.PID) {
		t.Fatalf("not running: %+v", st)
	}
	pid := st.PID
	s.Set(nil)
	waitFor(t, "the process to be gone", func() bool { return !pidAlive(pid) })
	if _, ok := s.Status("a"); ok {
		t.Error("still listed after stopping")
	}
	if _, err := os.Stat(conf); err == nil {
		t.Error("a secret file was left behind")
	}
}

func TestSameSpecIsLeftAloneChangedOneRestarts(t *testing.T) {
	fast(t)
	dir := t.TempDir()
	conf := filepath.Join(dir, "x.conf")
	spec := func(data string) Spec { return sh("a", "sleep 60", File{Path: conf, Data: []byte(data)}) }
	s := New(quiet())
	defer s.Close()
	s.Set([]Spec{spec("one")})
	waitFor(t, "start", func() bool { st, _ := s.Status("a"); return st.Running })
	first, _ := s.Status("a")
	s.Set([]Spec{spec("one")})
	time.Sleep(100 * time.Millisecond)
	if again, _ := s.Status("a"); again.PID != first.PID || again.Restarts != 0 {
		t.Errorf("an unchanged spec restarted the program: %+v -> %+v", first, again)
	}
	s.Set([]Spec{spec("two")})
	waitFor(t, "restart", func() bool { st, _ := s.Status("a"); return st.Running && st.PID != first.PID })
	if b, _ := os.ReadFile(conf); string(b) != "two" {
		t.Errorf("config not rewritten: %q", b)
	}
	waitFor(t, "the old process to be gone", func() bool { return !pidAlive(first.PID) })
}

func TestRestartsWhenItDies(t *testing.T) {
	fast(t)
	s := New(quiet())
	defer s.Close()
	s.Set([]Spec{sh("flaky", "echo boom; exit 3")})
	waitFor(t, "several restarts", func() bool { st, _ := s.Status("flaky"); return st.Restarts >= 2 })
	st, _ := s.Status("flaky")
	if !strings.Contains(st.LastError, "exit status 3") || len(st.Log) == 0 {
		t.Errorf("status: %+v", st)
	}
}

func TestMissingBinaryIsReported(t *testing.T) {
	fast(t)
	s := New(quiet())
	defer s.Close()
	s.Set([]Spec{{Name: "x", Binary: "/nonexistent/hostapd"}})
	waitFor(t, "an error", func() bool { st, _ := s.Status("x"); return st.LastError != "" && !st.Running })
}

func TestSignalAndStopKillsTheWholeGroup(t *testing.T) {
	fast(t)
	s := New(quiet())
	defer s.Close()
	// The shell starts a child of its own; stopping must take that down too.
	s.Set([]Spec{sh("a", "trap 'echo got-hup' HUP; sleep 100 & echo child=$!; while true; do sleep 0.1; done")})
	var child string
	waitFor(t, "the child's pid", func() bool {
		st, _ := s.Status("a")
		for _, l := range st.Log {
			if v, ok := strings.CutPrefix(l, "child="); ok {
				child = v
			}
		}
		return child != ""
	})
	if err := s.Signal("a", syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the signal to arrive", func() bool { st, _ := s.Status("a"); return strings.Contains(strings.Join(st.Log, "|"), "got-hup") })
	if err := s.Signal("nope", syscall.SIGHUP); err == nil {
		t.Error("signalling something that isn't running should fail")
	}
	s.Set(nil)
	var pid int
	for _, c := range child {
		pid = pid*10 + int(c-'0')
	}
	waitFor(t, "the grandchild to be gone", func() bool { return !pidAlive(pid) })
}

func TestFake(t *testing.T) {
	s := NewFake(quiet())
	s.Set([]Spec{{Name: "dnsmasq", Binary: "/usr/sbin/dnsmasq"}})
	if st, ok := s.Status("dnsmasq"); !ok || !st.Running || len(st.Log) == 0 {
		t.Errorf("fake status: %+v %v", st, ok)
	}
	s.Set(nil)
	if len(s.Names()) != 0 {
		t.Error("still listed")
	}
}
