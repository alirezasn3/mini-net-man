package health

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// fakePinger answers or times out on command and counts how often it is asked.
type fakePinger struct {
	mu    sync.Mutex
	fail  map[string]bool
	calls atomic.Int64
}

func (f *fakePinger) set(iface string, fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail == nil {
		f.fail = map[string]bool{}
	}
	f.fail[iface] = fail
}

func (f *fakePinger) Ping(_ context.Context, iface, _ string, _ time.Duration) (time.Duration, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail[iface] {
		return 0, errors.New("timed out")
	}
	return 7 * time.Millisecond, nil
}

func fast(t *testing.T) {
	t.Helper()
	i, o := intervalUnit, timeoutUnit
	intervalUnit, timeoutUnit = 10*time.Millisecond, time.Microsecond*100
	t.Cleanup(func() { intervalUnit, timeoutUnit = i, o })
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func chk(id, iface string) model.Check {
	return model.Check{ID: id, Name: id, Target: "1.1.1.1", Interface: iface, IntervalSecs: 1, TimeoutMs: 1000, FailAfter: 3, RecoverAfter: 2}
}

func TestDownAfterFailuresAndUpAfterRecovery(t *testing.T) {
	fast(t)
	p := &fakePinger{}
	var flips atomic.Int64
	m := New(p, func() { flips.Add(1) })
	defer m.Stop()
	m.Sync([]model.Check{chk("a", "wg0")})

	eventually(t, "the first reply to mark it up", func() bool { return m.Statuses()["a"].State == Up })
	if m.IsDown("a") {
		t.Fatal("a healthy check must not be down")
	}
	if st := m.Statuses()["a"]; st.RTTMs != 7 || st.Fails != 0 {
		t.Errorf("status = %+v", st)
	}

	p.set("wg0", true)
	eventually(t, "three misses to mark it down", func() bool { return m.IsDown("a") })
	if st := m.Statuses()["a"]; st.Error != "timed out" || st.Fails < 3 {
		t.Errorf("down status = %+v", st)
	}

	p.set("wg0", false)
	eventually(t, "two replies to bring it back", func() bool { return !m.IsDown("a") })
	if st := m.Statuses()["a"]; st.State != Up {
		t.Errorf("recovered status = %+v", st)
	}
	// Down once and up once: the engine hears about exactly the two changes that matter.
	eventually(t, "both notifications", func() bool { return flips.Load() == 2 })
}

// A single lost ping must not switch anything off, and a single reply must not switch it back on.
func TestOneBlipDoesNotFlap(t *testing.T) {
	fast(t)
	p := &fakePinger{}
	var flips atomic.Int64
	m := New(p, func() { flips.Add(1) })
	defer m.Stop()
	m.Sync([]model.Check{chk("a", "wg0")})
	eventually(t, "up", func() bool { return m.Statuses()["a"].State == Up })

	p.set("wg0", true)
	time.Sleep(15 * time.Millisecond) // about one interval: one or two misses at most
	p.set("wg0", false)
	time.Sleep(80 * time.Millisecond)
	if m.IsDown("a") || flips.Load() != 0 {
		t.Errorf("a brief blip flapped the check: down=%v flips=%d status=%+v", m.IsDown("a"), flips.Load(), m.Statuses()["a"])
	}
}

func TestUnknownCountsAsUpAndDownNeedsFullCount(t *testing.T) {
	fast(t)
	p := &fakePinger{}
	p.set("dead", true)
	m := New(p, nil)
	defer m.Stop()
	m.Sync([]model.Check{chk("d", "dead")})
	if m.IsDown("d") {
		t.Error("a check that has not been measured yet is not down")
	}
	eventually(t, "the dead interface to be marked down", func() bool { return m.IsDown("d") })
	if st := m.Statuses()["d"]; st.Fails < 3 {
		t.Errorf("marked down after only %d misses (want at least 3)", st.Fails)
	}
}

func TestSyncAddsRestartsAndRemoves(t *testing.T) {
	fast(t)
	p := &fakePinger{}
	m := New(p, nil)
	defer m.Stop()

	m.Sync([]model.Check{chk("a", "wg0"), chk("b", "wg1")})
	eventually(t, "both up", func() bool { return m.Statuses()["a"].State == Up && m.Statuses()["b"].State == Up })

	// Renaming keeps the check running (same measurement), so its state survives.
	renamed := chk("a", "wg0")
	renamed.Name = "Germany exit"
	since := m.Statuses()["a"].Since
	m.Sync([]model.Check{renamed, chk("b", "wg1")})
	if m.Statuses()["a"].Since != since {
		t.Error("a rename restarted the check")
	}

	// Changing what it pings restarts it from "unknown".
	moved := chk("a", "wg0")
	moved.Target = "9.9.9.9"
	m.Sync([]model.Check{moved, chk("b", "wg1")})
	if st := m.Statuses()["a"]; st.State != Unknown && st.State != Up {
		t.Errorf("restarted check state = %q", st.State)
	}

	// Removing stops the pings.
	m.Sync([]model.Check{chk("b", "wg1")})
	if _, ok := m.Statuses()["a"]; ok {
		t.Error("removed check still reported")
	}
	if m.IsDown("a") {
		t.Error("a removed check is never down")
	}
	before := p.calls.Load()
	m.Sync(nil)
	time.Sleep(60 * time.Millisecond)
	if after := p.calls.Load(); after > before+1 {
		t.Errorf("pings continued after Stop: %d -> %d", before, after)
	}
}
