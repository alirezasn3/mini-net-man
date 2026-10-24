// Package health runs the ping checks that policy rules can depend on.
//
// Each check pings its target out of one interface on an interval. After
// FailAfter misses in a row it is "down"; after RecoverAfter replies in a row
// it is "up" again. Until its first answer a check is "unknown", which counts
// as up so that a restart never switches rules off just because nothing has
// been measured yet.
package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// Pinger sends one echo out of an interface; the kernel backend implements it.
type Pinger interface {
	Ping(ctx context.Context, iface, target string, timeout time.Duration) (time.Duration, error)
}

// Units of the check settings; tests shrink them.
var (
	intervalUnit = time.Second
	timeoutUnit  = time.Millisecond
)

const (
	Unknown = "unknown"
	Up      = "up"
	Down    = "down"
)

// Status is the latest result of one check.
type Status struct {
	State     string    `json:"state"`
	Since     time.Time `json:"since"`            // when the state last changed
	LastProbe time.Time `json:"last_probe"`       // when it was last tried
	RTTMs     float64   `json:"rtt_ms,omitempty"` // of the last reply
	Error     string    `json:"error,omitempty"`  // why the last try failed
	Fails     int       `json:"fails"`            // consecutive misses
	Oks       int       `json:"oks"`              // consecutive replies
}

type runner struct {
	def    model.Check
	cancel context.CancelFunc
	st     Status
}

// Monitor owns the running checks.
type Monitor struct {
	p        Pinger
	onChange func() // called when a check flips between down and not-down

	mu      sync.Mutex
	runners map[string]*runner
}

// New returns a Monitor. onChange runs (on its own goroutine) whenever a
// check goes down or comes back up, so the caller can re-apply its config.
func New(p Pinger, onChange func()) *Monitor {
	return &Monitor{p: p, onChange: onChange, runners: map[string]*runner{}}
}

// probeKey is everything that changes how a check measures; changing any of
// it restarts the check, anything else (its name) leaves it running.
func probeKey(c model.Check) string {
	return fmt.Sprintf("%s|%s|%d|%d|%d|%d", c.Target, c.Interface, c.Interval(), c.Timeout(), c.Fails(), c.Recovers())
}

// Sync starts, restarts and stops checks to match the configured list.
func (m *Monitor) Sync(checks []model.Check) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[string]model.Check{}
	for _, c := range checks {
		want[c.ID] = c
	}
	for id, r := range m.runners {
		if c, ok := want[id]; !ok || probeKey(c) != probeKey(r.def) {
			r.cancel()
			delete(m.runners, id)
		}
	}
	for id, c := range want {
		if r, ok := m.runners[id]; ok {
			r.def = c
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		r := &runner{def: c, cancel: cancel, st: Status{State: Unknown, Since: time.Now()}}
		m.runners[id] = r
		// Timings are read here, on the caller's goroutine, not inside the new one.
		go m.run(ctx, id, r, c, time.Duration(c.Interval())*intervalUnit, time.Duration(c.Timeout())*timeoutUnit)
	}
}

// Stop ends every check.
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, r := range m.runners {
		r.cancel()
		delete(m.runners, id)
	}
}

// IsDown reports whether the check exists and is failing. Unknown counts as up.
func (m *Monitor) IsDown(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runners[id]
	return ok && r.st.State == Down
}

// Statuses returns a snapshot of every check's state, keyed by check id.
func (m *Monitor) Statuses() map[string]Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Status, len(m.runners))
	for id, r := range m.runners {
		out[id] = r.st
	}
	return out
}

func (m *Monitor) run(ctx context.Context, id string, r *runner, def model.Check, interval, timeout time.Duration) {
	timer := time.NewTimer(0) // the first probe is immediate
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		rtt, err := m.p.Ping(ctx, def.Interface, def.Target, timeout)
		if ctx.Err() != nil {
			return
		}
		if m.record(id, r, def, rtt, err) && m.onChange != nil {
			go m.onChange()
		}
		timer.Reset(interval)
	}
}

// record folds one result into the state and reports whether the check
// crossed between down and not-down.
func (m *Monitor) record(id string, r *runner, def model.Check, rtt time.Duration, err error) (flipped bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runners[id] != r {
		return false // replaced or removed while pinging
	}
	st := &r.st
	wasDown := st.State == Down
	st.LastProbe = time.Now()
	if err == nil {
		st.Oks++
		st.Fails = 0
		st.Error = ""
		st.RTTMs = float64(rtt.Microseconds()) / 1000
		switch {
		case st.State == Unknown, st.State == Down && st.Oks >= def.Recovers():
			st.State, st.Since = Up, st.LastProbe
		}
	} else {
		st.Fails++
		st.Oks = 0
		st.Error = err.Error()
		if st.State != Down && st.Fails >= def.Fails() {
			st.State, st.Since = Down, st.LastProbe
		}
	}
	return wasDown != (st.State == Down)
}

// SetUnitsForTest shortens the units of the check settings (a check's
// "1 second" interval becomes interval, its "1000 ms" timeout becomes
// timeout/1000*1000...). It returns a function that restores them. Test use only.
func SetUnitsForTest(interval, timeout time.Duration) (restore func()) {
	i, o := intervalUnit, timeoutUnit
	intervalUnit, timeoutUnit = interval, timeout
	return func() { intervalUnit, timeoutUnit = i, o }
}
