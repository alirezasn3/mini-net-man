// Package engine owns the config, applies it to the kernel and implements
// MikroTik-style safe mode.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/health"
	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/alirezasn3/mini-net-man/internal/tuning"
	"gopkg.in/yaml.v3"
)

type Engine struct {
	k    kernel.Kernel
	log  *slog.Logger
	path string // config.yaml; sidecar files live next to it

	mu      sync.Mutex
	cfg     model.Config
	issues  []model.Issue
	lastNFT string

	lastIssueKey string
	lastAddr     []kernel.Addr
	lastBridges  map[string]bridgeState
	safe         *safeSession

	mon *health.Monitor // pings for the health checks rules can depend on
}

type safeSession struct {
	baseline model.Config
	timeout  time.Duration
	deadline time.Time
}

// SafeStatus is what the UI polls.
type SafeStatus struct {
	Active        bool `json:"active"`
	RemainingSecs int  `json:"remaining_secs"`
	TimeoutSecs   int  `json:"timeout_secs"`
}

func New(k kernel.Kernel, cfg model.Config, path string, log *slog.Logger) *Engine {
	e := &Engine{k: k, cfg: cfg, path: path, log: log}
	e.mon = health.New(k, e.healthChanged)
	return e
}

// healthChanged runs when a health check goes down or comes back: rules that
// depend on it appear or disappear, so the kernel is reconciled.
func (e *Engine) healthChanged() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.applyLocked(false)
}

// CheckStatuses returns the latest result of every health check, by id.
func (e *Engine) CheckStatuses() map[string]health.Status { return e.mon.Statuses() }

func (e *Engine) baselinePath() string { return e.path + ".baseline" }
func (e *Engine) statePath() string    { return e.path + ".state" }

// Kernel exposes the kernel for read-only live views.
func (e *Engine) Kernel() kernel.Kernel { return e.k }

// Config returns a deep copy of the current config.
func (e *Engine) Config() model.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return clone(e.cfg)
}

func clone(c model.Config) model.Config {
	b, _ := yaml.Marshal(c)
	var out model.Config
	_ = yaml.Unmarshal(b, &out)
	return out
}

func (e *Engine) Issues() []model.Issue {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]model.Issue{}, e.issues...)
}

// Start recovers from an unconfirmed safe-mode session left by a crash or
// restart, then applies the config once.
func (e *Engine) Start() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if b, err := os.ReadFile(e.baselinePath()); err == nil {
		var base model.Config
		if yaml.Unmarshal(b, &base) == nil {
			e.log.Warn("unconfirmed safe-mode session found; restoring previous config")
			base.Web = e.cfg.Web
			e.cfg = base
			_ = SaveConfig(e.path, e.cfg)
		}
		_ = os.Remove(e.baselinePath())
	}
	st := loadState(e.statePath())
	e.lastAddr = st.Addresses
	e.lastBridges = st.Bridges
	e.mon.Sync(e.cfg.Checks)
	e.applyLocked(true)
}

// Timing of the reconcile loop; tests shorten them.
var (
	debounceDelay = 500 * time.Millisecond // a burst of kernel events becomes one reconcile
	retryMin      = time.Second            // first retry of items that failed to apply
	retryMax      = 30 * time.Second       // retries back off up to this
	tickEvery     = time.Second            // safe-mode expiry and retry checks
	stormWindow   = 10 * time.Second
	stormPause    = 30 * time.Second
)

// Run watches the kernel, retries items that failed to apply, and expires
// safe-mode sessions, until ctx ends.
//
// Failures are common at boot: the daemon can start before the interfaces
// it was told about (a WireGuard tunnel, say) exist. Kernel events normally
// bring them in, but events can be missed, so anything still failing is also
// retried on a timer with backoff.
func (e *Engine) Run(ctx context.Context) {
	events, err := e.k.Watch(ctx)
	if err != nil {
		e.log.Error("kernel watch failed; relying on timed retries only", "err", err)
	}
	tick := time.NewTicker(tickEvery)
	defer tick.Stop()
	var debounce <-chan time.Time
	var recent []time.Time // event-driven reconciles that really changed something
	wait, nextRetry := retryMin, time.Time{}
	defer e.mon.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-events:
			if debounce == nil {
				debounce = time.After(debounceDelay)
			}
		case <-debounce:
			debounce = nil
			e.mu.Lock()
			changed := e.applyLocked(false)
			e.mu.Unlock()
			if changed == 0 {
				recent = nil
				break
			}
			// Our own changes produce kernel events, which is fine once. If
			// every pass keeps changing something, something isn't converging:
			// back off, but still catch up with one reconcile at the end
			// rather than dropping what happened meanwhile.
			now := time.Now()
			recent = append(recent, now)
			for len(recent) > 0 && now.Sub(recent[0]) > stormWindow {
				recent = recent[1:]
			}
			if len(recent) >= 6 {
				e.log.Error("reconcile keeps changing the kernel; pausing event-driven reconciles", "for", stormPause)
				debounce, recent = time.After(stormPause), nil
			}
		case <-tick.C:
			e.expireSafe()

			e.mu.Lock()
			failing := len(e.issues) > 0
			e.mu.Unlock()
			now := time.Now()
			switch {
			case !failing:
				wait, nextRetry = retryMin, time.Time{}
			case nextRetry.IsZero():
				nextRetry = now.Add(wait)
			case now.After(nextRetry):
				e.mu.Lock()
				e.applyLocked(false)
				e.mu.Unlock()
				if wait *= 2; wait > retryMax {
					wait = retryMax
				}
				nextRetry = now.Add(wait)
			}
		}
	}
}

// Update applies fn to a copy of the config, validates it, saves it and
// reconciles the kernel. The returned issues are items the kernel rejected;
// they don't undo the change.
func (e *Engine) Update(fn func(c *model.Config) error) ([]model.Issue, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	next := clone(e.cfg)
	if err := fn(&next); err != nil {
		return nil, err
	}
	AllocateExits(&next)
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if err := SaveConfig(e.path, next); err != nil {
		return nil, err
	}
	e.cfg = next
	e.mon.Sync(next.Checks)
	e.applyLocked(false)
	return append([]model.Issue(nil), e.issues...), nil
}

// Reapply forces a full reconcile, including the firewall.
func (e *Engine) Reapply() []model.Issue {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.applyLocked(true)
	return append([]model.Issue(nil), e.issues...)
}

// Converge runs one non-forced reconcile and returns how many kernel changes
// it made. After a successful apply it should be 0; tests rely on that.
func (e *Engine) Converge() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.applyLocked(false)
}

// Desired returns the expanded desired state (manual + generated items).
func (e *Engine) Desired() Desired {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.desiredLocked()
}

func (e *Engine) desiredLocked() Desired {
	nets := map[string][]string{}
	if addrs, err := e.k.ListAddrs(); err == nil {
		for _, a := range addrs {
			nets[a.Interface] = append(nets[a.Interface], a.Address)
		}
	}
	return Expand(e.cfg, func(iface string) []string { return NetsOf(nets[iface]) }, e.mon.IsDown)
}

// ---- safe mode -----------------------------------------------------------

var ErrSafeActive = errors.New("safe mode is already active")

// SafeStart snapshots the config. Unless confirmed, everything changed from
// now on is rolled back after timeout without a heartbeat.
func (e *Engine) SafeStart(timeout time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.safe != nil {
		return ErrSafeActive
	}
	if timeout < 5*time.Second {
		timeout = 30 * time.Second
	}
	b, err := yaml.Marshal(e.cfg)
	if err != nil {
		return err
	}
	if err := writeAtomic(e.baselinePath(), b); err != nil {
		return err
	}
	e.safe = &safeSession{baseline: clone(e.cfg), timeout: timeout, deadline: time.Now().Add(timeout)}
	return nil
}

func (e *Engine) SafeHeartbeat() SafeStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.safe != nil {
		e.safe.deadline = time.Now().Add(e.safe.timeout)
	}
	return e.safeStatusLocked()
}

func (e *Engine) SafeStatus() SafeStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.safeStatusLocked()
}

func (e *Engine) safeStatusLocked() SafeStatus {
	if e.safe == nil {
		return SafeStatus{}
	}
	rem := int(time.Until(e.safe.deadline).Round(time.Second) / time.Second)
	if rem < 0 {
		rem = 0
	}
	return SafeStatus{Active: true, RemainingSecs: rem, TimeoutSecs: int(e.safe.timeout / time.Second)}
}

// SafeConfirm keeps the changes made during the session.
func (e *Engine) SafeConfirm() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.safe = nil
	_ = os.Remove(e.baselinePath())
}

// SafeCancel rolls back immediately.
func (e *Engine) SafeCancel() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.revertLocked()
}

func (e *Engine) expireSafe() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.safe != nil && time.Now().After(e.safe.deadline) {
		e.log.Warn("safe mode timed out; rolling back")
		e.revertLocked()
	}
}

func (e *Engine) revertLocked() {
	if e.safe == nil {
		return
	}
	base := clone(e.safe.baseline)
	base.Web = e.cfg.Web // panel settings aren't rolled back
	e.cfg = base
	e.mon.Sync(base.Checks)
	e.safe = nil
	_ = os.Remove(e.baselinePath())
	if err := SaveConfig(e.path, e.cfg); err != nil {
		e.log.Error("saving rolled-back config", "err", err)
	}
	e.applyLocked(true)
}

// ---- reconcile -----------------------------------------------------------

func addrKey(a kernel.Addr) string { return a.Interface + "|" + a.Address }

// applyLocked makes the kernel match the config. It never stops at the first
// failure: each item that can't be applied becomes an Issue.
//
// It returns how many kernel changes it made.
func (e *Engine) applyLocked(force bool) int {
	var issues []model.Issue
	muts := 0
	add := func(kind, id string, err error) {
		if err != nil {
			issues = append(issues, model.Issue{Kind: kind, ID: id, Message: err.Error()})
		}
	}
	// do records the outcome of a change: a failure becomes an issue, a
	// success counts as a change. Only successes count, so a route that keeps
	// failing (its interface isn't up yet) never looks like a runaway loop.
	do := func(kind, id string, err error) {
		if err != nil {
			add(kind, id, err)
			return
		}
		muts++
	}
	d := e.desiredLocked()

	for _, f := range []struct {
		v6   bool
		want *bool
		id   string
	}{{false, e.cfg.Sysctl.IPForward, "ip_forward"}, {true, e.cfg.Sysctl.IPv6Forward, "ipv6_forward"}} {
		if f.want == nil {
			continue
		}
		cur, err := e.k.IPForward(f.v6)
		if err == nil && cur != *f.want {
			do("sysctl", f.id, e.k.SetIPForward(f.v6, *f.want))
			continue
		}
		add("sysctl", f.id, err)
	}

	e.applyLinksLocked(d, add, do)

	// Addresses.
	live, err := e.k.ListAddrs()
	add("address", "", err)
	have := map[string]bool{}
	for _, a := range live {
		have[addrKey(a)] = true
	}
	want := map[string]bool{}
	var applied []kernel.Addr
	for _, a := range d.Addresses {
		n, _ := model.ParseAddr(a.Address)
		ka := kernel.Addr{Interface: a.Interface, Address: n.String()}
		want[addrKey(ka)] = true
		applied = append(applied, ka)
		if !have[addrKey(ka)] {
			do("address", a.ID, e.k.AddAddr(ka.Interface, ka.Address))
		}
	}
	for _, p := range e.lastAddr {
		if !want[addrKey(p)] && have[addrKey(p)] {
			do("address", "", e.k.DelAddr(p.Interface, p.Address))
		}
	}
	e.lastAddr = applied
	_ = saveState(e.statePath(), state{Addresses: applied, Bridges: e.lastBridges})

	// Routes: we only ever delete routes we stamped with our owner tag.
	liveRoutes, err := e.k.ListRoutes()
	add("route", "", err)
	desiredRoutes := map[string]model.Route{}
	for _, r := range d.Routes {
		desiredRoutes[r.Key()] = r
	}
	ownedSig := map[string]string{}
	for _, r := range liveRoutes {
		if !r.Owned {
			continue
		}
		if _, ok := desiredRoutes[r.Key()]; !ok {
			do("route", "", e.k.DelRoute(r.Route))
		} else {
			ownedSig[r.Key()] = r.Sig()
		}
	}
	for key, r := range desiredRoutes {
		if ownedSig[key] == r.Sig() {
			continue
		}
		do("route", r.ID, e.k.ReplaceRoute(r))
	}

	// Rules.
	liveRules, err := e.k.ListRules()
	add("rule", "", err)
	desiredRules := map[string]model.Rule{}
	for _, r := range d.Rules {
		desiredRules[r.Key()] = r
	}
	ownedRule := map[string]bool{}
	foreignRule := map[string]bool{}
	for _, r := range liveRules {
		switch {
		case r.Owned:
			if _, ok := desiredRules[r.Key()]; !ok {
				do("rule", "", e.k.DelRule(r.Rule))
			} else {
				ownedRule[r.Key()] = true
			}
		default:
			foreignRule[r.Key()] = true
		}
	}
	for key, r := range desiredRules {
		if ownedRule[key] {
			continue
		}
		if foreignRule[key] {
			// Same rule made by hand: take it over.
			_ = e.k.DelRule(r)
		}
		do("rule", r.ID, e.k.AddRule(r))
	}

	// Firewall: replaced atomically as one table.
	text := kernel.RenderNFT(d.Firewall)
	if force || text != e.lastNFT {
		if err := e.k.ApplyFirewall(d.Firewall); err != nil {
			add("firewall", "", err)
		} else {
			muts++
			e.lastNFT = text
		}
	}

	// Byte counting is a conntrack setting, which only exists once something
	// (the firewall above, usually) has loaded connection tracking.
	if want := e.cfg.Sysctl.ConntrackAcct; want != nil {
		cur, err := e.k.ConntrackAcct()
		if err == nil && cur != *want {
			err = e.k.SetConntrackAcct(*want)
			if err == nil {
				muts++
			}
		}
		if err != nil {
			err = fmt.Errorf("connection tracking is not active yet: add a NAT or connection-state firewall rule (%v)", err)
		}
		add("sysctl", "conntrack_acct", err)
	}

	// Managed kernel tuning. These come last because some only exist once the
	// firewall above has loaded connection tracking.
	ids := make([]string, 0, len(e.cfg.Sysctl.Tuning))
	for id := range e.cfg.Sysctl.Tuning {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		st, ok := tuning.Get(id)
		if !ok {
			continue // a setting a newer version knew about
		}
		want := e.cfg.Sysctl.Tuning[id]
		changed, err := false, error(nil)
		for _, key := range st.Keys {
			var cur string
			if cur, err = e.k.Sysctl(key); err != nil {
				break
			}
			if cur != want {
				if err = e.k.SetSysctl(key, want); err != nil {
					break
				}
				changed = true
			}
		}
		switch {
		case err != nil:
			add("sysctl", id, fmt.Errorf("%s: %w", st.Label, err))
		case changed:
			muts++
		}
	}

	e.issues = issues
	// Retries repeat the same failures; say each set of them once.
	var key strings.Builder
	for _, is := range issues {
		key.WriteString(is.Kind + "|" + is.ID + "|" + is.Message + "\n")
	}
	if key.String() != e.lastIssueKey {
		e.lastIssueKey = key.String()
		for _, is := range issues {
			e.log.Warn("apply issue (will retry)", "kind", is.Kind, "id", is.ID, "err", is.Message)
		}
		if len(issues) == 0 {
			e.log.Info("all configured items applied")
		}
	}
	return muts
}

// String helps debugging.
func (s SafeStatus) String() string {
	return fmt.Sprintf("safe=%v remaining=%ds", s.Active, s.RemainingSecs)
}
