// Package engine owns the config, applies it to the kernel and implements
// MikroTik-style safe mode.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
	"gopkg.in/yaml.v3"
)

type Engine struct {
	k    kernel.Kernel
	log  *slog.Logger
	path string // config.yaml; sidecar files live next to it

	mu       sync.Mutex
	cfg      model.Config
	issues   []model.Issue
	lastNFT  string
	lastAddr []kernel.Addr
	safe     *safeSession
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
	return &Engine{k: k, cfg: cfg, path: path, log: log}
}

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
	e.applyLocked(true)
}

// Run watches the kernel and expires safe-mode sessions until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	events, err := e.k.Watch(ctx)
	if err != nil {
		e.log.Error("kernel watch failed; link changes won't be re-applied", "err", err)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-events:
			// A burst of netlink events becomes one reconcile.
			if debounce == nil {
				debounce = time.After(500 * time.Millisecond)
			}
		case <-debounce:
			debounce = nil
			e.mu.Lock()
			e.applyLocked(false)
			e.mu.Unlock()
		case <-tick.C:
			e.expireSafe()
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
	return Expand(e.cfg, func(iface string) []string { return NetsOf(nets[iface]) })
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
func (e *Engine) applyLocked(force bool) {
	var issues []model.Issue
	add := func(kind, id string, err error) {
		if err != nil {
			issues = append(issues, model.Issue{Kind: kind, ID: id, Message: err.Error()})
		}
	}
	d := e.desiredLocked()

	if e.cfg.Sysctl.IPForward != nil {
		cur, err := e.k.IPForward()
		if err == nil && cur != *e.cfg.Sysctl.IPForward {
			err = e.k.SetIPForward(*e.cfg.Sysctl.IPForward)
		}
		add("sysctl", "ip_forward", err)
	}

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
			add("address", a.ID, e.k.AddAddr(ka.Interface, ka.Address))
		}
	}
	for _, p := range e.lastAddr {
		if !want[addrKey(p)] && have[addrKey(p)] {
			add("address", "", e.k.DelAddr(p.Interface, p.Address))
		}
	}
	e.lastAddr = applied
	_ = saveState(e.statePath(), state{Addresses: applied})

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
			add("route", "", e.k.DelRoute(r.Route))
		} else {
			ownedSig[r.Key()] = r.Sig()
		}
	}
	for key, r := range desiredRoutes {
		if ownedSig[key] == r.Sig() {
			continue
		}
		add("route", r.ID, e.k.ReplaceRoute(r))
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
				add("rule", "", e.k.DelRule(r.Rule))
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
		add("rule", r.ID, e.k.AddRule(r))
	}

	// Firewall: replaced atomically as one table.
	text := kernel.RenderNFT(d.Firewall)
	if force || text != e.lastNFT {
		if err := e.k.ApplyFirewall(d.Firewall); err != nil {
			add("firewall", "", err)
		} else {
			e.lastNFT = text
		}
	}

	e.issues = issues
	for _, is := range issues {
		e.log.Warn("apply issue", "kind", is.Kind, "id", is.ID, "err", is.Message)
	}
}

// String helps debugging.
func (s SafeStatus) String() string {
	return fmt.Sprintf("safe=%v remaining=%ds", s.Active, s.RemainingSecs)
}
