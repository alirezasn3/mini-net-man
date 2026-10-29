// Package dnslist keeps the addresses of domain names in address lists. A list
// entry that is a name (example.com) is resolved on a schedule that follows
// the DNS TTL, and its addresses are put in the list's dynamic sets with a
// timeout, so they leave by themselves when DNS stops returning them.
package dnslist

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/model"
)

// Sink is where addresses go: the kernel.
type Sink interface {
	AddToList(list string, addrs []netip.Addr, timeout time.Duration) error
	DelDynamic(list, address string) error
}

// Timing. Variables so tests can shorten them.
var (
	minInterval  = 30 * time.Second // names with a lower TTL are still looked up no more often than this
	maxInterval  = time.Hour        // and names with a higher TTL at least this often
	grace        = 30 * time.Second // an address outlives its refresh by this much, so a slow lookup doesn't open a gap
	retryMin     = 30 * time.Second // after a failed lookup; doubles up to retryMax
	retryMax     = 5 * time.Minute
	pushRetry    = 10 * time.Second // after the kernel refused the addresses
	queryTimeout = 10 * time.Second
	maxParallel  = 8
)

// Status is the state of one domain entry.
type Status struct {
	List       string    `json:"list"`
	Domain     string    `json:"domain"`
	Addresses  []string  `json:"addresses"`
	ResolvedAt time.Time `json:"resolved_at"` // zero until the first answer
	NextAt     time.Time `json:"next_at"`
	Error      string    `json:"error,omitempty"`
}

type held struct {
	addr    netip.Addr
	expires time.Time
}

type entry struct {
	list, domain string
	cancel       context.CancelFunc
	kick         chan struct{}

	mu         sync.Mutex
	cache      []held
	resolvedAt time.Time
	nextAt     time.Time
	err        string
}

type Resolver struct {
	sink   Sink
	lookup Lookup
	log    *slog.Logger
	sem    chan struct{}

	mu      sync.Mutex
	entries map[string]*entry // list|domain
	wg      sync.WaitGroup
}

func New(sink Sink, lookup Lookup, log *slog.Logger) *Resolver {
	return &Resolver{sink: sink, lookup: lookup, log: log, sem: make(chan struct{}, maxParallel), entries: map[string]*entry{}}
}

// SetLookup replaces how names are resolved. Names already being followed use
// the new one from their next lookup.
func (r *Resolver) SetLookup(l Lookup) {
	r.mu.Lock()
	r.lookup = l
	r.mu.Unlock()
}

func (r *Resolver) lookupFn() Lookup {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookup
}

// Sync makes the resolver follow exactly the domain entries given (disabled
// ones and plain addresses are ignored). New names are looked up at once;
// names no longer there have their addresses taken out of the lists.
func (r *Resolver) Sync(entries []model.AddressEntry) {
	want := map[string][2]string{}
	for _, e := range entries {
		if e.Disabled {
			continue
		}
		if d, err := model.ParseDomain(e.Address); err == nil && !model.IsAddressEntry(e.Address) {
			want[e.List+"|"+d] = [2]string{e.List, d}
		}
	}
	r.mu.Lock()
	var gone []*entry
	for k, e := range r.entries {
		if _, ok := want[k]; !ok {
			gone = append(gone, e)
			delete(r.entries, k)
		}
	}
	for k, w := range want {
		if _, ok := r.entries[k]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		e := &entry{list: w[0], domain: w[1], cancel: cancel, kick: make(chan struct{}, 1)}
		r.entries[k] = e
		r.wg.Add(1)
		go r.follow(ctx, e)
	}
	r.mu.Unlock()
	for _, e := range gone {
		e.cancel()
		e.mu.Lock()
		held := e.cache
		e.mu.Unlock()
		for _, h := range held {
			_ = r.sink.DelDynamic(e.list, h.addr.String())
		}
	}
}

// Kick puts every name's known addresses back in the kernel, for after the
// firewall was rebuilt from scratch (the lists' sets are new and empty).
func (r *Resolver) Kick() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		select {
		case e.kick <- struct{}{}:
		default:
		}
	}
}

// Close stops following every name.
func (r *Resolver) Close() {
	r.mu.Lock()
	for k, e := range r.entries {
		e.cancel()
		delete(r.entries, k)
	}
	r.mu.Unlock()
	r.wg.Wait()
}

// Statuses reports every followed name, sorted by list and name.
func (r *Resolver) Statuses() []Status {
	r.mu.Lock()
	es := make([]*entry, 0, len(r.entries))
	for _, e := range r.entries {
		es = append(es, e)
	}
	r.mu.Unlock()
	out := make([]Status, 0, len(es))
	now := time.Now()
	for _, e := range es {
		e.mu.Lock()
		st := Status{List: e.list, Domain: e.domain, Addresses: []string{}, ResolvedAt: e.resolvedAt, NextAt: e.nextAt, Error: e.err}
		for _, h := range e.cache {
			if h.expires.After(now) {
				st.Addresses = append(st.Addresses, h.addr.String())
			}
		}
		e.mu.Unlock()
		sort.Strings(st.Addresses)
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].List != out[j].List {
			return out[i].List < out[j].List
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}

// Labels maps "list|address" to the name it came from, for the addresses
// currently held, so the lists page can say where an address came from.
func (r *Resolver) Labels() map[string]string {
	out := map[string]string{}
	for _, st := range r.Statuses() {
		for _, a := range st.Addresses {
			out[st.List+"|"+a] = st.Domain
		}
	}
	return out
}

func clamp(d, lo, hi time.Duration) time.Duration { return max(lo, min(d, hi)) }

// follow looks a name up, puts its addresses in the list, waits, and repeats.
func (r *Resolver) follow(ctx context.Context, e *entry) {
	defer r.wg.Done()
	fails := 0
	for {
		var wait time.Duration
		select {
		case r.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		qctx, cancel := context.WithTimeout(ctx, queryTimeout)
		res, err := r.lookupFn()(qctx, e.domain)
		cancel()
		<-r.sem
		if ctx.Err() != nil {
			return
		}
		switch {
		case err != nil:
			fails++
			wait = min(retryMin<<(fails-1), retryMax)
			e.mu.Lock()
			e.err = err.Error()
			e.nextAt = time.Now().Add(wait)
			e.mu.Unlock()
			r.log.Warn("address list: lookup failed", "list", e.list, "name", e.domain, "err", err)
		default:
			fails = 0
			interval := clamp(res.TTL, minInterval, maxInterval)
			life := interval + grace
			now := time.Now()
			e.mu.Lock()
			e.cache = merge(e.cache, res.Addrs, now.Add(life), now)
			e.resolvedAt, e.err = now, ""
			e.mu.Unlock()
			if perr := r.sink.AddToList(e.list, res.Addrs, life); perr != nil {
				wait = pushRetry
				e.mu.Lock()
				e.err = perr.Error()
				e.mu.Unlock()
			} else {
				wait = interval
			}
			e.mu.Lock()
			e.nextAt = now.Add(wait)
			e.mu.Unlock()
		}
		if !r.sleep(ctx, e, wait) {
			return
		}
	}
}

// merge records the addresses just seen with their new expiry and forgets the
// ones that expired.
func merge(cache []held, seen []netip.Addr, expires, now time.Time) []held {
	var out []held
	for _, h := range cache {
		if h.expires.After(now) && !contains(seen, h.addr) {
			out = append(out, h)
		}
	}
	for _, a := range seen {
		out = append(out, held{a.Unmap(), expires})
	}
	return out
}

func contains(as []netip.Addr, a netip.Addr) bool {
	for _, x := range as {
		if x.Unmap() == a {
			return true
		}
	}
	return false
}

// sleep waits for d, and on a kick puts the cached addresses back first. It
// returns false when the entry was stopped.
func (r *Resolver) sleep(ctx context.Context, e *entry, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		case <-e.kick:
			r.repush(e)
		}
	}
}

func (r *Resolver) repush(e *entry) {
	now := time.Now()
	e.mu.Lock()
	var byLife = map[time.Duration][]netip.Addr{}
	for _, h := range e.cache {
		if left := h.expires.Sub(now); left > time.Second {
			// Whole seconds, so addresses from one lookup go in together.
			byLife[left.Truncate(time.Second)] = append(byLife[left.Truncate(time.Second)], h.addr)
		}
	}
	e.mu.Unlock()
	for life, as := range byLife {
		if err := r.sink.AddToList(e.list, as, life); err != nil && !errors.Is(err, context.Canceled) {
			r.log.Warn("address list: putting addresses back failed", "list", e.list, "name", e.domain, "err", err)
		}
	}
}
