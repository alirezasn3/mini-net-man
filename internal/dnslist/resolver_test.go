package dnslist

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/model"
	"golang.org/x/net/dns/dnsmessage"
)

type push struct {
	list  string
	addrs []string
	life  time.Duration
}

type fakeSink struct {
	mu      sync.Mutex
	pushes  []push
	deleted []string
	fail    error
}

func (f *fakeSink) AddToList(list string, addrs []netip.Addr, life time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	p := push{list: list, life: life}
	for _, a := range addrs {
		p.addrs = append(p.addrs, a.String())
	}
	sort.Strings(p.addrs)
	f.pushes = append(f.pushes, p)
	return nil
}

func (f *fakeSink) DelDynamic(list, addr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, list+" "+addr)
	return nil
}

func (f *fakeSink) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.pushes) }
func (f *fakeSink) last() push {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pushes) == 0 {
		return push{}
	}
	return f.pushes[len(f.pushes)-1]
}

// answers is a lookup that returns whatever the test last set.
type answers struct {
	mu    sync.Mutex
	addrs []string
	ttl   time.Duration
	err   error
	calls int
}

func (a *answers) set(ttl time.Duration, addrs ...string) {
	a.mu.Lock()
	a.addrs, a.ttl, a.err = addrs, ttl, nil
	a.mu.Unlock()
}
func (a *answers) fail(err error) { a.mu.Lock(); a.err = err; a.mu.Unlock() }
func (a *answers) n() int         { a.mu.Lock(); defer a.mu.Unlock(); return a.calls }
func (a *answers) lookup(_ context.Context, name string) (Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.err != nil {
		return Result{}, a.err
	}
	r := Result{TTL: a.ttl}
	for _, s := range a.addrs {
		r.Addrs = append(r.Addrs, netip.MustParseAddr(s))
	}
	return r, nil
}

func fast(t *testing.T) {
	t.Helper()
	o := [4]time.Duration{minInterval, grace, retryMin, retryMax}
	minInterval, grace, retryMin, retryMax = 40*time.Millisecond, 100*time.Millisecond, 30*time.Millisecond, 120*time.Millisecond
	t.Cleanup(func() { minInterval, grace, retryMin, retryMax = o[0], o[1], o[2], o[3] })
}

func entries(list string, addrs ...string) []model.AddressEntry {
	var out []model.AddressEntry
	for i, a := range addrs {
		out = append(out, model.AddressEntry{ID: list + string(rune('a'+i)), List: list, Address: a})
	}
	return out
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func newR(sink Sink, a *answers) *Resolver {
	return New(sink, a.lookup, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestResolvesAndRefreshes(t *testing.T) {
	fast(t)
	sink, a := &fakeSink{}, &answers{}
	a.set(0, "203.0.113.7", "2001:db8::7")
	r := newR(sink, a)
	defer r.Close()
	// Plain addresses and disabled names are not followed.
	r.Sync(append(entries("cdn", "Example.COM.", "10.0.0.1", "10.1.0.0/16"), model.AddressEntry{ID: "x", List: "cdn", Address: "off.example.com", Disabled: true}))
	waitFor(t, "first push", func() bool { return sink.count() >= 1 })
	p := sink.last()
	if p.list != "cdn" || strings.Join(p.addrs, ",") != "2001:db8::7,203.0.113.7" || p.life != minInterval+grace {
		t.Errorf("first push = %+v", p)
	}
	if a.n() > 2 {
		t.Errorf("%d lookups straight away for one name", a.n())
	}
	// It comes back on its own, and follows the answer.
	a.set(0, "203.0.113.8")
	waitFor(t, "refresh with the new answer", func() bool { return strings.Join(sink.last().addrs, ",") == "203.0.113.8" })
	st := r.Statuses()
	if len(st) != 1 || st[0].Domain != "example.com" || st[0].Error != "" || st[0].ResolvedAt.IsZero() {
		t.Errorf("statuses: %+v", st)
	}
	// The old address stays known until its own time runs out, then is forgotten.
	waitFor(t, "old addresses to age out", func() bool {
		s := r.Statuses()[0].Addresses
		return len(s) == 1 && s[0] == "203.0.113.8"
	})
	if l := r.Labels(); l["cdn|203.0.113.8"] != "example.com" {
		t.Errorf("labels: %v", l)
	}
}

func TestTTLSetsTheRhythm(t *testing.T) {
	fast(t)
	sink, a := &fakeSink{}, &answers{}
	a.set(300*time.Millisecond, "203.0.113.7") // above the minimum: refresh every 300 ms
	r := newR(sink, a)
	defer r.Close()
	r.Sync(entries("l", "slow.example.com"))
	waitFor(t, "first push", func() bool { return sink.count() == 1 })
	if p := sink.last(); p.life != 300*time.Millisecond+grace {
		t.Errorf("life = %v, want ttl+grace", p.life)
	}
	time.Sleep(150 * time.Millisecond)
	if sink.count() != 1 {
		t.Errorf("looked up again before the TTL passed")
	}
	waitFor(t, "second lookup", func() bool { return sink.count() >= 2 })
}

func TestFailureIsReportedAndRetried(t *testing.T) {
	fast(t)
	sink, a := &fakeSink{}, &answers{}
	a.fail(errors.New("example.com does not exist (NXDOMAIN)"))
	r := newR(sink, a)
	defer r.Close()
	r.Sync(entries("l", "gone.example.com"))
	waitFor(t, "an error to be reported", func() bool { s := r.Statuses(); return len(s) == 1 && strings.Contains(s[0].Error, "NXDOMAIN") })
	waitFor(t, "retries", func() bool { return a.n() >= 3 })
	if sink.count() != 0 {
		t.Error("pushed something for a name that doesn't resolve")
	}
	a.set(0, "203.0.113.9")
	waitFor(t, "recovery", func() bool { return sink.count() >= 1 })
	if s := r.Statuses()[0]; s.Error != "" || len(s.Addresses) != 1 {
		t.Errorf("after recovery: %+v", s)
	}
}

func TestKernelRefusalIsRetriedAndKickRestores(t *testing.T) {
	fast(t)
	oldPush := pushRetry
	pushRetry = 30 * time.Millisecond
	defer func() { pushRetry = oldPush }()
	sink, a := &fakeSink{fail: errors.New("list l has no sets yet")}, &answers{}
	a.set(10*time.Minute, "203.0.113.7")
	r := newR(sink, a)
	defer r.Close()
	r.Sync(entries("l", "late.example.com"))
	waitFor(t, "the refusal to be reported", func() bool { s := r.Statuses(); return len(s) == 1 && strings.Contains(s[0].Error, "no sets") })
	sink.mu.Lock()
	sink.fail = nil
	sink.mu.Unlock()
	waitFor(t, "the retry to succeed", func() bool { return sink.count() >= 1 && r.Statuses()[0].Error == "" })

	// A rebuilt firewall has empty sets: Kick puts the addresses back with the time they have left.
	before := sink.count()
	r.Kick()
	waitFor(t, "kick", func() bool { return sink.count() > before })
	if p := sink.last(); strings.Join(p.addrs, ",") != "203.0.113.7" || p.life <= 0 || p.life > 10*time.Minute+grace {
		t.Errorf("kick pushed %+v", p)
	}
}

func TestRemovedNamesLeaveTheList(t *testing.T) {
	fast(t)
	sink, a := &fakeSink{}, &answers{}
	a.set(0, "203.0.113.7")
	r := newR(sink, a)
	defer r.Close()
	r.Sync(entries("l", "a.example.com", "b.example.com"))
	waitFor(t, "both names", func() bool { return sink.count() >= 2 })
	r.Sync(entries("l", "a.example.com"))
	sink.mu.Lock()
	del := strings.Join(sink.deleted, ",")
	sink.mu.Unlock()
	if del != "l 203.0.113.7" {
		t.Errorf("deleted %q", del)
	}
	if st := r.Statuses(); len(st) != 1 || st[0].Domain != "a.example.com" {
		t.Errorf("still following: %+v", st)
	}
	// The same name in another list is its own entry.
	r.Sync(append(entries("l", "a.example.com"), entries("m", "a.example.com")...))
	if st := r.Statuses(); len(st) != 2 {
		t.Errorf("same name in two lists: %+v", st)
	}
}

// ---- the DNS client against a real (local) server -----------------------------------

func dnsServer(t *testing.T, handler func(q dnsmessage.Question) (dnsmessage.Header, []dnsmessage.Resource)) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			h, rrs := handler(q.Questions[0])
			h.ID, h.Response, h.RecursionAvailable = q.Header.ID, true, true
			out, _ := (&dnsmessage.Message{Header: h, Questions: q.Questions, Answers: rrs}).Pack()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

func rr(name string, t dnsmessage.Type, ttl uint32, body dnsmessage.ResourceBody) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: t, Class: dnsmessage.ClassINET, TTL: ttl}, Body: body}
}

func TestClientReadsAnswersAndTTLs(t *testing.T) {
	srv := dnsServer(t, func(q dnsmessage.Question) (dnsmessage.Header, []dnsmessage.Resource) {
		switch q.Name.String() {
		case "www.example.com.":
			chain := rr("www.example.com.", dnsmessage.TypeCNAME, 600, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.example.net.")})
			switch q.Type {
			case dnsmessage.TypeA:
				return dnsmessage.Header{}, []dnsmessage.Resource{chain,
					rr("edge.example.net.", dnsmessage.TypeA, 60, &dnsmessage.AResource{A: [4]byte{203, 0, 113, 1}}),
					rr("edge.example.net.", dnsmessage.TypeA, 120, &dnsmessage.AResource{A: [4]byte{203, 0, 113, 2}})}
			case dnsmessage.TypeAAAA:
				return dnsmessage.Header{}, []dnsmessage.Resource{chain,
					rr("edge.example.net.", dnsmessage.TypeAAAA, 300, &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()})}
			}
		case "v4only.example.com.":
			if q.Type == dnsmessage.TypeA {
				return dnsmessage.Header{}, []dnsmessage.Resource{rr("v4only.example.com.", dnsmessage.TypeA, 30, &dnsmessage.AResource{A: [4]byte{198, 51, 100, 1}})}
			}
			return dnsmessage.Header{}, nil // AAAA: no records, not an error
		case "empty.example.com.":
			return dnsmessage.Header{}, nil
		}
		return dnsmessage.Header{RCode: dnsmessage.RCodeNameError}, nil
	})
	c := Client{Servers: []string{srv}, Timeout: time.Second}
	ctx := context.Background()

	res, err := c.Lookup(ctx, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range res.Addrs {
		got = append(got, a.String())
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "2001:db8::1,203.0.113.1,203.0.113.2" || res.TTL != 60*time.Second {
		t.Errorf("www: %v ttl %v (want both families through the CNAME, lowest TTL 60s)", got, res.TTL)
	}
	if res, err := c.Lookup(ctx, "v4only.example.com"); err != nil || len(res.Addrs) != 1 || res.TTL != 30*time.Second {
		t.Errorf("v4only: %+v %v", res, err)
	}
	if _, err := c.Lookup(ctx, "nothing.example.com"); err == nil || !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Errorf("nxdomain: %v", err)
	}
	if _, err := c.Lookup(ctx, "empty.example.com"); err == nil || !strings.Contains(err.Error(), "no IPv4 or IPv6") {
		t.Errorf("no records: %v", err)
	}
	// A dead server is skipped for the next one.
	dead := "127.0.0.1:1"
	if res, err := (Client{Servers: []string{dead, srv}, Timeout: 300 * time.Millisecond}).Lookup(ctx, "v4only.example.com"); err != nil || len(res.Addrs) != 1 {
		t.Errorf("failover: %+v %v", res, err)
	}
	if _, err := (Client{}).Lookup(ctx, "x.example.com"); err == nil {
		t.Error("no servers should be an error")
	}
}
