package dnslist

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Result is what a name resolved to. TTL is the lowest TTL in the answers, the
// time after which at least one of them may have changed.
type Result struct {
	Addrs []netip.Addr
	TTL   time.Duration
}

// Lookup resolves a name to its IPv4 and IPv6 addresses.
type Lookup func(ctx context.Context, name string) (Result, error)

// SystemLookup asks the machine's own resolvers (/etc/resolv.conf), the way
// the address list entry would be resolved by anything else running here.
func SystemLookup(ctx context.Context, name string) (Result, error) {
	return Client{Servers: ResolvConf("/etc/resolv.conf")}.Lookup(ctx, name)
}

// ResolvConf returns the nameservers listed in a resolv.conf, as host:port.
func ResolvConf(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) >= 2 && fs[0] == "nameserver" {
			a, err := netip.ParseAddr(fs[1])
			if err != nil || a.Zone() != "" { // a link-local server needs an interface; skip it
				continue
			}
			out = append(out, net.JoinHostPort(a.String(), "53"))
		}
	}
	return out
}

// Client is a small DNS client: just enough to read A, AAAA and CNAME answers
// with their TTLs (Go's own resolver doesn't report TTLs).
type Client struct {
	Servers []string      // host:port, tried in order
	Timeout time.Duration // per server and query; default 3 s
}

func (c Client) Lookup(ctx context.Context, name string) (Result, error) {
	if len(c.Servers) == 0 {
		return Result{}, errors.New("no DNS servers in /etc/resolv.conf")
	}
	var res Result
	var firstErr error
	got := 0
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		addrs, ttl, err := c.ask(ctx, name, t)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		got++
		res.Addrs = append(res.Addrs, addrs...)
		if len(addrs) > 0 && (res.TTL == 0 || ttl < res.TTL) {
			res.TTL = ttl
		}
	}
	switch {
	case got == 0:
		return Result{}, firstErr
	case len(res.Addrs) == 0:
		return Result{}, fmt.Errorf("%s has no IPv4 or IPv6 address", name)
	}
	return res, nil
}

// ask sends one query to each server in turn until one answers.
func (c Client) ask(ctx context.Context, name string, qt dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	var last error
	for _, srv := range c.Servers {
		addrs, ttl, err := c.exchange(ctx, srv, name, qt)
		if err == nil {
			return addrs, ttl, nil
		}
		var nx nxError
		if errors.As(err, &nx) {
			return nil, 0, err // the server answered: asking others won't help
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, 0, last
}

type nxError struct{ name string }

func (e nxError) Error() string { return e.name + " does not exist (NXDOMAIN)" }

func (c Client) exchange(ctx context.Context, server, name string, qt dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	fqdn, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, 0, err
	}
	var id [2]byte
	_, _ = rand.Read(id[:])
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: fqdn, Type: qt, Class: dnsmessage.ClassINET}},
	}
	wire, err := q.Pack()
	if err != nil {
		return nil, 0, err
	}
	for _, network := range []string{"udp", "tcp"} {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		resp, err := roundTrip(cctx, network, server, wire)
		cancel()
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", server, err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(resp); err != nil || m.Header.ID != q.Header.ID {
			return nil, 0, fmt.Errorf("%s: bad answer", server)
		}
		if m.Header.Truncated && network == "udp" {
			continue // the answer didn't fit: ask again over TCP
		}
		switch m.Header.RCode {
		case dnsmessage.RCodeSuccess:
		case dnsmessage.RCodeNameError:
			return nil, 0, nxError{name}
		default:
			return nil, 0, fmt.Errorf("%s: %v", server, m.Header.RCode)
		}
		var addrs []netip.Addr
		ttl := time.Duration(0)
		note := func(h dnsmessage.ResourceHeader) {
			if d := time.Duration(h.TTL) * time.Second; ttl == 0 || d < ttl {
				ttl = d
			}
		}
		for _, rr := range m.Answers {
			switch b := rr.Body.(type) {
			case *dnsmessage.AResource:
				addrs = append(addrs, netip.AddrFrom4(b.A))
				note(rr.Header)
			case *dnsmessage.AAAAResource:
				addrs = append(addrs, netip.AddrFrom16(b.AAAA))
				note(rr.Header)
			case *dnsmessage.CNAMEResource:
				note(rr.Header) // the chain is only as fresh as its shortest link
			}
		}
		return addrs, ttl, nil
	}
	return nil, 0, fmt.Errorf("%s: answer too long", server)
}

func roundTrip(ctx context.Context, network, server string, wire []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if network == "tcp" {
		buf := make([]byte, 2, 2+len(wire))
		binary.BigEndian.PutUint16(buf, uint16(len(wire)))
		if _, err := conn.Write(append(buf, wire...)); err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return nil, err
		}
		out := make([]byte, binary.BigEndian.Uint16(l[:]))
		_, err := io.ReadFull(conn, out)
		return out, err
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	out := make([]byte, 4096)
	n, err := conn.Read(out)
	return out[:n], err
}

// DemoLookup answers without a network, for the -mock server: every name gets
// a stable pair of documentation addresses, except names under .invalid,
// which do not exist.
func DemoLookup(_ context.Context, name string) (Result, error) {
	if strings.HasSuffix(name, ".invalid") {
		return Result{}, nxError{name}
	}
	h := 0
	for _, c := range name {
		h = (h*31 + int(c)) % 200
	}
	return Result{
		Addrs: []netip.Addr{netip.AddrFrom4([4]byte{203, 0, 113, byte(h + 1)}), netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", h+1))},
		TTL:   5 * time.Minute,
	}, nil
}
