package server

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/model"
	"golang.org/x/crypto/bcrypt"
)

const (
	cookieName   = "mnm_session"
	sessionTTL   = 12 * time.Hour
	maxFailures  = 5
	lockDuration = time.Minute
)

type sessions struct {
	mu       sync.Mutex
	byToken  map[string]session
	failures map[string]*failure
}

type session struct {
	user    string
	expires time.Time
}

type failure struct {
	n     int
	until time.Time
}

func newSessions() *sessions {
	return &sessions{byToken: map[string]session{}, failures: map[string]*failure{}}
}

func (s *sessions) create(user string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	for t, v := range s.byToken { // drop expired ones
		if time.Now().After(v.expires) {
			delete(s.byToken, t)
		}
	}
	s.byToken[tok] = session{user, time.Now().Add(sessionTTL)}
	return tok
}

func (s *sessions) lookup(tok string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byToken[tok]
	if !ok || time.Now().After(v.expires) {
		delete(s.byToken, tok)
		return "", false
	}
	return v.user, true
}

func (s *sessions) drop(tok string) {
	s.mu.Lock()
	delete(s.byToken, tok)
	s.mu.Unlock()
}

// dropUser logs a user out everywhere (after a password change).
func (s *sessions) dropUser(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for t, v := range s.byToken {
		if v.user == user {
			delete(s.byToken, t)
		}
	}
}

// rename keeps a user's sessions alive under their new name.
func (s *sessions) rename(from, to string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for t, v := range s.byToken {
		if v.user == from {
			v.user = to
			s.byToken[t] = v
		}
	}
}

func (s *sessions) locked(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[ip]
	return f != nil && f.n >= maxFailures && time.Now().Before(f.until)
}

func (s *sessions) fail(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[ip]
	if f == nil || time.Now().After(f.until) {
		f = &failure{}
		s.failures[ip] = f
	}
	f.n++
	f.until = time.Now().Add(lockDuration)
}

func (s *sessions) clear(ip string) {
	s.mu.Lock()
	delete(s.failures, ip)
	s.mu.Unlock()
}

// checkPassword compares in constant-ish time even for unknown users.
func checkPassword(users []model.User, name, pw string) bool {
	dummy := []byte("$2a$10$7EqJtq98hPqEX7fNZaFWoOa5U3sQ1JpC8mYb8x6k1l1p7bF3o5k2e")
	for _, u := range users {
		if u.Name == name {
			return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pw)) == nil
		}
	}
	_ = bcrypt.CompareHashAndPassword(dummy, []byte(pw))
	return false
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// allowed reports whether ip matches any entry (IP or CIDR). With no entries
// only loopback is let in, so an empty list can never open the panel up.
func allowed(list []string, ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	if len(list) == 0 {
		return addr.IsLoopback()
	}
	for _, e := range list {
		e = strings.TrimSpace(e)
		if strings.Contains(e, "/") {
			if _, n, err := net.ParseCIDR(e); err == nil && n.Contains(addr) {
				return true
			}
		} else if p := net.ParseIP(e); p != nil && p.Equal(addr) {
			return true
		}
	}
	return false
}
