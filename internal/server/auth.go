package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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

const tokenPrefix = "mnm_"

// newToken returns a random API token. 256 random bits can't be guessed or
// brute-forced offline, so a plain SHA-256 is enough to store it.
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return tokenPrefix + hex.EncodeToString(b)
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// findToken looks the presented secret up without stopping at the first match,
// so the time taken doesn't depend on which token it was.
func findToken(tokens []model.Token, presented string) (model.Token, bool) {
	want := []byte(hashToken(presented))
	var hit model.Token
	found := 0
	for _, t := range tokens {
		if subtle.ConstantTimeCompare(want, []byte(t.Hash)) == 1 {
			hit, found = t, 1
		}
	}
	return hit, found == 1
}

// bearer extracts the secret from an "Authorization: Bearer ..." header.
func bearer(h string) (string, bool) {
	scheme, tok, ok := strings.Cut(strings.TrimSpace(h), " ")
	tok = strings.TrimSpace(tok)
	return tok, ok && strings.EqualFold(scheme, "Bearer") && tok != ""
}

// sessionOnly lists what a token may never do, whatever its scope: managing
// logins and tokens, locking the panel's own address list, replacing the binary.
func sessionOnly(method, path string) bool {
	switch {
	case path == "/api/password", path == "/api/username", path == "/api/update/install":
		return true
	case path == "/api/tokens", strings.HasPrefix(path, "/api/tokens/"):
		return true
	case path == "/api/settings/web" && method != http.MethodGet:
		return true
	}
	return false
}
