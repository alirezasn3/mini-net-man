// Package server serves the JSON API and the embedded web UI.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/detect"
	"github.com/alirezasn3/mini-net-man/internal/engine"
	"github.com/alirezasn3/mini-net-man/internal/importer"
	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/alirezasn3/mini-net-man/internal/update"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	eng  *engine.Engine
	log  *slog.Logger
	ui   fs.FS // may be nil
	sess *sessions
	mock bool

	configPath string
	scan       *importer.Proposal

	version string
	exe     string     // this binary's path, resolved before any update can rename it
	upMu    sync.Mutex // guards upCache, pending and serialises installs
	upCache *updateInfo
	pending string // version installed on disk but not yet running
}

func New(eng *engine.Engine, ui fs.FS, configPath string, mock bool, version string, log *slog.Logger) *Server {
	exe, _ := update.Executable()
	return &Server{eng: eng, ui: ui, configPath: configPath, mock: mock, version: version, exe: exe, log: log, sess: newSessions()}
}

type ctxKey struct{}

// Handler returns the full handler: allowed-IP gate, then auth, then routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	api := http.NewServeMux()

	api.HandleFunc("POST /api/login", s.login)
	api.HandleFunc("POST /api/logout", s.logout)

	authed := http.NewServeMux()
	authed.HandleFunc("GET /api/me", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]string{"user": userOf(r)}) })
	authed.HandleFunc("GET /api/overview", s.overview)
	authed.HandleFunc("POST /api/password", s.password)
	authed.HandleFunc("POST /api/reapply", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]any{"issues": s.eng.Reapply()}) })

	authed.HandleFunc("GET /api/links", func(w http.ResponseWriter, r *http.Request) {
		l, err := s.eng.Kernel().Links()
		respond(w, orEmpty(l), err)
	})
	authed.HandleFunc("GET /api/live/routes", func(w http.ResponseWriter, r *http.Request) {
		l, err := s.eng.Kernel().ListRoutes()
		respond(w, orEmpty(l), err)
	})
	authed.HandleFunc("GET /api/live/rules", func(w http.ResponseWriter, r *http.Request) {
		l, err := s.eng.Kernel().ListRules()
		respond(w, orEmpty(l), err)
	})
	authed.HandleFunc("GET /api/firewall/ruleset", s.ruleset)
	authed.HandleFunc("GET /api/generated", s.generated)

	crud(s, authed, "/api/addresses", func(c *model.Config) *[]model.Address { return &c.Addresses }, func(a *model.Address) *string { return &a.ID })
	crud(s, authed, "/api/routes", func(c *model.Config) *[]model.Route { return &c.Routes }, func(a *model.Route) *string { return &a.ID })
	crud(s, authed, "/api/rules", func(c *model.Config) *[]model.Rule { return &c.Rules }, func(a *model.Rule) *string { return &a.ID })
	crud(s, authed, "/api/firewall/rules", func(c *model.Config) *[]model.FWRule { return &c.Firewall.Rules }, func(a *model.FWRule) *string { return &a.ID })
	crud(s, authed, "/api/client-routing/clients", func(c *model.Config) *[]model.ClientRoute { return &c.ClientRouting.Clients }, func(a *model.ClientRoute) *string { return &a.ID })

	authed.HandleFunc("GET /api/firewall", func(w http.ResponseWriter, r *http.Request) {
		fw := s.eng.Config().Firewall
		fw.Rules = orEmpty(fw.Rules)
		writeJSON(w, fw)
	})
	authed.HandleFunc("PUT /api/firewall/policy", func(w http.ResponseWriter, r *http.Request) {
		var p model.FirewallPolicy
		if !decode(w, r, &p) {
			return
		}
		s.mutate(w, func(c *model.Config) error { c.Firewall.Policy = p; return nil })
	})
	authed.HandleFunc("GET /api/client-routing", func(w http.ResponseWriter, r *http.Request) {
		cr := s.eng.Config().ClientRouting
		cr.Exits, cr.Clients = orEmpty(cr.Exits), orEmpty(cr.Clients)
		writeJSON(w, cr)
	})
	authed.HandleFunc("PUT /api/client-routing", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Enabled      bool `json:"enabled"`
			TableBase    int  `json:"table_base"`
			PriorityBase int  `json:"priority_base"`
		}
		if !decode(w, r, &in) {
			return
		}
		s.mutate(w, func(c *model.Config) error {
			c.ClientRouting.Enabled, c.ClientRouting.TableBase, c.ClientRouting.PriorityBase = in.Enabled, in.TableBase, in.PriorityBase
			return nil
		})
	})
	authed.HandleFunc("PUT /api/sysctl", func(w http.ResponseWriter, r *http.Request) {
		var in model.Sysctl
		if !decode(w, r, &in) {
			return
		}
		s.mutate(w, func(c *model.Config) error { c.Sysctl = in; return nil })
	})

	authed.HandleFunc("GET /api/safe", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.eng.SafeStatus()) })
	authed.HandleFunc("POST /api/safe/start", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			TimeoutSecs int `json:"timeout_secs"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if err := s.eng.SafeStart(time.Duration(in.TimeoutSecs) * time.Second); err != nil {
			httpErr(w, http.StatusConflict, err)
			return
		}
		writeJSON(w, s.eng.SafeStatus())
	})
	authed.HandleFunc("POST /api/safe/heartbeat", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.eng.SafeHeartbeat()) })
	authed.HandleFunc("POST /api/safe/confirm", func(w http.ResponseWriter, r *http.Request) { s.eng.SafeConfirm(); writeJSON(w, s.eng.SafeStatus()) })
	authed.HandleFunc("POST /api/safe/cancel", func(w http.ResponseWriter, r *http.Request) { s.eng.SafeCancel(); writeJSON(w, s.eng.SafeStatus()) })

	authed.HandleFunc("GET /api/settings/web", func(w http.ResponseWriter, r *http.Request) {
		wc := s.eng.Config().Web
		names := []string{}
		for _, u := range wc.Users {
			names = append(names, u.Name)
		}
		writeJSON(w, map[string]any{"listen": wc.Listen, "port": wc.Port, "allowed_ips": orEmpty(wc.AllowedIPs), "users": names, "tls": wc.TLSCert != ""})
	})
	authed.HandleFunc("PUT /api/settings/web", s.putWebSettings)

	authed.HandleFunc("GET /api/update", s.updateStatus)
	authed.HandleFunc("POST /api/update/install", s.updateInstall)

	authed.HandleFunc("POST /api/import/scan", s.importScan)
	authed.HandleFunc("POST /api/import/apply", s.importApply)
	authed.HandleFunc("POST /api/import/disable-ufw", s.disableUFW)

	api.Handle("/api/", s.requireAuth(authed))
	mux.Handle("/api/", api)
	mux.Handle("/", s.static())
	return s.gate(mux)
}

// gate drops connections from addresses that aren't allowed without
// answering at all, so the panel doesn't reveal itself to scanners.
func (s *Server) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed(s.eng.Config().Web.AllowedIPs, clientIP(r)) {
			if hj, ok := w.(http.Hijacker); ok {
				if c, _, err := hj.Hijack(); err == nil {
					_ = c.Close()
					return
				}
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			httpErr(w, http.StatusUnauthorized, errors.New("not logged in"))
			return
		}
		user, ok := s.sess.lookup(c.Value)
		if !ok {
			httpErr(w, http.StatusUnauthorized, errors.New("session expired"))
			return
		}
		// State-changing calls must be JSON: browsers can't send that
		// cross-site without a CORS preflight, which we never grant.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			httpErr(w, http.StatusUnsupportedMediaType, errors.New("content-type must be application/json"))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, user)))
	})
}

func userOf(r *http.Request) string { u, _ := r.Context().Value(ctxKey{}).(string); return u }

func (s *Server) static() http.Handler {
	if s.ui == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "web UI not built; run `make web`", http.StatusNotFound)
		})
	}
	files := http.FileServerFS(s.ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(s.ui, p); err != nil {
			r.URL.Path = "/" // single-page app: unknown paths get the shell
		}
		if strings.HasSuffix(r.URL.Path, "index.html") || r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "no-store")
		}
		files.ServeHTTP(w, r)
	})
}

// ---- auth handlers ---------------------------------------------------------

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.sess.locked(ip) {
		httpErr(w, http.StatusTooManyRequests, errors.New("too many failed attempts; try again in a minute"))
		return
	}
	var in struct{ Username, Password string }
	if !decode(w, r, &in) {
		return
	}
	if !checkPassword(s.eng.Config().Web.Users, in.Username, in.Password) {
		s.sess.fail(ip)
		s.log.Warn("failed login", "user", in.Username, "ip", ip)
		httpErr(w, http.StatusUnauthorized, errors.New("wrong username or password"))
		return
	}
	s.sess.clear(ip)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.sess.create(in.Username), Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: int(sessionTTL.Seconds())})
	writeJSON(w, map[string]string{"user": in.Username})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sess.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) password(w http.ResponseWriter, r *http.Request) {
	var in struct{ Old, New string }
	if !decode(w, r, &in) {
		return
	}
	user := userOf(r)
	if !checkPassword(s.eng.Config().Web.Users, user, in.Old) {
		httpErr(w, http.StatusForbidden, errors.New("current password is wrong"))
		return
	}
	if len(in.New) < 8 {
		httpErr(w, http.StatusBadRequest, errors.New("new password must be at least 8 characters"))
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	s.mutate(w, func(c *model.Config) error {
		for i := range c.Web.Users {
			if c.Web.Users[i].Name == user {
				c.Web.Users[i].PasswordHash = string(h)
			}
		}
		return nil
	})
	s.sess.dropUser(user)
}

func (s *Server) putWebSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Listen     string   `json:"listen"`
		Port       int      `json:"port"`
		AllowedIPs []string `json:"allowed_ips"`
	}
	if !decode(w, r, &in) {
		return
	}
	for _, e := range in.AllowedIPs {
		if !allowed([]string{e}, strings.SplitN(e, "/", 2)[0]) {
			httpErr(w, http.StatusBadRequest, fmt.Errorf("invalid allowed ip %q", e))
			return
		}
	}
	// Refuse the one change that would cut off the person making it.
	if len(in.AllowedIPs) > 0 && !allowed(in.AllowedIPs, clientIP(r)) {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("that list would lock out your own address (%s)", clientIP(r)))
		return
	}
	if in.Port < 1 || in.Port > 65535 || net.ParseIP(in.Listen) == nil {
		httpErr(w, http.StatusBadRequest, errors.New("invalid listen address or port"))
		return
	}
	s.mutate(w, func(c *model.Config) error {
		c.Web.Listen, c.Web.Port, c.Web.AllowedIPs = in.Listen, in.Port, in.AllowedIPs
		return nil
	})
}

// ---- overview and live views ---------------------------------------------

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	links, _ := s.eng.Kernel().Links()
	links = orEmpty(links)
	fwd4, _ := s.eng.Kernel().IPForward(false)
	fwd6, _ := s.eng.Kernel().IPForward(true)
	host, _ := os.Hostname()
	cfg := s.eng.Config()
	writeJSON(w, map[string]any{
		"hostname": host, "mock": s.mock, "version": s.version,
		"links": links, "forwarding": map[string]any{
			"ipv4": map[string]bool{"on": fwd4, "managed": cfg.Sysctl.IPForward != nil},
			"ipv6": map[string]bool{"on": fwd6, "managed": cfg.Sysctl.IPv6Forward != nil},
		},
		"detect": detect.Run(), "issues": orEmpty(s.eng.Issues()), "safe": s.eng.SafeStatus(),
		"counts": map[string]int{"addresses": len(cfg.Addresses), "routes": len(cfg.Routes), "rules": len(cfg.Rules), "firewall": len(cfg.Firewall.Rules), "clients": len(cfg.ClientRouting.Clients)},
	})
}

func (s *Server) ruleset(w http.ResponseWriter, r *http.Request) {
	d := s.eng.Desired()
	live, _ := s.eng.Kernel().FirewallRuleset()
	writeJSON(w, map[string]string{"desired": kernel.RenderNFT(d.Firewall), "live": live})
}

// generated returns the items client routing produced, for read-only display
// next to the manual ones.
func (s *Server) generated(w http.ResponseWriter, r *http.Request) {
	d := s.eng.Desired()
	out := struct {
		Routes   []model.Route  `json:"routes"`
		Rules    []model.Rule   `json:"rules"`
		Firewall []model.FWRule `json:"firewall"`
	}{[]model.Route{}, []model.Rule{}, []model.FWRule{}}
	for _, x := range d.Routes {
		if x.Source != "" {
			out.Routes = append(out.Routes, x)
		}
	}
	for _, x := range d.Rules {
		if x.Source != "" {
			out.Rules = append(out.Rules, x)
		}
	}
	for _, x := range d.Firewall.Rules {
		if x.Source != "" {
			out.Firewall = append(out.Firewall, x)
		}
	}
	writeJSON(w, out)
}

// ---- import ------------------------------------------------------------------

func (s *Server) importScan(w http.ResponseWriter, r *http.Request) {
	p := importer.Scan(s.eng.Kernel())
	// Hide what the config already has.
	cfg := s.eng.Config()
	haveR, haveU, haveF := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, x := range cfg.Routes {
		haveR[x.Key()] = true
	}
	for _, x := range cfg.Rules {
		haveU[x.Key()] = true
	}
	for _, x := range cfg.Firewall.Rules {
		haveF[fwKey(x)] = true
	}
	p.Routes = filter(p.Routes, func(x model.Route) bool { return !haveR[x.Key()] })
	p.Rules = filter(p.Rules, func(x model.Rule) bool { return !haveU[x.Key()] })
	p.Firewall = filter(p.Firewall, func(x model.FWRule) bool { return !haveF[fwKey(x)] })
	p.Notes = orEmpty(p.Notes)
	s.scan = &p
	writeJSON(w, p)
}

func fwKey(r model.FWRule) string {
	r.ID, r.Source, r.Comment = "", "", ""
	return fmt.Sprintf("%+v", r)
}

// orEmpty makes a nil slice encode as [] rather than null.
func orEmpty[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

func filter[T any](in []T, keep func(T) bool) []T {
	out := []T{}
	for _, x := range in {
		if keep(x) {
			out = append(out, x)
		}
	}
	return out
}

func (s *Server) importApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Routes   []string `json:"routes"`
		Rules    []string `json:"rules"`
		Firewall []string `json:"firewall"`
		Policy   bool     `json:"policy"`
	}
	if !decode(w, r, &in) {
		return
	}
	if s.scan == nil {
		httpErr(w, http.StatusConflict, errors.New("scan first"))
		return
	}
	set := func(ids []string) map[string]bool {
		m := map[string]bool{}
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	sr, su, sf := set(in.Routes), set(in.Rules), set(in.Firewall)
	scan := *s.scan
	s.mutate(w, func(c *model.Config) error {
		for _, x := range scan.Routes {
			if sr[x.ID] {
				x.Source = ""
				c.Routes = append(c.Routes, x)
			}
		}
		for _, x := range scan.Rules {
			if su[x.ID] {
				x.Source = ""
				c.Rules = append(c.Rules, x)
			}
		}
		for _, x := range scan.Firewall {
			if sf[x.ID] {
				x.Source = ""
				c.Firewall.Rules = append(c.Firewall.Rules, x)
			}
		}
		if in.Policy && scan.Policy != nil {
			c.Firewall.Policy = *scan.Policy
		}
		return nil
	})
	s.scan = nil
}

func (s *Server) disableUFW(w http.ResponseWriter, r *http.Request) {
	if s.mock {
		writeJSON(w, map[string]string{"output": "(mock) ufw disable"})
		return
	}
	path, err := exec.LookPath("ufw")
	if err != nil {
		httpErr(w, http.StatusNotFound, errors.New("ufw is not installed"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "disable").CombinedOutput()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, fmt.Errorf("ufw disable: %v: %s", err, out))
		return
	}
	writeJSON(w, map[string]string{"output": strings.TrimSpace(string(out))})
}

// ---- generic CRUD ----------------------------------------------------------

func crud[T any](s *Server, mux *http.ServeMux, path string, list func(*model.Config) *[]T, id func(*T) *string) {
	mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		c := s.eng.Config()
		items := *list(&c)
		if items == nil {
			items = []T{}
		}
		writeJSON(w, items)
	})
	mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
		var item T
		if !decode(w, r, &item) {
			return
		}
		*id(&item) = engine.NewID()
		s.mutate(w, func(c *model.Config) error {
			l := list(c)
			*l = append(*l, item)
			return nil
		})
	})
	mux.HandleFunc("PUT "+path+"/{id}", func(w http.ResponseWriter, r *http.Request) {
		var item T
		if !decode(w, r, &item) {
			return
		}
		want := r.PathValue("id")
		*id(&item) = want
		s.mutate(w, func(c *model.Config) error {
			l := list(c)
			for i := range *l {
				if *id(&(*l)[i]) == want {
					(*l)[i] = item
					return nil
				}
			}
			return errNotFound
		})
	})
	mux.HandleFunc("DELETE "+path+"/{id}", func(w http.ResponseWriter, r *http.Request) {
		want := r.PathValue("id")
		s.mutate(w, func(c *model.Config) error {
			l := list(c)
			for i := range *l {
				if *id(&(*l)[i]) == want {
					*l = append((*l)[:i], (*l)[i+1:]...)
					return nil
				}
			}
			return errNotFound
		})
	})
	mux.HandleFunc("POST "+path+"/{id}/move", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			To int `json:"to"`
		}
		if !decode(w, r, &in) {
			return
		}
		want := r.PathValue("id")
		s.mutate(w, func(c *model.Config) error {
			l := list(c)
			from := -1
			for i := range *l {
				if *id(&(*l)[i]) == want {
					from = i
				}
			}
			if from < 0 {
				return errNotFound
			}
			to := max(0, min(in.To, len(*l)-1))
			item := (*l)[from]
			rest := append(append([]T{}, (*l)[:from]...), (*l)[from+1:]...)
			*l = append(rest[:to], append([]T{item}, rest[to:]...)...)
			return nil
		})
	})
}

var errNotFound = errors.New("not found")

// mutate runs a config change and answers with the apply issues.
func (s *Server) mutate(w http.ResponseWriter, fn func(*model.Config) error) {
	issues, err := s.eng.Update(fn)
	switch {
	case errors.Is(err, errNotFound):
		httpErr(w, http.StatusNotFound, err)
	case err != nil:
		httpErr(w, http.StatusBadRequest, err)
	default:
		if issues == nil {
			issues = []model.Issue{}
		}
		writeJSON(w, map[string]any{"issues": issues})
	}
}

// ---- helpers ---------------------------------------------------------------

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("bad request: %w", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func respond(w http.ResponseWriter, v any, err error) {
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, v)
}

func httpErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// ListenAndServe runs until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	wc := s.eng.Config().Web
	srv := &http.Server{
		Addr: net.JoinHostPort(wc.Listen, fmt.Sprint(wc.Port)), Handler: s.Handler(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	s.log.Info("web panel listening", "addr", srv.Addr, "tls", wc.TLSCert != "")
	var err error
	if wc.TLSCert != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		err = srv.ListenAndServeTLS(wc.TLSCert, wc.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
