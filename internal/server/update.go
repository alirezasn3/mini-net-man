package server

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/update"
)

const (
	updateCacheTTL = 6 * time.Hour
	serviceName    = "mini-net-man"
)

type updateInfo struct {
	Current    string    `json:"current"`
	Latest     string    `json:"latest,omitempty"`
	Available  bool      `json:"available"`
	URL        string    `json:"url,omitempty"`
	Notes      string    `json:"notes,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
	CanInstall bool      `json:"can_install"`
	Reason     string    `json:"reason,omitempty"` // why it can't be installed from here
	AutoCheck  bool      `json:"auto_check"`
	Error      string    `json:"error,omitempty"`
	// Pending is a version already installed on disk that is not running yet.
	Pending string `json:"pending,omitempty"`
}

// canInstall says whether this process can replace itself, and if not why.
func (s *Server) canInstall() (bool, string) {
	switch {
	case s.mock:
		return false, "running against the mock kernel"
	case runtime.GOOS != "linux":
		return false, "updates are only built for Linux"
	case !update.Comparable(s.version):
		return false, "this is a development build with no release version; install a release build first"
	case s.exe == "":
		return false, "cannot locate this program's file"
	}
	return true, ""
}

// checkUpdate asks GitHub for the latest release. The caller holds upMu.
func (s *Server) checkUpdate() *updateInfo {
	cfg := s.eng.Config()
	info := &updateInfo{Current: s.version, CheckedAt: time.Now(), AutoCheck: !cfg.Update.NoAutoCheck, Pending: s.pending}
	info.CanInstall, info.Reason = s.canInstall()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rel, err := update.New(cfg.Update.Repo).Latest(ctx)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.Latest, info.URL, info.Notes = rel.Tag, rel.URL, rel.Notes
	if update.Comparable(s.version) && s.pending == "" {
		info.Available, _ = update.Newer(s.version, rel.Tag)
	}
	return info
}

// updateStatus answers from a cache of up to six hours, and never contacts
// GitHub on its own when the config turns the automatic check off.
func (s *Server) updateStatus(w http.ResponseWriter, r *http.Request) {
	s.upMu.Lock()
	defer s.upMu.Unlock()
	refresh := r.URL.Query().Get("refresh") != ""
	auto := !s.eng.Config().Update.NoAutoCheck
	switch {
	case refresh || (auto && (s.upCache == nil || time.Since(s.upCache.CheckedAt) > updateCacheTTL)):
		s.upCache = s.checkUpdate()
	case s.upCache == nil:
		ok, why := s.canInstall()
		writeJSON(w, &updateInfo{Current: s.version, CanInstall: ok, Reason: why, AutoCheck: auto, Pending: s.pending})
		return
	}
	info := *s.upCache
	info.Pending = s.pending
	writeJSON(w, &info)
}

// updateInstall replaces this binary with the latest release and, when it
// runs as a systemd service, restarts itself on it.
func (s *Server) updateInstall(w http.ResponseWriter, r *http.Request) {
	s.upMu.Lock()
	defer s.upMu.Unlock()
	if ok, why := s.canInstall(); !ok {
		httpErr(w, http.StatusConflict, errors.New(why))
		return
	}
	if s.pending != "" {
		httpErr(w, http.StatusConflict, errors.New("version "+s.pending+" is already installed; restart mini-net-man to run it"))
		return
	}
	if s.eng.SafeStatus().Active {
		httpErr(w, http.StatusConflict, errors.New("finish safe mode first: confirm or revert your changes, then update"))
		return
	}
	client := update.New(s.eng.Config().Update.Repo)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	rel, err := client.Latest(ctx)
	if err != nil {
		httpErr(w, http.StatusBadGateway, err)
		return
	}
	if newer, err := update.Newer(s.version, rel.Tag); err != nil || !newer {
		httpErr(w, http.StatusConflict, errors.New("already on the latest version"))
		return
	}
	if _, err := client.Install(ctx, rel, s.exe); err != nil {
		httpErr(w, http.StatusBadGateway, err)
		return
	}
	s.log.Info("updated binary", "from", s.version, "to", rel.Tag, "path", s.exe)
	s.upCache = nil
	s.pending = rel.Tag

	restarting := update.UnderSystemd()
	writeJSON(w, map[string]any{"version": rel.Tag, "restarting": restarting})
	if restarting {
		go func() {
			time.Sleep(700 * time.Millisecond) // let the response reach the browser
			if err := update.RestartService(serviceName, true); err != nil {
				s.log.Error("restart after update failed", "err", err)
			}
		}()
	}
}
