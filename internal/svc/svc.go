// Package svc runs the helper programs mini-net-man manages (dnsmasq,
// hostapd) as child processes: it writes their config files, starts them,
// restarts them when their config changes or they die, keeps their latest log
// lines for the panel, and stops them with the panel.
//
// Running them as children, instead of editing the system's own service
// configuration, means mini-net-man never touches files it doesn't own and a
// distribution's own dnsmasq or hostapd service is left alone.
package svc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Timing; variables so tests can shorten them.
var (
	backoffMin   = time.Second
	backoffMax   = 30 * time.Second
	stableAfter  = 30 * time.Second // a run this long resets the backoff
	stopGrace    = 5 * time.Second
	logLinesKept = 200
)

// File is a config file written before the program starts.
type File struct {
	Path string
	Data []byte
	Mode os.FileMode
	// RemoveOnStop deletes it when the program is stopped for good, for files
	// that hold a secret.
	RemoveOnStop bool
}

// Spec is one program to keep running.
type Spec struct {
	Name   string
	Binary string
	Args   []string
	Files  []File
}

func (s Spec) hash() string {
	h := sha256.New()
	fmt.Fprintln(h, s.Binary, s.Args)
	for _, f := range s.Files {
		fmt.Fprintln(h, f.Path, f.Mode)
		h.Write(f.Data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Status is what the panel shows for one program.
type Status struct {
	Name      string    `json:"name"`
	Running   bool      `json:"running"`
	PID       int       `json:"pid,omitempty"`
	Since     time.Time `json:"since"`                // when it last started
	Restarts  int       `json:"restarts"`             // starts after the first
	LastError string    `json:"last_error,omitempty"` // why it last stopped, kept while it runs again
	Log       []string  `json:"log"`
}

type proc struct {
	spec   Spec
	hash   string
	cancel context.CancelFunc
	done   chan struct{}

	mu        sync.Mutex
	cmd       *exec.Cmd
	running   bool
	since     time.Time
	starts    int
	lastError string
	lines     []string
	partial   string
}

// Write collects the program's output line by line.
func (p *proc) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	data := p.partial + string(b)
	for {
		i := strings.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		p.lines = append(p.lines, data[:i])
		data = data[i+1:]
	}
	p.partial = data
	if extra := len(p.lines) - logLinesKept; extra > 0 {
		p.lines = p.lines[extra:]
	}
	return len(b), nil
}

type Supervisor struct {
	log  *slog.Logger
	fake bool

	mu    sync.Mutex
	procs map[string]*proc
}

func New(log *slog.Logger) *Supervisor {
	return &Supervisor{log: log, procs: map[string]*proc{}}
}

// NewFake never runs anything: every spec just counts as running. For the
// -mock server and tests that only care about what would be started.
func NewFake(log *slog.Logger) *Supervisor {
	return &Supervisor{log: log, fake: true, procs: map[string]*proc{}}
}

// Set makes exactly these programs run. One with an unchanged spec is left
// alone; one whose binary, arguments or files changed is restarted; one that
// is no longer listed is stopped.
func (s *Supervisor) Set(specs []Spec) {
	want := map[string]Spec{}
	for _, sp := range specs {
		want[sp.Name] = sp
	}
	s.mu.Lock()
	var stop []*proc
	for name, p := range s.procs {
		if sp, ok := want[name]; !ok || sp.hash() != p.hash {
			stop = append(stop, p)
			delete(s.procs, name)
		}
	}
	s.mu.Unlock()
	for _, p := range stop {
		s.stop(p)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, ok := s.procs[n]; ok {
			continue
		}
		sp := want[n]
		ctx, cancel := context.WithCancel(context.Background())
		p := &proc{spec: sp, hash: sp.hash(), cancel: cancel, done: make(chan struct{})}
		s.procs[n] = p
		if s.fake {
			p.running, p.since, p.starts = true, time.Now(), 1
			p.lines = []string{"(mock) " + sp.Binary + " would be running"}
			close(p.done)
			continue
		}
		go s.run(ctx, p)
	}
}

// Status reports a program, or false when it isn't one we are running.
func (s *Supervisor) Status(name string) (Status, bool) {
	s.mu.Lock()
	p := s.procs[name]
	s.mu.Unlock()
	if p == nil {
		return Status{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := Status{Name: name, Running: p.running, Since: p.since, LastError: p.lastError, Log: append([]string{}, p.lines...)}
	if p.starts > 0 {
		st.Restarts = p.starts - 1
	}
	if p.running && p.cmd != nil && p.cmd.Process != nil {
		st.PID = p.cmd.Process.Pid
	}
	return st, true
}

// Names lists what is being run.
func (s *Supervisor) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.procs))
	for n := range s.procs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Signal sends a signal to a running program, such as SIGHUP to make dnsmasq
// reread its host files.
func (s *Supervisor) Signal(name string, sig syscall.Signal) error {
	s.mu.Lock()
	p := s.procs[name]
	s.mu.Unlock()
	if p == nil {
		return fmt.Errorf("%s is not running", name)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil || p.cmd.Process == nil || !p.running {
		return fmt.Errorf("%s is not running", name)
	}
	return p.cmd.Process.Signal(sig)
}

// Close stops everything.
func (s *Supervisor) Close() {
	s.Set(nil)
}

func (s *Supervisor) stop(p *proc) {
	p.cancel()
	select {
	case <-p.done:
	case <-time.After(stopGrace + 2*time.Second):
	}
	for _, f := range p.spec.Files {
		if f.RemoveOnStop {
			_ = os.Remove(f.Path)
		}
	}
}

func writeFiles(files []File) error {
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
			return err
		}
		mode := f.Mode
		if mode == 0 {
			mode = 0o644
		}
		tmp := f.Path + ".tmp"
		if err := os.WriteFile(tmp, f.Data, mode); err != nil {
			return err
		}
		if err := os.Chmod(tmp, mode); err != nil {
			return err
		}
		if err := os.Rename(tmp, f.Path); err != nil {
			return err
		}
	}
	return nil
}

func (s *Supervisor) run(ctx context.Context, p *proc) {
	defer close(p.done)
	lockThread() // the kernel ties the child's lifetime to the thread that started it
	delay := backoffMin
	for {
		err := writeFiles(p.spec.Files)
		var ran time.Duration
		if err == nil {
			ran, err = s.once(ctx, p)
		}
		if ctx.Err() != nil {
			p.mu.Lock()
			p.running = false
			p.mu.Unlock()
			return
		}
		p.mu.Lock()
		p.running = false
		if err != nil {
			p.lastError = err.Error()
		}
		p.mu.Unlock()
		s.log.Warn("helper program stopped; restarting", "name", p.spec.Name, "err", err, "in", delay)
		if ran >= stableAfter {
			delay = backoffMin
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, backoffMax)
	}
}

// once runs the program until it exits or ctx is cancelled.
func (s *Supervisor) once(ctx context.Context, p *proc) (time.Duration, error) {
	cmd := exec.Command(p.spec.Binary, p.spec.Args...)
	cmd.Stdout, cmd.Stderr = p, p
	cmd.SysProcAttr = procAttr()
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	start := time.Now()
	p.mu.Lock()
	p.cmd, p.running, p.since = cmd, true, start // lastError stays: why it last stopped is still useful
	p.starts++
	p.mu.Unlock()

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		if err == nil {
			err = errors.New("exited")
		}
		return time.Since(start), err
	case <-ctx.Done():
		killGroup(cmd, syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(stopGrace):
			killGroup(cmd, syscall.SIGKILL)
			<-exited
		}
		return time.Since(start), nil
	}
}

func killGroup(cmd *exec.Cmd, sig syscall.Signal) {
	if cmd.Process == nil {
		return
	}
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		_ = syscall.Kill(-pgid, sig)
		return
	}
	_ = cmd.Process.Signal(sig)
}
