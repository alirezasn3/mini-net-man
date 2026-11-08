// Package initsys installs, stops and restarts mini-net-man's own service under
// whichever init system the machine runs: systemd, or OpenRC (Alpine, Gentoo).
package initsys

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	goOpenRC "github.com/alirezasn3/go-openrc"
	goSystemd "github.com/alirezasn3/go-systemd"
)

// Kind is an init system.
type Kind string

const (
	None    Kind = ""
	Systemd Kind = "systemd"
	OpenRC  Kind = "openrc"
)

// Spec describes the service to install.
type Spec struct {
	Name        string
	Description string
	ExecStart   string
}

// Status is what the init system says about a service.
type Status struct {
	Exists bool
	Active bool
}

// Detect reports which init system this machine runs. systemd wins when both
// are present, since a machine booted by systemd is the one it manages.
func Detect() Kind {
	if runtime.GOOS != "linux" {
		return None
	}
	// The same test sd_booted() uses.
	if st, err := os.Stat("/run/systemd/system"); err == nil && st.IsDir() {
		return Systemd
	}
	if goOpenRC.Available() {
		return OpenRC
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		return Systemd
	}
	return None
}

// ErrNone is returned when neither systemd nor OpenRC is available.
var ErrNone = errors.New("no supported init system found (needs systemd, or OpenRC with rc-service and rc-update); run `mini-net-man run` under your own supervisor instead")

func (k Kind) String() string {
	if k == None {
		return "no init system"
	}
	return string(k)
}

// Create writes the service, enables it at boot and starts it.
func (k Kind) Create(s Spec) error {
	switch k {
	case Systemd:
		return goSystemd.CreateService(&goSystemd.Service{
			Name:        s.Name,
			Description: s.Description,
			ExecStart:   s.ExecStart,
			Restart:     "on-failure",
			RestartSec:  "3s",
			After:       "network-online.target",
			Wants:       "network-online.target",
		})
	case OpenRC:
		return goOpenRC.CreateService(&goOpenRC.Service{
			Name:        s.Name,
			Description: s.Description,
			ExecStart:   s.ExecStart,
			Restart:     "on-failure",
			RestartSec:  "3s",
			After:       "network-online.target",
			Wants:       "network-online.target",
		})
	}
	return ErrNone
}

// Delete stops the service and removes it.
func (k Kind) Delete(name string) error {
	switch k {
	case Systemd:
		return goSystemd.DeleteService(name)
	case OpenRC:
		return goOpenRC.DeleteService(name)
	}
	return ErrNone
}

// Status looks the service up. A service that does not exist is not an error.
func (k Kind) Status(name string) (Status, error) {
	switch k {
	case Systemd:
		st, err := goSystemd.StatusService(name)
		if err != nil || st == nil {
			return Status{}, err
		}
		return Status{Exists: st.Exists, Active: st.Active}, nil
	case OpenRC:
		st, err := goOpenRC.StatusService(name)
		if err != nil || st == nil {
			return Status{}, err
		}
		return Status{Exists: st.Exists, Active: st.Active}, nil
	}
	return Status{}, ErrNone
}

// Stop stops the service.
func (k Kind) Stop(name string) error {
	switch k {
	case Systemd:
		return goSystemd.StopService(name)
	case OpenRC:
		return goOpenRC.StopService(name)
	}
	return ErrNone
}

// Restart restarts the service. With detached it only queues the restart and
// returns, which is what a service restarting itself needs: a blocking restart
// would be waiting on a process that the restart is about to kill.
func (k Kind) Restart(name string, detached bool) error {
	switch k {
	case Systemd:
		args := []string{"restart"}
		if detached {
			args = append(args, "--no-block")
		}
		out, err := exec.Command("systemctl", append(args, name)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl restart %s: %v: %s", name, err, strings.TrimSpace(string(out)))
		}
		return nil
	case OpenRC:
		if detached {
			return startDetached("rc-service", name, "restart")
		}
		out, err := exec.Command("rc-service", name, "restart").CombinedOutput()
		if err != nil {
			return fmt.Errorf("rc-service %s restart: %v: %s", name, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	return ErrNone
}

// RestartCmd is the command a person types to restart the service.
func (k Kind) RestartCmd(name string) string {
	if k == OpenRC {
		return "rc-service " + name + " restart"
	}
	return "systemctl restart " + name
}

// LogsHint says where the service's output goes.
func (k Kind) LogsHint(name string) string {
	if k == OpenRC {
		return "tail -f /var/log/" + name + ".log"
	}
	return "journalctl -u " + name + " -f"
}

// Supervised reports whether this process was started by the init system, so
// restarting the service restarts this process.
func (k Kind) Supervised() bool {
	switch k {
	case Systemd:
		return os.Getenv("INVOCATION_ID") != ""
	case OpenRC:
		// openrc-run exports the name of the service it is running.
		return os.Getenv("RC_SVCNAME") != ""
	}
	return false
}
