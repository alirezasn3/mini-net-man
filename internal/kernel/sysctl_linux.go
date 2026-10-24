//go:build linux

package kernel

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

func (Linux) Sysctl(key string) (string, error) {
	if err := checkSysctlKey(key, false); err != nil {
		return "", err
	}
	b, err := os.ReadFile(sysctlPath(key))
	if err != nil {
		return "", sysctlErr(key, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func (l Linux) SetSysctl(key, value string) error {
	if err := checkSysctlKey(key, true); err != nil {
		return err
	}
	// BBR and some queue disciplines are modules that may not be loaded yet.
	if key == "net.ipv4.tcp_congestion_control" {
		if err := l.ensureCongestionControl(value); err != nil {
			return err
		}
	}
	err := os.WriteFile(sysctlPath(key), []byte(value), 0o644)
	if err != nil && key == "net.core.default_qdisc" {
		if mod := ModuleFor(key, value); mod != "" && exec.Command("modprobe", "-q", mod).Run() == nil {
			err = os.WriteFile(sysctlPath(key), []byte(value), 0o644)
		}
	}
	if err != nil {
		return sysctlErr(key, err)
	}
	return nil
}

// ensureCongestionControl makes sure the named algorithm is available,
// loading its module if the kernel has it but hasn't loaded it.
func (l Linux) ensureCongestionControl(name string) error {
	const avail = "net.ipv4.tcp_available_congestion_control"
	have := func() []string {
		v, _ := l.Sysctl(avail)
		return strings.Fields(v)
	}
	if slices.Contains(have(), name) {
		return nil
	}
	_ = exec.Command("modprobe", "-q", ModuleFor("net.ipv4.tcp_congestion_control", name)).Run()
	if now := have(); !slices.Contains(now, name) {
		return fmt.Errorf("%s isn't available in this kernel (it offers: %s) and its %s module could not be loaded",
			name, strings.Join(now, ", "), ModuleFor("net.ipv4.tcp_congestion_control", name))
	}
	return nil
}

// sysctlErr turns a /proc/sys error into a sentence a person can act on.
func sysctlErr(key string, err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("this kernel doesn't have %s", key)
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM), errors.Is(err, unix.EROFS):
		return fmt.Errorf("this system doesn't let it change %s (read-only, as inside some containers)", key)
	case errors.Is(err, unix.EINVAL):
		return fmt.Errorf("the kernel refused that value for %s", key)
	}
	return fmt.Errorf("%s: %w", key, err)
}
