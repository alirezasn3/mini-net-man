package initsys

import (
	"os/exec"
	"syscall"
)

// startDetached starts a command in its own session and does not wait for it,
// so it survives the service that started it being stopped.
func startDetached(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
