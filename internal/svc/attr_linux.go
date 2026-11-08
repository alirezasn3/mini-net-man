//go:build linux

package svc

import (
	"runtime"
	"syscall"
)

// procAttr puts the child in its own process group and has the kernel kill it
// if mini-net-man dies, so a crash never leaves a stray dnsmasq or hostapd.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
}

func lockThread() { runtime.LockOSThread() }
