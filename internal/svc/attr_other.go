//go:build !linux

package svc

import "syscall"

func procAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

func lockThread() {}
