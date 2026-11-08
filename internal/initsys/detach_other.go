//go:build !linux

package initsys

import "errors"

func startDetached(name string, args ...string) error {
	return errors.New("only linux is supported")
}
