//go:build !linux

package kernel

import "errors"

// New reports that the real backend is Linux-only; use NewMock for UI work.
func New() (Kernel, error) {
	return nil, errors.New("the real kernel backend needs Linux (run with --mock to try the UI)")
}
