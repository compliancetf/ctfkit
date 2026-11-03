//go:build !linux && !darwin

package cli

import "errors"

// shortcut: no process start time or boot id off Linux and macOS, so no
// owner counts as gone and nothing is recovered or reaped automatically;
// add them if another OS becomes a supported verdict runner.
func procStart(int) (string, error) { return "", errors.ErrUnsupported }

func bootID() (string, error) { return "", errors.ErrUnsupported }
