//go:build !unix

package tfexec

import (
	"os"
	"os/exec"
)

// shortcut: off unix there is no O_NOFOLLOW and no owner check, so Open
// refuses to run terraform at all; add them if a Windows runner becomes a
// supported verdict runner.
const supported = false

const oNoFollow = 0

const oNonblock = 0

func ownedByUs(os.FileInfo) bool { return true }

func setProcessGroup(*exec.Cmd) {}

func killGroup(*exec.Cmd) {}
