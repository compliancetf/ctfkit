//go:build unix

package tfexec

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// supported: the owned-dir checks exist on this OS.
const supported = true

// oNoFollow makes an open fail on a symlink at the final path component.
const oNoFollow = syscall.O_NOFOLLOW

// oNonblock keeps an open of a fifo from blocking.
const oNonblock = syscall.O_NONBLOCK

// ownedByUs reports whether fi belongs to this process's uid.
func ownedByUs(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// setProcessGroup runs cmd in its own process group; cancel interrupts the
// whole group, so a child's own children stop too.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGINT) }
}

// killGroup kills what is left of cmd's process group after an interrupted
// run: WaitDelay kills only the leader, and a provider that ignored SIGINT
// must not keep changing infrastructure after the run is finalized.
//
// Wait has reaped the leader, so its pid is free unless the group still has
// members (a live group keeps its id from being reused). A process holding
// that pid now means the pid was recycled and the old group is empty: the
// group id may belong to someone else, so nothing is sent.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL) // ESRCH when the group is gone
}
