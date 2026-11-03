package cli

import (
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/sys/unix"
)

// procStart is the kinfo_proc p_starttime of pid. fs.ErrNotExist when the
// pid is absent: sysctl kern.proc.pid answers no bytes for it, which
// SysctlKinfoProc reports as EIO.
func procStart(pid int) (string, error) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if errors.Is(err, unix.EIO) || (err == nil && int(k.Proc.P_pid) != pid) {
		return "", fs.ErrNotExist
	}
	if err != nil {
		return "", err
	}
	t := k.Proc.P_starttime
	return fmt.Sprintf("%d.%06d", t.Sec, t.Usec), nil
}

func bootID() (string, error) { return unix.Sysctl("kern.bootsessionuuid") }
