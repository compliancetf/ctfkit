//go:build unix

package sink

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// checkOwned refuses a spool path owned by another uid or with mode bits beyond want.
func checkOwned(fi fs.FileInfo, want fs.FileMode) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read owner")
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("owned by uid %d, not the runner", st.Uid)
	}
	if got := fi.Mode().Perm(); got&^want != 0 {
		return fmt.Errorf("mode %04o is wider than %04o", got, want)
	}
	return nil
}

// ownedByRunner reports whether fi belongs to the effective uid.
func ownedByRunner(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the spool dir OpenSpool checked
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// lockDir takes an exclusive flock on dir/.lock and returns its release.
func lockDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, spoolLock), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- the spool dir OpenSpool checked
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { // #nosec G115 -- a file descriptor fits an int
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil // closing the descriptor releases the lock
}
