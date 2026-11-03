//go:build unix

package cli

import (
	"errors"
	"os"
	"syscall"
)

// oNoFollow makes an open fail on a symlink at the final path component.
const oNoFollow = syscall.O_NOFOLLOW

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- a directory this run created
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck // the sync result is what counts
	return d.Sync()
}

// ownedByUs reports whether fi belongs to this process's uid.
func ownedByUs(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// flockNB takes an exclusive flock without waiting; errLockHeld when another
// open file holds it. The kernel drops it when the holder exits.
func flockNB(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) // #nosec G115 -- a file descriptor fits an int
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return errLockHeld
	}
	return err
}

// linkCount is the number of hard links of fi, 1 when unknown.
func linkCount(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink) //nolint:unconvert // Nlink is uint16 on darwin
	}
	return 1
}
