//go:build !unix

package sink

import "io/fs"

// shortcut: no owner or mode check, no directory fsync and no spool lock off unix (Windows
// has no flock or dir fsync); add ACL checks and LockFileEx if a Windows runner becomes a
// supported verdict runner.
func checkOwned(fs.FileInfo, fs.FileMode) error { return nil }

func syncDir(string) error { return nil }

func ownedByRunner(fs.FileInfo) bool { return false }

func lockDir(string) (func(), error) { return func() {}, nil }
