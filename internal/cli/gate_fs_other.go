//go:build !unix

package cli

import (
	"os"
)

// shortcut: off unix there is no O_NOFOLLOW (O_EXCL still refuses an
// existing path) and no directory fsync; add them if a Windows runner becomes
// a supported verdict runner.
const oNoFollow = 0

func syncDir(string) error { return nil }

func ownedByUs(os.FileInfo) bool { return true }

// shortcut: off unix there is no flock, so concurrent runs on one set are
// not excluded; owner identity is unavailable, so no owner counts as gone.
func flockNB(*os.File) error { return nil }

func linkCount(os.FileInfo) uint64 { return 1 }
