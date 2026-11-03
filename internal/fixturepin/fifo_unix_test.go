//go:build unix

package fixturepin

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A FIFO or device in a tree is refused by ReadFiles, as by Scan, rather than
// read (a FIFO would block the read forever).
func TestReadFilesRefusesANonRegularFile(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "main.tf"), nil)
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600); err != nil {
		t.Skip(err)
	}
	if _, err := ReadFiles(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("ReadFiles err = %v, want a refused FIFO", err)
	}
	if _, err := Scan(dir, nil); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("Scan err = %v, want a refused FIFO", err)
	}
}
