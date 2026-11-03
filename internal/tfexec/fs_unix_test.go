//go:build unix

package tfexec

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestKillGroupAfterInterrupt: a child that ignores SIGINT does not outlive
// an interrupted run; WaitDelay alone kills only the group leader.
func TestKillGroupAfterInterrupt(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sh", "-c", `trap '' INT; sh -c 'trap "" INT; echo $$ > "$0"; exec sleep 60' "$1" & wait`, "sh", pidFile)
	setProcessGroup(cmd)
	cmd.WaitDelay = 200 * time.Millisecond
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var pid int
	for range 100 {
		if b, err := os.ReadFile(pidFile); err == nil && strings.TrimSpace(string(b)) != "" {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("the grandchild did not start")
	}
	cancel()
	_ = cmd.Wait()
	killGroup(cmd)
	for range 100 {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("pid %d outlived the interrupted run", pid)
}

// TestProcessGroup: terraform gets its own process group only when the caller
// can cancel it; otherwise it stays in ctfkit's group, so a terminal SIGINT
// reaches it.
func TestProcessGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		own  bool
	}{{"no cancel", nil, false}, {"cancelable", ctx, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, fakeOpts{onVersion: `ps -o pgid= -p $$ > @DIR@/pgid;`})
			cfg := config(t, f)
			cfg.Ctx = tc.ctx
			run(t, open(t, cfg), Version())
			b, err := os.ReadFile(filepath.Join(f.dir, "pgid"))
			if err != nil {
				t.Fatal(err)
			}
			pgid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil {
				t.Fatal(err)
			}
			if own := pgid != syscall.Getpgrp(); own != tc.own {
				t.Fatalf("own process group %v, want %v", own, tc.own)
			}
		})
	}
}

// TestSealFifo: a fifo planted at the pinned path is refused, not waited on.
func TestSealFifo(t *testing.T) {
	f := newFake(t, fakeOpts{})
	cfg := config(t, f)
	if err := os.Remove(f.bin); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(f.bin, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- open(t, cfg).Run(Version(), io.Discard, io.Discard) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotStarted) || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("version: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sealing blocked on a fifo")
	}
}

// TestSealTooLarge: a binary past the cap is refused before its digest, and nothing runs.
func TestSealTooLarge(t *testing.T) {
	f := newFake(t, fakeOpts{})
	cfg := config(t, f)
	defer func(n int64) { maxTerraformBytes = n }(maxTerraformBytes)
	maxTerraformBytes = 8
	err := open(t, cfg).Run(Version(), io.Discard, io.Discard)
	if !errors.Is(err, ErrNotStarted) || !strings.Contains(err.Error(), "larger than 8 bytes") {
		t.Fatalf("version: %v", err)
	}
	if _, err := os.Stat(f.log); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("terraform ran: %v", err)
	}
}
