package cli

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/internal/tfexec"
)

const helperEnv = "CTFKIT_KEYFILE_HELPER"

// helperJob is what the helper process runs: apply on set, killed by
// SIGKILL at custody step kill ("" never), its exit code written to exit.
type helperJob struct {
	Set, TF, Inputs, Kill, Exit string
}

// TestKeyFileHelper is the helper process of the crash and signal tests; it
// runs only when re-executed with helperEnv set.
func TestKeyFileHelper(t *testing.T) {
	raw := os.Getenv(helperEnv)
	if raw == "" {
		t.Skip("helper process only")
	}
	var job helperJob
	if err := json.Unmarshal([]byte(raw), &job); err != nil {
		t.Fatal(err)
	}
	tfexec.InterruptGrace = 5 * time.Second
	custodyHook = func(step string) {
		if step == job.Kill {
			if p, err := os.FindProcess(os.Getpid()); err == nil {
				_ = p.Kill() // SIGKILL on unix; compiles on Windows, where syscall.Kill does not exist
			}
			time.Sleep(time.Minute)
		}
	}
	code, msg := runGate(applyCLI(t, job.Inputs, signNow, signNow), applyArgs(job.Inputs, job.TF, job.Set, "apply"))
	if err := os.WriteFile(job.Exit, []byte(strconv.Itoa(code)+"\n"+msg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// helper starts the helper process on job.
func helper(t *testing.T, job helperJob) *exec.Cmd {
	t.Helper()
	b, _ := json.Marshal(job)
	cmd := exec.Command(os.Args[0], "-test.run=^TestKeyFileHelper$", "-test.count=1") // #nosec G204 -- the test binary
	cmd.Env = append(os.Environ(), helperEnv+"="+string(b))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func needIdentity(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("owner identity needs Linux or macOS")
	}
}

func linkedSet(t *testing.T) (fakeTF, string, string) {
	t.Helper()
	inputs := filepath.Join(gateInputs, "valid")
	f, set := signedSet(t, inputs, filepath.Join(gateCases, "linked-create", "plan.json"))
	return f, set, inputs
}

func applyRun(t *testing.T, f fakeTF, set, inputs string, extra ...string) (int, string) {
	t.Helper()
	return runGate(applyCLI(t, inputs, signNow, signNow), append(applyArgs(inputs, f.bin, set, "apply"), extra...))
}

func readTombstone(t *testing.T, set string) tombstone {
	t.Helper()
	tomb, err := readJSON[tombstone](filepath.Join(set, artifactTombstone))
	if err != nil {
		t.Fatal(err)
	}
	return tomb
}

// noLeftovers asserts no key, reaper-named key, temp file or staged dir.
func noLeftovers(t *testing.T, set string) {
	t.Helper()
	entries, _ := os.ReadDir(set)
	for _, e := range entries {
		n := e.Name()
		if n == artifactRunKey || n == artifactStaged || strings.HasPrefix(n, reapedPrefix) || strings.HasPrefix(n, tmpPrefix) {
			t.Errorf("left over: %s", n)
		}
	}
}

// TestKeyFileWrittenOnce: gate plan writes ctfkit-run.key 0600 beside the
// planfile with O_EXCL; a second write fails.
func TestKeyFileWrittenOnce(t *testing.T) {
	_, set, _ := linkedSet(t)
	st, err := os.Stat(filepath.Join(set, artifactRunKey))
	if err != nil || st.Mode().Perm() != 0o600 || !inSet(set, artifactPlanfile) {
		t.Fatalf("ctfkit-run.key: %v %v", st, err)
	}
	if err = writeExclusive(filepath.Join(set, artifactRunKey), []byte("again"), 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second write: %v", err)
	}
}

// TestKeyFileExactSet: a missing or altered artifact exits 2 and leaves the
// set as it is; a wider mode exits 2; a mode narrowed in transport is
// restored and the set applies.
func TestKeyFileExactSet(t *testing.T) {
	for name, mutate := range map[string]func(string){
		"missing": func(s string) { _ = os.Remove(filepath.Join(s, artifactFindings)) },
		"altered": func(s string) { _ = os.WriteFile(filepath.Join(s, artifactFindings), []byte("{}"), 0o600) },
		"wider":   func(s string) { _ = os.Chmod(filepath.Join(s, artifactRunKey), 0o644) },
	} {
		t.Run(name, func(t *testing.T) {
			f, set, inputs := linkedSet(t)
			mutate(set)
			if code, _ := applyRun(t, f, set, inputs); code != ExitEnvironment {
				t.Fatalf("exit %d", code)
			}
			if inSet(set, artifactResult) || inSet(set, artifactLock) {
				t.Error("the set was changed")
			}
		})
	}
	t.Run("narrowed", func(t *testing.T) {
		f, set, inputs := linkedSet(t)
		entries, _ := os.ReadDir(set)
		for _, e := range entries {
			_ = os.Chmod(filepath.Join(set, e.Name()), 0o400)
		}
		_ = os.Chmod(set, 0o500)
		if code, msg := applyRun(t, f, set, inputs); code != ExitOK {
			t.Fatalf("exit %d: %s", code, msg)
		}
		consumed(t, set, outcomeEnforced)
	})
}

// TestKeyFileCrashPoints: apply killed after each custody step; the next
// apply resumes (nothing durable yet) or finishes the dead run with a named
// refusal, and the set ends tombstoned with no key.
func TestKeyFileCrashPoints(t *testing.T) {
	needIdentity(t)
	for _, tc := range []struct{ step, want, outcome string }{
		{"locked", "", outcomeEnforced},
		{"started", "did not finish", outcomeFailed},
		{"applied", "did not finish", outcomeFailed},
		{"result", "ended with outcome enforced", outcomeEnforced},
		{"tombstone", "tombstoned", outcomeEnforced},
		{"renamed", "tombstoned", outcomeEnforced},
	} {
		t.Run(tc.step, func(t *testing.T) {
			f, set, inputs := linkedSet(t)
			cmd := helper(t, helperJob{Set: set, TF: f.bin, Inputs: inputs, Kill: tc.step, Exit: filepath.Join(t.TempDir(), "exit")})
			var exitErr *exec.ExitError
			if err := cmd.Wait(); !errors.As(err, &exitErr) || exitErr.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("helper was not killed: %v", err)
			}
			before := len(f.calls(t))
			code, msg := applyRun(t, f, set, inputs)
			switch {
			case tc.want == "" && code != ExitOK:
				t.Fatalf("resume: exit %d: %s", code, msg)
			case tc.want != "" && (code != ExitEnvironment || !strings.Contains(msg, tc.want)):
				t.Fatalf("exit %d (%s), want 2 (%s)", code, msg, tc.want)
			case tc.want != "" && len(f.calls(t)) != before:
				t.Fatal("terraform ran on a dead run's set")
			}
			if r := readResult(t, set); r.Outcome != tc.outcome || readTombstone(t, set).Outcome != tc.outcome {
				t.Errorf("result %q tombstone %q, want %q", r.Outcome, readTombstone(t, set).Outcome, tc.outcome)
			}
			noLeftovers(t, set)
			if code, msg = applyRun(t, f, set, inputs); code != ExitEnvironment || !strings.Contains(msg, "tombstoned") {
				t.Fatalf("replay: exit %d (%s)", code, msg)
			}
		})
	}
}

// TestKeyFileSIGTERM: SIGTERM during terraform apply interrupts terraform,
// then result.json (outcome failed), the tombstone and the key unlink follow.
func TestKeyFileSIGTERM(t *testing.T) {
	needIdentity(t)
	f, set, inputs := linkedSet(t)
	if err := os.WriteFile(f.applyExit+".sleep", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	exit := filepath.Join(t.TempDir(), "exit")
	cmd := helper(t, helperJob{Set: set, TF: f.bin, Inputs: inputs, Exit: exit})
	for i := 0; ; i++ {
		if _, err := os.Stat(f.applyExit + ".started"); err == nil {
			break
		}
		if i == 400 {
			_ = cmd.Process.Kill()
			t.Fatal("terraform apply never started")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	b, err := os.ReadFile(exit)
	if err != nil || !strings.HasPrefix(string(b), "1\n") || !strings.Contains(string(b), "interrupted by a signal") {
		t.Fatalf("helper: %q %v", b, err)
	}
	consumed(t, set, outcomeFailed)
	noLeftovers(t, set)
}

// TestKeyFileOwnerLock: a second apply on a set whose owner lock is held
// exits 2 and changes nothing.
func TestKeyFileOwnerLock(t *testing.T) {
	needIdentity(t)
	f, set, inputs := linkedSet(t)
	lock, err := lockSet(set)
	if err != nil {
		t.Fatal(err)
	}
	if err = lock.claim(); err != nil {
		t.Fatal(err)
	}
	code, msg := applyRun(t, f, set, inputs)
	if code != ExitEnvironment || !strings.Contains(msg, "in use by ctfkit pid "+strconv.Itoa(os.Getpid())) {
		t.Fatalf("exit %d (%s)", code, msg)
	}
	if inSet(set, artifactResult) || inSet(set, artifactStart) {
		t.Error("the set was changed")
	}
	lock.release()
	if code, msg = applyRun(t, f, set, inputs); code != ExitOK {
		t.Fatalf("after release: exit %d (%s)", code, msg)
	}
}

// TestKeyFileOwnerIdentity: this process is live; the same pid with another
// start time or boot id, and a pid that exited, count as gone.
func TestKeyFileOwnerIdentity(t *testing.T) {
	needIdentity(t)
	me := self()
	if me.Start == "" || me.Boot == "" || me.gone() {
		t.Fatalf("self %+v gone", me)
	}
	other := me
	other.Start += "1"
	if !other.gone() {
		t.Error("another start time counts as live")
	}
	other = me
	other.Boot = "00000000-0000-0000-0000-000000000000"
	if !other.gone() {
		t.Error("another boot id counts as live")
	}
	c := exec.Command("/usr/bin/true")
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	if dead := (owner{PID: c.Process.Pid, Start: me.Start, Boot: me.Boot}); !dead.gone() {
		t.Error("an exited pid counts as live")
	}
}

// TestKeyFileReaper: an orphan older than verdict.max_ttl is reaped when its
// owner is gone, by a refused result, the tombstone and the key renamed then
// unlinked; it is kept while its owner lock is held, while its recorded
// owner lives and while it is young; a tombstoned set is never touched; a
// dead apply is finished as failed at any age. The reaper never records a
// passing outcome.
func TestKeyFileReaper(t *testing.T) {
	needIdentity(t)
	old := time.Now().Add(-25 * time.Hour)
	// reapNow is past the expiry of the fixture verdicts, signed at signNow.
	reapNow := func() time.Time {
		if late := signNow.Add(25 * time.Hour); late.After(time.Now()) {
			return late
		}
		return time.Now()
	}
	reapSetAt := func(t *testing.T, set string, now time.Time) []string {
		t.Helper()
		_, cand, _, err := readArtifactSet(set, true)
		if err != nil {
			t.Fatal(err)
		}
		return reap(filepath.Dir(set), "", cand.OrgID, cand.ProfileDigest, 24*time.Hour, now)
	}
	reapSet := func(t *testing.T, set string) []string { return reapSetAt(t, set, reapNow()) }
	age := func(t *testing.T, set string) {
		t.Helper()
		if err := os.Chtimes(filepath.Join(set, artifactCandidate), old, old); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("orphan", func(t *testing.T) {
		_, set, _ := linkedSet(t)
		age(t, set)
		if notes := reapSet(t, set); len(notes) != 1 || !strings.Contains(notes[0], "reaped") {
			t.Fatalf("notes %q", notes)
		}
		consumed(t, set, outcomeRefused)
		noLeftovers(t, set)
	})
	t.Run("verdict-valid", func(t *testing.T) {
		// signed late: candidate older than max_ttl, verdict not expired yet
		_, set, _ := linkedSet(t)
		now := signNow.Add(time.Hour)
		late := now.Add(-25 * time.Hour)
		if err := os.Chtimes(filepath.Join(set, artifactCandidate), late, late); err != nil {
			t.Fatal(err)
		}
		if notes := reapSetAt(t, set, now); len(notes) != 0 || inSet(set, artifactLock) {
			t.Fatalf("a set with a valid verdict was touched: %q", notes)
		}
		unchanged(t, set)
	})
	t.Run("unsigned-interrupted", func(t *testing.T) {
		// a reap killed after its result: the next pass still finds the set
		f := newFakeTFSchema(t, filepath.Join(gateCases, "linked-create", "plan.json"), filepath.Join(gateCases, "schema.json"), 0)
		set := planCandidate(t, filepath.Join(gateInputs, "valid"), f)
		age(t, set)
		_, cand, _, err := readArtifactSet(set, false)
		if err != nil {
			t.Fatal(err)
		}
		again := func() []string {
			return reap(filepath.Dir(set), "", cand.OrgID, cand.ProfileDigest, 24*time.Hour, reapNow())
		}
		hook := custodyHook
		custodyHook = func(step string) {
			if step == "result" {
				panic("killed")
			}
		}
		func() {
			defer func() { _ = recover() }()
			again()
		}()
		custodyHook = hook
		if !inSet(set, artifactResult) || inSet(set, artifactTombstone) {
			t.Fatal("the interrupted reap did not stop between result and tombstone")
		}
		if notes := again(); len(notes) != 1 {
			t.Fatalf("notes %q", notes)
		}
		consumed(t, set, outcomeRefused)
		noLeftovers(t, set)
	})
	t.Run("signed-while-reaping", func(t *testing.T) {
		// gate sign publishes a valid verdict between the reaper's first
		// read and its lock: the read under the lock keeps the set
		_, set, _ := linkedSet(t)
		now := signNow.Add(time.Hour)
		late := now.Add(-25 * time.Hour)
		if err := os.Chtimes(filepath.Join(set, artifactCandidate), late, late); err != nil {
			t.Fatal(err)
		}
		_, cand, _, err := readArtifactSet(set, true)
		if err != nil {
			t.Fatal(err)
		}
		v, aside := filepath.Join(set, artifactVerdict), filepath.Join(t.TempDir(), artifactVerdict)
		if err = os.Rename(v, aside); err != nil {
			t.Fatal(err)
		}
		hook := custodyHook
		custodyHook = func(step string) {
			if step == "reap-read" {
				_ = os.Rename(aside, v)
			}
		}
		defer func() { custodyHook = hook }()
		if notes := reap(filepath.Dir(set), "", cand.OrgID, cand.ProfileDigest, 24*time.Hour, now); len(notes) != 0 {
			t.Fatalf("notes %q", notes)
		}
		unchanged(t, set)
	})
	t.Run("young", func(t *testing.T) {
		_, set, _ := linkedSet(t)
		if notes := reapSet(t, set); len(notes) != 0 || inSet(set, artifactLock) {
			t.Fatalf("a young set was touched: %q", notes)
		}
		unchanged(t, set)
	})
	t.Run("lock-held", func(t *testing.T) {
		_, set, _ := linkedSet(t)
		age(t, set)
		lock, err := lockSet(set)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.release()
		if notes := reapSet(t, set); len(notes) != 1 || !strings.Contains(notes[0], "in use") {
			t.Fatalf("notes %q", notes)
		}
		unchanged(t, set)
	})
	t.Run("owner-live", func(t *testing.T) {
		_, set, _ := linkedSet(t)
		age(t, set)
		b, _ := json.Marshal(self())
		if err := os.WriteFile(filepath.Join(set, artifactLock), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if notes := reapSet(t, set); len(notes) != 0 {
			t.Fatalf("notes %q", notes)
		}
		unchanged(t, set)
	})
	t.Run("owner-reused-pid", func(t *testing.T) {
		_, set, _ := linkedSet(t)
		age(t, set)
		o := self()
		o.Start += "1"
		b, _ := json.Marshal(o)
		if err := os.WriteFile(filepath.Join(set, artifactLock), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if notes := reapSet(t, set); len(notes) != 1 {
			t.Fatalf("notes %q", notes)
		}
		consumed(t, set, outcomeRefused)
	})
	t.Run("tombstoned", func(t *testing.T) {
		f, set, inputs := linkedSet(t)
		if code, msg := applyRun(t, f, set, inputs); code != ExitOK {
			t.Fatalf("apply: exit %d (%s)", code, msg)
		}
		age(t, set)
		before, _ := os.ReadFile(filepath.Join(set, artifactTombstone))
		if notes := reap(filepath.Dir(set), "", "bobthecorp", "", 0, reapNow()); len(notes) != 0 {
			t.Fatalf("notes %q", notes)
		}
		if after, _ := os.ReadFile(filepath.Join(set, artifactTombstone)); string(after) != string(before) {
			t.Fatal("the tombstone changed")
		}
	})
	t.Run("dead-apply", func(t *testing.T) {
		f, set, inputs := linkedSet(t)
		cmd := helper(t, helperJob{Set: set, TF: f.bin, Inputs: inputs, Kill: "applied", Exit: filepath.Join(t.TempDir(), "exit")})
		_ = cmd.Wait()
		if notes := reapSet(t, set); len(notes) != 1 || !strings.Contains(notes[0], "did not finish") {
			t.Fatalf("notes %q", notes)
		}
		consumed(t, set, outcomeFailed)
		noLeftovers(t, set)
	})
}

// TestKeyFileBaselineChildOnly: --baseline-key-file reaches the terraform
// apply child as a staged copy and never the parent env; a file wider than
// 0600 exits 2 before the set is touched.
func TestKeyFileBaselineChildOnly(t *testing.T) {
	f, set, inputs := linkedSet(t)
	key := filepath.Join(t.TempDir(), "baseline.key")
	if err := os.WriteFile(key, []byte("org baseline key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, msg := applyRun(t, f, set, inputs, "--baseline-key-file", key); code != ExitEnvironment || !strings.Contains(msg, "0600") {
		t.Fatalf("wide key: exit %d (%s)", code, msg)
	}
	unchanged(t, set)
	_ = os.Chmod(key, 0o600)
	if code, msg := applyRun(t, f, set, inputs, "--baseline-key-file", key); code != ExitOK {
		t.Fatalf("exit %d (%s)", code, msg)
	}
	env, _ := os.ReadFile(f.applyEnv)
	abs, _ := filepath.Abs(set)
	if !strings.Contains(string(env), envBaselineKeyFile+"="+filepath.Join(abs, artifactStaged, "baseline.key")+"\n") {
		t.Errorf("child env has no staged baseline key:\n%s", env)
	}
	if os.Getenv(envBaselineKeyFile) != "" {
		t.Error("the baseline key env reached the parent")
	}
	noLeftovers(t, set)
}

// TestKeyFileGateSignRefusesCustody: gate sign refuses a set holding a
// custody file of ctfkit apply.
func TestKeyFileGateSignRefusesCustody(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	f := newFakeTFSchema(t, filepath.Join(gateCases, "linked-create", "plan.json"), filepath.Join(gateCases, "schema.json"), 0)
	set := planCandidate(t, inputs, f)
	if err := os.WriteFile(filepath.Join(set, artifactStart), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, msg := runGate(signCLI(t, inputs, verdictKeyL), signArgs(inputs, f.bin, set)); code != ExitEnvironment || !strings.Contains(msg, artifactStart) {
		t.Fatalf("exit %d (%s)", code, msg)
	}
}

// TestKeyFileHardLinkedLock: a lock file with another hard link is refused
// before claim could truncate the other file.
func TestKeyFileHardLinkedLock(t *testing.T) {
	_, set, _ := linkedSet(t)
	other := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(other, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(other, filepath.Join(set, artifactLock)); err != nil {
		t.Skip("no hard links here:", err)
	}
	if lock, err := lockSet(set); err == nil {
		lock.release()
		t.Fatal("a hard-linked lock file was taken")
	}
	if b, _ := os.ReadFile(other); string(b) != "keep" {
		t.Fatalf("the linked file changed: %q", b)
	}
}

// TestKeyFileTombstoneThroughSymlink: --artifacts naming a symlink to a
// tombstoned set is refused without touching the set.
func TestKeyFileTombstoneThroughSymlink(t *testing.T) {
	f, set, inputs := linkedSet(t)
	if code, msg := applyRun(t, f, set, inputs); code != ExitOK {
		t.Fatalf("apply: exit %d (%s)", code, msg)
	}
	if err := os.Chmod(filepath.Join(set, artifactResult), 0o400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(set, link); err != nil {
		t.Fatal(err)
	}
	if code, _ := applyRun(t, f, link, inputs); code != ExitEnvironment {
		t.Fatalf("exit %d", code)
	}
	if st, err := os.Stat(filepath.Join(set, artifactResult)); err != nil || st.Mode().Perm() != 0o400 {
		t.Fatalf("the tombstoned set was changed through the symlink: %v %v", st.Mode().Perm(), err)
	}
}

// TestKeyFileRemoveStagedNarrowed: a staged dir narrowed to 0500 in
// transport is still removed.
func TestKeyFileRemoveStagedNarrowed(t *testing.T) {
	set := t.TempDir()
	staged := filepath.Join(set, artifactStaged)
	if err := os.Mkdir(staged, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "run.key"), []byte("k"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(staged, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := removeStaged(set); err != nil || inSet(set, artifactStaged) {
		t.Fatalf("removeStaged: %v, still there: %v", err, inSet(set, artifactStaged))
	}
}
