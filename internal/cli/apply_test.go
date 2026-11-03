package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/pkg/verdict"
)

func readResult(t *testing.T, set string) applyResult {
	t.Helper()
	var r applyResult
	b, err := os.ReadFile(filepath.Join(set, artifactResult))
	if err == nil {
		err = json.Unmarshal(b, &r)
	}
	if err != nil {
		t.Fatalf("result.json: %v", err)
	}
	return r
}

// consumed asserts result.json with outcome, the tombstone and no run key.
func consumed(t *testing.T, set, outcome string) {
	t.Helper()
	if r := readResult(t, set); r.Outcome != outcome {
		t.Errorf("result outcome %q, want %q", r.Outcome, outcome)
	}
	if _, err := os.Stat(filepath.Join(set, artifactTombstone)); err != nil {
		t.Errorf("no tombstone: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(set, artifactRunKey)); !errors.Is(err, fs.ErrNotExist) {
		t.Error("ctfkit-run.key was not unlinked")
	}
}

// TestApply: a signed linked plan is verified, then applied from the sealed
// copy with the allowlisted argv and env, the verdict and key env in the
// child only; the set is consumed once.
func TestApply(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	t.Setenv("CTFKIT_APPLY_PARENT_MARK", "1")
	f, set := signedSet(t, inputs, filepath.Join(gateCases, "linked-create", "plan.json"))
	key, _ := os.ReadFile(filepath.Join(set, artifactRunKey))

	before := len(f.calls(t))
	if code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, set, "apply")); code != ExitOK {
		t.Fatalf("apply: exit %d: %s", code, msg)
	}
	// The apply-env oracle: the argv templates and the exact child env
	// names (the shell adds PWD, SHLVL, _ and OLDPWD itself).
	var oracle struct{ Argv, Env []string }
	raw, err := os.ReadFile("testdata/apply-env/expected.json")
	if err == nil {
		err = json.Unmarshal(raw, &oracle)
	}
	if err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(f.applyEnv)
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{}
	var names []string
	for _, l := range strings.Split(strings.TrimSpace(string(env)), "\n") {
		name, val, _ := strings.Cut(l, "=")
		if !slices.Contains([]string{"PWD", "SHLVL", "_", "OLDPWD"}, name) {
			vars[name], names = val, append(names, name)
		}
	}
	if slices.Sort(names); !slices.Equal(names, oracle.Env) {
		t.Errorf("child env %q, want %q", names, oracle.Env)
	}
	dir, _ := filepath.Abs(signConfig)
	owned := filepath.Dir(vars["TF_DATA_DIR"])
	calls := f.calls(t)[before:]
	for i := range calls {
		calls[i] = strings.ReplaceAll(strings.ReplaceAll(calls[i], dir, "<dir>"), owned, "<owned>")
	}
	if !slices.Equal(calls, oracle.Argv) {
		t.Fatalf("argv %q, want %q", calls, oracle.Argv)
	}
	if b, _ := os.ReadFile(f.applied); string(b) != "fake planfile" {
		t.Fatalf("applied %q", b)
	}
	absSet, _ := filepath.Abs(set)
	staged := filepath.Join(absSet, artifactStaged)
	if v := vars[envVerdictKeyFile]; v != filepath.Join(staged, artifactRunKey) {
		t.Errorf("%s=%q, want the staged key copy", envVerdictKeyFile, v)
	}
	if v := vars[envVerdict]; v != filepath.Join(staged, artifactVerdict) {
		t.Errorf("%s=%q, want the staged verdict copy", envVerdict, v)
	}
	if inSet(absSet, artifactStaged) {
		t.Error("the staged copies outlived the run")
	}
	if os.Getenv(envVerdict) != "" || os.Getenv(envVerdictKeyFile) != "" {
		t.Error("the verdict env reached the parent")
	}

	consumed(t, set, outcomeEnforced)
	r := readResult(t, set)
	var tomb tombstone
	b, _ := os.ReadFile(filepath.Join(set, artifactTombstone))
	if err = json.Unmarshal(b, &tomb); err != nil || tomb.NonceDigest != rawDigest(key) || tomb.RunID == "" || tomb.RunID != r.RunID {
		t.Errorf("tombstone %s (%v)", b, err)
	}
	if r.Exit != "0" || r.TerraformExit != "0" || len(r.Rows) == 0 {
		t.Errorf("result %+v", r)
	}

	// A tombstoned set is refused before terraform runs.
	before = len(f.calls(t))
	code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, set, "apply"))
	if code != ExitEnvironment || !strings.Contains(msg, "tombstoned") || len(f.calls(t)) != before {
		t.Fatalf("replay: exit %d (%s)", code, msg)
	}
}

// TestApplyTerraformOutcomes: a failing terraform apply and a pending
// decision (no post-apply check yet) exit 1 with outcome failed.
func TestApplyTerraformOutcomes(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	t.Run("apply-fails", func(t *testing.T) {
		f, set := signedSet(t, inputs, filepath.Join(gateCases, "linked-create", "plan.json"))
		if err := os.WriteFile(f.applyExit, []byte("3"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, set, "apply"))
		if code != ExitFindings || !strings.Contains(msg, "terraform apply failed") {
			t.Fatalf("exit %d (%s)", code, msg)
		}
		consumed(t, set, outcomeFailed)
		if r := readResult(t, set); r.TerraformExit != "3" || r.Exit != "1" {
			t.Errorf("result %+v", r)
		}
	})
	t.Run("pending", func(t *testing.T) {
		f, set := signedSet(t, inputs, filepath.Join(gateCases, "linked-create", "plan.json"))
		resign(t, inputs, set, func(d *verdict.Document) { d.Instances[0].Decisions[0].Result = "pending" })
		code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, set, "apply"))
		if code != ExitFindings || !strings.Contains(msg, "post-apply linkage check") {
			t.Fatalf("exit %d (%s)", code, msg)
		}
		if _, err := os.Stat(f.applied); err != nil {
			t.Fatal("a pending decision did not apply")
		}
		consumed(t, set, outcomeFailed)
	})
}

// TestApplyRefuses: every refusal exits 2 and terraform apply never runs.
// A refusal after the exact set was read records result.json, tombstones
// the set and unlinks the key; a set that is not exact is left as it is.
func TestApplyRefuses(t *testing.T) {
	for name, tc := range refusals() {
		t.Run(name, func(t *testing.T) {
			set := refuse(t, tc, "apply")
			if tc.consumed {
				consumed(t, set, outcomeRefused)
				return
			}
			unchanged(t, set)
		})
	}
}

// TestApplyAirgapIgnoresLocalClock: under floor_mode airgap an exception
// valid at the floor's issued_at applies though the runner clock is past
// its expiry.
func TestApplyAirgapIgnoresLocalClock(t *testing.T) {
	inputs := filepath.Join(gateInputs, "airgap")
	f, set := signedSet(t, inputs, filepath.Join(gateCases, "linked-create", "plan.json"))
	resign(t, inputs, set, func(d *verdict.Document) {
		d.Exceptions = []verdict.ExceptionRef{{Digest: "sha256:" + strings.Repeat("e", 64), Source: "grant", Expires: "2026-10-19T07:00:00Z"}}
	})
	c := applyCLI(t, inputs, signNow, time.Time{})
	c.evidenceTime = noEvidenceAPI
	if code, msg := runGate(c, applyArgs(inputs, f.bin, set, "apply")); code != ExitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	consumed(t, set, outcomeEnforced)
}

// TestFinalizeKeepsKey: when result.json cannot be written the key stays,
// no tombstone is written and the run exits 2.
func TestFinalizeKeepsKey(t *testing.T) {
	dir := t.TempDir()
	for n, b := range map[string]string{artifactRunKey: "key", artifactResult: "another run"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := finalize(dir, []byte("key"), &applyResult{Outcome: outcomeEnforced}, nil)
	if ExitCode(err) != ExitEnvironment {
		t.Fatalf("finalize: %v", err)
	}
	if _, err = os.Stat(filepath.Join(dir, artifactRunKey)); err != nil {
		t.Fatal("the key was unlinked before the result was written")
	}
	if _, err = os.Lstat(filepath.Join(dir, artifactTombstone)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("tombstone written without a result")
	}
}

// TestApplyFailure: only a terraform that never started is refused; one that
// ran and then failed, or whose output could not be copied, ends failed.
func TestApplyFailure(t *testing.T) {
	run, err := newTFRun(context.Background(), filepath.Join(t.TempDir(), "missing"), "sha256:00", t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	defer run.cleanup() //nolint:errcheck // a test temp dir
	res := &applyResult{Outcome: outcomeFailed}
	if err := applyFailure(res, run.apply(io.Discard)); ExitCode(err) != ExitEnvironment || res.Outcome != outcomeRefused {
		t.Fatalf("not started: %v, outcome %s", err, res.Outcome)
	}
	res = &applyResult{Outcome: outcomeFailed}
	if err := applyFailure(res, errors.New("write |1: broken pipe")); ExitCode(err) != ExitEnvironment || res.Outcome != outcomeFailed {
		t.Fatalf("copy error: %v, outcome %s", err, res.Outcome)
	}
}
