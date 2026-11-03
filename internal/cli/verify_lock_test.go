package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// verifyLockFixtures is the verify-lock fixture pack, relative to this package.
const verifyLockFixtures = "../../testdata/fixtures/verifylock"

// verifyLockCases are the fixture cases, each with the rule it must fire (none
// for good) and its exit code. Every rule of the family fires in one case and
// stays silent in good.
var verifyLockCases = []struct {
	name string
	args []string
	exit int
	rule string
}{
	{name: "good", exit: ExitOK},
	{name: "missing", exit: ExitFindings, rule: "ctf.lock.missing"},
	{name: "upstream-present", exit: ExitFindings, rule: "ctf.lock.upstream_present"},
	{name: "wrapper-missing", exit: ExitFindings, rule: "ctf.lock.wrapper_missing"},
	{name: "wrapper-unhashed", exit: ExitFindings, rule: "ctf.lock.wrapper_unhashed"},
	{name: "source-mismatch", exit: ExitFindings, rule: "ctf.lock.source_mismatch"},
	{name: "source-mismatch-implied", exit: ExitFindings, rule: "ctf.lock.source_mismatch"},
	{name: "unwrapped", exit: ExitFindings, rule: "ctf.lock.unwrapped"},
}

// TestVerifyLockFixtures runs verify-lock over every case and compares the
// SARIF with expected/findings.sarif byte for byte. CTFKIT_RERECORD=1 writes
// the rendered document instead.
func TestVerifyLockFixtures(t *testing.T) {
	refuseSwitchesInCI(t)
	for _, tc := range verifyLockCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			base, err := filepath.Abs(filepath.Join(verifyLockFixtures, tc.name))
			if err != nil {
				t.Fatal(err)
			}
			got := runScanIn(t, filepath.Join(base, "input"), append([]string{"verify-lock", "--format", "sarif"}, tc.args...)...)
			if got.code != tc.exit {
				t.Fatalf("exit = %d, want %d (%v)", got.code, tc.exit, got.err)
			}
			if tc.rule != "" && !strings.Contains(got.stdout, `"ruleId": "`+tc.rule+`"`) {
				t.Errorf("%s did not fire:\n%s", tc.rule, got.stdout)
			}
			path := filepath.Join(base, "expected", "findings.sarif")
			if os.Getenv(rerecordEnv) == "1" {
				if err := os.WriteFile(path, []byte(got.stdout), 0o644); err != nil { //nolint:gosec // a committed fixture
					t.Fatal(err)
				}
				return
			}
			if want := string(readFile(t, path)); got.stdout != want {
				t.Errorf("SARIF differs from %s:\n%s", path, got.stdout)
			}
		})
	}
}

// A lock file that does not decode, here an attribute Terraform never writes,
// is an environment error rather than an empty lock.
func TestVerifyLockMalformedLock(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join(verifyLockFixtures, "malformed", "input"))
	if err != nil {
		t.Fatal(err)
	}
	got := runScanIn(t, dir, "verify-lock")
	if got.code != ExitEnvironment || !strings.Contains(got.err.Error(), "does not parse as a dependency lock file") {
		t.Fatalf("exit = %d, err = %v; want 2 and a lock file parse error", got.code, got.err)
	}
}

// --provider replaces the settings: checking google only, the aws case with
// a missing wrapper is clean; an unknown type is exit 2.
func TestVerifyLockProviderFlag(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join(verifyLockFixtures, "wrapper-missing", "input"))
	if err != nil {
		t.Fatal(err)
	}
	if got := runScanIn(t, dir, "verify-lock", "--provider", "google"); got.code != ExitOK {
		t.Errorf("--provider google: exit = %d (%v), want 0", got.code, got.err)
	}
	if got := runScanIn(t, dir, "verify-lock", "--provider", "random"); got.code != ExitEnvironment {
		t.Errorf("--provider random: exit = %d, want 2", got.code)
	}
}

// scan --stage pre_plan runs the ctf.lock rules when wrapped_providers is set,
// and not otherwise.
func TestScanRunsLockRulesWhenWrapped(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join(verifyLockFixtures, "unwrapped", "input"))
	if err != nil {
		t.Fatal(err)
	}
	unwrappedDir, err := filepath.Abs(filepath.Join(verifyLockFixtures, "upstream-present", "input"))
	if err != nil {
		t.Fatal(err)
	}
	got := runScanIn(t, dir, "scan", "--stage", "pre_plan", "--format", "sarif", "--fail-on", "never", "--catalog", "embedded")
	if got.code != ExitOK || !strings.Contains(got.stdout, `"ruleId": "ctf.lock.unwrapped"`) {
		t.Errorf("wrapped_providers set: exit %d (%v), want ctf.lock.unwrapped in:\n%s", got.code, got.err, got.stdout)
	}

	got = runScanIn(t, unwrappedDir, "scan", "--stage", "pre_plan", "--format", "sarif", "--fail-on", "never", "--catalog", "embedded")
	if strings.Contains(got.stdout, `"ruleId": "ctf.lock.`) {
		t.Errorf("no wrapped_providers: a ctf.lock rule fired:\n%s", got.stdout)
	}
}

// A directory with no configuration is a mistyped path, never a clean run.
func TestVerifyLockEmptyDirectory(t *testing.T) {
	if got := runScanIn(t, t.TempDir(), "verify-lock"); got.code != ExitEnvironment {
		t.Errorf("exit = %d (%v), want 2", got.code, got.err)
	}
}
