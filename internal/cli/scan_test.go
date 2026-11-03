package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/internal/conformance"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// planFixtures is the plan fixture pack, relative to this package.
const planFixtures = "../../testdata/fixtures/plan"

// scanRunContext is the run context the fixture pack README pins for every
// recorded projection.
var scanRunContext = []string{
	"--run-id", conformance.FixtureRunID,
	"--commit", conformance.FixtureCommit,
	"--platform", "local",
}

// scanCases is the plan fixture table the conformance harness owns: argv,
// exit code and any known deviation. The post_apply case is the harness's own
// and is not a scan parity row.
var scanCases = func() []conformance.Case {
	var cases []conformance.Case
	for _, c := range conformance.PlanCases {
		if c.Stage != ctfkit.PostApply {
			cases = append(cases, c)
		}
	}
	return cases
}()

// scanResult is what one in-process run produced.
type scanResult struct {
	stdout, stderr string
	code           int
	err            error
}

// runScanIn runs ctfkit with args in process, from dir, with the fixture clock
// and version. dir is the process working directory, which is what every path
// argument and the policy-file discovery root resolve against.
func runScanIn(t *testing.T, dir string, args ...string) scanResult {
	t.Helper()

	clock, err := time.Parse(time.RFC3339, fixtureClock)
	if err != nil {
		t.Fatalf("parse the fixture clock: %v", err)
	}
	t.Chdir(dir)

	cli := New(fixtureVersion)
	cli.now = func() time.Time { return clock }

	var stdout, stderr bytes.Buffer
	cli.rootCmd.SetOut(&stdout)
	cli.rootCmd.SetErr(&stderr)
	cli.rootCmd.SetArgs(args)

	runErr := cli.Execute()
	return scanResult{stdout: stdout.String(), stderr: stderr.String(), code: ExitCode(runErr), err: runErr}
}

// fixtureInput is the absolute input directory of a plan case.
func fixtureInput(t *testing.T, name string) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join(planFixtures, name, "input"))
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return dir
}

// rerecordEnv set to 1 makes TestScanFixtureParity write what the command
// renders over expected/findings.sarif instead of comparing, which is how the
// plan pack is re-recorded (testdata/fixtures/README.md "Regenerating").
const rerecordEnv = "CTFKIT_RERECORD"

// TestScanFixtureParity runs the argv column of every plan fixture from a clean
// HOME at the fixture clock and compares the SARIF with the recorded bytes,
// byte for byte.
func TestScanFixtureParity(t *testing.T) {
	refuseSwitchesInCI(t)
	for _, tc := range scanCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			path, err := filepath.Abs(filepath.Join(planFixtures, tc.Name, "expected", "findings.sarif"))
			if err != nil {
				t.Fatal(err)
			}
			want := readFile(t, path)
			for _, drop := range tc.Drop {
				trimmed := drop.ReplaceAll(want, nil)
				if bytes.Equal(trimmed, want) {
					t.Fatalf("a known deviation no longer matches the recorded file; remove it: %s", tc.Deviation)
				}
				want = trimmed
			}

			got := runScanIn(t, fixtureInput(t, tc.Name), fixtureArgs(t, tc, tc.Argv, "--format", "sarif")...)
			if got.code != tc.Exit {
				t.Errorf("exit = %d, want %d (%v)", got.code, tc.Exit, got.err)
			}
			if !strings.Contains(got.stdout, `"ctf.catalogVersion": {`) {
				t.Errorf("run object carries no ctf.catalogVersion:\n%s", got.stdout)
			}
			rendered := []byte(conformance.InvocationsBlock.ReplaceAllString(
				conformance.CatalogVersionBlock.ReplaceAllString(got.stdout, ""), ""))
			if os.Getenv(rerecordEnv) == "1" {
				if err := os.WriteFile(path, rendered, 0o644); err != nil { //nolint:gosec // a committed fixture, read by everyone
					t.Fatal(err)
				}
				return
			}
			assertSameBytes(t, tc.Name+"/expected/findings.sarif", want, rendered)
		})
	}
}

// fixtureArgs is argv plus the pinned run context, catalog and extra flags of
// a case. Paths are made absolute: the run's working directory is the case's
// input directory.
func fixtureArgs(t *testing.T, tc conformance.Case, argv []string, more ...string) []string {
	t.Helper()
	args := append(append([]string{}, argv...), more...)
	args = append(args, scanRunContext...)
	if tc.Catalog != "" {
		args = append(args, "--catalog", absPath(t, tc.Catalog))
	}
	return args
}

// TestScanRecordedExitCodes checks the exit-code file of every case that
// carries one against the command.
func TestScanRecordedExitCodes(t *testing.T) {
	for _, tc := range scanCases {
		path := filepath.Join(planFixtures, tc.Name, "expected", "exit-code")
		raw, err := os.ReadFile(path) //nolint:gosec // a fixture path
		if err != nil {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			got := runScanIn(t, fixtureInput(t, tc.Name), fixtureArgs(t, tc, tc.Argv)...)
			if want := strings.TrimSpace(string(raw)); want != string(rune('0'+got.code)) {
				t.Errorf("exit = %d, recorded %s (%v)", got.code, want, got.err)
			}
		})
	}
}

// parseResults returns the results of a rendered SARIF document.
func parseResults(t *testing.T, doc string) []map[string]any {
	t.Helper()
	var parsed struct {
		Runs []struct {
			Results []map[string]any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil || len(parsed.Runs) != 1 {
		t.Fatalf("not a one-run SARIF document (%v):\n%s", err, doc)
	}
	return parsed.Runs[0].Results
}
