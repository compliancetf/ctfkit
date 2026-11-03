// Package fixtures holds the F1 fixture pack. The test guards the layout
// contract only: which files each case must carry, and that every JSON file in
// the pack parses. What the expected outputs SAY is asserted by the analyzer
// and renderer tests once those exist.
//
// Go excludes directories named testdata from wildcard package patterns, so
// `go test ./...` does not reach this package. Run it with the explicit path:
//
//	go test ./testdata/fixtures/
package fixtures

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// reportCases render all four projections. Order is the documented reading
// order, not an execution order.
var reportCases = []string{
	"served-leaf",
	"blueprint-wrapper",
	"example-multi-instance",
	"degraded-build",
	"missing-manifest",
	"helper-module",
	"delegated-with-sibling",
	"delegated-without-sibling",
	"supporting-clauses",
}

// schema4Stub exits 2 before any projection is rendered, so it carries an exit
// code and a stderr transcript instead.
const schema4Stub = "schema-4-stub"

var reportProjections = []string{
	"report.md",
	"receipt.json",
	"findings.sarif",
	"ctfkit.custom.spacelift.json",
}

var planCases = []string{
	"01-raw-s3-no-ctf",
	"02-ctf-module-intact",
	"03-ctf-module-disabled-control",
	"04-floating-ref",
	"05-mixed-origin",
	"06-sentinel-exception",
	"07-expired-exception",
	"08-missing-tags",
	"09-unknown-provider",
	"10-post-apply-state",
	"11-sensitive-public-exposure",
	"12-sensitive-wildcard-iam",
	"13-sensitive-audit-log-removal",
	"14-sensitive-encryption-disablement",
	"15-sensitive-destructive-stateful",
	"16-secret-canary",
	"17-exec-pre-plan",
}

// scanPlanCases are the plan cases added with the scan command's fixture set.
// They carry the exit code the scan must return under the default --fail-on.
var scanPlanCases = map[string]string{
	"11-sensitive-public-exposure":        "1",
	"12-sensitive-wildcard-iam":           "1",
	"13-sensitive-audit-log-removal":      "1",
	"14-sensitive-encryption-disablement": "1",
	"15-sensitive-destructive-stateful":   "1",
	"16-secret-canary":                    "1",
}

// canarySecrets are the two fake secrets planted in 16-secret-canary. The
// recorded plan must carry them (or the case proves nothing), and no expected
// output may.
var canarySecrets = []string{
	"CANARY-50c488e396915cedcc5b650db695f0d2",
	"canary-pass-8fdf8eaa189601fd",
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("missing fixture file: %v", err)
	}
}

func TestReportCasesHaveInputsAndProjections(t *testing.T) {
	for _, c := range reportCases {
		t.Run(c, func(t *testing.T) {
			mustExist(t, filepath.Join("report", c, "input", ".terraform", "modules", "modules.json"))
			for _, p := range reportProjections {
				mustExist(t, filepath.Join("report", c, "expected", p))
			}
			mustExist(t, filepath.Join("report", c, "expected", "exit-code"))
		})
	}
}

func TestSchema4StubIsAnEnvironmentError(t *testing.T) {
	dir := filepath.Join("report", schema4Stub)
	mustExist(t, filepath.Join(dir, "input", ".terraform", "modules", "modules.json"))
	mustExist(t, filepath.Join(dir, "expected", "stderr.txt"))

	code, err := os.ReadFile(filepath.Join(dir, "expected", "exit-code"))
	if err != nil {
		t.Fatalf("reading exit code: %v", err)
	}
	if got := strings.TrimSpace(string(code)); got != "2" {
		t.Errorf("exit code = %q, want 2", got)
	}

	// No projection is rendered when the manifest major is unsupported.
	for _, p := range reportProjections {
		if _, err := os.Stat(filepath.Join(dir, "expected", p)); err == nil {
			t.Errorf("%s must not carry a %s projection", schema4Stub, p)
		}
	}
}

func TestPlanCasesHaveInputAndExpectedSarif(t *testing.T) {
	for _, c := range planCases {
		t.Run(c, func(t *testing.T) {
			mustExist(t, filepath.Join("plan", c, "input", "plan.json"))
			mustExist(t, filepath.Join("plan", c, "expected", "findings.sarif"))
		})
	}
}

func TestScanPlanCasesCarryTheirExitCode(t *testing.T) {
	for c, want := range scanPlanCases {
		raw, err := os.ReadFile(filepath.Join("plan", c, "expected", "exit-code"))
		if err != nil {
			t.Errorf("reading exit code of %s: %v", c, err)
			continue
		}
		if got := strings.TrimSpace(string(raw)); got != want {
			t.Errorf("%s exit code = %q, want %q", c, got, want)
		}
	}
}

// TestSecretCanaryIsPlantedAndNeverExpected is the positive control for the
// canary: both secrets are in the recorded input, and neither is in anything
// under expected/.
func TestSecretCanaryIsPlantedAndNeverExpected(t *testing.T) {
	dir := filepath.Join("plan", "16-secret-canary")
	plan, err := os.ReadFile(filepath.Join(dir, "input", "plan.json"))
	if err != nil {
		t.Fatalf("reading plan: %v", err)
	}
	expected, err := os.ReadDir(filepath.Join(dir, "expected"))
	if err != nil {
		t.Fatalf("reading expected: %v", err)
	}
	for _, secret := range canarySecrets {
		if !strings.Contains(string(plan), secret) {
			t.Errorf("recorded plan does not carry the canary %q", secret)
		}
		for _, e := range expected {
			raw, err := os.ReadFile(filepath.Join(dir, "expected", e.Name()))
			if err != nil {
				t.Fatalf("reading %s: %v", e.Name(), err)
			}
			if strings.Contains(string(raw), secret) {
				t.Errorf("expected/%s carries the canary %q", e.Name(), secret)
			}
		}
	}
}

// TestExecPrePlanCarriesNoValue: 17-exec-pre-plan plants CANARY- markers in
// the command and program its findings are about, and the recorded SARIF
// names the blocks without quoting either.
func TestExecPrePlanCarriesNoValue(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("plan", "17-exec-pre-plan", "expected", "findings.sarif"))
	if err != nil {
		t.Fatalf("reading expected SARIF: %v", err)
	}
	if strings.Contains(string(raw), "CANARY-") {
		t.Error("expected/findings.sarif carries a CANARY- value from the configuration")
	}
}

// evidenceCases are the ctfkit evidence ship cases, one per provider-run
// receipt status plus a break-glass run with degraded evidence and chains
// that fail verification, and the exit code each carries: 0 only for
// enforced (F13).
var evidenceCases = map[string]string{
	"enforced":             "0",
	"evidence-degraded":    "1",
	"overridden":           "1",
	"overridden-degraded":  "1",
	"single-resource-only": "1",
	"failed":               "1",
	"tampered":             "1",
}

func evidenceCaseNames() []string {
	names := make([]string, 0, len(evidenceCases))
	for n := range evidenceCases {
		names = append(names, n)
	}
	return names
}

func TestEvidenceCasesCarryChainsReceiptAndExitCode(t *testing.T) {
	for c, want := range evidenceCases {
		t.Run(c, func(t *testing.T) {
			mustExist(t, filepath.Join("evidence", c, "input", "chains"))
			mustExist(t, filepath.Join("evidence", c, "expected", "receipt.json"))
			code, err := os.ReadFile(filepath.Join("evidence", c, "expected", "exit-code"))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(string(code)); got != want {
				t.Errorf("exit code = %q, want %q", got, want)
			}
		})
	}
}

// TestCaseListsMatchTheDirectories catches a case added on disk but not wired
// into the lists above, and the reverse.
func TestCaseListsMatchTheDirectories(t *testing.T) {
	for _, tc := range []struct {
		root  string
		known []string
	}{
		{"report", append(append([]string{}, reportCases...), schema4Stub)},
		{"plan", planCases},
		{"evidence", evidenceCaseNames()},
	} {
		entries, err := os.ReadDir(tc.root)
		if err != nil {
			t.Fatalf("reading %s: %v", tc.root, err)
		}
		known := make(map[string]bool, len(tc.known))
		for _, k := range tc.known {
			known[k] = true
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if !known[e.Name()] {
				t.Errorf("%s/%s is on disk but not in the case list", tc.root, e.Name())
			}
			delete(known, e.Name())
		}
		for name := range known {
			t.Errorf("%s/%s is in the case list but not on disk", tc.root, name)
		}
	}
}

func TestEveryJSONFileParses(t *testing.T) {
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if filepath.Base(path) == "tests.json" {
			// tofu test -json output is a stream of JSON objects, one per line.
			for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				var v any
				if err := json.Unmarshal([]byte(line), &v); err != nil {
					t.Errorf("%s line %d: %v", path, i+1, err)
				}
			}
			return nil
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking fixtures: %v", err)
	}
}

// TestProjectionsCarryNoWatermark: every case is recorded without
// --watermark, so no projection carries a watermark field or property.
func TestProjectionsCarryNoWatermark(t *testing.T) {
	const watermark = "watermark"
	for _, c := range reportCases {
		for _, p := range reportProjections {
			path := filepath.Join("report", c, "expected", p)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("reading %s: %v", path, err)
				continue
			}
			if strings.Contains(string(raw), watermark) {
				t.Errorf("%s carries a watermark", path)
			}
		}
	}
	for _, c := range planCases {
		path := filepath.Join("plan", c, "expected", "findings.sarif")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("reading %s: %v", path, err)
			continue
		}
		if strings.Contains(string(raw), watermark) {
			t.Errorf("%s carries a watermark", path)
		}
	}
}
