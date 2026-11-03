package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A manifest_missing finding names the module call it is about, so a
// rule-keyed exception scoped to that module waives it, and only it. Before
// the finding carried a module logical location its subject was empty, and the
// loader requires a resource, so no entry could ever reach it.
func TestReportRuleExceptionWaivesManifestMissing(t *testing.T) {
	t.Chdir(repoRoot)

	tests := []struct {
		name       string
		resource   string
		wantCode   int
		wantWaived bool
	}{
		{name: "the module address waives it", resource: "module.replication_role", wantCode: ExitOK, wantWaived: true},
		{name: "another module address does not", resource: "module.other", wantCode: ExitFindings},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			registry := filepath.Join(dir, "exceptions.yaml")
			writeFile(t, registry, `schema_version: "1.0"
exceptions:
  - rule: ctf.coverage.manifest_missing
    resource: `+tt.resource+`
    justification: "Local IAM role module, reviewed by the platform team."
    approved_by: compliance@bobthecorp.example
    approval_ticket: SEC-1
    review_date: "2027-06-01"
`)

			out := filepath.Join(dir, "findings.sarif")
			args := append([]string{
				"--path", fixturePath("missing-manifest"),
				"--exceptions", registry,
				"--format", "sarif",
				"--out", out,
			}, fixtureContext...)

			if _, code := runReport(t, args...); code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d", code, tt.wantCode)
			}

			var doc struct {
				Runs []struct {
					Results []struct {
						RuleID       string            `json:"ruleId"`
						Suppressions []json.RawMessage `json:"suppressions"`
					} `json:"results"`
				} `json:"runs"`
			}
			if err := json.Unmarshal(readFile(t, out), &doc); err != nil {
				t.Fatalf("parse %s: %v", out, err)
			}

			waived := 0
			for _, r := range doc.Runs[0].Results {
				if len(r.Suppressions) == 0 {
					continue
				}
				if r.RuleID != "ctf.coverage.manifest_missing" {
					t.Errorf("%s is suppressed; the entry waives manifest_missing only", r.RuleID)
				}
				waived++
			}
			if want := map[bool]int{true: 1, false: 0}[tt.wantWaived]; waived != want {
				t.Errorf("suppressed results = %d, want %d", waived, want)
			}
		})
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
