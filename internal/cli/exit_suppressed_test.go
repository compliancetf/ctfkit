package cli

import (
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

func finding(level string) ctfkit.Finding {
	return ctfkit.Finding{RuleID: "ctf.coverage.manifest_missing", Level: level}
}

func waived(f ctfkit.Finding) ctfkit.Finding {
	f.Props.Exception = &ctfkit.ExceptionProperty{Allowed: true, EntryID: "bobthecorp-1"}
	return f
}

func lapsed(f ctfkit.Finding) ctfkit.Finding {
	f.Props.Exception = &ctfkit.ExceptionProperty{Allowed: false, EntryID: "bobthecorp-1"}
	return f
}

// The exit code follows the same waiver rule as the verdict: a finding an
// allowed exception covers does not count toward --fail-on. Nothing tested this
// path before, although it decides whether a pipeline goes red.
func TestExitCodeIgnoresWaivedFindings(t *testing.T) {
	plan := outputPlan{formats: []string{formatMarkdown}}

	tests := []struct {
		name      string
		threshold string
		findings  ctfkit.Findings
		wantCode  int
		wantCount string // the count the message names, when the run fails
	}{
		{
			name:      "the only error is waived",
			threshold: ctfkit.LevelError,
			findings:  ctfkit.Findings{waived(finding(ctfkit.LevelError))},
			wantCode:  ExitOK,
		},
		{
			name:      "a waived error beside an unwaived one counts one",
			threshold: ctfkit.LevelError,
			findings:  ctfkit.Findings{waived(finding(ctfkit.LevelError)), finding(ctfkit.LevelError)},
			wantCode:  ExitFindings,
			wantCount: "1 finding(s)",
		},
		{
			// A waiver nobody renewed is recorded and waives nothing, so the
			// pipeline goes red when it lapses rather than staying quietly green.
			name:      "a lapsed waiver still counts",
			threshold: ctfkit.LevelError,
			findings:  ctfkit.Findings{lapsed(finding(ctfkit.LevelError))},
			wantCode:  ExitFindings,
			wantCount: "1 finding(s)",
		},
		{
			name:      "a waived warning under a widened threshold",
			threshold: ctfkit.LevelWarning,
			findings:  ctfkit.Findings{waived(finding(ctfkit.LevelWarning))},
			wantCode:  ExitOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := exitFor(plan, tt.threshold, tt.findings)
			if got := ExitCode(err); got != tt.wantCode {
				t.Fatalf("exit code = %d, want %d (err = %v)", got, tt.wantCode, err)
			}
			if tt.wantCount != "" && !strings.Contains(err.Error(), tt.wantCount) {
				t.Errorf("error = %q, want it to name %s", err, tt.wantCount)
			}
		})
	}
}
