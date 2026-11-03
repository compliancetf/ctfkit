package output

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/compliancetf/ctfkit/internal/validator"
)

func oneViolation(severity validator.Severity) []validator.Violation {
	return []validator.Violation{{
		Rule:     "ctf-004",
		Severity: severity,
		Message:  "a finding",
		File:     "main.tf",
		Line:     7,
	}}
}

// Severity is the only thing that distinguishes these three lines, so the
// label has to distinguish them too. Before this change the text formatter
// chose with a single != SeverityError check and printed info as [WARNING].
func TestTextLabelsEachSeverityDistinctly(t *testing.T) {
	want := map[validator.Severity]string{
		validator.SeverityError:   "[ERROR]",
		validator.SeverityWarning: "[WARNING]",
		validator.SeverityInfo:    "[INFO]",
	}

	seen := make(map[string]validator.Severity, len(want))
	for severity, label := range want {
		got, err := NewTextFormatter().Format(oneViolation(severity))
		if err != nil {
			t.Fatalf("Format(%s) error = %v", severity, err)
		}
		if !strings.Contains(string(got), label) {
			t.Errorf("severity %q: want label %s, got:\n%s", severity, label, got)
		}
		if prev, ok := seen[label]; ok {
			t.Errorf("severities %q and %q both render as %s", prev, severity, label)
		}
		seen[label] = severity
	}
}

var summaryLine = regexp.MustCompile(`Summary: (\d+) total, (\d+) errors, (\d+) warnings, (\d+) info`)

// The summary counted only errors and warnings, so a run with one of each
// severity ended with "3 total, 1 errors, 1 warnings" and the parts did not
// add up to the total.
func TestTextSummaryAccountsForEverySeverity(t *testing.T) {
	got, err := NewTextFormatter().Format(sampleViolations())
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	m := summaryLine.FindStringSubmatch(string(got))
	if m == nil {
		t.Fatalf("no summary line with an info count in:\n%s", got)
	}

	total, errs, warnings, info := atoi(t, m[1]), atoi(t, m[2]), atoi(t, m[3]), atoi(t, m[4])
	if sum := errs + warnings + info; sum != total {
		t.Errorf("summary parts sum to %d but the total says %d: %q", sum, total, m[0])
	}
	if total != len(sampleViolations()) {
		t.Errorf("summary total = %d, want %d", total, len(sampleViolations()))
	}
}

// The pretty formatter picked its icon with the same single check, so info
// carried the warning icon.
func TestPrettyIconsAreDistinctPerSeverity(t *testing.T) {
	restore := color.NoColor
	color.NoColor = true // compare icons, not escape sequences
	t.Cleanup(func() { color.NoColor = restore })

	icons := make(map[string]validator.Severity)
	for _, severity := range []validator.Severity{
		validator.SeverityError,
		validator.SeverityWarning,
		validator.SeverityInfo,
	} {
		got, err := NewPrettyFormatter().Format(oneViolation(severity))
		if err != nil {
			t.Fatalf("Format(%s) error = %v", severity, err)
		}

		icon := iconBefore(t, string(got), "a finding")
		if prev, ok := icons[icon]; ok {
			t.Errorf("severities %q and %q share the icon %q", prev, severity, icon)
		}
		icons[icon] = severity
	}
}

// iconBefore returns the marker the pretty formatter prints ahead of a message.
func iconBefore(t *testing.T, out, message string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasSuffix(line, message) {
			return strings.TrimSpace(strings.TrimSuffix(line, message))
		}
	}
	t.Fatalf("no line ending in %q:\n%s", message, out)
	return ""
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("not a number: %q", s)
	}
	return n
}
