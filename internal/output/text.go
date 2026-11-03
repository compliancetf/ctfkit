package output

import (
	"fmt"
	"strings"

	"github.com/compliancetf/ctfkit/internal/validator"
)

// TextFormatter formats violations as plain text without colors
type TextFormatter struct{}

// NewTextFormatter creates a new text formatter
func NewTextFormatter() *TextFormatter {
	return &TextFormatter{}
}

// Format formats violations as plain text
func (f *TextFormatter) Format(violations []validator.Violation) ([]byte, error) {
	var output strings.Builder

	if len(violations) == 0 {
		output.WriteString("All checks passed!\n")
		return []byte(output.String()), nil
	}

	output.WriteString(fmt.Sprintf("Found %d violations:\n\n", len(violations)))

	for _, v := range violations {
		label, _, _ := severityDisplay(v.Severity)

		output.WriteString(fmt.Sprintf("[%s] %s\n", label, v.Message))
		output.WriteString(fmt.Sprintf("  File: %s:%d\n", v.File, v.Line))
		output.WriteString(fmt.Sprintf("  Rule: %s\n", v.Rule))
		if v.Remediation != "" {
			output.WriteString(fmt.Sprintf("  Fix: %s\n", v.Remediation))
		}
		output.WriteString("\n")
	}

	// Summary. Every severity is counted, so the parts add up to the total: an
	// omitted one made a finding disappear from the line that is meant to be
	// the at-a-glance answer.
	output.WriteString(fmt.Sprintf("Summary: %d total, %d errors, %d warnings, %d info\n",
		len(violations),
		countBySeverity(violations, validator.SeverityError),
		countBySeverity(violations, validator.SeverityWarning),
		countBySeverity(violations, validator.SeverityInfo)))

	return []byte(output.String()), nil
}
