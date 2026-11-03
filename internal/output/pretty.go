package output

import (
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/compliancetf/ctfkit/internal/validator"
)

// PrettyFormatter formats violations with colors and icons for terminal display.
//
// It is deliberately kept separate from TextFormatter rather than merged with
// it: pretty is the interactive default and adds ANSI color and icons, while
// text is the pipe-safe format and is the only one of the two that ends with a
// machine-readable summary line. Merging them behind a color flag would mean
// either dropping that summary from text or adding it to the interactive
// output, and both are behavior changes for existing consumers. The golden
// files in testdata/ pin the difference.
type PrettyFormatter struct{}

// NewPrettyFormatter creates a new pretty formatter
func NewPrettyFormatter() *PrettyFormatter {
	return &PrettyFormatter{}
}

// Format formats violations with colors and icons
func (f *PrettyFormatter) Format(violations []validator.Violation) ([]byte, error) {
	var output strings.Builder

	// Summary header
	output.WriteString(fmt.Sprintf("\n%s Validation Results\n", color.CyanString("📋")))

	if len(violations) == 0 {
		output.WriteString(fmt.Sprintf("\n%s All checks passed!\n", color.GreenString("✅")))
		return []byte(output.String()), nil
	}

	// Violations
	output.WriteString(fmt.Sprintf("\n%s Found %d violations:\n\n", color.RedString("❌"), len(violations)))

	for _, v := range violations {
		_, icon, colorize := severityDisplay(v.Severity)

		output.WriteString(fmt.Sprintf("%s %s\n", icon, colorize(v.Message)))
		output.WriteString(fmt.Sprintf("   File: %s:%d\n", v.File, v.Line))
		output.WriteString(fmt.Sprintf("   Rule: %s\n", v.Rule))
		if v.Remediation != "" {
			output.WriteString(fmt.Sprintf("   Fix: %s\n", v.Remediation))
		}
		output.WriteString("\n")
	}

	return []byte(output.String()), nil
}
