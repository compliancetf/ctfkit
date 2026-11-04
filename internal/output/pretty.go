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
	fmt.Fprintf(&output, "\n%s Validation Results\n", color.CyanString("📋"))

	if len(violations) == 0 {
		fmt.Fprintf(&output, "\n%s All checks passed!\n", color.GreenString("✅"))
		return []byte(output.String()), nil
	}

	// Violations
	fmt.Fprintf(&output, "\n%s Found %d violations:\n\n", color.RedString("❌"), len(violations))

	for _, v := range violations {
		_, icon, colorize := severityDisplay(v.Severity)

		fmt.Fprintf(&output, "%s %s\n", icon, colorize(v.Message))
		fmt.Fprintf(&output, "   File: %s:%d\n", v.File, v.Line)
		fmt.Fprintf(&output, "   Rule: %s\n", v.Rule)
		if v.Remediation != "" {
			fmt.Fprintf(&output, "   Fix: %s\n", v.Remediation)
		}
		output.WriteString("\n")
	}

	return []byte(output.String()), nil
}
