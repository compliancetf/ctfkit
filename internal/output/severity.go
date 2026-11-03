package output

import (
	"github.com/fatih/color"

	"github.com/compliancetf/ctfkit/internal/validator"
)

// severityDisplay is the single place a severity maps to how it is presented.
//
// The text and pretty formatters each used to derive this themselves with an
// `if v.Severity == SeverityError` check, so everything that was not an error
// - info included - was presented as a warning, in both of them, for the same
// reason. Adding a severity now means editing one switch instead of finding
// every place that guessed.
//
// The default arm is deliberate: an unrecognized severity is presented as a
// warning rather than silently taking the label of whichever arm happens to be
// last, and it is never mistaken for a clean result.
func severityDisplay(severity validator.Severity) (label, icon string, colorize func(string, ...interface{}) string) {
	switch severity {
	case validator.SeverityError:
		return "ERROR", "🚫", color.RedString
	case validator.SeverityInfo:
		return "INFO", "ℹ️", color.CyanString
	case validator.SeverityWarning:
		return "WARNING", "⚠️", color.YellowString
	default:
		return "WARNING", "⚠️", color.YellowString
	}
}
