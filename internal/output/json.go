package output

import (
	"encoding/json"

	"github.com/compliancetf/ctfkit/internal/validator"
)

// JSONFormatter formats violations as JSON
type JSONFormatter struct{}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

// Format formats violations as JSON
func (f *JSONFormatter) Format(violations []validator.Violation) ([]byte, error) {
	result := map[string]interface{}{
		"violations": violations,
		"summary": map[string]int{
			"total":    len(violations),
			"errors":   countBySeverity(violations, validator.SeverityError),
			"warnings": countBySeverity(violations, validator.SeverityWarning),
		},
	}

	return json.MarshalIndent(result, "", "  ")
}

func countBySeverity(violations []validator.Violation, severity validator.Severity) int {
	count := 0
	for _, v := range violations {
		if v.Severity == severity {
			count++
		}
	}
	return count
}
