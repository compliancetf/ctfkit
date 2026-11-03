package validator

import (
	"time"

	"github.com/compliancetf/ctfkit/internal/config"
	"github.com/compliancetf/ctfkit/internal/parser"
)

// Validator is the main interface all validators implement
type Validator interface {
	Name() string
	Validate(input ValidationInput) []Violation
}

// ValidationInput contains all data needed for validation
type ValidationInput struct {
	Modules   []parser.Module
	Resources []parser.Resource
	Variables []parser.Variable
	Config    *config.Config
	Context   map[string]interface{}
}

// Violation represents a validation failure
type Violation struct {
	Rule        string   `json:"rule"`
	Severity    Severity `json:"severity"`
	Message     string   `json:"message"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column,omitempty"`
	Module      string   `json:"module,omitempty"`
	Resource    string   `json:"resource,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// Severity represents the severity level of a violation.
type Severity string

const (
	// Severity levels for violations
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Results contains validation results
type Results struct {
	Violations   []Violation   `json:"violations"`
	FilesScanned int           `json:"files_scanned"`
	ModulesFound int           `json:"modules_found"`
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Duration     time.Duration `json:"duration"`
}

// HasViolations returns true if there are any violations.
func (r *Results) HasViolations() bool {
	return len(r.Violations) > 0
}

// HasErrors returns true if there are any error-level violations.
func (r *Results) HasErrors() bool {
	for _, v := range r.Violations {
		if v.Severity == SeverityError {
			return true
		}
	}
	return false
}
