// Package validator provides compliance validation logic for Terraform configurations.
package validator

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/compliancetf/ctfkit/internal/config"
)

// ControlDisableDetector detects attempts to disable compliance controls
type ControlDisableDetector struct {
	disablePatterns []string
	failOnDisable   bool
}

// NewControlDisableDetector creates a new control disable detector
func NewControlDisableDetector(cfg *config.Config) Validator {
	return &ControlDisableDetector{
		disablePatterns: cfg.DisablePatterns,
		failOnDisable:   cfg.FailOnControlDisable,
	}
}

// Name returns the detector name.
func (d *ControlDisableDetector) Name() string {
	return "control-disable-detector"
}

// Validate detects control bypass attempts in module parameters.
func (d *ControlDisableDetector) Validate(input ValidationInput) []Violation {
	var violations []Violation

	for _, module := range input.Modules {
		if params := d.extractQueryParams(module.Source); params != nil {
			for key, values := range params {
				for _, value := range values {
					if d.isDisablePattern(key, value) {
						severity := SeverityWarning
						if d.failOnDisable {
							severity = SeverityError
						}

						violations = append(violations, Violation{
							Rule:        "ctf-002",
							Severity:    severity,
							Message:     fmt.Sprintf("Module source contains control bypass attempt: %s=%s", key, value),
							File:        module.Location.File,
							Line:        module.Location.Line,
							Column:      module.Location.Column,
							Module:      module.Name,
							Remediation: "Remove control bypass parameters from module source",
						})
					}
				}
			}
		}

		// Also check module variables for disable patterns
		for varName, varValue := range module.Variables {
			if d.isDisablePatternInVariable(varName, varValue) {
				severity := SeverityWarning
				if d.failOnDisable {
					severity = SeverityError
				}

				violations = append(violations, Violation{
					Rule:        "ctf-003",
					Severity:    severity,
					Message:     fmt.Sprintf("Module variable potentially disables controls: %s", varName),
					File:        module.Location.File,
					Line:        module.Location.Line,
					Column:      module.Location.Column,
					Module:      module.Name,
					Remediation: "Review and remove control bypass variables",
				})
			}
		}
	}

	return violations
}

func (d *ControlDisableDetector) extractQueryParams(source string) url.Values {
	// Extract query parameters from various source formats

	// Handle git sources with ref parameters
	if strings.Contains(source, "?") {
		parts := strings.SplitN(source, "?", 2)
		if len(parts) == 2 {
			params, err := url.ParseQuery(parts[1])
			if err == nil {
				return params
			}
		}
	}

	// Handle registry sources with version constraints that might have parameters
	if strings.Contains(source, "//") && strings.Contains(source, "?") {
		if u, err := url.Parse("https://" + source); err == nil {
			return u.Query()
		}
	}

	return nil
}

func (d *ControlDisableDetector) isDisablePattern(key, value string) bool {
	keyLower := strings.ToLower(key)
	valueLower := strings.ToLower(value)

	// Check if key contains disable patterns
	for _, pattern := range d.disablePatterns {
		if strings.Contains(keyLower, strings.ToLower(pattern)) {
			return true
		}
	}

	// Check for boolean false values
	if valueLower == "false" || valueLower == "0" || valueLower == "disabled" || valueLower == "off" || valueLower == "no" {
		// Only flag if the key suggests it's a control/security setting
		if strings.Contains(keyLower, "control") ||
			strings.Contains(keyLower, "compliance") ||
			strings.Contains(keyLower, "security") ||
			strings.Contains(keyLower, "enforce") ||
			strings.Contains(keyLower, "validate") ||
			strings.Contains(keyLower, "check") {
			return true
		}
	}

	return false
}

func (d *ControlDisableDetector) isDisablePatternInVariable(name string, value interface{}) bool {
	nameLower := strings.ToLower(name)

	// Check if variable name contains disable patterns
	for _, pattern := range d.disablePatterns {
		if strings.Contains(nameLower, strings.ToLower(pattern)) {
			return true
		}
	}

	// Check if it's explicitly setting something to false
	if boolVal, ok := value.(bool); ok && !boolVal {
		if strings.Contains(nameLower, "enable") ||
			strings.Contains(nameLower, "enforce") ||
			strings.Contains(nameLower, "compliance") {
			return true
		}
	}

	return false
}
