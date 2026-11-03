package validator

import (
	"fmt"

	"github.com/compliancetf/ctfkit/internal/config"
)

// ResourceTypeValidator validates resource types against allowed list
type ResourceTypeValidator struct {
	allowedTypes map[string]bool
	enabled      bool
}

// NewResourceTypeValidator creates a new resource type validator
func NewResourceTypeValidator(cfg *config.Config) Validator {
	allowedTypes := make(map[string]bool)
	for _, t := range cfg.AllowedResources {
		allowedTypes[t] = true
	}

	return &ResourceTypeValidator{
		allowedTypes: allowedTypes,
		enabled:      len(cfg.AllowedResources) > 0,
	}
}

// Name returns the validator name.
func (v *ResourceTypeValidator) Name() string {
	return "resource-type-validator"
}

// Validate checks resource types against allowlist.
func (v *ResourceTypeValidator) Validate(input ValidationInput) []Violation {
	if !v.enabled {
		return nil
	}

	var violations []Violation

	for _, resource := range input.Resources {
		if !v.allowedTypes[resource.Type] {
			violations = append(violations, Violation{
				Rule:        "ctf-004",
				Severity:    SeverityError,
				Message:     fmt.Sprintf("Resource type '%s' is not allowed", resource.Type),
				File:        resource.Location.File,
				Line:        resource.Location.Line,
				Column:      resource.Location.Column,
				Resource:    resource.Name,
				Remediation: "Use only allowed resource types as defined in configuration",
			})
		}
	}

	return violations
}
