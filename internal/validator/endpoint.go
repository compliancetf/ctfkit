package validator

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/compliancetf/ctfkit/internal/config"
)

// EndpointValidator validates module sources against allowed endpoints
type EndpointValidator struct {
	allowedEndpoints []string
	compiledPatterns []*regexp.Regexp
}

// NewEndpointValidator creates a new endpoint validator
func NewEndpointValidator(cfg *config.Config) Validator {
	v := &EndpointValidator{
		allowedEndpoints: cfg.AllowedEndpoints,
	}
	v.compilePatterns()
	return v
}

// Name returns the validator name.
func (v *EndpointValidator) Name() string {
	return "endpoint-validator"
}

func (v *EndpointValidator) compilePatterns() {
	for _, endpoint := range v.allowedEndpoints {
		// Create regex pattern for each endpoint
		// Escape dots and allow for module paths
		escaped := regexp.QuoteMeta(endpoint)
		pattern := fmt.Sprintf(`^%s/[\w-]+/[\w-]+/[\w-]+`, escaped)
		if compiled, err := regexp.Compile(pattern); err == nil {
			v.compiledPatterns = append(v.compiledPatterns, compiled)
		}
	}
}

// Validate validates module sources against allowed endpoints.
func (v *EndpointValidator) Validate(input ValidationInput) []Violation {
	var violations []Violation

	for _, module := range input.Modules {
		if !v.isAllowedSource(module.Source) {
			violations = append(violations, Violation{
				Rule:        "ctf-001",
				Severity:    SeverityError,
				Message:     fmt.Sprintf("Module source '%s' is not from an allowed compliance.tf endpoint", module.Source),
				File:        module.Location.File,
				Line:        module.Location.Line,
				Column:      module.Location.Column,
				Module:      module.Name,
				Remediation: fmt.Sprintf("Use a module from one of: %s", strings.Join(v.allowedEndpoints, ", ")),
			})
		}
	}

	return violations
}

func (v *EndpointValidator) isAllowedSource(source string) bool {
	// Handle empty source
	if source == "" {
		return false
	}

	// Skip local modules
	if strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") || strings.HasPrefix(source, "/") {
		return true
	}

	// Handle git sources
	if strings.HasPrefix(source, "git::") || strings.HasPrefix(source, "git@") {
		urlStr := strings.TrimPrefix(source, "git::")
		urlStr = strings.TrimPrefix(urlStr, "git@")

		// Check if any allowed endpoint is in the git URL
		for _, endpoint := range v.allowedEndpoints {
			if strings.Contains(urlStr, endpoint) {
				return true
			}
		}
		return false
	}

	// Handle HTTP/HTTPS sources
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		u, err := url.Parse(source)
		if err != nil {
			return false
		}
		for _, endpoint := range v.allowedEndpoints {
			if strings.Contains(u.Host, endpoint) {
				return true
			}
		}
		return false
	}

	// Handle S3/GCS sources
	if strings.HasPrefix(source, "s3::") || strings.HasPrefix(source, "gcs::") {
		// For now, reject cloud storage sources unless they contain allowed endpoints
		for _, endpoint := range v.allowedEndpoints {
			if strings.Contains(source, endpoint) {
				return true
			}
		}
		return false
	}

	// Check registry sources (the most common case)
	// Format: endpoint/namespace/name/provider
	for _, pattern := range v.compiledPatterns {
		if pattern.MatchString(source) {
			return true
		}
	}

	// Also check if source starts with any allowed endpoint
	for _, endpoint := range v.allowedEndpoints {
		if strings.HasPrefix(source, endpoint+"/") {
			return true
		}
	}

	return false
}
