package validator

import (
	"fmt"
	"os"
	"time"

	"github.com/compliancetf/ctfkit/internal/config"
	"github.com/compliancetf/ctfkit/internal/parser"
)

// ValidatorEngine orchestrates all validators
// Engine represents the validation engine for compliance checks.
type ValidatorEngine struct {
	validators []Validator
	config     *config.Config
	failFast   bool
}

// New creates a new validator engine
func New(cfg *config.Config) *ValidatorEngine {
	ve := &ValidatorEngine{
		config:   cfg,
		failFast: cfg.FailFast,
	}

	// Register validators based on config
	ve.validators = append(ve.validators, NewEndpointValidator(cfg))

	if cfg.FailOnControlDisable {
		ve.validators = append(ve.validators, NewControlDisableDetector(cfg))
	}

	if len(cfg.AllowedResources) > 0 {
		ve.validators = append(ve.validators, NewResourceTypeValidator(cfg))
	}

	return ve
}

// ValidatePaths validates Terraform files at given paths
func (ve *ValidatorEngine) ValidatePaths(paths []string) (*Results, error) {
	results := &Results{
		StartTime: time.Now(),
	}

	// Parse all files
	p := parser.New()
	parseResult := &parser.ParseResult{}

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("failed to stat %s: %w", path, err)
		}

		if info.IsDir() {
			pr, err := p.ParseDirectory(path)
			if err != nil {
				return nil, fmt.Errorf("failed to parse directory %s: %w", path, err)
			}
			parseResult.Merge(pr)
		} else {
			pr, err := p.ParseFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to parse file %s: %w", path, err)
			}
			parseResult.Merge(pr)
		}
	}

	// Create validation input
	input := ValidationInput{
		Modules:   parseResult.Modules,
		Resources: parseResult.Resources,
		Variables: parseResult.Variables,
		Config:    ve.config,
		Context:   make(map[string]interface{}),
	}

	// Run validators
	for _, validator := range ve.validators {
		violations := validator.Validate(input)
		results.Violations = append(results.Violations, violations...)

		if ve.failFast && len(violations) > 0 {
			break
		}
	}

	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)
	results.FilesScanned = len(parseResult.Files)
	results.ModulesFound = len(parseResult.Modules)

	return results, nil
}

// ValidateModulesJSON validates a modules.json file
func (ve *ValidatorEngine) ValidateModulesJSON(path string) (*Results, error) {
	results := &Results{
		StartTime: time.Now(),
	}

	// Parse modules.json
	mjParser := parser.NewModulesJSONParser(false)
	modules, err := mjParser.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse modules.json: %w", err)
	}

	// Convert to ParseResult
	parseResult := parser.ConvertModulesJSONToParseResult(modules)

	// Create validation input
	input := ValidationInput{
		Modules: parseResult.Modules,
		Config:  ve.config,
		Context: map[string]interface{}{
			"post-init": true,
		},
	}

	// Run validators
	for _, validator := range ve.validators {
		violations := validator.Validate(input)
		results.Violations = append(results.Violations, violations...)

		if ve.failFast && len(violations) > 0 {
			break
		}
	}

	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)
	results.FilesScanned = 1
	results.ModulesFound = len(parseResult.Modules)

	return results, nil
}
