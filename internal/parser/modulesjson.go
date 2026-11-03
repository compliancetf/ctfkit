package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ModulesJSON represents the structure of .terraform/modules/modules.json
type ModulesJSON struct {
	Version string        `json:"version"`
	Modules []ModuleEntry `json:"Modules"`
}

// ModuleEntry represents a single module in modules.json
type ModuleEntry struct {
	Key      string        `json:"Key"`
	Source   string        `json:"Source"`
	Version  string        `json:"Version,omitempty"`
	Dir      string        `json:"Dir"`
	Registry *RegistryInfo `json:"Registry,omitempty"`
	Git      *GitInfo      `json:"Git,omitempty"`
}

// RegistryInfo contains Terraform Registry module information
type RegistryInfo struct {
	Host      string `json:"host"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
}

// GitInfo contains Git source information
type GitInfo struct {
	URL string `json:"url"`
	Ref string `json:"ref"`
}

// ModulesJSONParser handles .terraform/modules/modules.json parsing
type ModulesJSONParser interface {
	Parse(path string) (*ModulesJSON, error)
	ParseContent(content []byte) (*ModulesJSON, error)
}

type modulesJSONParser struct {
	strict bool
}

// NewModulesJSONParser creates a new modules.json parser
func NewModulesJSONParser(strict bool) ModulesJSONParser {
	return &modulesJSONParser{
		strict: strict,
	}
}

// Parse reads and parses a modules.json file
func (p *modulesJSONParser) Parse(path string) (*ModulesJSON, error) {
	content, err := os.ReadFile(path) //nolint:gosec // Reading modules.json file
	if err != nil {
		return nil, fmt.Errorf("failed to read modules.json: %w", err)
	}

	return p.ParseContent(content)
}

// ParseContent parses modules.json content from bytes
func (p *modulesJSONParser) ParseContent(content []byte) (*ModulesJSON, error) {
	var modules ModulesJSON

	if err := json.Unmarshal(content, &modules); err != nil {
		return nil, fmt.Errorf("failed to parse modules.json: %w", err)
	}

	// Validate if in strict mode
	if p.strict {
		if err := p.validate(&modules); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
	}

	// Resolve relative paths to absolute
	for i := range modules.Modules {
		if !filepath.IsAbs(modules.Modules[i].Dir) {
			// In real implementation, resolve relative to modules.json location
			modules.Modules[i].Dir = filepath.Clean(modules.Modules[i].Dir)
		}
	}

	return &modules, nil
}

// validate performs validation on the parsed modules.json
func (p *modulesJSONParser) validate(modules *ModulesJSON) error {
	if modules.Version == "" {
		return fmt.Errorf("modules.json missing version field")
	}

	for i, module := range modules.Modules {
		if module.Key == "" {
			return fmt.Errorf("module %d missing Key field", i)
		}
		if module.Source == "" {
			return fmt.Errorf("module %s missing Source field", module.Key)
		}
		if module.Dir == "" {
			return fmt.Errorf("module %s missing Dir field", module.Key)
		}
	}

	return nil
}

// ConvertModulesJSONToParseResult converts ModulesJSON to ParseResult for validation
func ConvertModulesJSONToParseResult(modules *ModulesJSON) *ParseResult {
	result := &ParseResult{}

	for _, entry := range modules.Modules {
		// The root module is recorded with an empty key and no source. It is
		// the configuration being validated, not a module it pulled in.
		if entry.Key == "" {
			continue
		}

		module := Module{
			Name:           entry.Key,
			Source:         entry.Source,
			Version:        entry.Version,
			ResolvedSource: entry.Source,
		}

		// Add location information if available
		module.Location = Location{
			File: filepath.Join(entry.Dir, "module.tf"),
			Line: 1, // Unknown from modules.json
		}

		result.Modules = append(result.Modules, module)
	}

	return result
}
