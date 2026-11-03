package output

import (
	"encoding/json"

	"github.com/compliancetf/ctfkit/internal/validator"
)

// SARIFFormatter outputs results in SARIF format for GitHub Code Scanning
type SARIFFormatter struct {
	version string
}

// NewSARIFFormatter creates a new SARIF formatter
func NewSARIFFormatter() *SARIFFormatter {
	return &SARIFFormatter{
		version: "1.0.0", // Should come from build version
	}
}

// SARIF structures (SARIF 2.1.0 specification)
type SARIF struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a SARIF run
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool represents a SARIF tool
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents a SARIF driver
type SARIFDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule represents a SARIF rule
type SARIFRule struct {
	ID                   string       `json:"id"`
	Name                 string       `json:"name"`
	ShortDescription     SARIFMessage `json:"shortDescription"`
	FullDescription      SARIFMessage `json:"fullDescription"`
	DefaultConfiguration SARIFConfig  `json:"defaultConfiguration"`
	HelpURI              string       `json:"helpUri,omitempty"`
}

// SARIFConfig represents SARIF configuration
type SARIFConfig struct {
	Level string `json:"level"`
}

// SARIFMessage represents a SARIF message
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFResult represents a SARIF result
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

// SARIFLocation represents a SARIF location
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation represents physical location
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

// SARIFArtifactLocation represents artifact location
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion represents a SARIF region
type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// Format formats results as SARIF
func (f *SARIFFormatter) Format(violations []validator.Violation) ([]byte, error) {
	sarif := SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "ctfkit",
						InformationURI: "https://github.com/compliancetf/ctfkit",
						Version:        f.version,
						Rules:          f.buildRules(),
					},
				},
				Results: f.buildResults(violations),
			},
		},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

func (f *SARIFFormatter) buildRules() []SARIFRule {
	return []SARIFRule{
		{
			ID:   "ctf-001",
			Name: "non-compliant-module-source",
			ShortDescription: SARIFMessage{
				Text: "Module source is not from an allowed compliance.tf endpoint",
			},
			FullDescription: SARIFMessage{
				Text: "Terraform modules must use approved compliance.tf endpoints to ensure compliance controls are enforced",
			},
			DefaultConfiguration: SARIFConfig{Level: "error"},
			HelpURI:              "https://github.com/compliancetf/ctfkit#ctf-001",
		},
		{
			ID:   "ctf-002",
			Name: "control-bypass-query-parameter",
			ShortDescription: SARIFMessage{
				Text: "Module source contains control bypass attempt via query parameters",
			},
			FullDescription: SARIFMessage{
				Text: "Query parameters attempting to disable or bypass compliance controls are not allowed",
			},
			DefaultConfiguration: SARIFConfig{Level: "error"},
			HelpURI:              "https://github.com/compliancetf/ctfkit#ctf-002",
		},
		{
			ID:   "ctf-003",
			Name: "control-bypass-variable",
			ShortDescription: SARIFMessage{
				Text: "Module variable potentially disables compliance controls",
			},
			FullDescription: SARIFMessage{
				Text: "Module variables with names suggesting control bypass (disable_, skip_, etc.) are flagged for review",
			},
			DefaultConfiguration: SARIFConfig{Level: "warning"},
			HelpURI:              "https://github.com/compliancetf/ctfkit#ctf-003",
		},
		{
			ID:   "ctf-004",
			Name: "disallowed-resource-type",
			ShortDescription: SARIFMessage{
				Text: "Resource type is not in the allowed list",
			},
			FullDescription: SARIFMessage{
				Text: "Only specific resource types are allowed according to the configuration",
			},
			DefaultConfiguration: SARIFConfig{Level: "error"},
			HelpURI:              "https://github.com/compliancetf/ctfkit#ctf-004",
		},
	}
}

func (f *SARIFFormatter) buildResults(violations []validator.Violation) []SARIFResult {
	results := make([]SARIFResult, 0, len(violations))

	for _, v := range violations {
		level := "warning"
		switch v.Severity {
		case validator.SeverityError:
			level = "error"
		case validator.SeverityInfo:
			level = "note"
		}

		result := SARIFResult{
			RuleID: v.Rule,
			Level:  level,
			Message: SARIFMessage{
				Text: v.Message,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: v.File,
						},
						Region: SARIFRegion{
							StartLine:   v.Line,
							StartColumn: v.Column,
						},
					},
				},
			},
		}

		results = append(results, result)
	}

	return results
}
