package parser

// Parser is the main interface for parsing Terraform configurations
type Parser interface {
	ParseFile(path string) (*ParseResult, error)
	ParseDirectory(path string) (*ParseResult, error)
	ParseContent(content []byte, filename string) (*ParseResult, error)
}

// ParseResult contains all extracted data from parsing
type ParseResult struct {
	Modules   []Module
	Resources []Resource
	Variables []Variable
	// DataSources are the data blocks.
	DataSources []DataSource
	// EphemeralResources are the ephemeral blocks, which are opened at plan.
	EphemeralResources []DataSource
	// Actions are the action blocks, which run at apply through a lifecycle
	// action_trigger or on -invoke.
	Actions []DataSource
	// Provisioners are the provisioner blocks of every resource and removed
	// block, the only blocks Terraform and OpenTofu run one from.
	Provisioners []Provisioner
	Files        []string
	Errors       []ParseError
}

// DataSource represents a Terraform data block, top level or nested in a
// check block.
type DataSource struct {
	Type string
	Name string
	// Scope is "check.<name>" for a data block nested in a check block, and
	// empty for a top-level one.
	Scope    string
	Location Location
}

// Provisioner represents a provisioner block inside a resource or removed
// block.
type Provisioner struct {
	// Type is the provisioner's label, for example "local-exec".
	Type string
	// Owner is the address of the block it sits in: "type.name" for a
	// resource, the from address for a removed block, or "removed" when that
	// address is not a plain reference.
	Owner    string
	Location Location
}

// Module represents a Terraform module block
type Module struct {
	Name           string
	Source         string
	Version        string
	RawSource      string
	ResolvedSource string
	Providers      map[string]string
	Variables      map[string]interface{}
	Count          *string
	ForEach        *string
	DependsOn      []string
	Location       Location
}

// Resource represents a Terraform resource block
type Resource struct {
	Type      string
	Name      string
	Provider  string
	Count     *string
	ForEach   *string
	DependsOn []string
	Location  Location
}

// Variable represents a Terraform variable definition
type Variable struct {
	Name        string
	Type        string
	Default     interface{}
	Description string
	Sensitive   bool
	Location    Location
}

// Location provides source code location information
type Location struct {
	File      string
	Line      int
	Column    int
	EndLine   int
	EndColumn int
}

// ParseError represents a non-fatal parsing error
type ParseError struct {
	Message  string
	Location Location
	Severity ParseErrorSeverity
}

type ParseErrorSeverity int

const (
	ParseErrorWarning ParseErrorSeverity = iota
	ParseErrorError
)

// Merge combines two ParseResults
func (pr *ParseResult) Merge(other *ParseResult) {
	if other == nil {
		return
	}
	pr.Modules = append(pr.Modules, other.Modules...)
	pr.Resources = append(pr.Resources, other.Resources...)
	pr.Variables = append(pr.Variables, other.Variables...)
	pr.DataSources = append(pr.DataSources, other.DataSources...)
	pr.EphemeralResources = append(pr.EphemeralResources, other.EphemeralResources...)
	pr.Actions = append(pr.Actions, other.Actions...)
	pr.Provisioners = append(pr.Provisioners, other.Provisioners...)
	pr.Files = append(pr.Files, other.Files...)
	pr.Errors = append(pr.Errors, other.Errors...)
}
