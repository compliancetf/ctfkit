// Package parser provides HCL and Terraform configuration file parsing capabilities.
package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

type hclParser struct {
	parser *hclparse.Parser
}

// New creates a new HCL parser
func New() Parser {
	return &hclParser{
		parser: hclparse.NewParser(),
	}
}

// ParseFile parses a single Terraform configuration file
func (p *hclParser) ParseFile(path string) (*ParseResult, error) {
	content, err := os.ReadFile(path) //nolint:gosec // Reading HCL file
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	return p.ParseContent(content, path)
}

// ParseContent parses HCL content from bytes
func (p *hclParser) ParseContent(content []byte, filename string) (*ParseResult, error) {
	file, diags := p.parser.ParseHCL(content, filename)
	return parseResult(file, diags, filename), nil
}

// ParseConfigFile parses one configuration file in the syntax its name
// names: .tf and .tofu are native syntax, .tf.json and .tofu.json are JSON.
// Any other name is not configuration and returns a nil file and no
// diagnostics.
func ParseConfigFile(content []byte, filename string) (*hcl.File, hcl.Diagnostics) {
	switch {
	case strings.HasSuffix(filename, ".tf.json"), strings.HasSuffix(filename, ".tofu.json"):
		return hcljson.Parse(content, filename)
	case strings.HasSuffix(filename, ".tf"), strings.HasSuffix(filename, ".tofu"):
		return hclsyntax.ParseConfig(content, filename, hcl.InitialPos)
	}
	return nil, nil
}

// ParseConfigContent is ParseContent for a configuration file in either
// syntax, chosen by ParseConfigFile. A native-syntax file gives exactly what
// ParseContent gives; a file that is not configuration gives an empty result.
func ParseConfigContent(content []byte, filename string) *ParseResult {
	file, diags := ParseConfigFile(content, filename)
	return parseResult(file, diags, filename)
}

// parseResult collects what one parsed file declares, parse errors included.
func parseResult(file *hcl.File, diags hcl.Diagnostics, filename string) *ParseResult {
	result := &ParseResult{
		Files: []string{filename},
	}

	// Collect parse errors (non-fatal)
	for _, diag := range diags {
		result.Errors = append(result.Errors, ParseError{
			Message:  diag.Summary + ": " + diag.Detail,
			Location: locationFromDiag(filename, diag),
			Severity: severityFromDiag(diag),
		})
	}

	// If we couldn't parse at all, return early
	if file == nil || file.Body == nil {
		return result
	}

	// Extract modules, resources, and variables
	extractBlocks(file.Body, filename, result)

	return result
}

// ParseDirectory recursively parses all .tf files in a directory
func (p *hclParser) ParseDirectory(path string) (*ParseResult, error) {
	result := &ParseResult{}

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Skip .terraform directories
			if info.Name() == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process .tf files
		if !strings.HasSuffix(filePath, ".tf") {
			return nil
		}

		// Parse the file
		fileResult, err := p.ParseFile(filePath)
		if err != nil {
			// Log error but continue processing
			result.Errors = append(result.Errors, ParseError{
				Message:  fmt.Sprintf("Failed to parse %s: %v", filePath, err),
				Location: Location{File: filePath},
				Severity: ParseErrorError,
			})
			return nil
		}

		// Merge results
		result.Merge(fileResult)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", path, err)
	}

	return result, nil
}

// extractBlocks extracts modules, resources, and variables from HCL body
func extractBlocks(body hcl.Body, filename string, result *ParseResult) {
	content, _, diags := body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "module", LabelNames: []string{"name"}},
			{Type: "resource", LabelNames: []string{"type", "name"}},
			{Type: "variable", LabelNames: []string{"name"}},
			{Type: "data", LabelNames: []string{"type", "name"}},
			{Type: "removed"},
			{Type: "check", LabelNames: []string{"name"}},
		},
	})

	// Add any new diagnostics as errors
	for _, diag := range diags {
		if diag.Severity == hcl.DiagError {
			result.Errors = append(result.Errors, ParseError{
				Message:  diag.Summary,
				Location: locationFromDiag(filename, diag),
				Severity: ParseErrorError,
			})
		}
	}

	// Process each block type
	for _, block := range content.Blocks {
		switch block.Type {
		case "module":
			if module := extractModule(block, filename); module != nil {
				result.Modules = append(result.Modules, *module)
			}
		case "resource":
			if resource := extractResource(block, filename); resource != nil {
				result.Resources = append(result.Resources, *resource)
				result.Provisioners = append(result.Provisioners,
					extractProvisioners(block, filename, resource.Type+"."+resource.Name)...)
			}
		case "removed":
			result.Provisioners = append(result.Provisioners,
				extractProvisioners(block, filename, removedFrom(block))...)
		case "data":
			if len(block.Labels) != 2 {
				continue
			}
			result.DataSources = append(result.DataSources, DataSource{
				Type: block.Labels[0], Name: block.Labels[1], Location: locationFromBlock(filename, block),
			})
		case "check":
			if len(block.Labels) != 1 {
				continue
			}
			result.DataSources = append(result.DataSources, scopedDataSources(block, filename)...)
		case "variable":
			if variable := extractVariable(block, filename); variable != nil {
				result.Variables = append(result.Variables, *variable)
			}
		}
	}
}

// extractModule extracts a module block
func extractModule(block *hcl.Block, filename string) *Module {
	if len(block.Labels) == 0 {
		return nil
	}

	module := &Module{
		Name:      block.Labels[0],
		Variables: make(map[string]interface{}),
		Providers: make(map[string]string),
		Location:  locationFromBlock(filename, block),
	}

	// Parse the module body
	attrs, _ := block.Body.JustAttributes()

	for name, attr := range attrs {
		switch name {
		case "source":
			// Try to evaluate the source attribute
			val, diags := attr.Expr.Value(&hcl.EvalContext{})
			if !diags.HasErrors() && val.Type() == cty.String {
				module.Source = val.AsString()
				module.ResolvedSource = val.AsString()
			} else {
				// If we can't evaluate, try to get raw source
				if expr, ok := attr.Expr.(*hclsyntax.TemplateExpr); ok && len(expr.Parts) > 0 {
					if lit, ok := expr.Parts[0].(*hclsyntax.LiteralValueExpr); ok {
						if lit.Val.Type() == cty.String {
							module.Source = lit.Val.AsString()
							module.RawSource = lit.Val.AsString()
						}
					}
				}
			}
		case "version":
			val, diags := attr.Expr.Value(&hcl.EvalContext{})
			if !diags.HasErrors() && val.Type() == cty.String {
				module.Version = val.AsString()
			}
		case "count":
			countStr := exprToString(attr.Expr)
			module.Count = &countStr
		case "for_each":
			forEachStr := exprToString(attr.Expr)
			module.ForEach = &forEachStr
		case "depends_on":
			// Extract depends_on if it's a tuple
			val, diags := attr.Expr.Value(&hcl.EvalContext{})
			if !diags.HasErrors() && val.Type().IsTupleType() {
				for it := val.ElementIterator(); it.Next(); {
					_, elem := it.Element()
					if elem.Type() == cty.String {
						module.DependsOn = append(module.DependsOn, elem.AsString())
					}
				}
			}
		case "providers":
			// Handle providers map
			// This is complex in HCL, simplified here
		default:
			// Store other attributes as variables
			val, diags := attr.Expr.Value(&hcl.EvalContext{})
			if !diags.HasErrors() {
				module.Variables[name] = ctyValueToInterface(val)
			}
		}
	}

	return module
}

// extractResource extracts a resource block
func extractResource(block *hcl.Block, filename string) *Resource {
	if len(block.Labels) < 2 {
		return nil
	}

	resource := &Resource{
		Type:     block.Labels[0],
		Name:     block.Labels[1],
		Location: locationFromBlock(filename, block),
	}

	// Parse resource attributes
	attrs, _ := block.Body.JustAttributes()

	for name, attr := range attrs {
		switch name {
		case "provider":
			val, diags := attr.Expr.Value(&hcl.EvalContext{})
			if !diags.HasErrors() && val.Type() == cty.String {
				resource.Provider = val.AsString()
			}
		case "count":
			countStr := exprToString(attr.Expr)
			resource.Count = &countStr
		case "for_each":
			forEachStr := exprToString(attr.Expr)
			resource.ForEach = &forEachStr
		case "depends_on":
			val, diags := attr.Expr.Value(&hcl.EvalContext{})
			if !diags.HasErrors() && val.Type().IsTupleType() {
				for it := val.ElementIterator(); it.Next(); {
					_, elem := it.Element()
					if elem.Type() == cty.String {
						resource.DependsOn = append(resource.DependsOn, elem.AsString())
					}
				}
			}
		}
	}

	return resource
}

// provisionerSchema selects the provisioner blocks of a resource or removed
// block, in native syntax and JSON alike.
var provisionerSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{{Type: "provisioner", LabelNames: []string{"type"}}},
}

// extractProvisioners lists the provisioner blocks of block, each spanning
// its own header to closing brace. A provisioner block HCL cannot read, one
// with no type label, is one Terraform refuses to run, so it is not listed.
func extractProvisioners(block *hcl.Block, filename, owner string) []Provisioner {
	content, _, _ := block.Body.PartialContent(provisionerSchema)
	if content == nil {
		return nil
	}
	out := make([]Provisioner, 0, len(content.Blocks))
	for _, p := range content.Blocks {
		out = append(out, Provisioner{Type: p.Labels[0], Owner: owner, Location: locationFromBlock(filename, p)})
	}
	return out
}

// scopedDataSources lists the data blocks nested in a check block, each
// scoped to it: Terraform and OpenTofu read a check's scoped data source at
// plan time like any other, so a scoped external data source runs a program
// all the same.
func scopedDataSources(check *hcl.Block, filename string) []DataSource {
	content, _, _ := check.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{{Type: "data", LabelNames: []string{"type", "name"}}},
	})
	if content == nil {
		return nil
	}
	out := make([]DataSource, 0, len(content.Blocks))
	for _, d := range content.Blocks {
		out = append(out, DataSource{
			Type: d.Labels[0], Name: d.Labels[1], Scope: "check." + check.Labels[0],
			Location: locationFromBlock(filename, d),
		})
	}
	return out
}

// removedFrom is the from address of a removed block, for example
// "aws_instance.web" or "module.app", or "removed" when from is absent or is
// not a plain reference.
func removedFrom(block *hcl.Block) string {
	content, _, _ := block.Body.PartialContent(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "from"}}})
	if content == nil || content.Attributes["from"] == nil {
		return "removed"
	}
	traversal, diags := hcl.AbsTraversalForExpr(content.Attributes["from"].Expr)
	if diags.HasErrors() {
		return "removed"
	}
	var b strings.Builder
	for _, step := range traversal {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			b.WriteString(s.Name)
		case hcl.TraverseAttr:
			b.WriteString("." + s.Name)
		}
	}
	return b.String()
}

// extractVariable extracts a variable block
func extractVariable(block *hcl.Block, filename string) *Variable {
	if len(block.Labels) == 0 {
		return nil
	}

	variable := &Variable{
		Name:     block.Labels[0],
		Location: locationFromBlock(filename, block),
	}

	// Parse variable attributes
	attrs, _ := block.Body.JustAttributes()

	for name, attr := range attrs {
		switch name {
		case "type":
			variable.Type = exprToString(attr.Expr)
		case "default":
			val, diags := attr.Expr.Value(&hcl.EvalContext{})
			if !diags.HasErrors() {
				variable.Default = ctyValueToInterface(val)
			}
		case "description":
			val, diags := attr.Expr.Value(&hcl.EvalContext{})
			if !diags.HasErrors() && val.Type() == cty.String {
				variable.Description = val.AsString()
			}
		case "sensitive":
			val, diags := attr.Expr.Value(&hcl.EvalContext{})
			if !diags.HasErrors() && val.Type() == cty.Bool {
				variable.Sensitive = val.True()
			}
		}
	}

	return variable
}

// Helper functions

func locationFromDiag(filename string, diag *hcl.Diagnostic) Location {
	loc := Location{
		File: filename,
	}
	if diag.Subject != nil {
		loc.Line = diag.Subject.Start.Line
		loc.Column = diag.Subject.Start.Column
		loc.EndLine = diag.Subject.End.Line
		loc.EndColumn = diag.Subject.End.Column
	}
	return loc
}

// BlockRange is the source a block spans: from its type keyword to its
// closing brace in native syntax, and from its key to the closing brace of
// its object in JSON, whose body has no source range of its own but reports
// that brace as the place a missing item would go.
func BlockRange(block *hcl.Block) hcl.Range {
	if body, ok := block.Body.(*hclsyntax.Body); ok {
		return hcl.RangeBetween(block.TypeRange, body.SrcRange)
	}
	end := block.Body.MissingItemRange()
	if end.Filename != block.DefRange.Filename || end.End.Byte < block.DefRange.Start.Byte {
		return block.DefRange
	}
	return hcl.RangeBetween(block.DefRange, end)
}

// locationFromBlock spans the whole block, as BlockRange does.
func locationFromBlock(filename string, block *hcl.Block) Location {
	r := BlockRange(block)
	return Location{
		File:      filename,
		Line:      r.Start.Line,
		Column:    r.Start.Column,
		EndLine:   r.End.Line,
		EndColumn: r.End.Column,
	}
}

// Region is the SARIF region of a block the parser saw: its first and last
// line. It is nil when the line is unknown.
func (l Location) Region() *ctfkit.Region {
	if l.Line < 1 {
		return nil
	}
	return &ctfkit.Region{StartLine: l.Line, EndLine: max(l.EndLine, l.Line)}
}

// BlockRegion is Region for a block read with hcl directly rather than through
// this parser, native or JSON.
func BlockRegion(block *hcl.Block) *ctfkit.Region {
	return locationFromBlock("", block).Region()
}

// RangeRegion is Region for a range read with hcl directly rather than through
// this parser.
func RangeRegion(r hcl.Range) *ctfkit.Region {
	return Location{Line: r.Start.Line, EndLine: r.End.Line}.Region()
}

func severityFromDiag(diag *hcl.Diagnostic) ParseErrorSeverity {
	if diag.Severity == hcl.DiagError {
		return ParseErrorError
	}
	return ParseErrorWarning
}

func exprToString(expr hcl.Expression) string {
	// Simple string representation of expression
	// In real implementation, this would be more sophisticated
	return fmt.Sprintf("%v", expr)
}

func ctyValueToInterface(val cty.Value) interface{} {
	if val.IsNull() {
		return nil
	}
	if val.Type() == cty.String {
		return val.AsString()
	}
	if val.Type() == cty.Number {
		f, _ := val.AsBigFloat().Float64()
		return f
	}
	if val.Type() == cty.Bool {
		return val.True()
	}
	// Handle complex types
	return val.GoString()
}
