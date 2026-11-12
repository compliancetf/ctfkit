// Package disabledcontrol implements ctf.policy.disabled_control: the pre_plan
// rules that find a compliance.tf module source turning a control off with
// ?disable=<id>, and say which control it turned off.
//
// A token counts as a disabled control only when the control catalog holds
// the id. There is no keyword matching: the ctf-003 heuristic, which flagged
// any module variable prefixed disable_, skip_, ignore_, bypass_ or no_, is
// dropped, because it fired on any no_* input and never named a control.
//
// Exceptions are not an input. The analyzer reports every disable it finds;
// the runner looks the finding up with ctfkit.Decide afterwards and records
// the verdict, so a covered disable stays visible in every projection.
//
// The values are stateless, so the family is pure and safe to run
// concurrently.
package disabledcontrol

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/parser"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// forcedGetter matches a leading go-getter prefix such as "git::". It is
// anchored so that a "::" inside a query value never truncates the source.
var forcedGetter = regexp.MustCompile(`^[A-Za-z0-9]+::`)

// moduleSchema and sourceSchema read module blocks and their source through
// the generic hcl.Body API, so native and JSON configuration share one reader.
var (
	moduleSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "module", LabelNames: []string{"name"}}}}
	sourceSchema = &hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "source"}}}
)

// Descriptors returns the tool.driver.rules entries of the family, for the
// runner to hand to the SARIF renderer.
func Descriptors() []sarif.RuleDescriptor {
	return sarif.WithHelpURI(sarif.AnalyzerDocs+"#disabled-controls", []sarif.RuleDescriptor{
		{
			ID:               ruleDisabledControl,
			ShortDescription: "A compliance.tf module source disables a control",
			Level:            ctfkit.LevelError,
		},
		{
			ID:               ruleUnknown,
			ShortDescription: "A compliance.tf module source disables a token the control catalog does not hold",
			Level:            ctfkit.LevelError,
		},
	})
}

// The rule ids of the family.
const (
	ruleDisabledControl = "ctf.policy.disabled_control"
	ruleUnknown         = "ctf.policy.disabled_control_unknown"
)

// Message templates, formatted with control ids and disable tokens from the
// module source only. Neither names an exception: the runner records the
// exception verdict in ctf.exception, so the message holds whether or not an
// entry covers the disable.
const (
	msgDisabledControl = "Module source disables control %s"
	msgUnknown         = "Module source disables %s, which is not a control id in catalog %s; " +
		"it is a typo, or a control outside this catalog%s"
)

// schemaVersion is the findings format version every finding carries.
const schemaVersion = "1.0"

// disableParam is the query parameter a compliance.tf source disables
// controls with. Its value is a comma separated list of control ids, and the
// parameter may repeat.
const disableParam = "disable"

// hostSuffix marks a compliance.tf registry endpoint: a framework host such as
// soc2.compliance.tf or an organization host such as bobthecorp.compliance.tf.
const hostSuffix = ".compliance.tf"

// Register adds both rules of the family to r, at pre_plan.
func Register(r ctfkit.Registry) {
	ctfkit.MustRegister(r, DisabledControl{}, Unknown{})
}

// DisabledControl is ctf.policy.disabled_control: one error per catalog
// control id a compliance.tf source disables.
type DisabledControl struct{}

// ID returns the rule id.
func (DisabledControl) ID() string { return ruleDisabledControl }

// Stage returns pre_plan.
func (DisabledControl) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze reports every known control a module source disables.
func (DisabledControl) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return analyze(ctx, in, true)
}

// Unknown is ctf.policy.disabled_control_unknown: one error per disable token
// the catalog does not hold. It is an error, like a known disable: the
// embedded catalog holds only the CIS v6.0 controls, so a real control outside
// it lands here, and a weaker level would let that disable pass CI.
type Unknown struct{}

// ID returns the rule id.
func (Unknown) ID() string { return ruleUnknown }

// Stage returns pre_plan.
func (Unknown) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze reports every disable token that names no catalog control.
func (Unknown) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return analyze(ctx, in, false)
}

// disable is one token of a ?disable= list on one module call.
type disable struct {
	file   string
	region *ctfkit.Region
	module string
	token  string
}

// analyze builds the findings of one rule: the known ids when known is true,
// the unknown tokens otherwise.
func analyze(ctx context.Context, in ctfkit.AnalyzerInput, known bool) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if in.Config == nil {
		return nil, nil
	}
	if in.Catalog == nil {
		return nil, fmt.Errorf("disabledcontrol: no control catalog")
	}

	disables, err := collect(in.Config)
	if err != nil {
		return nil, err
	}

	var out ctfkit.Findings
	for _, d := range disables {
		ref, ok := in.Catalog.Control(ctfkit.ControlID(d.token))
		if ok != known {
			continue
		}
		f, findingErr := newFinding(d, ref, ok, in.Catalog)
		if findingErr != nil {
			return nil, findingErr
		}
		out = append(out, f)
	}
	return out, nil
}

// newFinding builds the finding for one disable token.
//
// ctf.preventive is false and ctf.remediation is unset on both rules, which is
// what the recorded fixture freezes: the configuration already uses the
// compliance.tf module, so the fix is removing the parameter, not a module.
func newFinding(d disable, ref ctfkit.ControlRef, known bool, cat ctfkit.ControlCatalog) (ctfkit.Finding, error) {
	locations := []ctfkit.Location{{
		PhysicalLocation: &ctfkit.PhysicalLocation{ArtifactLocation: ctfkit.ArtifactLocation{URI: d.file}, Region: d.region},
		LogicalLocations: []ctfkit.LogicalLocation{{
			FullyQualifiedName: "module." + d.module,
			Kind:               ctfkit.LogicalLocationModule,
		}},
	}}

	if !known {
		return ctfkit.NewFinding(ruleUnknown, ctfkit.LevelError, ctfkit.KindFail,
			ctfkit.Message{Text: fmt.Sprintf(msgUnknown, d.token, cat.Version().Version, catalog.EmbeddedSubsetNote(cat.Version()))},
			locations,
			ctfkit.Properties{Schema: schemaVersion, Stage: ctfkit.PrePlan})
	}

	var frameworks []ctfkit.FrameworkClauses
	for _, framework := range cat.Frameworks(ref.ID) {
		frameworks = append(frameworks, ctfkit.FrameworkClauses{
			ID:      framework,
			Clauses: catalog.ClauseIdentifiers(cat.Framework(ref.ID, framework)),
		})
	}
	return ctfkit.NewFinding(ruleDisabledControl, ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: fmt.Sprintf(msgDisabledControl, ref.ID)},
		locations,
		ctfkit.Properties{
			Schema:     schemaVersion,
			Stage:      ctfkit.PrePlan,
			ControlIDs: []ctfkit.ControlID{ref.ID},
			Frameworks: frameworks,
		})
}

// collect returns every disable token on a compliance.tf module source, in
// file order, each token once per module call.
//
// Every configuration file is read, root or not: a monorepo keeps its root
// modules in subdirectories, and a skipped file is a silent false negative on
// the one bypass that leaves no trace in the resource. The address is
// module.<name> relative to the file's own module; the uri says which file.
func collect(config *ctfkit.ConfigArchive) ([]disable, error) {
	// The local modules the walk did not read ("../", or a skipped directory
	// such as .terraform.d) are installed by init too, so they are read here.
	files := config.Files
	for _, module := range config.LocalModules {
		files = append(files[:len(files):len(files)], module.Files...)
	}
	var out []disable
	for _, file := range files {
		body, err := parse(file)
		if err != nil {
			return nil, err
		}
		if body == nil {
			continue
		}

		content, _, _ := body.PartialContent(moduleSchema)
		for _, block := range content.Blocks {
			for _, token := range disabledTokens(sourceOf(block.Body)) {
				out = append(out, disable{file: file.Path, region: parser.BlockRegion(block), module: block.Labels[0], token: token})
			}
		}
	}
	return out, nil
}

// parse reads one configuration file in native or JSON syntax. It returns a
// nil body for a file that is neither.
func parse(file ctfkit.ConfigFile) (hcl.Body, error) {
	var parsed *hcl.File
	var diags hcl.Diagnostics
	switch {
	case strings.HasSuffix(file.Path, ".tf"), strings.HasSuffix(file.Path, ".tofu"):
		parsed, diags = hclsyntax.ParseConfig(file.Bytes, file.Path, hcl.InitialPos)
	case strings.HasSuffix(file.Path, ".tf.json"), strings.HasSuffix(file.Path, ".tofu.json"):
		parsed, diags = hcljson.Parse(file.Bytes, file.Path)
	default:
		return nil, nil
	}
	if diags.HasErrors() || parsed == nil {
		// The diagnostics quote the repository's own text, so the reason is
		// reported without them.
		return nil, fmt.Errorf("disabledcontrol: %s is not valid configuration", file.Path)
	}
	return parsed.Body, nil
}

// sourceOf returns the literal source of a module block, or "" when it has
// none or it is not a literal string.
func sourceOf(body hcl.Body) string {
	content, _, _ := body.PartialContent(sourceSchema)
	attr, ok := content.Attributes["source"]
	if !ok {
		return ""
	}
	value, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || !value.IsKnown() || value.IsNull() || value.Type() != cty.String {
		return ""
	}
	return value.AsString()
}

// disabledTokens returns the tokens of every disable parameter on a
// compliance.tf source, deduplicated, in the order they appear. Any other
// source returns none.
func disabledTokens(source string) []string {
	if source == "" {
		return nil
	}
	// A forced getter such as git:: is not how compliance.tf is served, but
	// the address after it is still the one to classify.
	source = forcedGetter.ReplaceAllString(source, "")
	if !strings.Contains(source, "://") {
		source = "https://" + source
	}

	u, err := url.Parse(source)
	if err != nil || !strings.HasSuffix(strings.ToLower(u.Hostname()), hostSuffix) {
		return nil
	}

	var out []string
	seen := map[string]bool{}
	for _, value := range u.Query()[disableParam] {
		for _, token := range strings.Split(value, ",") {
			token = strings.TrimSpace(token)
			if token == "" || seen[token] {
				continue
			}
			seen[token] = true
			out = append(out, token)
		}
	}
	return out
}
