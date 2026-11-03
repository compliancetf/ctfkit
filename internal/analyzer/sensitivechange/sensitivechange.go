// Package sensitivechange implements ctf.risk.sensitive_change: the post_plan
// rules that stop five classes of change a reviewer would stop in a pull
// request even with no compliance program at all.
//
// Five rule ids, one Analyzer value each, as the SDK contract requires:
//
//   - ctf.risk.sensitive_change_public_exposure: a change opens a resource to
//     public or unrestricted access.
//   - ctf.risk.sensitive_change_wildcard_iam: an IAM policy allows wildcard
//     actions on every resource with no condition.
//   - ctf.risk.sensitive_change_audit_log_removal: a change removes or narrows
//     audit logging.
//   - ctf.risk.sensitive_change_encryption_disablement: a change turns off
//     encryption at rest.
//   - ctf.risk.sensitive_change_destructive_stateful: a change deletes or
//     replaces a stateful resource, or removes its deletion safeguard.
//
// The analyzer is deliberately narrow: exactly these five classes, with the
// attribute rules the analyzer spec lists, and nothing else. Which resource
// types and attributes a class checks is data, the rule pack of the change's
// provider (internal/rulepack); this package holds the predicates the rules
// name, and a provider dialect for what a rule file cannot express. A change
// whose provider no pack describes is not checked. Every condition reads
// change.before and change.after only. An attribute that is unknown at plan
// time never fires a rule, and a resource whose actions are no-op or read is
// skipped.
//
// A finding names the resource address and the attribute names concerned,
// never a value. It carries a control id only when the catalog covers the
// resource type with a control about the changed attribute, one control id per
// finding, and ctf.preventive is true exactly when it carries one.
//
// The values are stateless, so the family is pure and safe to run
// concurrently.
package sensitivechange

import (
	"context"
	"regexp"
	"slices"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/parser"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/internal/rulepack"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The rule ids of the family.
const (
	rulePublicExposure        = "ctf.risk.sensitive_change_public_exposure"
	ruleWildcardIAM           = "ctf.risk.sensitive_change_wildcard_iam"
	ruleAuditLogRemoval       = "ctf.risk.sensitive_change_audit_log_removal"
	ruleEncryptionDisablement = "ctf.risk.sensitive_change_encryption_disablement"
	ruleDestructiveStateful   = "ctf.risk.sensitive_change_destructive_stateful"
)

// schemaVersion is the findings format version every finding states.
const schemaVersion = "1.0"

// Register adds every rule of the family to r, at post_plan.
func Register(r ctfkit.Registry) {
	ctfkit.MustRegister(r, PublicExposure{}, WildcardIAM{}, AuditLogRemoval{},
		EncryptionDisablement{}, DestructiveStateful{})
}

// Descriptors returns the tool.driver.rules entries of the family, for the
// runner to hand to the SARIF renderer. The texts are the recorded fixture
// texts, byte for byte.
func Descriptors() []sarif.RuleDescriptor {
	return []sarif.RuleDescriptor{
		{ID: rulePublicExposure, ShortDescription: "A change opens a resource to public or unrestricted access", Level: ctfkit.LevelError},
		{ID: ruleWildcardIAM, ShortDescription: "An IAM policy allows wildcard actions on every resource with no condition", Level: ctfkit.LevelError},
		{ID: ruleAuditLogRemoval, ShortDescription: "A change removes or narrows audit logging", Level: ctfkit.LevelError},
		{ID: ruleEncryptionDisablement, ShortDescription: "A change turns off encryption at rest", Level: ctfkit.LevelError},
		{ID: ruleDestructiveStateful, ShortDescription: "A change deletes or replaces a stateful resource, or removes its deletion safeguard", Level: ctfkit.LevelError},
	}
}

// PublicExposure reports class 1.
type PublicExposure struct{}

// ID returns the rule id.
func (PublicExposure) ID() string { return rulePublicExposure }

// Stage returns post_plan.
func (PublicExposure) Stage() ctfkit.Stage { return ctfkit.PostPlan }

// Analyze reports every change that opens a resource to public access.
func (r PublicExposure) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return emit(ctx, in, r.ID(), "public_exposure")
}

// WildcardIAM reports class 2.
type WildcardIAM struct{}

// ID returns the rule id.
func (WildcardIAM) ID() string { return ruleWildcardIAM }

// Stage returns post_plan.
func (WildcardIAM) Stage() ctfkit.Stage { return ctfkit.PostPlan }

// Analyze reports every IAM policy that allows wildcard actions everywhere.
func (r WildcardIAM) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return emit(ctx, in, r.ID(), "wildcard_iam")
}

// AuditLogRemoval reports class 3.
type AuditLogRemoval struct{}

// ID returns the rule id.
func (AuditLogRemoval) ID() string { return ruleAuditLogRemoval }

// Stage returns post_plan.
func (AuditLogRemoval) Stage() ctfkit.Stage { return ctfkit.PostPlan }

// Analyze reports every change that removes or narrows audit logging.
func (r AuditLogRemoval) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return emit(ctx, in, r.ID(), "audit_log_removal")
}

// EncryptionDisablement reports class 4.
type EncryptionDisablement struct{}

// ID returns the rule id.
func (EncryptionDisablement) ID() string { return ruleEncryptionDisablement }

// Stage returns post_plan.
func (EncryptionDisablement) Stage() ctfkit.Stage { return ctfkit.PostPlan }

// Analyze reports every change that turns off encryption at rest.
func (r EncryptionDisablement) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return emit(ctx, in, r.ID(), "encryption_disablement")
}

// DestructiveStateful reports class 5.
type DestructiveStateful struct{}

// ID returns the rule id.
func (DestructiveStateful) ID() string { return ruleDestructiveStateful }

// Stage returns post_plan.
func (DestructiveStateful) Stage() ctfkit.Stage { return ctfkit.PostPlan }

// Analyze reports every delete or replace of a stateful resource and every
// removed deletion safeguard.
func (r DestructiveStateful) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return emit(ctx, in, r.ID(), "destructive_stateful")
}

// hit is one reason a class fires on one resource: the level, the message
// template, and the attribute it is about, empty for a whole-resource change.
// A replacement is a whole-resource change that still names the attributes
// forcing it; whole keeps those from picking up a control id.
type hit struct {
	level    string
	template string
	attr     string
	whole    bool
}

// emit runs one class over every managed resource change, in plan order, and
// builds one finding per resource, level, message and control id. Each change
// is judged by the rule pack of its provider; a provider no pack describes
// has no rules, which is not an error.
func emit(ctx context.Context, in ctfkit.AnalyzerInput, ruleID, class string) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if in.PlanJSON == nil {
		return nil, nil
	}
	set := packs()
	var lock *ctfkit.Lockfile
	if in.Config != nil {
		lock = in.Config.Lockfile
	}
	files := rootResourceFiles(in.Config)

	var findings ctfkit.Findings
	for _, rc := range in.PlanJSON.ResourceChanges {
		if rc == nil || rc.Change == nil || rc.Mode != tfjson.ManagedResourceMode {
			continue
		}
		actions := rc.Change.Actions
		if !actions.Create() && !actions.Update() && !actions.Delete() && !actions.Replace() {
			continue
		}
		pack := set.Select(rc.ProviderName, lock)
		if pack == nil {
			continue
		}
		for _, g := range group(evaluate(pack, class, newChange(rc)), rc.Type, pack, in.Catalog) {
			f, err := newFinding(ruleID, rc.Address, g, in.Catalog, files)
			if err != nil {
				return nil, err
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// finding is the hits of one resource that share a level, a template and a
// control id: one finding.
type finding struct {
	level    string
	template string
	control  ctfkit.ControlID
	attrs    []string
}

// group resolves each hit's control id and merges hits that share a level,
// a template and a control id, keeping first-seen order.
func group(hits []hit, resourceType string, pack *rulepack.Pack, cat ctfkit.ControlCatalog) []finding {
	var out []finding
	for _, h := range hits {
		attr := h.attr
		if h.whole {
			attr = ""
		}
		for _, control := range controlsFor(resourceType, attr, pack, cat) {
			i := slices.IndexFunc(out, func(f finding) bool {
				return f.level == h.level && f.template == h.template && f.control == control
			})
			if i < 0 {
				out = append(out, finding{level: h.level, template: h.template, control: control})
				i = len(out) - 1
			}
			if h.attr != "" && !slices.Contains(out[i].attrs, h.attr) {
				out[i].attrs = append(out[i].attrs, h.attr)
			}
		}
	}
	return out
}

// controlsFor is the catalog controls about one attribute of a resource type
// that the pack names and the catalog covers the type with, or a single empty
// id when there is none.
func controlsFor(resourceType, attr string, pack *rulepack.Pack, cat ctfkit.ControlCatalog) []ctfkit.ControlID {
	none := []ctfkit.ControlID{""}
	if attr == "" || cat == nil {
		return none
	}
	var out []ctfkit.ControlID
	covered := cat.ControlsFor(resourceType)
	for _, id := range pack.Controls(resourceType, attr) {
		if slices.Contains(covered, id) {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return none
	}
	return out
}

func newFinding(ruleID, address string, g finding, cat ctfkit.ControlCatalog, files map[string]ctfkit.PhysicalLocation) (ctfkit.Finding, error) {
	slices.Sort(g.attrs)
	text := strings.NewReplacer("{address}", address, "{attributes}", strings.Join(g.attrs, ", ")).Replace(g.template)

	props := ctfkit.Properties{Schema: schemaVersion, Stage: ctfkit.PostPlan, Attributes: g.attrs}
	if g.control != "" {
		props.ControlIDs = []ctfkit.ControlID{g.control}
		props.Preventive = true
		for _, framework := range cat.Frameworks(g.control) {
			props.Frameworks = append(props.Frameworks, ctfkit.FrameworkClauses{
				ID: framework, Clauses: catalog.ClauseIdentifiers(cat.Framework(g.control, framework)),
			})
		}
	}
	return ctfkit.NewFinding(ruleID, g.level, ctfkit.KindFail, ctfkit.Message{Text: text},
		[]ctfkit.Location{location(address, files)}, props)
}

// instanceKey matches the instance key of one address step, [0] or ["a"].
var instanceKey = regexp.MustCompile(`\[[^\]]*\]`)

// rootResourceFiles maps "type.name" of each resource block declared directly
// in the root module to the file that declares it.
func rootResourceFiles(config *ctfkit.ConfigArchive) map[string]ctfkit.PhysicalLocation {
	out := make(map[string]ctfkit.PhysicalLocation)
	if config == nil {
		return out
	}
	for _, file := range parser.PrimaryFiles(config.Files) {
		if strings.Contains(file.Path, "/") {
			continue
		}
		if file.Path == fallbackFile {
			out[fallbackFile] = ctfkit.PhysicalLocation{ArtifactLocation: ctfkit.ArtifactLocation{URI: fallbackFile}}
		}
		// .tf, .tofu, .tf.json and .tofu.json; anything else parses to nothing.
		for _, r := range parser.ParseConfigContent(file.Bytes, file.Path).Resources {
			if _, seen := out[r.Type+"."+r.Name]; !seen {
				out[r.Type+"."+r.Name] = ctfkit.PhysicalLocation{
					ArtifactLocation: ctfkit.ArtifactLocation{URI: file.Path},
					Region:           r.Location.Region(),
				}
			}
		}
	}
	return out
}

// fallbackFile anchors a root-module resource that no file declares any more,
// which is a resource the plan deletes because its block was removed.
// ponytail: the block is gone, so main.tf, Terraform's conventional entry
// file, is a guess; the plan does not record which file held it.
const fallbackFile = "main.tf"

// location names the resource and, for a root-module resource, the file and
// lines that declare it, or main.tf with no lines for one whose block was
// removed.
// ponytail: resources inside modules get the address only; anchoring them
// needs the module call's source directory.
func location(address string, files map[string]ctfkit.PhysicalLocation) ctfkit.Location {
	loc := ctfkit.Location{LogicalLocations: []ctfkit.LogicalLocation{{
		FullyQualifiedName: address, Kind: ctfkit.LogicalLocationResource,
	}}}
	at, ok := files[instanceKey.ReplaceAllString(address, "")]
	if !ok && !strings.HasPrefix(address, "module.") {
		at, ok = files[fallbackFile]
	}
	if ok {
		loc.PhysicalLocation = &at
	}
	return loc
}
