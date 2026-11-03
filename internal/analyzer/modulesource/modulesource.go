// Package modulesource implements ctf.coverage.module_source: the rule that
// reads where every module block and every planned aws_* resource came from,
// and for anything a compliance.tf module already covers names the exact
// replacement source, its version constraint and the controls it enforces.
//
// One rule id runs at two stages, which the SDK expresses as two registered
// values sharing one implementation: at pre_plan over the module blocks of the
// configuration, and at post_plan over the root module calls of the plan
// document and the resources it plans. Only one stage runs per invocation, so
// no finding is produced twice.
//
// The remediation is the only sales touchpoint in the output, and it is never
// paywalled. It informs: one module source, one version constraint and the
// controls that source would enforce. There is no pricing, no tier name, no
// upgrade prompt, no score, no percentage and no grade.
//
// Three rows of the classification table emit nothing, and the silence is
// deliberate in each case. A served module is already where it should be. A
// served module carrying a disable query belongs to
// ctf.policy.disabled_control, which is what the recorded fixture carries. A
// source that is not a registry address at all - a local path, a forced getter
// such as git::, an archive URL - belongs to the origin rules. See classify.go.
package modulesource

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"

	catalogpkg "github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/parser"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/internal/rulepack"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The rule ids of the family. They are the SARIF ruleId, the exception join
// key and the taxonomy entry, so they never change once published.
//
// ctf.coverage.module_source_disabled, which the draft spec lists as a third
// id, is deliberately absent: the recorded disabled-control fixture carries no
// result under it, and emitting a hand-off marker beside
// ctf.policy.disabled_control would report one module call twice.
const (
	ruleModuleSource    = "ctf.coverage.module_source"
	ruleUnknownRegistry = "ctf.coverage.module_source_unknown_registry"
)

// Descriptors returns the tool.driver.rules entries of the family, for the
// runner to hand to the SARIF renderer. The texts of the rule ids a recorded
// fixture carries are that fixture's bytes.
func Descriptors() []sarif.RuleDescriptor {
	return []sarif.RuleDescriptor{
		{
			ID:               ruleModuleSource,
			ShortDescription: "Module sources outside compliance.tf endpoints, and raw resources a compliance.tf module covers",
			Level:            ctfkit.LevelError,
		},
		{
			ID:               ruleUnknownRegistry,
			ShortDescription: "A module source names a registry host ctfkit cannot classify",
			Level:            ctfkit.LevelWarning,
		},
	}
}

// schemaVersion is the findings format version every finding of this family
// carries in ctf.schema.
const schemaVersion = "1.0"

// Message templates. They are analyzer constants formatted with resource
// addresses, module sources and module paths, and never with an attribute
// value read from a configuration or a plan. Every source and host they carry
// has passed ctfkit.RedactSource, which drops its query and userinfo.
const (
	msgRawResource = "Raw %s where the compliance.tf module %s exists"
	// The British spelling in this message is the recorded fixture's, byte for
	// byte, so the constant follows the oracle rather than the US locale.
	msgUpstream = "Upstream %s is a migration candidate; " +
		"the same path is served under this organisation's framework host"
	msgThirdParty      = "Third-party module %s has no compliance.tf equivalent; it is listed for inventory only"
	msgUnknownRegistry = "Module source %s resolves to the registry host %s, " +
		"which the endpoint allowlist does not name"
)

// logicalKinds of a SARIF logical location, as the recorded findings spell
// them.
const (
	kindModule   = "module"
	kindResource = "resource"
)

// Register adds every value of the family to r: one rule id at two stages is
// two values, and the family has two ids.
//
// The registration order is the emission order of a run, so a module call is
// reported before a resource and a coverage finding before an unknown
// registry, which is the order the recorded documents carry.
func Register(r ctfkit.Registry) {
	ctfkit.MustRegister(r,
		ModuleSourcePrePlan{},
		ModuleSourcePostPlan{},
		UnknownRegistryPrePlan{},
		UnknownRegistryPostPlan{},
	)
}

// ModuleSourcePrePlan is ctf.coverage.module_source over the module blocks of
// the configuration.
type ModuleSourcePrePlan struct{}

// ID returns the rule id.
func (ModuleSourcePrePlan) ID() string { return ruleModuleSource }

// Stage returns pre_plan.
func (ModuleSourcePrePlan) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze reports one finding per classified module block.
func (a ModuleSourcePrePlan) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return analyze(ctx, in, a.ID(), a.Stage())
}

// ModuleSourcePostPlan is ctf.coverage.module_source over the root module
// calls of a plan document and the resources it plans.
type ModuleSourcePostPlan struct{}

// ID returns the rule id.
func (ModuleSourcePostPlan) ID() string { return ruleModuleSource }

// Stage returns post_plan.
func (ModuleSourcePostPlan) Stage() ctfkit.Stage { return ctfkit.PostPlan }

// Analyze reports one finding per classified module call and per planned
// resource a compliance.tf module covers.
func (a ModuleSourcePostPlan) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return analyze(ctx, in, a.ID(), a.Stage())
}

// UnknownRegistryPrePlan is ctf.coverage.module_source_unknown_registry over
// the module blocks of the configuration.
type UnknownRegistryPrePlan struct{}

// ID returns the rule id.
func (UnknownRegistryPrePlan) ID() string { return ruleUnknownRegistry }

// Stage returns pre_plan.
func (UnknownRegistryPrePlan) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze reports one finding per module block on a registry host the
// endpoint allowlist does not name.
func (a UnknownRegistryPrePlan) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return analyze(ctx, in, a.ID(), a.Stage())
}

// UnknownRegistryPostPlan is ctf.coverage.module_source_unknown_registry over
// the root module calls of a plan document.
type UnknownRegistryPostPlan struct{}

// ID returns the rule id.
func (UnknownRegistryPostPlan) ID() string { return ruleUnknownRegistry }

// Stage returns post_plan.
func (UnknownRegistryPostPlan) Stage() ctfkit.Stage { return ctfkit.PostPlan }

// Analyze reports one finding per module call on a registry host the endpoint
// allowlist does not name.
func (a UnknownRegistryPostPlan) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return analyze(ctx, in, a.ID(), a.Stage())
}

// call is one module block or module call, read far enough to classify it.
type call struct {
	// name is the module call key, for example "iam_policy".
	name string
	// raw is the source exactly as the configuration wrote it.
	raw string
	// version is the version constraint the call declared, empty when it
	// declared none. It is carried across to the remediation of an upstream
	// module, because the replacement is the same module at the same version.
	version string
	// at is where the block was found, empty when the configuration was not
	// supplied.
	at site
}

// planned is one planned resource, read far enough to classify it.
type planned struct {
	// address is the absolute resource address, for example
	// "aws_s3_bucket.logs".
	address string
	// resourceType is the Terraform resource type.
	resourceType string
	// at is where the block was found, empty when the configuration was not
	// supplied or the resource is not the root's.
	at site
}

// site is where a block sits in the configuration: its file and the lines it
// spans. Both are empty when the configuration was not supplied.
type site struct {
	file   string
	region *ctfkit.Region
}

// analyze is the one implementation both rule ids and both stages share.
//
// A missing input is not an error: an analyzer selected at a stage whose
// inputs the loader did not populate reports nothing, which is the loader's
// contract rather than a malfunction. A nil catalog is the same answer: the
// runner always supplies one, and without it nothing here can name a control
// or a host.
func analyze(ctx context.Context, in ctfkit.AnalyzerInput, ruleID string, stage ctfkit.Stage) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("modulesource: %w", err)
	}
	if in.Catalog == nil {
		return nil, nil
	}

	index := indexConfig(in.Config)

	var findings ctfkit.Findings
	for _, c := range moduleCalls(in, stage, index) {
		finding, ok, err := callFinding(c, ruleID, stage, in)
		if err != nil {
			return nil, err
		}
		if ok {
			findings = append(findings, finding)
		}
	}

	if ruleID != ruleModuleSource {
		// Only the coverage rule reports a raw resource: a resource has no
		// source, so it can never be on an unknown registry.
		return findings, nil
	}

	for _, p := range plannedResources(in, stage, index) {
		finding, ok, err := resourceFinding(p, ruleID, stage, in)
		if err != nil {
			return nil, err
		}
		if ok {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// callFinding classifies one module call and builds the finding its row
// carries, if any.
func callFinding(c call, ruleID string, stage ctfkit.Stage, in ctfkit.AnalyzerInput) (ctfkit.Finding, bool, error) {
	classified := classify(c.raw, in.Settings.Endpoints)

	var (
		level       string
		text        string
		remediation *ctfkit.Remediation
	)
	switch {
	case classified.class == classUpstream && ruleID == ruleModuleSource:
		level = ctfkit.LevelError
		text = fmt.Sprintf(msgUpstream, ctfkit.RedactSource(c.raw))
		remediation = &ctfkit.Remediation{
			ModuleSource: servedPath(in.Catalog, in.Metadata.Frameworks, classified.path),
			Version:      c.version,
		}
	case classified.class == classThirdParty && ruleID == ruleModuleSource:
		level = ctfkit.LevelNote
		text = fmt.Sprintf(msgThirdParty, ctfkit.RedactSource(c.raw))
	case classified.class == classUnknownRegistry && ruleID == ruleUnknownRegistry:
		level = ctfkit.LevelWarning
		text = fmt.Sprintf(msgUnknownRegistry, ctfkit.RedactSource(c.raw), ctfkit.RedactSource(classified.host))
	default:
		return ctfkit.Finding{}, false, nil
	}

	finding, err := newFinding(ruleID, level, stage, text,
		location(c.at, "module."+c.name, kindModule), nil, nil, remediation)
	if err != nil {
		return ctfkit.Finding{}, false, err
	}

	return finding, true, nil
}

// resourceFinding builds the finding for one planned resource a compliance.tf
// module covers.
//
// A resource type the catalog holds no module for is not a finding. The rule
// names migration candidates, and a type nothing covers is not one; guessing a
// module for it is what the specification's non-goals refuse.
func resourceFinding(p planned, ruleID string, stage ctfkit.Stage, in ctfkit.AnalyzerInput) (ctfkit.Finding, bool, error) {
	module, ok := in.Catalog.ModuleFor(p.resourceType)
	if !ok {
		return ctfkit.Finding{}, false, nil
	}

	// ctf.controlIds carries the controls the catalog holds for the resource
	// type, which is what the recorded fixtures 01, 05, 06 and 07 carry. The
	// draft spec's prose says a coverage finding carries none; the recorded
	// bytes are the oracle and win.
	//
	// The consequence sits outside this package. Fixture
	// 06-sentinel-exception records this finding suppressed by one
	// control-level entry naming one of its three controls. ctfkit.Decide as
	// it stands requires an entry for every control id a finding carries, so
	// it leaves that finding unsuppressed; the runner's exception matching,
	// not this analyzer, has to change to meet that fixture.
	moduleSource := strings.ReplaceAll(module.Source, "{host}",
		remediationHost(in.Catalog, in.Metadata.Frameworks))
	controls := in.Catalog.ControlsFor(p.resourceType)

	finding, err := newFinding(ruleID, ctfkit.LevelError, stage,
		fmt.Sprintf(msgRawResource, p.resourceType, moduleSource),
		location(p.at, p.address, kindResource),
		controls, frameworkClauses(in.Catalog, controls),
		&ctfkit.Remediation{ModuleSource: moduleSource, Version: module.Version})
	if err != nil {
		return ctfkit.Finding{}, false, err
	}

	return finding, true, nil
}

// newFinding builds one finding of the family, so the schema version, the
// kind and the preventive rule are stated once.
//
// Preventive follows the remediation: a compliance.tf module would have
// prevented the finding exactly when one is named, which is the invariant the
// findings format requires of a preventive finding.
func newFinding(ruleID, level string, stage ctfkit.Stage, text string, locs []ctfkit.Location,
	controls []ctfkit.ControlID, frameworks []ctfkit.FrameworkClauses, remediation *ctfkit.Remediation,
) (ctfkit.Finding, error) {
	return ctfkit.NewFinding(ruleID, level, ctfkit.KindFail, ctfkit.Message{Text: text}, locs,
		ctfkit.Properties{
			Schema:      schemaVersion,
			Stage:       stage,
			ControlIDs:  controls,
			Frameworks:  frameworks,
			Preventive:  remediation != nil,
			Remediation: remediation,
		})
}

// location is the one location a finding of this family carries: the
// configuration file and lines the block spans, when the configuration was
// supplied, and the address of the block itself. The address, not the line,
// is what an exception is keyed on, so a block moving changes the region and
// nothing else.
func location(at site, address, kind string) []ctfkit.Location {
	loc := ctfkit.Location{
		LogicalLocations: []ctfkit.LogicalLocation{{FullyQualifiedName: address, Kind: kind}},
	}
	if at.file != "" {
		loc.PhysicalLocation = &ctfkit.PhysicalLocation{
			ArtifactLocation: ctfkit.ArtifactLocation{URI: at.file},
			Region:           at.region,
		}
	}

	return []ctfkit.Location{loc}
}

// moduleCalls are the module blocks of the root module, in a stable order:
// configuration order at pre_plan, module call key order at post_plan, where
// the plan document holds a map.
//
// Only the root module's calls are classified. A module call inside a
// third-party module is that vendor's choice and not one this configuration
// can act on, so reporting it would be a finding nobody can fix.
func moduleCalls(in ctfkit.AnalyzerInput, stage ctfkit.Stage, index *configIndex) []call {
	if stage != ctfkit.PostPlan {
		return index.calls
	}
	if in.PlanJSON == nil || in.PlanJSON.Config == nil || in.PlanJSON.Config.RootModule == nil {
		return nil
	}

	declared := in.PlanJSON.Config.RootModule.ModuleCalls
	names := make([]string, 0, len(declared))
	for name, moduleCall := range declared {
		// A null entry is a malformed plan document; it declares no source to
		// classify, and it must not crash the run.
		if moduleCall != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	out := make([]call, 0, len(names))
	for _, name := range names {
		out = append(out, call{
			name:    name,
			raw:     declared[name].Source,
			version: declared[name].VersionConstraint,
			at:      index.moduleSites[name],
		})
	}

	return out
}

// plannedResources are the managed aws_* resources the plan creates, in plan
// order, with everything a compliance.tf module governs left out.
//
// A resource declared inside a served module is the module's, not the
// configuration's: the served module already enforces its controls, and
// reporting its buckets would tell a reader to migrate what is migrated. A
// resource inside any other module is still the configuration's risk, because
// instantiating that module is the choice that created it.
func plannedResources(in ctfkit.AnalyzerInput, stage ctfkit.Stage, index *configIndex) []planned {
	if stage != ctfkit.PostPlan || in.PlanJSON == nil || in.PlanJSON.PlannedValues == nil {
		return nil
	}

	root := in.PlanJSON.PlannedValues.RootModule
	var served map[string]bool
	if config := in.PlanJSON.Config; config != nil && config.RootModule != nil {
		served = servedSubtrees(config.RootModule, "", in.Settings.Endpoints)
	} else {
		// Without the configuration tree nothing says which child module is
		// served, and guessing "none" would report every resource of a served
		// module as raw. Only the root's own resources are classified.
		if root == nil {
			return nil
		}
		root = &tfjson.StateModule{Resources: root.Resources}
	}

	var out []planned
	collect(root, served, index, &out)

	return out
}

// collect walks one planned module and its children, skipping a subtree a
// served module governs.
func collect(module *tfjson.StateModule, served map[string]bool, index *configIndex, out *[]planned) {
	if module == nil {
		return
	}

	for _, resource := range module.Resources {
		if resource == nil || resource.Mode != tfjson.ManagedResourceMode {
			continue
		}
		if !packedType(resource.Type) {
			continue
		}
		*out = append(*out, planned{
			address:      resource.Address,
			resourceType: resource.Type,
			at:           index.resourceSites[resource.Address],
		})
	}

	for _, child := range module.ChildModules {
		if child == nil || served[moduleCallPath(child.Address)] {
			continue
		}
		collect(child, served, index, out)
	}
}

// packedType reports whether a resource type has the resource prefix of a
// provider a rule pack describes. Only those providers have catalog modules
// to migrate to.
func packedType(resourceType string) bool {
	return slices.ContainsFunc(rulepack.Embedded().ResourcePrefixes(), func(prefix string) bool {
		return strings.HasPrefix(resourceType, prefix)
	})
}

// moduleCallPath reduces an expanded module instance address to the module
// call path the configuration declares: "module.s3_bucket[0]" and
// `module.s3_bucket["logs"]` both become "module.s3_bucket". The planned
// values name instances; the configuration names calls, and a served module
// instantiated with count or for_each is still the served module.
func moduleCallPath(address string) string {
	return instanceKey.ReplaceAllString(address, "")
}

// instanceKey matches one count or for_each index of a module address. A
// for_each key is a quoted string that may itself hold a bracket, so a quoted
// key is matched as a whole before an unquoted index.
var instanceKey = regexp.MustCompile(`\[(?:"(?:[^"\\]|\\.)*"|[^\]]*)\]`)

// servedSubtrees is the set of module addresses a compliance.tf module
// governs, built from the plan's own configuration tree.
func servedSubtrees(module *tfjson.ConfigModule, prefix string, endpoints []string) map[string]bool {
	out := make(map[string]bool)
	if module == nil {
		return out
	}

	for name, declared := range module.ModuleCalls {
		if declared == nil {
			continue
		}
		address := prefix + "module." + name
		switch classify(declared.Source, endpoints).class {
		case classServed, classServedDisabled:
			// The whole subtree is the served module's, children included.
			out[address] = true
		case classIgnored, classUpstream, classThirdParty, classUnknownRegistry:
			for nested := range servedSubtrees(declared.Module, address+".", endpoints) {
				out[nested] = true
			}
		}
	}

	return out
}

// configIndex is the configuration read once: the module blocks in file
// order, and the file each module block and each root resource block sits in,
// which is what anchors a finding to a file.
type configIndex struct {
	calls         []call
	moduleSites   map[string]site
	resourceSites map[string]site
}

// indexConfig parses the supplied configuration. It is nil-safe: at post_plan
// the configuration is optional, and a finding then carries its address alone.
//
// A file that does not parse contributes the blocks that did. Configuration
// validity is terraform's answer to give, and a parse error here is never a
// finding.
func indexConfig(config *ctfkit.ConfigArchive) *configIndex {
	index := &configIndex{
		moduleSites:   make(map[string]site),
		resourceSites: make(map[string]site),
	}
	if config == nil {
		return index
	}

	// A site is where a block is declared: never an override file, which only
	// restates it, nor a .tf copy its .tofu twin shadows. Calls
	// are read from every file, as before.
	primary := make(map[string]bool, len(config.Files))
	for _, file := range parser.PrimaryFiles(config.Files) {
		primary[file.Path] = true
	}
	for _, file := range config.Files {
		// Native syntax and JSON alike, by file name.
		parsed := parser.ParseConfigContent(file.Bytes, file.Path)
		for _, module := range parsed.Modules {
			index.calls = append(index.calls, call{
				name:    module.Name,
				raw:     module.Source,
				version: module.Version,
				at:      site{file.Path, module.Location.Region()},
			})
			if !primary[file.Path] {
				continue
			}
			if _, seen := index.moduleSites[module.Name]; !seen {
				index.moduleSites[module.Name] = site{file.Path, module.Location.Region()}
			}
		}
		if !primary[file.Path] {
			continue
		}
		for _, resource := range parsed.Resources {
			address := resource.Type + "." + resource.Name
			if _, seen := index.resourceSites[address]; !seen {
				index.resourceSites[address] = site{file.Path, resource.Location.Region()}
			}
		}
	}

	return index
}

// frameworkClauses is the ctf.frameworks list of a coverage finding: every
// framework the controls of the replacement module map to, with the clauses
// they satisfy.
//
// Two controls may satisfy the same clause, so the clauses are a set. A
// framework the catalog lists with no clause for any of these controls is left
// out: naming a framework with an empty clause list says nothing a reader can
// act on.
func frameworkClauses(catalog ctfkit.ControlCatalog, controls []ctfkit.ControlID) []ctfkit.FrameworkClauses {
	clauses := make(map[string]map[string]bool)
	for _, control := range controls {
		for _, framework := range catalog.Frameworks(control) {
			for _, clause := range catalogpkg.ClauseIdentifiers(catalog.Framework(control, framework)) {
				if clauses[framework] == nil {
					clauses[framework] = make(map[string]bool)
				}
				clauses[framework][clause] = true
			}
		}
	}

	out := make([]ctfkit.FrameworkClauses, 0, len(clauses))
	for framework, set := range clauses {
		identifiers := make([]string, 0, len(set))
		for clause := range set {
			identifiers = append(identifiers, clause)
		}
		// NewFinding sorts the list and the clauses inside it, so nothing
		// here has to: two runs over the same catalog emit the same bytes.
		out = append(out, ctfkit.FrameworkClauses{ID: framework, Clauses: identifiers})
	}

	return out
}

// servedPath is the upstream module's own path under the organization's
// framework host. The replacement is the same module, so the path is carried
// across unchanged and only the host is new.
func servedPath(catalog ctfkit.ControlCatalog, frameworks []string, path string) string {
	return remediationHost(catalog, frameworks) + complianceSuffix + "/" + path
}

// remediationHost is the registry endpoint label substituted for the {host}
// placeholder of a catalog module source. The run's own framework wins when
// the catalog hosts it, and the catalog's default answers otherwise.
//
// The host comes from the catalog and the run, never from the settings file:
// a repository input that could choose the remediation host could point every
// reader of its findings at an endpoint the organization never served. The
// runner resolves --remediation-host into the run's frameworks before an
// analyzer sees it.
//
// internal/analyzer/coverage carries the same twelve lines. A third caller is
// the point at which they move to a shared helper; two is not worth a package.
func remediationHost(catalog ctfkit.ControlCatalog, frameworks []string) string {
	hosts := catalog.Hosts()
	for _, framework := range frameworks {
		if label, ok := hosts[framework]; ok {
			return label
		}
	}

	fallback := catalog.DefaultHost()
	if label, ok := hosts[fallback]; ok {
		return label
	}

	return fallback
}
