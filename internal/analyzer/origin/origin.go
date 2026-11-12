// Package origin implements the supply-chain rules of ctfkit: which providers
// a configuration may download (the ctf.origin.provider family) and whether a
// module reference can move under the same commit (the
// ctf.policy.floating_ref family).
//
// Every rule reads only what the configuration, the lock file and the plan
// already state. Nothing here contacts a registry, resolves a constraint or
// verifies a checksum.
//
// One Analyzer value implements one (rule id, stage) pair. ctf.origin.provider
// and ctf.origin.provider_resource_type run at pre_plan over the configuration
// and at post_plan over the plan, as two values of one type. Every finding
// carries an empty ctf.controlIds and ctf.frameworks: this is
// framework-agnostic hygiene, so a waiver for one is a rule-level exception
// entry, never a control entry.
package origin

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/internal/tfroots"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The rule ids of both families.
const (
	ruleProvider             = "ctf.origin.provider"
	ruleProviderUnpinned     = "ctf.origin.provider_unpinned"
	ruleProviderUnverified   = "ctf.origin.provider_unverified"
	ruleProviderResourceType = "ctf.origin.provider_resource_type"
	ruleFloatingRef          = "ctf.policy.floating_ref"
	ruleFloatingRefUnbounded = "ctf.policy.floating_ref_unbounded"
)

// Descriptors returns the tool.driver.rules entries of the family, for the
// runner to hand to the SARIF renderer. The texts of the rule ids a recorded
// fixture carries are that fixture's bytes.
func Descriptors() []sarif.RuleDescriptor {
	return sarif.WithHelpURI(sarif.AnalyzerDocs+"#provider-and-module-origin", []sarif.RuleDescriptor{
		{
			ID:               ruleProvider,
			ShortDescription: "A provider outside the approved list is in use",
			Level:            ctfkit.LevelWarning,
		},
		{
			ID:               ruleProviderUnpinned,
			ShortDescription: "A provider has no upper-bounded version constraint",
			Help:             helpProviderUnpinned,
			Level:            ctfkit.LevelWarning,
		},
		{
			ID:               ruleProviderUnverified,
			ShortDescription: "A provider has no dependency lock entry with recorded hashes",
			Level:            ctfkit.LevelWarning,
		},
		{
			ID:               ruleProviderResourceType,
			ShortDescription: "A resource type outside the allowed_resources list is in use",
			Level:            ctfkit.LevelError,
		},
		{
			ID:               ruleFloatingRef,
			ShortDescription: "A module source is not pinned to an immutable reference",
			Level:            ctfkit.LevelWarning,
		},
		{
			ID:               ruleFloatingRefUnbounded,
			ShortDescription: "A registry module source has no upper-bounded version constraint",
			Level:            ctfkit.LevelWarning,
		},
	})
}

// Message templates. They are formatted with provider sources, module
// sources, resource types and refs, all repository text, and never with an
// attribute value. A module source passes ctfkit.RedactSource (displaySource)
// first; NewFinding strips URL userinfo from the result.
const (
	msgProviderUnapproved = "Provider %s is not in the approved provider list"
	msgProviderUnpinned   = "Provider %s has no upper-bounded version constraint, " +
		"so a later release can be installed without a configuration change"
	msgProviderUnverified = "Provider %s has no .terraform.lock.hcl entry with recorded hashes, " +
		"so the downloaded package is not checked against a known checksum"
	msgResourceType = "Resource type %s is not in the allowed_resources list"
	msgRefAbsent    = "Module source %s has no ref, so the code that runs can change " +
		"without a configuration change"
	msgRefMutable = "Module source %s is pinned to ref %s, which is a branch or tag and can move; " +
		"pin it to a commit SHA"
	msgRegistryUnbounded = "Module source %s has no upper-bounded version constraint, " +
		"so a later release can be installed without a configuration change"
)

// helpProviderUnpinned is the SARIF help of ctf.origin.provider_unpinned. The
// docs/analyzers.md section "Provider constraints in reusable modules" states
// the same rules and misses in its own words; change both together.
const helpProviderUnpinned = "Reports a required_providers entry with no upper-bounded version " +
	"constraint in a deployable root. A reusable module states the lowest provider version it " +
	"supports and leaves the ceiling to the root that calls it, so a directory scan does not " +
	"report entries in module directories. A directory is a root when it has a backend or cloud " +
	"block; otherwise it is a module when a directory with a backend, cloud or provider block " +
	"calls it through a ./ or ../ source; otherwise the scan root is a root, and so is a " +
	"directory with a provider block. An explicit file list reports every entry. " +
	"Known misses: (1) a deployable directory with no backend, cloud or provider block that " +
	"nothing calls is taken for a module - scan it on its own; (2) a deployable directory that " +
	"another root in the same scan calls is taken for a module - scan it on its own, or pass its " +
	"files as a list when its callers sit below it; (3) a module's unbounded constraint still " +
	"applies to a root that declares no constraint of its own for that provider - bound the " +
	"provider in every deployable root."

const schemaVersion = "1.0"

// Register adds both families to r. The order is the emission order when two
// rules produce the same level.
func Register(r ctfkit.Registry) {
	ctfkit.MustRegister(r,
		Provider{At: ctfkit.PrePlan},
		ProviderUnpinned{},
		ProviderUnverified{},
		ResourceType{At: ctfkit.PrePlan},
		FloatingRef{},
		FloatingRefUnbounded{},
		Provider{At: ctfkit.PostPlan},
		ResourceType{At: ctfkit.PostPlan},
	)
}

// Provider is ctf.origin.provider: a provider source outside
// Settings.AllowedProviders. At pre_plan it is reported once per source, at
// the first place the configuration names it: a required_providers entry,
// then a provider block, then a resource whose type implies it. At post_plan
// it is reported once per provider instance of configuration.provider_config.
type Provider struct {
	// At is the stage this value runs at: pre_plan or post_plan.
	At ctfkit.Stage
}

// ID implements ctfkit.Analyzer.
func (Provider) ID() string { return ruleProvider }

// Stage implements ctfkit.Analyzer.
func (p Provider) Stage() ctfkit.Stage { return p.At }

// Analyze implements ctfkit.Analyzer.
func (p Provider) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	allow := newAllowlist(in.Settings.AllowedProviders)
	if allow == nil {
		return nil, nil
	}

	if p.At == ctfkit.PostPlan {
		return providerInstances(in, allow)
	}
	if in.Config == nil {
		return nil, nil
	}

	var out ctfkit.Findings
	seen := make(map[string]bool)
	for _, use := range parseConfig(in.Config).providerUses() {
		key := canonical(use.source)
		if seen[key] || allow.permits(use.source) {
			continue
		}
		seen[key] = true
		f, err := newFinding(ruleProvider, ctfkit.LevelWarning, in.Stage,
			fmt.Sprintf(msgProviderUnapproved, use.source), use.location)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// providerInstances is the post_plan half of Provider.
func providerInstances(in ctfkit.AnalyzerInput, allow allowlist) (ctfkit.Findings, error) {
	if in.PlanJSON == nil || in.PlanJSON.Config == nil {
		return nil, nil
	}
	keys := make([]string, 0, len(in.PlanJSON.Config.ProviderConfigs))
	for k := range in.PlanJSON.Config.ProviderConfigs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out ctfkit.Findings
	for _, k := range keys {
		pc := in.PlanJSON.Config.ProviderConfigs[k]
		if pc == nil || pc.FullName == "" || allow.permits(pc.FullName) {
			continue
		}
		address := providerAddress(pc.FullName)
		if pc.Alias != "" {
			address += "." + pc.Alias
		}
		if pc.ModuleAddress != "" {
			address = pc.ModuleAddress + "." + address
		}
		f, err := newFinding(ruleProvider, ctfkit.LevelWarning, in.Stage,
			fmt.Sprintf(msgProviderUnapproved, pc.FullName),
			ctfkit.Location{LogicalLocations: []ctfkit.LogicalLocation{{
				FullyQualifiedName: address, Kind: ctfkit.LogicalLocationProvider,
			}}})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// ProviderUnpinned is ctf.origin.provider_unpinned: a required_providers
// entry with no version constraint, or one with no upper bound.
//
// The upper bound belongs to a deployable root. A reusable module states the
// lowest version it supports and leaves the ceiling to its caller, so when the
// archive asks for classification (a directory scan), an entry in a directory
// that roots.go classifies as a module is never reported. The finding is not
// created at all rather than suppressed, so counts and --fail-on only go down.
type ProviderUnpinned struct{}

// ID implements ctfkit.Analyzer.
func (ProviderUnpinned) ID() string { return ruleProviderUnpinned }

// Stage implements ctfkit.Analyzer.
func (ProviderUnpinned) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze implements ctfkit.Analyzer.
func (ProviderUnpinned) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil || in.Config == nil {
		return nil, err
	}
	var modules map[string]bool
	if in.Config.ClassifyModules {
		modules = tfroots.ModuleDirs(in.Config)
	}
	var out ctfkit.Findings
	for _, rp := range parseConfig(in.Config).required {
		if bounded(rp.version) || modules[rp.dir] {
			continue
		}
		f, err := newFinding(ruleProviderUnpinned, ctfkit.LevelWarning, in.Stage,
			fmt.Sprintf(msgProviderUnpinned, rp.source), rp.location)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// ProviderUnverified is ctf.origin.provider_unverified: a required_providers
// entry that the lock file does not record with hashes.
//
// A configuration with no lock file at all is not reported. That follows the
// recorded fixtures, which carry none and expect no such finding; the spec
// prose says the absence is a finding, and the fixture bytes win.
type ProviderUnverified struct{}

// ID implements ctfkit.Analyzer.
func (ProviderUnverified) ID() string { return ruleProviderUnverified }

// Stage implements ctfkit.Analyzer.
func (ProviderUnverified) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze implements ctfkit.Analyzer.
func (ProviderUnverified) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil || in.Config == nil || in.Config.Lockfile == nil {
		return nil, err
	}
	hashed := make(map[string]bool)
	for _, lp := range in.Config.Lockfile.Providers {
		if len(lp.Hashes) > 0 {
			hashed[canonical(lp.Source)] = true
		}
	}
	var out ctfkit.Findings
	for _, rp := range parseConfig(in.Config).required {
		if hashed[canonical(rp.source)] {
			continue
		}
		f, err := newFinding(ruleProviderUnverified, ctfkit.LevelWarning, in.Stage,
			fmt.Sprintf(msgProviderUnverified, rp.source), rp.location)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// ResourceType is ctf.origin.provider_resource_type: a declared (pre_plan) or
// planned (post_plan) resource type outside Settings.AllowedResources,
// reported once per type at its first occurrence. Data sources are not
// resources and are not checked.
type ResourceType struct {
	// At is the stage this value runs at: pre_plan or post_plan.
	At ctfkit.Stage
}

// ID implements ctfkit.Analyzer.
func (ResourceType) ID() string { return ruleProviderResourceType }

// Stage implements ctfkit.Analyzer.
func (r ResourceType) Stage() ctfkit.Stage { return r.At }

// Analyze implements ctfkit.Analyzer.
func (r ResourceType) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil || len(in.Settings.AllowedResources) == 0 {
		return nil, err
	}
	allowed := make(map[string]bool, len(in.Settings.AllowedResources))
	for _, t := range in.Settings.AllowedResources {
		allowed[t] = true
	}

	var uses []resourceUse
	switch {
	case r.At == ctfkit.PostPlan && in.PlanJSON != nil:
		for _, rc := range in.PlanJSON.ResourceChanges {
			if rc == nil || rc.Mode == "data" {
				continue
			}
			uses = append(uses, resourceUse{typ: rc.Type})
		}
	case r.At == ctfkit.PrePlan && in.Config != nil:
		for _, res := range parseConfig(in.Config).resources {
			uses = append(uses, resourceUse{typ: res.typ, file: res.file, region: res.region})
		}
	}

	var out ctfkit.Findings
	seen := make(map[string]bool)
	for _, u := range uses {
		if allowed[u.typ] || seen[u.typ] {
			continue
		}
		seen[u.typ] = true
		f, err := newFinding(ruleProviderResourceType, ctfkit.LevelError, in.Stage,
			fmt.Sprintf(msgResourceType, u.typ), resourceLocation(u.file, u.region, u.typ))
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// resourceUse is one declared or planned resource type. The finding's subject
// is the type itself, not an instance address: a rule-level exception names
// the type as its resource, and the subject stays put as instances come and go.
type resourceUse struct {
	typ    string
	file   string // empty at post_plan, where the plan carries no file
	region *ctfkit.Region
}

// FloatingRef is ctf.policy.floating_ref: a git or GitHub module source with
// no ref, or a ref that is not a 40-character commit SHA.
//
// Level is warning for every flavor. The recorded fixture 04 fixes warning for
// an absent ref; the spec prose says error for a branch, and one level per
// rule keeps the SARIF default level honest. ctf.preventive is false: whether
// compliance.tf serves an equivalent needs the resource types of the remote
// module, which a pre_plan run does not have.
type FloatingRef struct{}

// ID implements ctfkit.Analyzer.
func (FloatingRef) ID() string { return ruleFloatingRef }

// Stage implements ctfkit.Analyzer.
func (FloatingRef) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze implements ctfkit.Analyzer.
func (FloatingRef) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil || in.Config == nil {
		return nil, err
	}
	var out ctfkit.Findings
	for _, m := range parseConfig(in.Config).modules {
		if !isGitSource(m.source) {
			continue
		}
		ref := gitRef(m.source)
		var text string
		switch {
		case ref == "":
			text = fmt.Sprintf(msgRefAbsent, displaySource(m.source))
		case isCommitSHA(ref):
			continue
		default:
			text = fmt.Sprintf(msgRefMutable, displaySource(m.source), ref)
		}
		f, err := newFinding(ruleFloatingRef, ctfkit.LevelWarning, in.Stage, text, m.location)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// FloatingRefUnbounded is ctf.policy.floating_ref_unbounded: a registry
// module source with no version, or a constraint with no upper bound.
type FloatingRefUnbounded struct{}

// ID implements ctfkit.Analyzer.
func (FloatingRefUnbounded) ID() string { return ruleFloatingRefUnbounded }

// Stage implements ctfkit.Analyzer.
func (FloatingRefUnbounded) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze implements ctfkit.Analyzer.
func (FloatingRefUnbounded) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil || in.Config == nil {
		return nil, err
	}
	var out ctfkit.Findings
	for _, m := range parseConfig(in.Config).modules {
		if !isRegistrySource(m.source) || bounded(m.version) {
			continue
		}
		f, err := newFinding(ruleFloatingRefUnbounded, ctfkit.LevelWarning, in.Stage,
			fmt.Sprintf(msgRegistryUnbounded, displaySource(m.source)), m.location)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// newFinding builds one finding of either family: zero controls, framework
// agnostic, not preventive.
func newFinding(ruleID, level string, stage ctfkit.Stage, text string, loc ctfkit.Location) (ctfkit.Finding, error) {
	return ctfkit.NewFinding(ruleID, level, ctfkit.KindFail,
		ctfkit.Message{Text: text},
		[]ctfkit.Location{loc},
		ctfkit.Properties{
			Schema:     schemaVersion,
			Stage:      stage,
			ControlIDs: []ctfkit.ControlID{},
			Frameworks: []ctfkit.FrameworkClauses{},
		})
}

// bounded reports whether a version constraint caps the version from above:
// an exact version, "=", "~>", "<" or "<=" in any of its comma-separated
// parts. Empty, ">", ">=" and "!=" alone leave it open.
func bounded(constraint string) bool {
	for _, part := range strings.Split(constraint, ",") {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
		case strings.HasPrefix(part, ">"), strings.HasPrefix(part, "!="):
		default:
			return true
		}
	}
	return false
}
