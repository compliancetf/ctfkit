// Package tagging implements ctf.policy.tagging: the post_plan rules that hold
// every planned, taggable resource to the organization's tag policy, read
// from Settings.Tags.
//
// Three rule ids, one Analyzer value each, as the SDK contract requires:
//
//   - ctf.policy.tagging: a required key is absent from the effective tags.
//   - ctf.policy.tagging_value: a key is present with a value the policy's
//     allowed set or pattern rejects.
//   - ctf.policy.tagging_unresolved: the value, or the whole tags map, is not
//     known until apply, so the rule cannot judge it and says so.
//
// Each rule emits at most one finding per resource address, naming every key
// concerned in alphabetical order. Tags are org policy, not a catalog
// control: findings carry no control id, no framework and ctf.preventive
// false. A tag value never reaches a finding; the message names keys and, for
// a value rule, the policy's own allowed values or pattern.
//
// The values are stateless, so the family is pure and safe to run
// concurrently.
package tagging

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/parser"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/internal/rulepack"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The rule ids of the family. The missing-tag rule is the bare family id
// because the recorded 08-missing-tags fixture says so.
const (
	ruleMissing    = "ctf.policy.tagging"
	ruleValue      = "ctf.policy.tagging_value"
	ruleUnresolved = "ctf.policy.tagging_unresolved"
)

// Descriptors returns the tool.driver.rules entries of the family, for the
// runner to hand to the SARIF renderer. The texts of the rule ids a recorded
// fixture carries are that fixture's bytes.
func Descriptors() []sarif.RuleDescriptor {
	return []sarif.RuleDescriptor{
		{
			ID:               ruleMissing,
			ShortDescription: "A resource is missing tags the organisation requires", //nolint:misspell // recorded fixture bytes
			Level:            ctfkit.LevelWarning,
		},
		{
			ID:               ruleValue,
			ShortDescription: "A resource has tag values the organization policy does not allow",
			Level:            ctfkit.LevelWarning,
		},
		{
			ID:               ruleUnresolved,
			ShortDescription: "A resource has tags whose values are not known until apply",
			Level:            ctfkit.LevelNote,
		},
	}
}

// schemaVersion is the findings format version every finding states.
const schemaVersion = "1.0"

// Message templates, formatted with resource addresses, tag keys and the
// policy's own allowed values or pattern, never with a value from the plan.
const (
	msgMissing    = "%s is missing required tags %s"
	msgValue      = "%s has tag values the policy does not allow: %s"
	msgUnresolved = "%s has tags whose values are not known until apply: %s"
)

// Register adds every rule of the family to r, at post_plan.
func Register(r ctfkit.Registry) {
	ctfkit.MustRegister(r, Missing{}, Value{}, Unresolved{})
}

// Missing reports a resource whose effective tags lack a required key.
type Missing struct{}

// ID returns the rule id.
func (Missing) ID() string { return ruleMissing }

// Stage returns post_plan.
func (Missing) Stage() ctfkit.Stage { return ctfkit.PostPlan }

// Analyze reports one finding per resource missing at least one required key.
func (r Missing) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return emit(ctx, in, r.ID(), ctfkit.LevelWarning, ctfkit.KindFail, msgMissing,
		func(v verdict) []string { return v.missing })
}

// Value reports a resource with a tag value outside the policy.
type Value struct{}

// ID returns the rule id.
func (Value) ID() string { return ruleValue }

// Stage returns post_plan.
func (Value) Stage() ctfkit.Stage { return ctfkit.PostPlan }

// Analyze reports one finding per resource with at least one rejected value.
func (r Value) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return emit(ctx, in, r.ID(), ctfkit.LevelWarning, ctfkit.KindFail, msgValue,
		func(v verdict) []string { return v.rejected })
}

// Unresolved reports a resource whose tags cannot be judged before apply.
type Unresolved struct{}

// ID returns the rule id.
func (Unresolved) ID() string { return ruleUnresolved }

// Stage returns post_plan.
func (Unresolved) Stage() ctfkit.Stage { return ctfkit.PostPlan }

// Analyze reports one finding per resource with at least one unjudged key.
func (r Unresolved) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return emit(ctx, in, r.ID(), ctfkit.LevelNote, ctfkit.KindOpen, msgUnresolved,
		func(v verdict) []string { return v.unresolved })
}

// verdict is what the policy says about one resource. Each list is sorted.
type verdict struct {
	address    string
	missing    []string
	rejected   []string
	unresolved []string
}

func emit(ctx context.Context, in ctfkit.AnalyzerInput, ruleID, level, kind, template string,
	pick func(verdict) []string,
) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(in.Settings.Tags) == 0 || in.PlanJSON == nil {
		return nil, nil
	}

	patterns, err := compile(in.Settings.Tags)
	if err != nil {
		return nil, err
	}
	var lock *ctfkit.Lockfile
	if in.Config != nil {
		lock = in.Config.Lockfile
	}
	verdicts := evaluate(in.PlanJSON, lock, in.Settings.Tags, patterns)
	files := rootResourceFiles(in.Config)

	var findings ctfkit.Findings
	for _, v := range verdicts {
		keys := pick(v)
		if len(keys) == 0 {
			continue
		}
		f, buildErr := ctfkit.NewFinding(ruleID, level, kind,
			ctfkit.Message{Text: fmt.Sprintf(template, v.address, strings.Join(keys, ", "))},
			[]ctfkit.Location{location(v.address, files)},
			ctfkit.Properties{Schema: schemaVersion, Stage: ctfkit.PostPlan})
		if buildErr != nil {
			return nil, buildErr
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// compile turns each rule's Pattern into a regexp. The loader has already
// rejected a pattern that does not compile, so an error here is a broken
// invariant and the analyzer reports it as its own failure.
func compile(rules []ctfkit.TagRule) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, len(rules))
	for i, rule := range rules {
		if rule.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("tagging: tag %s has a pattern that does not compile: %w", rule.Key, err)
		}
		out[i] = re
	}
	return out, nil
}

// evaluate judges every managed resource the plan creates, updates or
// replaces, in plan order. Which attributes hold a resource's tags is its
// provider's rule pack fact. A resource whose planned values have no tags
// attribute is out of scope.
func evaluate(plan *tfjson.Plan, lock *ctfkit.Lockfile, rules []ctfkit.TagRule, patterns []*regexp.Regexp) []verdict {
	configs := providerConfigByResource(plan)
	packs := rulepack.Embedded()

	var out []verdict
	for _, rc := range plan.ResourceChanges {
		if rc == nil || rc.Change == nil || rc.Mode != tfjson.ManagedResourceMode {
			continue
		}
		actions := rc.Change.Actions
		if !actions.Create() && !actions.Update() && !actions.Replace() {
			continue
		}
		attrs := packs.TagsFor(rc.ProviderName, lock)
		t, ok := effectiveTags(rc.Change, constantDefaultTags(configs[configAddress(rc.Address)], attrs.ProviderDefault), attrs)
		if !ok {
			continue
		}

		v := verdict{address: rc.Address}
		for i, rule := range rules {
			if len(rule.ResourceTypes) > 0 && !slices.Contains(rule.ResourceTypes, rc.Type) {
				continue
			}
			judge(&v, rule, patterns[i], t)
		}
		sort.Strings(v.missing)
		sort.Strings(v.rejected)
		sort.Strings(v.unresolved)
		out = append(out, v)
	}
	return out
}

// tags is the effective tag set of one resource.
type tags struct {
	// values holds every key whose value is known.
	values map[string]string
	// unknownKeys holds keys present with a value not known until apply.
	unknownKeys map[string]bool
	// opaque is set when the resource's own tags map is unknown as a whole,
	// so which keys it will hold is not known either.
	opaque bool
}

func judge(v *verdict, rule ctfkit.TagRule, pattern *regexp.Regexp, t tags) {
	value, known := t.values[rule.Key]
	constrained := len(rule.AllowedValues) > 0 || pattern != nil

	switch {
	case known:
		if len(rule.AllowedValues) > 0 && !slices.Contains(rule.AllowedValues, value) {
			v.rejected = append(v.rejected,
				fmt.Sprintf("%s (must be one of %s)", rule.Key, strings.Join(rule.AllowedValues, ", ")))
		}
		if pattern != nil && !pattern.MatchString(value) {
			v.rejected = append(v.rejected, fmt.Sprintf("%s (must match %s)", rule.Key, rule.Pattern))
		}
	case t.unknownKeys[rule.Key]:
		if constrained {
			v.unresolved = append(v.unresolved, rule.Key)
		}
	case t.opaque:
		if rule.Required || constrained {
			v.unresolved = append(v.unresolved, rule.Key)
		}
	case rule.Required:
		v.missing = append(v.missing, rule.Key)
	}
}

// effectiveTags merges the provider's default tags under the resource's own
// tags, then adds the effective map when the provider already resolved it. It
// reports false for a resource with no tags attribute.
//
// The effective map unknown as a whole is ignored rather than treated as
// opaque: a provider marks it unknown on every create, and it is derived from
// the two inputs merged here.
func effectiveTags(change *tfjson.Change, defaults map[string]string, attrs rulepack.Tags) (tags, bool) {
	after, _ := change.After.(map[string]any)
	unknown, _ := change.AfterUnknown.(map[string]any)

	own := attrs.Attribute
	_, hasTags := after[own]
	_, hasEffective := after[attrs.Effective]
	_, tagsUnknown := unknown[own]
	if !hasTags && (attrs.Effective == "" || !hasEffective) && !tagsUnknown {
		return tags{}, false
	}

	t := tags{values: make(map[string]string), unknownKeys: make(map[string]bool)}
	for k, val := range defaults {
		t.values[k] = val
	}
	for _, attr := range []string{own, attrs.Effective} {
		if attr == "" {
			continue
		}
		m, _ := after[attr].(map[string]any)
		for k, val := range m {
			if s, ok := val.(string); ok {
				t.values[k] = s
			}
		}
		switch u := unknown[attr].(type) {
		case bool:
			if u && attr == own {
				t.opaque = true
			}
		case map[string]any:
			for k, isUnknown := range u {
				b, ok := isUnknown.(bool)
				if !ok || !b {
					continue
				}
				// An unknown own tag overrides a provider default; an unknown
				// effective entry never hides a value already known.
				if _, known := t.values[k]; attr == own || !known {
					delete(t.values, k)
					t.unknownKeys[k] = true
				}
			}
		}
	}
	return t, true
}

// providerConfigByResource maps each configuration resource address to the
// provider configuration it uses.
func providerConfigByResource(plan *tfjson.Plan) map[string]*tfjson.ProviderConfig {
	out := make(map[string]*tfjson.ProviderConfig)
	if plan.Config == nil || plan.Config.RootModule == nil {
		return out
	}

	var walk func(prefix string, m *tfjson.ConfigModule)
	walk = func(prefix string, m *tfjson.ConfigModule) {
		for _, r := range m.Resources {
			if r == nil {
				continue
			}
			if pc := plan.Config.ProviderConfigs[r.ProviderConfigKey]; pc != nil {
				out[prefix+r.Address] = pc
			}
		}
		for name, call := range m.ModuleCalls {
			if call != nil && call.Module != nil {
				walk(prefix+"module."+name+".", call.Module)
			}
		}
	}
	walk("", plan.Config.RootModule)
	return out
}

// constantDefaultTags reads the constant default tags of a provider
// configuration at path, dot separated through nested blocks, for example
// "default_tags.tags". A value that is not a constant is left out: the
// effective map carries it once the provider resolves it at plan time.
func constantDefaultTags(pc *tfjson.ProviderConfig, path string) map[string]string {
	if pc == nil || path == "" {
		return nil
	}
	steps := strings.Split(path, ".")
	e := pc.Expressions[steps[0]]
	for _, step := range steps[1:] {
		if e == nil || e.ExpressionData == nil || len(e.NestedBlocks) == 0 {
			return nil
		}
		e = e.NestedBlocks[0][step]
	}
	if e == nil || e.ExpressionData == nil {
		return nil
	}
	m, _ := e.ConstantValue.(map[string]any)
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// instanceKey matches the instance key of one address step, [0] or ["a"].
var instanceKey = regexp.MustCompile(`\[[^\]]*\]`)

// configAddress is a planned address with its instance keys removed, which
// is how the configuration names the same resource.
func configAddress(address string) string {
	return instanceKey.ReplaceAllString(address, "")
}

// rootResourceFiles maps "type.name" of each resource block declared directly
// in the root module to the file that declares it, in either syntax. A file
// that does not parse contributes the blocks that did parse.
func rootResourceFiles(config *ctfkit.ConfigArchive) map[string]ctfkit.PhysicalLocation {
	out := make(map[string]ctfkit.PhysicalLocation)
	if config == nil {
		return out
	}
	for _, file := range parser.PrimaryFiles(config.Files) {
		if strings.Contains(file.Path, "/") {
			continue
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

// location names the resource and, for a root-module resource whose block
// was found, the file and lines that declare it.
// ponytail: resources inside modules get the address only; anchoring them
// needs the module call's source directory.
func location(address string, files map[string]ctfkit.PhysicalLocation) ctfkit.Location {
	loc := ctfkit.Location{LogicalLocations: []ctfkit.LogicalLocation{{
		FullyQualifiedName: address, Kind: ctfkit.LogicalLocationResource,
	}}}
	if at, ok := files[configAddress(address)]; ok {
		loc.PhysicalLocation = &at
	}
	return loc
}
