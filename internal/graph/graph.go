// Package graph implements ctf.graph.companion, the post_plan analyzer that
// decides the graph controls of a bundle: whether each target resource has
// a linked companion resource, such as a bucket and its public access block.
//
// Linkage is decided only by known, scope-compatible identity equality. Plan
// JSON references never prove a link, whatever their shape: a companion
// written as a direct reference, as format() over one, or as a literal is
// judged by the planned value alone. Anything that cannot be decided from
// values is not_evaluable with a reason, never "no edge":
//
//	link value or target identity unknown, or null   unknown_reference
//	value in another form of the identity (ARN, name) identity_alias
//	value with a wildcard (* or ?)                    wildcard
//	value in no form of the identity catalog          catalog_miss
//	scope not established                             ambiguous_reference
//	target attributes naming two objects              identity_conflict
//
// A target fails companion_present only when every candidate companion is
// decided "not linked"; one not_evaluable candidate makes the target
// not_evaluable, even next to a linked one. The identity catalog is the rule
// pack's identities.yaml. Graph controls come from the verified bundle, so
// the analyzer is built with them; the gate wires it.
package graph

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/rulepack"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// RuleID is the analyzer's rule id.
const RuleID = "ctf.graph.companion"

// Graph rules, as bundle 2.0 spells them.
const (
	RuleCompanionPresent         = "companion_present"
	RuleCompanionAbsentForbidden = "companion_absent_forbidden"
)

// Decision results.
const (
	ResultPass         = "pass"
	ResultFail         = "fail"
	ResultNotEvaluable = "not_evaluable"
)

// not_evaluable reasons, as verdict-1 spells them.
const (
	ReasonUnknownReference   = "unknown_reference"
	ReasonIdentityAlias      = "identity_alias"
	ReasonWildcard           = "wildcard"
	ReasonCatalogMiss        = "catalog_miss"
	ReasonAmbiguousReference = "ambiguous_reference"
	ReasonIdentityConflict   = "identity_conflict"
)

// Control is the part of a bundle 2.0 graph control (kind graph) the
// analyzer reads. Its json names are those of the provider's controls.json,
// so a control decodes from bundle bytes unchanged; other members are
// ignored.
type Control struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
	Graph        struct {
		Rule          string   `json:"rule"`
		CompanionType string   `json:"companion_type"`
		LinkAttr      string   `json:"link_attr"`
		TargetAttrs   []string `json:"target_attrs"`
		CompanionExpr *string  `json:"companion_expr"`
	} `json:"graph"`
}

// Decision is the result of one graph control for one target instance.
// Reason is set only when Result is not_evaluable.
type Decision struct {
	Address string `json:"address"`
	Deposed string `json:"deposed,omitempty"` // a deposed object's key (deletion guards)
	Control string `json:"control"`
	Version string `json:"version"`
	Result  string `json:"result"`
	Reason  string `json:"reason,omitempty"`
	// Action is the deciding control's action; controls may share an id
	// across versions and resource types, so it travels with the decision.
	Action string `json:"-"`
}

// Companion is the ctf.graph.companion analyzer over a set of graph
// controls. The value is immutable, so it is pure and safe to run
// concurrently.
type Companion struct {
	Controls []Control
}

// ID returns the rule id.
func (Companion) ID() string { return RuleID }

// Stage returns post_plan.
func (Companion) Stage() ctfkit.Stage { return ctfkit.PostPlan }

// Analyze emits one finding per decision: pass as a note, fail and
// not_evaluable at error, or warning for a control whose action is warn.
func (c Companion) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if in.PlanJSON == nil {
		return nil, nil
	}
	var lock *ctfkit.Lockfile
	if in.Config != nil {
		lock = in.Config.Lockfile
	}
	decisions, err := Evaluate(in.PlanJSON, lock, c.Controls)
	if err != nil {
		return nil, err
	}
	return Findings(decisions)
}

// Findings are decisions as SDK findings, one each: pass as a note, fail
// and not_evaluable at error, or warning for a control whose action is warn.
func Findings(decisions []Decision) (ctfkit.Findings, error) {
	var findings ctfkit.Findings
	for _, d := range decisions {
		addr := d.Address
		if d.Deposed != "" {
			addr += " deposed " + d.Deposed
		}
		level, kind, text := ctfkit.LevelNote, ctfkit.KindPass, fmt.Sprintf("%s: %s %s", addr, d.Control, d.Result)
		if d.Result != ResultPass {
			level, kind = ctfkit.LevelError, ctfkit.KindFail
			if d.Action == "warn" {
				level = ctfkit.LevelWarning
			}
		}
		if d.Result == ResultNotEvaluable {
			kind, text = ctfkit.KindOpen, text+" ("+d.Reason+")"
		}
		f, err := ctfkit.NewFinding(RuleID, level, kind, ctfkit.Message{Text: text},
			[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{{
				FullyQualifiedName: d.Address, Kind: ctfkit.LogicalLocationResource,
			}}}},
			ctfkit.Properties{Schema: "1.0", Stage: ctfkit.PostPlan})
		if err != nil {
			return nil, err
		}
		f.Discriminator = d.Control
		findings = append(findings, f)
	}
	return findings, nil
}

// Evaluate decides every companion_present control for every target instance
// the plan does not only delete, sorted by address, control and version.
// companion_absent_forbidden is a deletion guard the verdict builder decides
// on the full plan, so it is skipped here. A control Evaluate cannot judge is
// an error, never a pass.
func Evaluate(plan *tfjson.Plan, lock *ctfkit.Lockfile, controls []Control) ([]Decision, error) {
	if plan == nil {
		return nil, nil
	}
	instances := planned(plan, lock)
	var out []Decision
	for _, ctl := range controls {
		g := ctl.Graph
		switch {
		case g.Rule == RuleCompanionAbsentForbidden:
			continue
		case g.Rule != RuleCompanionPresent:
			return nil, fmt.Errorf("graph: control %s: unknown rule %q", ctl.ID, g.Rule)
		case g.CompanionExpr != nil:
			// shortcut: no CEL engine in ctfkit yet; a companion_expr control
			// fails the run (exit 2) until one evaluates it.
			return nil, fmt.Errorf("graph: control %s: companion_expr is not supported", ctl.ID)
		case ctl.ResourceType == "" || g.CompanionType == "" || g.LinkAttr == "" || len(g.TargetAttrs) == 0:
			return nil, fmt.Errorf("graph: control %s: resource_type, companion_type, link_attr and target_attrs are required", ctl.ID)
		}
		var candidates []instance
		for _, in := range instances {
			if in.typ == g.CompanionType {
				candidates = append(candidates, in)
			}
		}
		for _, target := range instances {
			if target.typ != ctl.ResourceType {
				continue
			}
			result, reason := decide(target, candidates, g.LinkAttr, g.TargetAttrs)
			out = append(out, Decision{Address: target.address, Control: ctl.ID, Version: ctl.Version, Result: result, Reason: reason, Action: ctl.Action})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		if a.Control != b.Control {
			return a.Control < b.Control
		}
		return a.Version < b.Version
	})
	return out, nil
}

// instance is one managed resource instance the plan keeps.
type instance struct {
	address, typ string
	deposed      string // deposed object key, deleted instances only
	configKey    string // provider_config_key of its configuration block
	provider     *tfjson.ProviderConfig
	after        map[string]any
	unknown      map[string]any
	catalog      *rulepack.Identities
}

// planned returns every managed instance whose planned action keeps it:
// create, update, replace or no-op, in address order.
func planned(plan *tfjson.Plan, lock *ctfkit.Lockfile) []instance {
	keys := configKeys(plan)
	var providers map[string]*tfjson.ProviderConfig
	if plan.Config != nil {
		providers = plan.Config.ProviderConfigs
	}
	packs := rulepack.Embedded()
	var out []instance
	for _, rc := range plan.ResourceChanges {
		if rc == nil || rc.Change == nil || rc.Mode != tfjson.ManagedResourceMode {
			continue
		}
		if a := rc.Change.Actions; !a.Create() && !a.Update() && !a.Replace() && !a.NoOp() {
			continue
		}
		in := instance{address: rc.Address, typ: rc.Type, configKey: keys[configAddress(rc.Address)]}
		in.provider = providers[in.configKey]
		in.after, _ = rc.Change.After.(map[string]any)
		in.unknown, _ = rc.Change.AfterUnknown.(map[string]any)
		in.catalog = catalogFor(packs, rc.ProviderName, lock)
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].address < out[j].address })
	return out
}

// catalogFor is the identity catalog of a resource's provider. The
// compliance.tf provider serves the hashicorp/aws resources unchanged, so
// its resources take the hashicorp/aws catalog.
func catalogFor(packs *rulepack.Set, provider string, lock *ctfkit.Lockfile) *rulepack.Identities {
	if strings.HasSuffix(strings.ToLower(provider), "/compliancetf/aws") {
		provider = "registry.terraform.io/hashicorp/aws"
	}
	if p := packs.Select(provider, lock); p != nil {
		return p.Identities
	}
	return nil
}

// value is one attribute value classified against the identity catalog.
type value struct {
	form, text string
	reason     string // set when the value cannot take part in a comparison
}

// classify reads attribute attr of an instance. Null and unknown are both
// unknown_reference: a reference that resolves to no value proves nothing.
func (in instance) classify(attr string) value {
	if in.catalog.Forms(in.typ, attr) == nil {
		return value{reason: ReasonCatalogMiss}
	}
	if u, _ := in.unknown[attr].(bool); u {
		return value{reason: ReasonUnknownReference}
	}
	s, ok := in.after[attr].(string)
	switch {
	case !ok:
		return value{reason: ReasonUnknownReference}
	case strings.ContainsAny(s, "*?"):
		return value{reason: ReasonWildcard}
	}
	form, ok := in.catalog.Classify(in.typ, attr, s)
	if !ok {
		return value{reason: ReasonCatalogMiss}
	}
	return value{form: form, text: s}
}

// identity is a target's identity: per form, its one known value, and the
// forms whose attributes are all unknown.
type identity struct {
	known   map[string]string
	pending map[string]bool
}

// targetIdentity reads the target attributes. A wildcard, a catalog miss or
// two known values of one form make the whole target undecidable.
func targetIdentity(target instance, attrs []string) (identity, string) {
	id := identity{known: map[string]string{}, pending: map[string]bool{}}
	for _, attr := range attrs {
		v := target.classify(attr)
		switch {
		case v.reason == ReasonUnknownReference:
			// Null target attributes are absent; unknown ones may still name
			// the object in their declared form.
			if u, _ := target.unknown[attr].(bool); u {
				for _, f := range target.catalog.Forms(target.typ, attr) {
					id.pending[f] = true
				}
			}
		case v.reason != "":
			return id, v.reason
		case id.known[v.form] != v.text && hasForm(id.known, v.form):
			return id, ReasonIdentityConflict
		default:
			id.known[v.form] = v.text
		}
	}
	return id, ""
}

func hasForm(known map[string]string, form string) bool {
	_, ok := known[form]
	return ok
}

// decide aggregates every candidate for one target.
func decide(target instance, candidates []instance, linkAttr string, targetAttrs []string) (string, string) {
	if len(candidates) == 0 {
		return ResultFail, ""
	}
	id, reason := targetIdentity(target, targetAttrs)
	if reason != "" {
		return ResultNotEvaluable, reason
	}
	linked := false
	for _, c := range candidates {
		switch r := link(target, id, c, linkAttr); r {
		case "linked":
			linked = true
		case "":
		default:
			return ResultNotEvaluable, r
		}
	}
	if linked {
		return ResultPass, ""
	}
	return ResultFail, ""
}

// link compares one candidate with the target: "linked", "" for not linked,
// or a not_evaluable reason.
func link(target instance, id identity, c instance, linkAttr string) string {
	v := c.classify(linkAttr)
	if v.reason != "" {
		return v.reason
	}
	known, ok := id.known[v.form]
	switch {
	case ok && known != v.text:
		// Two values of one form are two objects, in any scope.
		return ""
	case ok:
		return scope(target, c)
	case id.pending[v.form] || len(id.known) == 0:
		return ReasonUnknownReference
	default:
		return ReasonIdentityAlias
	}
}

// scope reports "linked" when the two instances share a provider
// configuration and agree on every scope attribute, "" when a scope
// attribute is known on both sides and differs, and ambiguous_reference when
// the scope cannot be established.
//
// Terraform resolves module calls in the plan JSON: a resource whose module
// inherits a default configuration or is passed one (providers = {...})
// carries the source configuration's key, through any depth of nesting and
// for every count or for_each instance of the module. So one key present in
// provider_config is one configuration. A key absent from provider_config
// (unresolved, as older Terraform wrote module keys) or a configuration
// iterated with for_each (its arguments reference each.*) is not established.
// Two different keys are never proved to share an account: identical
// arguments can still resolve different credentials.
func scope(target, c instance) string {
	if target.configKey == "" || target.configKey != c.configKey || target.provider == nil || iterated(target.provider.Expressions) {
		return ReasonAmbiguousReference
	}
	for _, attr := range target.catalog.Scope {
		tu, _ := target.unknown[attr].(bool)
		cu, _ := c.unknown[attr].(bool)
		ta, tok := target.after[attr].(string)
		cb, cok := c.after[attr].(string)
		switch {
		case tu || cu:
			return ReasonAmbiguousReference
		case target.after[attr] == nil && c.after[attr] == nil:
		case !tok || !cok:
			return ReasonAmbiguousReference
		case ta != cb:
			return ""
		}
	}
	return "linked"
}

// iterated reports whether provider configuration arguments reference
// each.*, the mark of an OpenTofu provider for_each whose instances share one
// key.
//
// shortcut: an iterated configuration whose arguments never use each.* is
// not visible in plan JSON and counts as one configuration; its instances
// then have identical arguments.
func iterated(exprs map[string]*tfjson.Expression) bool {
	for _, e := range exprs {
		if e == nil || e.ExpressionData == nil {
			continue
		}
		for _, r := range e.References {
			if r == "each" || strings.HasPrefix(r, "each.") {
				return true
			}
		}
		for _, nested := range e.NestedBlocks {
			if iterated(nested) {
				return true
			}
		}
	}
	return false
}

// configKeys maps each configuration resource address to the provider
// configuration key it uses.
func configKeys(plan *tfjson.Plan) map[string]string {
	out := map[string]string{}
	if plan.Config == nil || plan.Config.RootModule == nil {
		return out
	}
	var walk func(prefix string, m *tfjson.ConfigModule)
	walk = func(prefix string, m *tfjson.ConfigModule) {
		for _, r := range m.Resources {
			if r != nil {
				out[prefix+r.Address] = r.ProviderConfigKey
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

// instanceKey matches the instance key of one address step, [0] or ["a"],
// including a string key that holds "]" or an escaped quote.
var instanceKey = regexp.MustCompile(`\[(?:"(?:[^"\\]|\\.)*"|[^\]"]*)\]`)

// configAddress is a planned address with its instance keys removed.
func configAddress(address string) string {
	return instanceKey.ReplaceAllString(address, "")
}
