package sensitivechange

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/rulepack"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The class names rule files declare, each the suffix of one rule id.
var classes = []string{"public_exposure", "wildcard_iam", "audit_log_removal", "encryption_disablement", "destructive_stateful"}

// Message templates a predicate uses when its rule gives none. {address} is
// the resource address, {attributes} the attribute names concerned and {kind}
// the word the rule's kinds give the resource type. No template takes a value.
const (
	msgTurnsOff       = "{address} turns {attributes} from true to false"
	msgTurnsOn        = "{address} turns {attributes} from false to true"
	msgRemoves        = "{address} removes {attributes}"
	msgNarrows        = "{address} narrows {attributes} to a strict subset of its prior value"
	msgShortens       = "{address} shortens {attributes}"
	msgOpenIngress    = "{address} opens ingress to any address in {attributes}"
	msgDeleted        = "{address} is deleted, which destroys the {kind} and the data it holds"
	msgReplacedBefore = "{address} is replaced, which deletes the existing {kind} before the new one is created"
	msgReplacedAfter  = "{address} is replaced, which deletes the existing {kind} after the new one is created"
)

// predicate returns the hits of one rule on one resource change.
type predicate func(c change, r *rulepack.Rule) []hit

// predicates are the generic checks a rule names; each reads only
// change.before, change.after and the rule's own arguments.
var predicates = map[string]predicate{
	"turned_off":    turnedOff,
	"turned_on":     turnedOn,
	"removed":       removed,
	"block_removed": blockRemoved,
	"narrowed":      narrowed,
	"shortened":     shortened,
	"deleted":       deleted,
	"replaced":      replaced,
	"value_in":      valueIn,
	"open_cidr":     openCIDR,
}

// dialects are the provider plug-ins, by the name a pack's dialect field
// gives: checks whose semantics a rule file cannot express, such as a
// provider's policy language.
var dialects = map[string]map[string]predicate{}

// wholeResource are the predicates about the resource as a whole. Once one
// fires, the class has said what it has to say about that resource.
var wholeResource = []string{"deleted", "replaced"}

// predicateFor finds a rule's predicate among the generic ones and the
// pack's dialect.
func predicateFor(p *rulepack.Pack, name string) predicate {
	if f, ok := predicates[name]; ok {
		return f
	}
	return dialects[p.Dialect][name]
}

// packs is the embedded pack set, each pack checked against the predicates
// this build has. A pack naming a predicate or argument that does not exist
// is a broken build, not a quiet rule that never fires.
var packs = sync.OnceValue(func() *rulepack.Set {
	s := rulepack.Embedded()
	for _, p := range s.Packs() {
		if err := checkPack(p); err != nil {
			panic(fmt.Sprintf("rule pack %s: %v", p.Name, err))
		}
	}
	return s
})

// evaluate runs every rule of one class that applies to the change's
// resource type, in pack order.
func evaluate(p *rulepack.Pack, class string, c change) []hit {
	var out []hit
	for _, r := range p.For(class, c.rc.Type) {
		if !c.matches(r.When) {
			continue
		}
		hits := predicateFor(p, r.Predicate)(c, r)
		out = append(out, hits...)
		if len(hits) > 0 && slices.Contains(wholeResource, r.Predicate) {
			break
		}
	}
	return out
}

// change is one resource_changes entry, read through untyped maps.
type change struct {
	rc      *tfjson.ResourceChange
	actions tfjson.Actions
	before  map[string]any
	after   map[string]any
	unknown map[string]any
}

func newChange(rc *tfjson.ResourceChange) change {
	before, _ := rc.Change.Before.(map[string]any)
	after, _ := rc.Change.After.(map[string]any)
	unknown, _ := rc.Change.AfterUnknown.(map[string]any)
	return change{rc: rc, actions: rc.Change.Actions, before: before, after: after, unknown: unknown}
}

// matches reports whether the planned object has every value when lists.
func (c change) matches(when map[string]string) bool {
	for attr, want := range when {
		if got, ok := c.after[attr].(string); !ok || got != want {
			return false
		}
	}
	return true
}

// deletes reports whether the actions contain a delete, a replacement included.
func (c change) deletes() bool { return c.actions.Delete() || c.actions.Replace() }

// isUnknown reports whether any part of an attribute is not known until apply.
func (c change) isUnknown(attr string) bool { return holdsTrue(c.unknown[attr]) }

func holdsTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case []any:
		return slices.ContainsFunc(x, holdsTrue)
	case map[string]any:
		for _, e := range x {
			if holdsTrue(e) {
				return true
			}
		}
	}
	return false
}

// newHit is a hit of rule r about one attribute, or about the whole resource
// when attr is empty. The template's {kind} is resolved here, since it
// belongs to the resource type.
func newHit(c change, r *rulepack.Rule, level, template, attr string) hit {
	template = strings.ReplaceAll(template, "{kind}", r.Kind(c.rc.Type))
	return hit{level: level, template: template, attr: attr}
}

// message is the rule's own template, or the predicate's when it has none.
func message(r *rulepack.Rule, fallback string) string {
	if r.Message != "" {
		return r.Message
	}
	return fallback
}

// ---- generic predicates ----

// turnedOff reports an attribute true in before and false in after. With
// or_removed it also reports one true in before and absent or null in after,
// as a removal. With as_string the strings "true" and "false" count as well
// as the booleans: an attribute that became a string in one provider major
// is still read correctly in a plan made with the major before it, which
// the same pack judges when the lock file pins a major with no pack.
func turnedOff(c change, r *rulepack.Rule) []hit {
	a := r.Attribute
	is := func(v any, b bool) bool {
		return v == b || (r.AsString && v == strconv.FormatBool(b))
	}
	if !is(c.before[a], true) || c.after == nil || is(c.after[a], true) || c.isUnknown(a) {
		return nil
	}
	if is(c.after[a], false) {
		return []hit{newHit(c, r, r.Level, message(r, msgTurnsOff), a)}
	}
	if r.OrRemoved {
		return []hit{newHit(c, r, r.Level, msgRemoves, a)}
	}
	return nil
}

// turnedOn reports an attribute false or absent in before and true in after.
func turnedOn(c change, r *rulepack.Rule) []hit {
	a := r.Attribute
	if c.before[a] != true && c.after[a] == true && !c.isUnknown(a) {
		return []hit{newHit(c, r, r.Level, message(r, msgTurnsOn), a)}
	}
	return nil
}

// removed reports an attribute set in before and empty in after.
func removed(c change, r *rulepack.Rule) []hit {
	a := r.Attribute
	if !isEmpty(c.before[a]) && c.after != nil && isEmpty(c.after[a]) && !c.isUnknown(a) {
		return []hit{newHit(c, r, r.Level, message(r, msgRemoves), a)}
	}
	return nil
}

// blockRemoved reports a nested block present in before and absent in after.
// With flag it reports a block whose first element has flag true in before
// and not in after.
func blockRemoved(c change, r *rulepack.Rule) []hit {
	a := r.Attribute
	var had, has bool
	if r.Flag == "" {
		had, has = len(list(c.before[a])) > 0, len(list(c.after[a])) > 0
	} else {
		had, has = obj(first(c.before[a]))[r.Flag] == true, obj(first(c.after[a]))[r.Flag] == true
	}
	if had && c.after != nil && !has && !c.isUnknown(a) {
		return []hit{newHit(c, r, r.Level, message(r, msgRemoves), a)}
	}
	return nil
}

// narrowed reports a list attribute whose after is a strict subset of before.
func narrowed(c change, r *rulepack.Rule) []hit {
	a := r.Attribute
	if c.after == nil || c.isUnknown(a) {
		return nil
	}
	before, after := strs(c.before[a]), strs(c.after[a])
	for _, v := range after {
		if !slices.Contains(before, v) {
			return nil
		}
	}
	for _, v := range before {
		if !slices.Contains(after, v) {
			return []hit{newHit(c, r, r.Level, message(r, msgNarrows), a)}
		}
	}
	return nil
}

// shortened reports a number that decreases. With zero_is_unlimited, 0 means
// no limit: a move away from 0 is a decrease and a move to 0 is not.
func shortened(c change, r *rulepack.Rule) []hit {
	a := r.Attribute
	before, okBefore := c.before[a].(float64)
	after, okAfter := c.after[a].(float64)
	if !okBefore || !okAfter || c.isUnknown(a) {
		return nil
	}
	shorter := after < before
	if r.ZeroIsUnlimited {
		shorter = after != 0 && (before == 0 || after < before)
	}
	if shorter {
		return []hit{newHit(c, r, r.Level, message(r, msgShortens), a)}
	}
	return nil
}

// deleted reports a resource the plan deletes, or replaces, as a whole.
func deleted(c change, r *rulepack.Rule) []hit {
	if c.deletes() {
		return []hit{newHit(c, r, r.Level, message(r, msgDeleted), "")}
	}
	return nil
}

// replaced reports a resource the plan replaces, naming the attributes that
// force the replacement. They name the finding but never pick up a control
// id: the finding is about the whole resource.
func replaced(c change, r *rulepack.Rule) []hit {
	if !c.actions.Replace() {
		return nil
	}
	template := msgReplacedBefore
	if c.actions.CreateBeforeDestroy() {
		template = msgReplacedAfter
	}
	var out []hit
	for _, attr := range replacePaths(c.rc.Change.ReplacePaths) {
		h := newHit(c, r, r.Level, template, attr)
		h.whole = true
		out = append(out, h)
	}
	if len(out) == 0 {
		out = []hit{newHit(c, r, r.Level, template, "")}
	}
	return out
}

// replacePaths is the top-level attribute of each replace_paths entry,
// deduplicated.
func replacePaths(paths []any) []string {
	var out []string
	for _, p := range paths {
		if name, ok := first(p).(string); ok && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// valueIn reports an attribute whose planned value is one of values, while
// every attribute unset lists is empty and known.
func valueIn(c change, r *rulepack.Rule) []hit {
	v, ok := c.after[r.Attribute].(string)
	if !ok || !slices.Contains(r.Values, v) {
		return nil
	}
	for _, u := range r.Unset {
		if !isEmpty(c.after[u]) || c.isUnknown(u) {
			return nil
		}
	}
	return []hit{newHit(c, r, r.Level, r.Message, r.Attribute)}
}

// openCIDR reports ingress open to 0.0.0.0/0 or ::/0. With attribute, each
// element of that nested block list is a rule and the finding names the
// block; without, the resource itself is the rule and the finding names the
// matching CIDR attribute. note_ports lowers the level to note when the rule's
// port range is exactly one of those ports.
func openCIDR(c change, r *rulepack.Rule) []hit {
	if r.Attribute != "" {
		if c.isUnknown(r.Attribute) {
			return nil
		}
		var out []hit
		for _, rule := range list(c.after[r.Attribute]) {
			out = append(out, openIngress(c, r, obj(rule))...)
		}
		return out
	}
	if c.isUnknown(r.IPv4) || c.isUnknown(r.IPv6) {
		return nil
	}
	return openIngress(c, r, c.after)
}

func openIngress(c change, r *rulepack.Rule, rule map[string]any) []hit {
	level := r.Level
	if len(r.Ports) == 2 {
		if from, ok := rule[r.Ports[0]].(float64); ok && rule[r.Ports[1]] == rule[r.Ports[0]] && slices.Contains(r.NotePorts, from) {
			level = ctfkit.LevelNote
		}
	}
	var out []hit
	for _, cidr := range [][2]string{{r.IPv4, "0.0.0.0/0"}, {r.IPv6, "::/0"}} {
		if cidrAttr := cidr[0]; cidrAttr != "" && slices.Contains(strs(rule[cidrAttr]), cidr[1]) {
			name := r.Attribute
			if name == "" {
				name = cidrAttr
			}
			out = append(out, newHit(c, r, level, message(r, msgOpenIngress), name))
		}
	}
	return out
}

// ---- pack check ----

// placeholder matches one {name} of a message template.
var placeholder = regexp.MustCompile(`\{[^}]*\}`)

// checkPack holds every rule of a pack to the predicates and arguments this
// build has.
func checkPack(p *rulepack.Pack) error {
	if p.Dialect != "" && dialects[p.Dialect] == nil {
		return fmt.Errorf("dialect %q does not exist", p.Dialect)
	}
	for _, r := range p.Rules {
		if err := checkRule(p, r); err != nil {
			return fmt.Errorf("%s: %s %s: %w", r.File, r.Predicate, strings.Join(r.Types, ","), err)
		}
	}
	return nil
}

func checkRule(p *rulepack.Pack, r *rulepack.Rule) error {
	if !slices.Contains(classes, r.Class) {
		return fmt.Errorf("class %q is not one of %s", r.Class, strings.Join(classes, ", "))
	}
	if predicateFor(p, r.Predicate) == nil {
		return fmt.Errorf("predicate %q does not exist", r.Predicate)
	}
	for _, arg := range setArguments(r) {
		if !slices.Contains(arguments[r.Predicate], arg) {
			return fmt.Errorf("%s does not read %s", r.Predicate, arg)
		}
	}
	attributeFree := slices.Contains(wholeResource, r.Predicate) || r.Predicate == "open_cidr"
	if r.Attribute == "" && !attributeFree {
		return fmt.Errorf("%s needs attribute", r.Predicate)
	}
	for _, name := range placeholder.FindAllString(r.Message, -1) {
		if !slices.Contains([]string{"{address}", "{attributes}", "{kind}"}, name) {
			return fmt.Errorf("message placeholder %s does not exist", name)
		}
	}
	needsKind := strings.Contains(r.Message, "{kind}") || r.Predicate == "replaced" ||
		(r.Predicate == "deleted" && r.Message == "")
	if needsKind && len(r.Kinds) == 0 {
		return fmt.Errorf("%s needs kinds for its message", r.Predicate)
	}
	switch r.Predicate {
	case "value_in":
		if len(r.Values) == 0 || r.Message == "" {
			return fmt.Errorf("value_in needs values and message")
		}
	case "replaced":
		if r.Message != "" {
			return fmt.Errorf("replaced has its own messages")
		}
	case "open_cidr":
		if r.IPv4 == "" && r.IPv6 == "" {
			return fmt.Errorf("open_cidr needs ipv4 or ipv6")
		}
		if len(r.NotePorts) > 0 && len(r.Ports) != 2 {
			return fmt.Errorf("note_ports needs ports: [from, to]")
		}
	}
	if check := dialectChecks[r.Predicate]; check != nil {
		return check(r)
	}
	return nil
}

// dialectChecks hold a dialect predicate's own arguments to account.
var dialectChecks = map[string]func(r *rulepack.Rule) error{}

// arguments are the rule fields each predicate reads beyond types, kinds,
// level and when. A field set on a predicate that does not read it is an
// error: it would otherwise be ignored, and the rule would quietly do less
// than it says. A dialect adds its predicates here.
var arguments = map[string][]string{
	"turned_off":    {"attribute", "or_removed", "as_string", "message"},
	"turned_on":     {"attribute", "message"},
	"removed":       {"attribute", "message"},
	"block_removed": {"attribute", "flag", "message"},
	"narrowed":      {"attribute", "message"},
	"shortened":     {"attribute", "zero_is_unlimited", "message"},
	"deleted":       {"message"},
	"replaced":      {},
	"value_in":      {"attribute", "values", "unset", "message"},
	"open_cidr":     {"attribute", "ipv4", "ipv6", "ports", "note_ports", "message"},
}

// setArguments names the predicate arguments a rule sets, by their YAML keys.
func setArguments(r *rulepack.Rule) []string {
	var out []string
	for name, set := range map[string]bool{
		"attribute": r.Attribute != "", "message": r.Message != "", "values": len(r.Values) > 0,
		"unset": len(r.Unset) > 0, "or_removed": r.OrRemoved, "as_string": r.AsString, "flag": r.Flag != "",
		"zero_is_unlimited": r.ZeroIsUnlimited, "ipv4": r.IPv4 != "", "ipv6": r.IPv6 != "",
		"ports": len(r.Ports) > 0, "note_ports": len(r.NotePorts) > 0, "field": r.Field != "",
		"service_level": r.ServiceLevel != "",
	} {
		if set {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// ---- untyped JSON helpers ----

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func first(v any) any {
	if l := list(v); len(l) > 0 {
		return l[0]
	}
	return nil
}

// strs reads a string or a list of strings.
func strs(v any) []string {
	if s, ok := v.(string); ok {
		return []string{s}
	}
	var out []string
	for _, e := range list(v) {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// isEmpty reports null, an empty string, an empty list or an empty object.
func isEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}
