// Package gate builds the verdict ctfkit gate sign signs (verdict-1): one
// entry per managed resource change of the sealed plan, with the instance
// keys gate plan computed, the graph decisions of the verified bundles in
// decision-state-machine states, deletion guards decided on the full plan,
// not_evaluable reasons and the exemptions it may list. It is pure: the
// caller verifies the inputs, keys and exemptions first and signs after.
package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/graph"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/resolve"
	keyjson "github.com/compliancetf/ctfkit/pkg/verdict/tfjson"
)

// Control kinds of bundle 2.0 the builder reads.
const (
	KindGraph         = "graph"
	KindResource      = "resource"
	KindDeletionGuard = "deletion_guard"
)

// ReasonStateAction is the not_evaluable reason of every graph control on an
// import or move entry (E8).
const ReasonStateAction = "state_action"

// Control is one bundle 2.0 control as controls.json writes it.
type Control struct {
	graph.Control
	Kind               string   `json:"kind"`
	ExemptionCoverable []string `json:"exemption_coverable"`
}

// ParseControls decodes a verified bundle's controls.json (a JSON array).
// A kind or graph rule the provider does not know refuses the run, so no control drops out
// of the verdict unseen.
func ParseControls(raw []byte) ([]Control, error) {
	var cs []Control
	if err := json.Unmarshal(raw, &cs); err != nil {
		return nil, fmt.Errorf("controls.json: %w", err)
	}
	for _, c := range cs {
		switch {
		case !slices.Contains(controlKinds, c.Kind):
			return nil, fmt.Errorf("controls.json: control %s: unknown kind %q", c.ID, c.Kind)
		case c.Kind == KindGraph && c.Graph.Rule != graph.RuleCompanionPresent && c.Graph.Rule != graph.RuleCompanionAbsentForbidden:
			return nil, fmt.Errorf("controls.json: control %s: unknown graph rule %q", c.ID, c.Graph.Rule)
		}
	}
	return cs, nil
}

// controlKinds are the bundle 2.0 control kinds (the provider's list).
var controlKinds = []string{KindResource, "data_source", "ephemeral", KindDeletionGuard, KindGraph}

// Exemption is a grant or self-service entry the caller verified (signature
// or sidecar rules, scope, expiry, content binding) and matched (selector)
// to the instances it names, each as Ref.
type Exemption struct {
	Kind      string // resolve.KindGrant or resolve.KindSelfService
	Digest    string // exceptiondigest
	Expires   string // RFC 3339 UTC
	Controls  []string
	Instances []string
}

// Ref names an instance: its address, plus " deposed <key>" for a deposed
// object.
func Ref(address, deposed string) string {
	if deposed == "" {
		return address
	}
	return address + " deposed " + deposed
}

// Input is what Build decides.
type Input struct {
	Plan     *tfjson.Plan       // the sealed plan's show -json
	Lock     *ctfkit.Lockfile   // for the identity catalog major
	Keys     []keyjson.Instance // gate plan's keyed changes, checked against the candidate
	Controls []Control          // every control of the verified bundles
	Mode     resolve.ModeTable
	// Coverable is the effective coverable list of a control: its signed
	// exemption_coverable after the profile and floor mode restrictions.
	Coverable  func(id string) []string
	Exemptions []Exemption
}

// Output is the built verdict body.
type Output struct {
	Instances  []verdict.Instance
	Exceptions []verdict.ExceptionRef
	Findings   []graph.Decision          // every graph decision, for SARIF
	Required   map[string]resolve.Halves // the control set Resolve checks, per type
}

// Build builds the verdict instances of in.Plan. An error refuses the run.
func Build(in Input) (*Output, error) {
	if in.Plan == nil {
		return nil, errors.New("no plan")
	}
	present, guards := split(in.Controls)
	decided, err := graph.Evaluate(in.Plan, in.Lock, present)
	if err != nil {
		return nil, err
	}
	guarded, err := graph.EvaluateGuards(in.Plan, in.Lock, guards)
	if err != nil {
		return nil, err
	}
	keys := map[string]*keyjson.Instance{}
	for i := range in.Keys {
		k := &in.Keys[i]
		if k.Err != nil {
			return nil, fmt.Errorf("%s: %w", Ref(k.Address, k.Deposed), k.Err)
		}
		keys[Ref(k.Address, k.Deposed)] = k
	}
	out := &Output{Instances: []verdict.Instance{}, Exceptions: []verdict.ExceptionRef{}, Required: map[string]resolve.Halves{},
		Findings: slices.Concat(decided, guarded)}
	for _, rc := range in.Plan.ResourceChanges {
		if rc == nil || rc.Mode != tfjson.ManagedResourceMode {
			continue
		}
		if rc.Change == nil {
			return nil, fmt.Errorf("%s: no change", rc.Address)
		}
		ref := Ref(rc.Address, rc.DeposedKey)
		inst, err := entry(rc, keys[ref])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ref, err)
		}
		delete(keys, ref)
		req, ok := out.Required[rc.Type]
		if !ok {
			req = required(in, rc.Type, present, guards)
			out.Required[rc.Type] = req
		}
		if inst.Action != "delete" {
			inst.Decisions = decisions(rc.Address, req.Decisions, decided, inst.Action)
		}
		if inst.DeleteDecisions != nil {
			inst.DeleteDecisions = decisions(ref, req.DeleteDecisions, guarded, "delete")
		}
		for _, ds := range [][]verdict.Decision{inst.Decisions, inst.DeleteDecisions} {
			for _, d := range ds {
				if d.Result == resolve.StateNotEvaluable {
					inst.NotEvaluable = append(inst.NotEvaluable, verdict.NotEvaluable{Control: d.Control, Reason: reasonOf(out.Findings, ref, d, inst.Action)})
				}
			}
		}
		out.Instances = append(out.Instances, inst)
	}
	if len(keys) > 0 {
		refs := slices.Sorted(maps.Keys(keys))
		return nil, fmt.Errorf("%s: keyed by gate plan but not in the plan", refs[0])
	}
	list(in, out)
	return out, nil
}

// split returns the graph controls: companion_present ones and deletion
// guards.
func split(controls []Control) (present, guards []graph.Control) {
	for _, c := range controls {
		if c.Kind != KindGraph {
			continue
		}
		if c.Graph.Rule == graph.RuleCompanionAbsentForbidden {
			guards = append(guards, c.Control)
		} else {
			present = append(present, c.Control)
		}
	}
	return present, guards
}

// Required is the control set Resolve checks for each type of instances,
// from in.Controls and in.Coverable alone: the same set Build returns, so
// ctfkit apply resolves a signed verdict before terraform runs.
func Required(in Input, instances []verdict.Instance) map[string]resolve.Halves {
	present, guards := split(in.Controls)
	out := map[string]resolve.Halves{}
	for _, inst := range instances {
		if _, ok := out[inst.Type]; !ok {
			out[inst.Type] = required(in, inst.Type, present, guards)
		}
	}
	return out
}

// actions maps a change to its verdict action.
func action(rc *tfjson.ResourceChange) (string, error) {
	a := rc.Change.Actions
	switch {
	case a.Replace():
		return "replace", nil
	case a.Create():
		return "create", nil
	case a.Update():
		return "update", nil
	case a.Delete():
		return "delete", nil
	case a.NoOp() && rc.Change.Importing != nil:
		return "import", nil
	case a.NoOp() && rc.PreviousAddress != "" && rc.PreviousAddress != rc.Address:
		return "move", nil
	case a.NoOp():
		return "no-op", nil
	}
	return "", fmt.Errorf("unsupported actions %v", a)
}

// entry is the verdict entry of one change, without decisions. Keys come
// from gate plan: a mutation must have them, anything else must not.
func entry(rc *tfjson.ResourceChange, k *keyjson.Instance) (verdict.Instance, error) {
	act, err := action(rc)
	if err != nil {
		return verdict.Instance{}, err
	}
	inst := verdict.Instance{Address: rc.Address, Deposed: rc.DeposedKey, Type: rc.Type, Action: act,
		Refreshed: "true", UnknownPaths: [][]string{}, Decisions: []verdict.Decision{}, NotEvaluable: []verdict.NotEvaluable{},
		Exceptions: []string{}, Baselines: []string{}, BreakGlass: []string{}}
	if rc.PreviousAddress != rc.Address {
		inst.PreviousAddress = rc.PreviousAddress
	}
	switch {
	case rc.DeposedKey != "" && act != "delete":
		return inst, errors.New("a deposed object takes only a delete entry")
	case act == "delete" || act == "replace":
		inst.DeleteDecisions = []verdict.Decision{}
	}
	mutation := act == "create" || act == "update" || act == "delete" || act == "replace"
	switch {
	case !mutation && k != nil:
		return inst, errors.New("gate plan keyed a change that mutates nothing")
	case !mutation:
		inst.PriorIdentityKind = priorKind(rc.Change)
		return inst, nil
	case k == nil:
		return inst, errors.New("a mutation gate plan did not key")
	}
	inst.PriorIdentityKind = keyjson.KindNone
	for _, key := range k.Keys {
		switch key.Field {
		case "instance_key":
			inst.InstanceKey, inst.UnknownPaths = key.Key, key.UnknownPaths
		case "delete_key":
			inst.DeleteKey = key.Key
		}
		if key.PriorIdentityKind != keyjson.KindNone {
			inst.PriorIdentityKind = key.PriorIdentityKind
		}
	}
	wantCreate, wantDelete := act != "delete", act == "delete" || act == "replace"
	if wantCreate != (inst.InstanceKey != "") || wantDelete != (inst.DeleteKey != "") {
		return inst, errors.New("gate plan keys do not fit the action")
	}
	if inst.UnknownPaths == nil {
		inst.UnknownPaths = [][]string{}
	}
	return inst, nil
}

// priorKind is prior_identity_kind of an entry with no mutation key:
// identity when before_identity is non-null, else id when before.id is a
// known string, else none.
func priorKind(c *tfjson.Change) string {
	if c.BeforeIdentity != nil {
		return keyjson.KindIdentity
	}
	if b, ok := c.Before.(map[string]any); ok {
		if id, ok := b["id"].(string); ok && id != "" {
			return keyjson.KindID
		}
	}
	return keyjson.KindNone
}

// required is the control set of a type: companion_present controls of the
// type for the create half, deletion guards whose companion is the type for
// the delete half.
func required(in Input, typ string, present, guards []graph.Control) resolve.Halves {
	h := resolve.Halves{Decisions: []resolve.Control{}, DeleteDecisions: []resolve.Control{}}
	cov := func(c graph.Control) resolve.Control {
		var kinds []string
		if in.Coverable != nil {
			kinds = in.Coverable(c.ID)
		}
		return resolve.Control{ID: c.ID, Version: c.Version, Action: c.Action, Coverable: kinds}
	}
	for _, c := range present {
		if c.ResourceType == typ {
			h.Decisions = append(h.Decisions, cov(c))
		}
	}
	for _, c := range guards {
		if c.Graph.CompanionType == typ {
			h.DeleteDecisions = append(h.DeleteDecisions, cov(c))
		}
	}
	return h
}

// decisions is the decision of every required control for one entry: the
// graph result, not_evaluable for an import or move (state_action), and a
// required control the analyzer left undecided fails closed.
func decisions(ref string, req []resolve.Control, decided []graph.Decision, act string) []verdict.Decision {
	out := []verdict.Decision{}
	for _, c := range req {
		d := verdict.Decision{Control: c.ID, Version: c.Version, Result: resolve.StateNotEvaluable, Action: c.Action}
		if i := slices.IndexFunc(decided, func(g graph.Decision) bool {
			return Ref(g.Address, g.Deposed) == ref && g.Control == c.ID && g.Version == c.Version
		}); i >= 0 && act != "import" && act != "move" {
			d.Result = decided[i].Result
		}
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b verdict.Decision) int {
		return strings.Compare(a.Control+"\x00"+a.Version, b.Control+"\x00"+b.Version)
	})
	return out
}

// reasonOf is the not_evaluable reason of decision d of entry ref.
func reasonOf(found []graph.Decision, ref string, d verdict.Decision, act string) string {
	if act == "import" || act == "move" {
		return ReasonStateAction
	}
	for _, g := range found {
		if Ref(g.Address, g.Deposed) == ref && g.Control == d.Control && g.Version == d.Version && g.Reason != "" {
			return g.Reason
		}
	}
	return graph.ReasonUnknownReference
}
