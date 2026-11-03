package graph

import (
	"fmt"
	"sort"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/rulepack"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// EvaluateGuards decides every companion_absent_forbidden control (a
// deletion guard) on the full plan. A guard reads like companion_present:
// resource_type is the target, companion_type the companion whose link_attr
// names one of the target's target_attrs. It is decided for each companion
// instance the plan deletes (delete, the destroy half of a replace, a deposed
// object), on the companion's prior values:
//
//	fail           its prior value links to a target the plan keeps, and no
//	               companion the plan keeps links to that target
//	not_evaluable  either link cannot be decided (the linkage reasons)
//	pass           otherwise, also when no kept target exists
//
// The decision belongs to the companion's delete half (delete_decisions).
func EvaluateGuards(plan *tfjson.Plan, lock *ctfkit.Lockfile, controls []Control) ([]Decision, error) {
	if plan == nil {
		return nil, nil
	}
	kept := planned(plan, lock)
	deleted := deleting(plan, lock)
	var out []Decision
	for _, ctl := range controls {
		g := ctl.Graph
		switch {
		case g.Rule != RuleCompanionAbsentForbidden:
			continue
		case g.CompanionExpr != nil:
			// shortcut: no CEL engine in ctfkit yet; such a guard fails the run
			// (exit 2) until one evaluates it.
			return nil, fmt.Errorf("graph: control %s: companion_expr is not supported", ctl.ID)
		case ctl.ResourceType == "" || g.CompanionType == "" || g.LinkAttr == "" || len(g.TargetAttrs) == 0:
			return nil, fmt.Errorf("graph: control %s: resource_type, companion_type, link_attr and target_attrs are required", ctl.ID)
		}
		var targets, companions []instance
		for _, in := range kept {
			switch in.typ {
			case ctl.ResourceType:
				targets = append(targets, in)
			case g.CompanionType:
				companions = append(companions, in)
			}
		}
		for _, c := range deleted {
			if c.typ != g.CompanionType {
				continue
			}
			result, reason := guard(c, targets, companions, g.LinkAttr, g.TargetAttrs)
			out = append(out, Decision{Address: c.address, Deposed: c.deposed, Control: ctl.ID, Version: ctl.Version,
				Result: result, Reason: reason, Action: ctl.Action})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		if a.Deposed != b.Deposed {
			return a.Deposed < b.Deposed
		}
		return a.Control < b.Control
	})
	return out, nil
}

// guard decides one deleted companion against the kept targets.
func guard(c instance, targets, companions []instance, linkAttr string, targetAttrs []string) (string, string) {
	for _, t := range targets {
		id, reason := targetIdentity(t, targetAttrs)
		if reason != "" {
			return ResultNotEvaluable, reason
		}
		switch r := link(t, id, c, linkAttr); r {
		case "":
			continue
		case "linked":
		default:
			return ResultNotEvaluable, r
		}
		// The deleted companion served t: t must keep another one.
		switch result, reason := decide(t, companions, linkAttr, targetAttrs); result {
		case ResultFail:
			return ResultFail, ""
		case ResultNotEvaluable:
			return ResultNotEvaluable, reason
		}
	}
	return ResultPass, ""
}

// deleting returns every managed instance whose planned action deletes it,
// its prior values standing in for the planned ones.
func deleting(plan *tfjson.Plan, lock *ctfkit.Lockfile) []instance {
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
		if a := rc.Change.Actions; !a.Delete() && !a.Replace() {
			continue
		}
		in := instance{address: rc.Address, deposed: rc.DeposedKey, typ: rc.Type, configKey: keys[configAddress(rc.Address)]}
		in.provider = providers[in.configKey]
		in.after, _ = rc.Change.Before.(map[string]any)
		in.unknown = map[string]any{}
		in.catalog = catalogFor(packs, rc.ProviderName, lock)
		out = append(out, in)
	}
	return out
}
