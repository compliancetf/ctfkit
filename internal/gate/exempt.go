package gate

import (
	"slices"
	"strings"

	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/resolve"
)

// list lists the exemptions of in on the entries they cover. For each named
// entry and each named control, the exemption counts only when the control
// is a resource-local control loaded for the entry's type and half, a
// failure of it blocks under the mode table (the provider warns a pending
// exemption at plan only then), and its effective coverable list holds the
// exemption's kind. Then the entry records the control as provisional, the
// state the provider reported at plan, and lists the digest; Resolve and the
// provider pass it at apply only with that listed proof. An exemption that
// covers nothing is never listed.
//
// shortcut: ctfkit evaluates no CEL, so it records a resource-local
// decision only where a verified exemption covers it; a failing control
// without one is not recorded and the provider's own evaluation blocks it at
// apply. A CEL evaluator (or the provider's plan results) would record every
// provisional decision.
func list(in Input, out *Output) {
	refs := map[string]int{}
	for i, inst := range out.Instances {
		refs[Ref(inst.Address, inst.Deposed)] = i
	}
	listed := map[string]bool{}
	for _, ex := range in.Exemptions {
		if ex.Kind != resolve.KindGrant && ex.Kind != resolve.KindSelfService {
			continue
		}
		for _, ref := range ex.Instances {
			i, ok := refs[ref]
			if !ok {
				continue
			}
			inst := &out.Instances[i]
			used := false
			for _, c := range in.Controls {
				if !slices.Contains(ex.Controls, c.ID) || c.ResourceType != inst.Type || !covers(in, c, ex.Kind) {
					continue
				}
				switch {
				case c.Kind == KindResource && inst.Action != "delete":
					inst.Decisions = provisional(inst.Decisions, c)
				case c.Kind == KindDeletionGuard && inst.DeleteDecisions != nil:
					inst.DeleteDecisions = provisional(inst.DeleteDecisions, c)
				default:
					continue
				}
				used = true
			}
			if !used {
				continue
			}
			if !slices.Contains(inst.Exceptions, ex.Digest) {
				inst.Exceptions = append(inst.Exceptions, ex.Digest)
				slices.Sort(inst.Exceptions)
			}
			if !listed[ex.Digest] {
				listed[ex.Digest] = true
				out.Exceptions = append(out.Exceptions, verdict.ExceptionRef{Digest: ex.Digest, Source: ex.Kind, Expires: ex.Expires})
			}
		}
	}
	slices.SortFunc(out.Exceptions, func(a, b verdict.ExceptionRef) int { return strings.Compare(a.Digest, b.Digest) })
}

// covers reports whether an exemption of kind may stand for a blocking
// failure of c.
func covers(in Input, c Control, kind string) bool {
	if in.Coverable == nil || !slices.Contains(in.Coverable(c.ID), kind) {
		return false
	}
	rc := resolve.Control{ID: c.ID, Version: c.Version, Action: c.Action}
	return resolve.Blocks(in.Mode.Mode(rc), rc)
}

// provisional adds c as provisional to ds unless ds decides it already.
func provisional(ds []verdict.Decision, c Control) []verdict.Decision {
	if slices.ContainsFunc(ds, func(d verdict.Decision) bool { return d.Control == c.ID && d.Version == c.Version }) {
		return ds
	}
	ds = append(ds, verdict.Decision{Control: c.ID, Version: c.Version, Result: resolve.StateProvisional, Action: c.Action})
	slices.SortFunc(ds, func(a, b verdict.Decision) int {
		return strings.Compare(a.Control+"\x00"+a.Version, b.Control+"\x00"+b.Version)
	})
	return ds
}
