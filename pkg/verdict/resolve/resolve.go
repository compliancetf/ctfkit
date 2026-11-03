// Package resolve is the decision state machine of a signed verdict (spec
// B10, D10): it turns the raw decisions gate sign recorded, the mode table,
// and the exemptions the caller verified into what applies, what warns and
// what blocks. `ctfkit apply` runs it over the whole plan before terraform
// apply and refuses on any blocking row; the compliance.tf provider runs the
// same rules per instance for its RPC's half. It is pure: callers verify
// signatures, expiry, selectors and identity matching first, and pass only
// what verified.
package resolve

import (
	"slices"

	"github.com/compliancetf/ctfkit/pkg/verdict"
)

// Modes, in order (phase-0b mode table).
const (
	Advisory    = "advisory"
	SoftFail    = "soft_fail"
	Grandfather = "grandfather"
	HardFail    = "hard_fail"
)

// Decision states the gate records (verdict decisions[].result).
const (
	StatePass         = "pass"
	StateFail         = "fail"
	StateNotEvaluable = "not_evaluable"
	StateProvisional  = "provisional"
	StatePending      = "pending"
)

// Row results; the names equal the provider's situation results.
const (
	ResultPass         = "pass"
	ResultFail         = "fail"
	ResultNotEvaluable = "not_evaluable"
	ResultPending      = "pending"
	ResultExcepted     = "excepted"           // provisional with its final proof
	ResultUnproven     = "exemption_unproven" // provisional without it
	ResultMissing      = "missing_decision"
	ResultUnknownType  = "unknown_type" // no required-control set for the type
	ResultInvalidHalf  = "invalid_half" // Decisions.Half is neither create nor delete
)

// Severities: none is evidence only, error blocks.
const (
	SevNone    = "none"
	SevWarning = "warning"
	SevError   = "error"
)

// Exemption kinds (coverable list members).
const (
	KindGrant       = "grant"
	KindSelfService = "self_service"
	KindBaseline    = "baseline"
	KindBreakGlass  = "break_glass"
)

// Halves of an instance.
const (
	HalfCreate = "create" // decisions, matched by instance_key
	HalfDelete = "delete" // delete_decisions, matched by delete_key
)

// ModeTable is the resolved mode table: per-control mode is
// max(RunMode, ControlFloors[id], DenyFloor when the action is deny). An
// empty or unknown mode resolves as hard_fail (fail closed).
type ModeTable struct {
	RunMode       string            `json:"run_mode"`
	DenyFloor     string            `json:"deny_floor,omitempty"`
	ControlFloors map[string]string `json:"control_floors,omitempty"`
}

// Control is a control loaded from the verified bundle for a type: its
// action and its compliance.tf-signed coverable list.
type Control struct {
	ID        string   `json:"id"`
	Version   string   `json:"version"`
	Action    string   `json:"action"`
	Coverable []string `json:"coverable"`
}

// Halves are the controls a type requires a decision for, per half.
type Halves struct {
	Decisions       []Control `json:"decisions"`
	DeleteDecisions []Control `json:"delete_decisions"`
}

// Decisions is what Resolve decides: the verdict instances and, per resource
// type, the controls the verified bundle loads. A type absent from Required
// refuses (a zero-control type needs an empty entry). Half selects one half
// for every instance (the provider's RPC); "" picks by instance action:
// replace both, delete the delete half, every other action the create half.
// Any other Half refuses every instance (invalid_half).
type Decisions struct {
	Instances []verdict.Instance `json:"instances"`
	Required  map[string]Halves  `json:"required"`
	Half      string             `json:"half,omitempty"`
}

// Exception is a verified signed grant or self-service entry.
type Exception struct {
	Digest   string   `json:"digest"`
	Kind     string   `json:"kind"` // grant or self_service; any other kind is ignored
	Controls []string `json:"controls"`
}

// Baseline is a verified baseline entry the caller matched to its instance
// (identity, read digest, control manifest digest, expiry, revocation).
type Baseline struct {
	Digest  string `json:"digest"`
	Control string `json:"control"`
}

// Receipt is a verified break-glass consume receipt.
type Receipt struct {
	Digest     string   `json:"digest"`
	OverrideID string   `json:"override_id"`
	Controls   []string `json:"controls"`
	ActionKeys []string `json:"action_keys"`
}

// Proof names the exemption a row used.
type Proof struct {
	Kind       string `json:"kind"`
	Digest     string `json:"digest"`
	OverrideID string `json:"override_id,omitempty"`
}

// Row is the outcome of one required (control, version) of one half.
// Final is the state written to evidence: pass, fail, or "" for pending
// (the post-apply linkage check decides it).
type Row struct {
	Address  string `json:"address"`
	Deposed  string `json:"deposed,omitempty"`
	Half     string `json:"half"`
	Control  string `json:"control,omitempty"`
	Version  string `json:"version,omitempty"`
	State    string `json:"state,omitempty"` // the recorded decision result
	Result   string `json:"result"`
	Severity string `json:"severity"`
	Final    string `json:"final"`
	Proof    *Proof `json:"proof,omitempty"`
}

// Outcome is the whole decision: Refuse when any row blocks.
type Outcome struct {
	Refuse bool  `json:"refuse"`
	Rows   []Row `json:"rows"`
}

var modeRank = map[string]int{Advisory: 0, SoftFail: 1, Grandfather: 2, HardFail: 3}

// Mode is the per-control mode. An unknown mode string ranks hard_fail
// (fail closed); the loaders reject it before this.
func (t ModeTable) Mode(c Control) string {
	m := t.RunMode
	for _, f := range []string{t.ControlFloors[c.ID], deny(c, t.DenyFloor)} {
		if f != "" && rank(f) > rank(m) {
			m = f
		}
	}
	if _, ok := modeRank[m]; !ok {
		return HardFail
	}
	return m
}

func deny(c Control, floor string) string {
	if c.Action == "deny" {
		return floor
	}
	return ""
}

func rank(m string) int {
	if r, ok := modeRank[m]; ok {
		return r
	}
	return modeRank[HardFail]
}

// failRow is the apply_pre fail row of the provider severity matrix:
// blocking (deny, and hard_fail or grandfather) is error, non-blocking
// advisory none, else warning. Grandfather blocks: a baseline proves only a
// provisional decision.
func failRow(mode string, c Control) string {
	if Blocks(mode, c) {
		return SevError
	}
	if mode == Advisory {
		return SevNone
	}
	return SevWarning
}

// Blocks reports whether a failing decision of c blocks under mode: a deny
// control under hard_fail or grandfather.
func Blocks(mode string, c Control) bool {
	return c.Action == "deny" && (mode == HardFail || mode == Grandfather)
}

// Resolve decides in. ex, bl and bg are what the caller verified; each
// counts for an instance only when the instance lists its digest and the
// control's coverable list holds its kind.
func Resolve(in Decisions, mode ModeTable, ex []Exception, bl []Baseline, bg []Receipt) Outcome {
	var out Outcome
	for i := range in.Instances {
		inst := &in.Instances[i]
		req, ok := in.Required[inst.Type]
		for _, half := range halves(inst.Action, in.Half) {
			if half != HalfCreate && half != HalfDelete {
				out.add(Row{Address: inst.Address, Deposed: inst.Deposed, Half: half, Result: ResultInvalidHalf, Severity: SevError, Final: StateFail})
				continue
			}
			if !ok {
				out.add(Row{Address: inst.Address, Deposed: inst.Deposed, Half: half, Result: ResultUnknownType, Severity: SevError, Final: StateFail})
				continue
			}
			ctls, decs, key := req.Decisions, inst.Decisions, inst.InstanceKey
			if half == HalfDelete {
				ctls, decs, key = req.DeleteDecisions, inst.DeleteDecisions, inst.DeleteKey
			}
			p := proofs{inst: inst, key: key, ex: ex, bl: bl, bg: bg}
			for _, c := range ctls {
				out.add(decide(inst, half, c, decs, mode.Mode(c), p))
			}
		}
	}
	return out
}

func (o *Outcome) add(r Row) {
	o.Rows = append(o.Rows, r)
	o.Refuse = o.Refuse || r.Severity == SevError
}

func halves(action, only string) []string {
	switch {
	case only != "":
		return []string{only}
	case action == "replace":
		return []string{HalfCreate, HalfDelete}
	case action == "delete":
		return []string{HalfDelete}
	}
	return []string{HalfCreate}
}

func decide(inst *verdict.Instance, half string, c Control, decs []verdict.Decision, mode string, p proofs) Row {
	r := Row{Address: inst.Address, Deposed: inst.Deposed, Half: half, Control: c.ID, Version: c.Version,
		Severity: failRow(mode, c), Final: StateFail}
	i := slices.IndexFunc(decs, func(d verdict.Decision) bool { return d.Control == c.ID && d.Version == c.Version })
	if i < 0 {
		r.Result = ResultMissing
		return r
	}
	r.State = decs[i].Result
	switch r.State {
	case StatePass:
		r.Result, r.Severity, r.Final = ResultPass, SevNone, StatePass
	case StatePending: // never exemptible; at most a warning
		r.Result, r.Final = ResultPending, ""
		if r.Severity == SevError {
			r.Severity = SevWarning
		}
	case StateProvisional:
		if r.Proof = p.find(c, mode, r.State); r.Proof != nil {
			r.Result, r.Severity, r.Final = ResultExcepted, SevNone, StatePass
			return r
		}
		// A provisional decision exists only for a blocking control: without
		// final proof it blocks in every mode.
		r.Result, r.Severity = ResultUnproven, SevError
	case StateFail, StateNotEvaluable:
		r.Result = r.State
		// An honored receipt downgrades the block to a warning; the final
		// state stays fail.
		if r.Proof = p.receipt(c, r.State); r.Proof != nil && r.Severity == SevError {
			r.Severity = SevWarning
		}
	default: // any other state takes the not_evaluable row, never overridden
		r.Result = ResultNotEvaluable
	}
	return r
}

type proofs struct {
	inst *verdict.Instance
	key  string
	ex   []Exception
	bl   []Baseline
	bg   []Receipt
}

// find is the final proof of a provisional decision, in the provider's
// order: baseline (mode grandfather, refreshed), exception, receipt.
func (p proofs) find(c Control, mode, state string) *Proof {
	if mode == Grandfather && p.inst.Refreshed == "true" && slices.Contains(c.Coverable, KindBaseline) {
		for _, b := range p.bl {
			if b.Control == c.ID && slices.Contains(p.inst.Baselines, b.Digest) {
				return &Proof{Kind: KindBaseline, Digest: b.Digest}
			}
		}
	}
	for _, e := range p.ex {
		if (e.Kind == KindGrant || e.Kind == KindSelfService) && slices.Contains(c.Coverable, e.Kind) &&
			slices.Contains(p.inst.Exceptions, e.Digest) && slices.Contains(e.Controls, c.ID) {
			return &Proof{Kind: e.Kind, Digest: e.Digest}
		}
	}
	return p.receipt(c, state)
}

// receipt is the first listed receipt covering the control on the half's
// action key; only fail, not_evaluable and provisional are coverable.
func (p proofs) receipt(c Control, state string) *Proof {
	if !slices.Contains([]string{StateFail, StateNotEvaluable, StateProvisional}, state) ||
		!slices.Contains(c.Coverable, KindBreakGlass) || p.key == "" {
		return nil
	}
	for _, g := range p.bg {
		if slices.Contains(p.inst.BreakGlass, g.Digest) && slices.Contains(g.Controls, c.ID) && slices.Contains(g.ActionKeys, p.key) {
			return &Proof{Kind: KindBreakGlass, Digest: g.Digest, OverrideID: g.OverrideID}
		}
	}
	return nil
}
