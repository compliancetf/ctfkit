package ctfkit

import (
	"context"
	"fmt"
)

// Stage names the point in a Terraform or OpenTofu workflow at which an
// analyzer runs. The set of stages is frozen: adapters, the ctf.stage property
// of a finding and the manifests that describe an adapter all use these exact
// strings.
type Stage string

const (
	// PrePlan runs against configuration only, before init or plan.
	PrePlan Stage = "pre_plan"
	// PostInit runs after init and before plan, when .terraform/modules and
	// the module manifests exist but no plan does.
	PostInit Stage = "post_init"
	// PostPlan runs against the plan JSON.
	PostPlan Stage = "post_plan"
	// PreApply runs against the plan JSON immediately before apply, where a
	// platform separates the two.
	PreApply Stage = "pre_apply"
	// PostApply runs against the applied state.
	PostApply Stage = "post_apply"
)

// stageRanks is the workflow order of the stages, earliest first. It exists so
// that "later than post_init" is expressed as a comparison of ranks; the Stage
// strings themselves are names, and comparing them with < or >= compares them
// alphabetically, which is not the workflow order.
var stageRanks = map[Stage]int{
	PrePlan:   0,
	PostInit:  1,
	PostPlan:  2,
	PreApply:  3,
	PostApply: 4,
}

// Rank returns the position of s in the workflow, from 0 for pre_plan to 4 for
// post_apply. An unknown stage ranks -1, so it sorts before every real stage
// and never silently counts as a late one.
func (s Stage) Rank() int {
	if r, ok := stageRanks[s]; ok {
		return r
	}
	return -1
}

// String returns the stage name, which is the wire form used by ctf.stage and
// by every adapter.
func (s Stage) String() string { return string(s) }

// ParseStage converts a stage name to a Stage. It is the only supported way to
// turn input into a Stage, so an unknown word fails at the boundary rather
// than reaching an analyzer as a stage that matches nothing.
func ParseStage(name string) (Stage, error) {
	s := Stage(name)
	if _, ok := stageRanks[s]; ok {
		return s, nil
	}
	return "", fmt.Errorf("ctfkit: unknown stage %q, want one of %s, %s, %s, %s, %s",
		name, PrePlan, PostInit, PostPlan, PreApply, PostApply)
}

// Analyzer is the contract every check implements. Implementations MUST be
// pure: no file I/O, no logging, no network access, no global mutable state.
// The same Analyzer value may be run concurrently for different inputs.
type Analyzer interface {
	// ID returns the stable rule id, for example "ctf.coverage.module_source".
	// It is the SARIF ruleId and the join key used by exceptions and by the
	// findings taxonomy, so it never changes once published.
	ID() string

	// Stage returns the single stage at which this analyzer runs. An analyzer
	// that needs two stages is two analyzers with two ids.
	Stage() Stage

	// Analyze inspects in and returns the findings it produced, which may be
	// empty.
	//
	// A returned error means the analyzer itself malfunctioned - malformed
	// input it cannot interpret, a broken invariant, a canceled context. A
	// compliance failure is never an error: it is a Finding with Level
	// LevelError. A runner that receives an error reports a tool failure and
	// exits 2; it does not report a policy violation.
	Analyze(ctx context.Context, in AnalyzerInput) (Findings, error)
}
