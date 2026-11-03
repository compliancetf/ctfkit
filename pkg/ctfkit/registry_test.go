package ctfkit_test

import (
	"context"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// stubAnalyzer is a minimal Analyzer for exercising the registry.
type stubAnalyzer struct {
	id    string
	stage ctfkit.Stage
}

func (s stubAnalyzer) ID() string          { return s.id }
func (s stubAnalyzer) Stage() ctfkit.Stage { return s.stage }

func (s stubAnalyzer) Analyze(_ context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	f, err := ctfkit.NewFinding(s.id, ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: "stub"}, nil,
		ctfkit.Properties{Schema: "1.0", Stage: in.Stage})
	if err != nil {
		return nil, err
	}
	return ctfkit.Findings{f}, nil
}

// mustRegister fails the test rather than the run, which is what a test wants
// where MustRegister would panic.
func mustRegister(t *testing.T, r ctfkit.Registry, analyzers ...ctfkit.Analyzer) {
	t.Helper()
	for _, a := range analyzers {
		if err := r.Register(a); err != nil {
			t.Fatalf("Register(%s) returned %v, want no error", a.ID(), err)
		}
	}
}

func TestRegistryRegisterAndLookup(t *testing.T) {
	coverage := stubAnalyzer{id: "ctf.coverage.manifest", stage: ctfkit.PostInit}
	source := stubAnalyzer{id: "ctf.coverage.module_source", stage: ctfkit.PostPlan}

	r := ctfkit.NewRegistry()
	mustRegister(t, r, coverage, source)

	if got := len(r.All()); got != 2 {
		t.Fatalf("All() returned %d analyzers, want 2", got)
	}
	if got := r.All()[0].ID(); got != coverage.id {
		t.Errorf("All() is not in registration order: first is %q, want %q", got, coverage.id)
	}

	postInit := r.ByStage(ctfkit.PostInit)
	if len(postInit) != 1 || postInit[0].ID() != coverage.id {
		t.Errorf("ByStage(post_init) = %v, want only %q", ids(postInit), coverage.id)
	}
	if got := r.ByStage(ctfkit.PostApply); len(got) != 0 {
		t.Errorf("ByStage(post_apply) = %v, want none", ids(got))
	}

	if got := r.ByID(source.id, ctfkit.PostPlan); got == nil || got.ID() != source.id {
		t.Errorf("ByID(%q, post_plan) = %v, want the registered analyzer", source.id, got)
	}
	if got := r.ByID("ctf.absent.check", ctfkit.PostPlan); got != nil {
		t.Errorf("ByID of an unregistered id = %v, want nil", got)
	}
}

// One rule id runs at two stages: module_source reads module blocks at
// pre_plan and planned resources at post_plan. Both register, and the stage
// tells them apart.
func TestRegistrySameIDAtTwoStages(t *testing.T) {
	const id = "ctf.coverage.module_source"

	r := ctfkit.NewRegistry()
	mustRegister(t, r,
		stubAnalyzer{id: id, stage: ctfkit.PrePlan},
		stubAnalyzer{id: id, stage: ctfkit.PostPlan},
	)

	if got := len(r.All()); got != 2 {
		t.Fatalf("All() returned %d analyzers, want both stage registrations", got)
	}
	if got := r.ByID(id, ctfkit.PrePlan); got == nil || got.Stage() != ctfkit.PrePlan {
		t.Errorf("ByID(%q, pre_plan) = %v, want the pre_plan registration", id, got)
	}
	if got := r.ByID(id, ctfkit.PostPlan); got == nil || got.Stage() != ctfkit.PostPlan {
		t.Errorf("ByID(%q, post_plan) = %v, want the post_plan registration", id, got)
	}
	if got := r.ByID(id, ctfkit.PreApply); got != nil {
		t.Errorf("ByID(%q, pre_apply) = %v, want nil: nothing registered at that stage", id, got)
	}
}

func TestRegistryRegisterRejects(t *testing.T) {
	tests := []struct {
		name     string
		analyzer ctfkit.Analyzer
	}{
		{"nil analyzer", nil},
		{"id without the ctf prefix", stubAnalyzer{id: "coverage.module_source", stage: ctfkit.PrePlan}},
		{"id with too few parts", stubAnalyzer{id: "ctf.coverage", stage: ctfkit.PrePlan}},
		{"id with upper case", stubAnalyzer{id: "ctf.coverage.moduleSource", stage: ctfkit.PrePlan}},
		{"id with a dash", stubAnalyzer{id: "ctf.coverage.module-source", stage: ctfkit.PrePlan}},
		{"underscore in the family segment", stubAnalyzer{id: "ctf.s3_bucket.enabled", stage: ctfkit.PrePlan}},
		{"unknown stage", stubAnalyzer{id: "ctf.coverage.module_source", stage: "post_destroy"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ctfkit.NewRegistry()
			if err := r.Register(tt.analyzer); err == nil {
				t.Error("Register accepted the analyzer, want an error")
			}
			if got := len(r.All()); got != 0 {
				t.Errorf("a rejected analyzer was still recorded: All() has %d", got)
			}
		})
	}
}

// Digits are inside the frozen rule id format, for a family or a check that
// needs one.
func TestRegistryAcceptsDigitsInARuleID(t *testing.T) {
	r := ctfkit.NewRegistry()
	mustRegister(t, r, stubAnalyzer{id: "ctf.policy.s3_acl2", stage: ctfkit.PrePlan})
	if got := r.ByID("ctf.policy.s3_acl2", ctfkit.PrePlan); got == nil {
		t.Error("a rule id with a digit was not registered")
	}
}

// The published schemas end with (\.[a-z0-9_]+)+, so a rule id may carry more
// than three segments. This case was asserted to be rejected until the SDK
// followed the schemas.
func TestRegistryAcceptsAFourSegmentRuleID(t *testing.T) {
	const id = "ctf.coverage.delegation.unresolved"
	r := ctfkit.NewRegistry()
	mustRegister(t, r, stubAnalyzer{id: id, stage: ctfkit.PrePlan})
	if got := r.ByID(id, ctfkit.PrePlan); got == nil {
		t.Errorf("a four-segment rule id was not registered: %s", id)
	}
}

// A typed nil reaches Register as a non-nil interface holding a nil pointer,
// and calling ID on it panics, so it has to be caught by inspecting the value.
func TestRegistryRejectsTypedNil(t *testing.T) {
	var typedNil *pointerAnalyzer
	r := ctfkit.NewRegistry()

	if err := r.Register(typedNil); err == nil {
		t.Error("Register accepted a typed nil analyzer, want an error")
	}
	if got := len(r.All()); got != 0 {
		t.Errorf("the typed nil was recorded: All() has %d analyzers", got)
	}
}

// pointerAnalyzer has pointer receivers, so a nil *pointerAnalyzer satisfies
// Analyzer while every call on it panics.
type pointerAnalyzer struct {
	id string
}

func (p *pointerAnalyzer) ID() string          { return p.id }
func (p *pointerAnalyzer) Stage() ctfkit.Stage { return ctfkit.PrePlan }

func (p *pointerAnalyzer) Analyze(context.Context, ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return nil, nil
}

func TestRegistryRejectsDuplicateIDAndStage(t *testing.T) {
	r := ctfkit.NewRegistry()
	a := stubAnalyzer{id: "ctf.policy.tagging", stage: ctfkit.PostPlan}
	mustRegister(t, r, a)

	if err := r.Register(a); err == nil {
		t.Error("Register accepted the same (id, stage) pair twice, want an error")
	}
	if got := len(r.All()); got != 1 {
		t.Errorf("the rejected duplicate was recorded: All() has %d analyzers", got)
	}
}

func TestMustRegisterPanicsOnError(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustRegister did not panic on a rejected analyzer")
		}
	}()
	ctfkit.MustRegister(ctfkit.NewRegistry(), stubAnalyzer{id: "not-a-rule-id", stage: ctfkit.PrePlan})
}

func TestMustRegisterAcceptsValidAnalyzers(t *testing.T) {
	r := ctfkit.NewRegistry()
	ctfkit.MustRegister(r,
		stubAnalyzer{id: "ctf.coverage.module_source", stage: ctfkit.PrePlan},
		stubAnalyzer{id: "ctf.origin.provider", stage: ctfkit.PrePlan},
	)
	if got := len(r.All()); got != 2 {
		t.Errorf("All() returned %d analyzers, want 2", got)
	}
}

func ids(as []ctfkit.Analyzer) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.ID())
	}
	return out
}
