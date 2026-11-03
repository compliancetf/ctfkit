package ctfkit_test

import (
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

func TestStageRankIsWorkflowOrder(t *testing.T) {
	ordered := []ctfkit.Stage{
		ctfkit.PrePlan, ctfkit.PostInit, ctfkit.PostPlan, ctfkit.PreApply, ctfkit.PostApply,
	}
	for i, s := range ordered {
		if got := s.Rank(); got != i {
			t.Errorf("%s.Rank() = %d, want %d", s, got, i)
		}
	}

	// The reason Rank exists: the names sort alphabetically, which puts
	// post_apply before pre_plan, the opposite of the workflow order.
	if string(ctfkit.PostApply) >= string(ctfkit.PrePlan) {
		t.Error("stage names unexpectedly sort into workflow order; the Rank rationale needs revisiting")
	}
	if ctfkit.PostApply.Rank() <= ctfkit.PrePlan.Rank() {
		t.Error("Rank does not order post_apply after pre_plan")
	}
}

func TestStageRankUnknown(t *testing.T) {
	if got := ctfkit.Stage("post_destroy").Rank(); got != -1 {
		t.Errorf("unknown stage ranks %d, want -1", got)
	}
}

func TestParseStage(t *testing.T) {
	for _, want := range []ctfkit.Stage{
		ctfkit.PrePlan, ctfkit.PostInit, ctfkit.PostPlan, ctfkit.PreApply, ctfkit.PostApply,
	} {
		got, err := ctfkit.ParseStage(want.String())
		if err != nil {
			t.Errorf("ParseStage(%q) returned %v, want the stage", want, err)
			continue
		}
		if got != want {
			t.Errorf("ParseStage(%q) = %q, want %q", want, got, want)
		}
	}

	for _, name := range []string{"", "post_destroy", "Pre_Plan", "pre plan"} {
		if _, err := ctfkit.ParseStage(name); err == nil {
			t.Errorf("ParseStage(%q) accepted an unknown stage", name)
		}
	}
}
