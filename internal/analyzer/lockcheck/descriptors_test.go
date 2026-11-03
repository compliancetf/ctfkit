package lockcheck_test

import (
	"testing"

	"github.com/compliancetf/ctfkit/internal/analyzer/lockcheck"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Every registered rule has a descriptor and every descriptor a rule: the
// SARIF renderer refuses a finding whose rule has none.
func TestDescriptorsCoverEveryRegisteredRule(t *testing.T) {
	r := ctfkit.NewRegistry()
	lockcheck.Register(r)
	registered := map[string]bool{}
	for _, a := range r.All() {
		registered[a.ID()] = true
	}
	described := map[string]bool{}
	for _, d := range lockcheck.Descriptors() {
		if described[d.ID] || !registered[d.ID] || d.ShortDescription == "" {
			t.Errorf("descriptor %s is a duplicate, has no rule or has no text", d.ID)
		}
		described[d.ID] = true
	}
	if len(described) != len(registered) {
		t.Errorf("%d descriptors for %d rules", len(described), len(registered))
	}
}

// Without wrapped types or without root lock files the rules are silent: a
// scan of an explicit file list reads no lock files.
func TestSilentWithoutInputs(t *testing.T) {
	r := ctfkit.NewRegistry()
	lockcheck.Register(r)
	archive := &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{{Path: "main.tf", Bytes: []byte("terraform {\n  backend \"local\" {}\n}\n")}}}
	for _, in := range []ctfkit.AnalyzerInput{
		{Stage: ctfkit.PrePlan, Config: archive, Settings: ctfkit.Settings{WrappedProviders: []string{"aws"}}},
		{Stage: ctfkit.PrePlan, Config: &ctfkit.ConfigArchive{Files: archive.Files, Lockfiles: map[string]*ctfkit.Lockfile{}}},
	} {
		for _, a := range r.All() {
			got, err := a.Analyze(t.Context(), in)
			if err != nil || len(got) != 0 {
				t.Errorf("%s: %d findings, err %v; want none", a.ID(), len(got), err)
			}
		}
	}
}
