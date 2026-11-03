package tagging_test

import (
	"sort"
	"testing"

	"github.com/compliancetf/ctfkit/internal/analyzer/tagging"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Every rule the family registers needs a tool.driver.rules entry, and every
// entry has to name a rule the family can report. The SARIF renderer refuses a
// finding whose rule has no descriptor, so a rule added without one fails a
// run; a descriptor with no rule is dead text. The registry is keyed by
// (id, stage), so an id registered at two stages is counted once.
func TestDescriptorsCoverEveryRegisteredRule(t *testing.T) {
	r := ctfkit.NewRegistry()
	tagging.Register(r)

	registered := map[string]bool{}
	for _, a := range r.All() {
		registered[a.ID()] = true
	}

	described := map[string]bool{}
	for _, d := range tagging.Descriptors() {
		if described[d.ID] {
			t.Errorf("descriptor %s appears twice", d.ID)
		}
		described[d.ID] = true
		if d.ShortDescription == "" {
			t.Errorf("descriptor %s has no short description", d.ID)
		}
	}

	if got, want := keys(described), keys(registered); !equal(got, want) {
		t.Errorf("descriptor ids %v, registered rule ids %v", got, want)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
