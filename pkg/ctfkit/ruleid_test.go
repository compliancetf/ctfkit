package ctfkit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// collectRuleIDPatterns walks a decoded schema and returns every "pattern"
// value that constrains a rule id, wherever it sits. cff-1 keeps it in
// $defs.ruleId and spacelift-1 writes it inline, and a third copy appearing
// anywhere in either file should show up here rather than go unnoticed.
func collectRuleIDPatterns(node interface{}, out *[]string) {
	switch n := node.(type) {
	case map[string]interface{}:
		if p, ok := n["pattern"].(string); ok && strings.Contains(p, "ctf") {
			*out = append(*out, p)
		}
		for _, v := range n {
			collectRuleIDPatterns(v, out)
		}
	case []interface{}:
		for _, v := range n {
			collectRuleIDPatterns(v, out)
		}
	}
}

// The schemas are the published contract for the wire shape, so the SDK's
// regexp has to be the same string, not merely a compatible one. Comparing the
// source text rather than behavior is deliberate: two regexps that accept the
// same ids today can drift apart on the next edit to either side.
func TestRuleIDPatternMatchesPublishedSchemas(t *testing.T) {
	for _, name := range []string{"cff-1.schema.json", "spacelift-1.schema.json"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "schema", name)
			data, err := os.ReadFile(path) //nolint:gosec // a fixed path to a repo file
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			var doc interface{}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}

			var found []string
			collectRuleIDPatterns(doc, &found)
			if len(found) == 0 {
				t.Fatalf("%s declares no rule id pattern; this test is no longer checking anything", name)
			}

			for _, p := range found {
				if p != ctfkit.RuleIDPattern.String() {
					t.Errorf("%s constrains a rule id with %q, but ctfkit.RuleIDPattern is %q",
						name, p, ctfkit.RuleIDPattern.String())
				}
			}
		})
	}
}

func TestRuleIDPatternAcceptsTheIdsTheSchemasAccept(t *testing.T) {
	tests := []struct {
		id   string
		want bool
		why  string
	}{
		{"ctf.coverage.manifest_missing", true, "a shipped id"},
		{"ctf.module.source_not_pinned", true, "a shipped id"},
		{"ctf.coverage.delegation.unresolved", true, "four segments: the schemas allow one or more trailing segments"},
		{"ctf.a.b.c.d.e", true, "any number of trailing segments"},
		{"ctf.s3_bucket.enabled", false, "an underscore in the family segment, which both schemas forbid"},
		{"ctf.coverage", false, "no check segment"},
		{"ctf.", false, "empty family"},
		{"ctf", false, "no segments at all"},
		{"CTF.coverage.x", false, "upper case"},
		{"other.coverage.x", false, "not the ctf namespace"},
		{"ctf.coverage.Manifest", false, "upper case in the check segment"},
		{"ctf.coverage.manifest-missing", false, "a hyphen, which neither schema allows"},
		{" ctf.coverage.x", false, "leading space"},
		{"ctf.coverage.x ", false, "trailing space"},
		{"ctf.coverage.x\nctf.coverage.y", false, "a newline cannot smuggle a second id past the anchors"},
	}

	for _, tt := range tests {
		if got := ctfkit.RuleIDPattern.MatchString(tt.id); got != tt.want {
			t.Errorf("RuleIDPattern.MatchString(%q) = %v, want %v (%s)", tt.id, got, tt.want, tt.why)
		}
	}
}

// Finding.Validate and Registry.Register are the two boundaries that enforce
// the id format, so both have to move with the pattern rather than keep a
// private copy.
func TestValidateAndRegisterAgreeWithTheExportedPattern(t *testing.T) {
	ids := []string{
		"ctf.coverage.manifest_missing",
		"ctf.coverage.delegation.unresolved",
		"ctf.s3_bucket.enabled",
		"ctf.coverage",
	}

	for _, id := range ids {
		want := ctfkit.RuleIDPattern.MatchString(id)

		f := validFindingWithRuleID(id)
		if got := f.Validate() == nil; got != want {
			t.Errorf("Finding.Validate() accepted=%v for %q, want %v", got, id, want)
		}

		r := ctfkit.NewRegistry()
		err := r.Register(stubAnalyzer{id: id, stage: ctfkit.PostInit})
		if got := err == nil; got != want {
			t.Errorf("Registry.Register() accepted=%v for %q, want %v (err=%v)", got, id, want, err)
		}
	}
}

func TestRuleIDPatternIsAnchored(t *testing.T) {
	p := ctfkit.RuleIDPattern.String()
	if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") {
		t.Errorf("RuleIDPattern = %q, want it anchored at both ends", p)
	}
}

// validFindingWithRuleID builds a finding by hand rather than through
// NewFinding, which checks the id itself and so would reject the invalid cases
// before Validate ever saw them.
func validFindingWithRuleID(id string) ctfkit.Finding {
	return ctfkit.Finding{
		RuleID:  id,
		Level:   ctfkit.LevelError,
		Kind:    ctfkit.KindFail,
		Message: ctfkit.Message{Text: "a finding"},
		Props:   ctfkit.Properties{Schema: "1.0", Stage: ctfkit.PostInit},
	}
}
