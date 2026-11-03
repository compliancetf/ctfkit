package graph_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/graph"
	"github.com/compliancetf/ctfkit/internal/rulepack"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

const fixtures = "../../testdata/fixtures/graph"

// cases is every graph fixture, the cross-module/ ones included, and
// the identity catalog pairs (lb-waf-*, vpc-flow-log*); a directory not
// listed here fails TestFixtureList, so a case cannot be added without being
// run.
var cases = []string{
	"arn-name-alias", "catalog-miss", "conditional", "contradiction",
	"cross-module/count-module", "cross-module/equal-root-configs", "cross-module/for-each-module",
	"cross-module/inherited-default", "cross-module/iterated-provider", "cross-module/module-output-known",
	"cross-module/module-output-unknown", "cross-module/nested-modules", "cross-module/passed-alias",
	"cross-module/passed-alias-mismatch", "cross-module/unresolved-module-key",
	"direct-ref-known", "direct-ref-unknown", "equal-identity", "format-ref-known",
	"format-ref-unknown", "identity-conflict", "lb-waf-association", "lb-waf-association-unknown",
	"linked-and-undecidable", "missing", "repeated", "unknown-scope", "unresolved-ref",
	"vpc-flow-log", "vpc-flow-log-alias", "wildcard",
}

func controls(t *testing.T) []graph.Control {
	t.Helper()
	var out []graph.Control
	if err := json.Unmarshal(read(t, filepath.Join(fixtures, "controls.json")), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadPlan(t *testing.T, c string) *tfjson.Plan {
	t.Helper()
	var p tfjson.Plan
	if err := json.Unmarshal(read(t, filepath.Join(fixtures, c, "plan.json")), &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

// TestFixtures decides each fixture plan and compares the decisions with
// expected.json byte for byte.
func TestFixtures(t *testing.T) {
	ctls := controls(t)
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			got, err := graph.Evaluate(loadPlan(t, c), nil, ctls)
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			want := read(t, filepath.Join(fixtures, c, "expected.json"))
			if !bytes.Equal(append(b, '\n'), want) {
				t.Errorf("decisions:\n%s\nwant:\n%s", b, want)
			}
		})
	}
}

// TestReferencesNeverLink: the direct and format() cases carry identical
// references lists, and the contradiction case references the target while
// its value names another bucket; only values decide.
func TestReferencesNeverLink(t *testing.T) {
	refs := func(c string) string {
		p := loadPlan(t, c)
		for _, r := range p.Config.RootModule.Resources {
			if e := r.Expressions["bucket"]; r.Type == "aws_s3_bucket_public_access_block" && e != nil && e.ExpressionData != nil {
				return strings.Join(e.References, ",")
			}
		}
		return ""
	}
	// The cross-module pairs reference a module output identically; only the
	// value and the provider configuration decide.
	for _, pair := range [][2]string{
		{"direct-ref-known", "format-ref-known"}, {"direct-ref-unknown", "format-ref-unknown"},
		{"cross-module/module-output-known", "cross-module/module-output-unknown"},
		{"cross-module/passed-alias", "cross-module/passed-alias-mismatch"},
	} {
		if a, b := refs(pair[0]), refs(pair[1]); a == "" || a != b {
			t.Errorf("%s and %s references differ: %q, %q", pair[0], pair[1], a, b)
		}
	}
	if refs("contradiction") != refs("direct-ref-known") {
		t.Error("contradiction must reference the target exactly like direct-ref-known")
	}
}

func TestFixtureList(t *testing.T) {
	entries, err := os.ReadDir(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() != "cross-module" {
			dirs = append(dirs, e.Name())
			continue
		}
		sub, err := os.ReadDir(filepath.Join(fixtures, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range sub {
			if s.IsDir() {
				dirs = append(dirs, e.Name()+"/"+s.Name())
			}
		}
	}
	if strings.Join(dirs, " ") != strings.Join(cases, " ") {
		t.Errorf("fixture directories %v, cases %v", dirs, cases)
	}
}

// TestAnalyzer runs the analyzer value: one finding per decision, the level
// following the control's action, the reason in the message.
func TestAnalyzer(t *testing.T) {
	ctls := controls(t)
	r := ctfkit.NewRegistry()
	if err := r.Register(graph.Companion{Controls: ctls}); err != nil {
		t.Fatal(err)
	}
	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, PlanJSON: loadPlan(t, "linked-and-undecidable")}
	got, err := graph.Companion{Controls: ctls}.Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Level != ctfkit.LevelError || got[0].Kind != ctfkit.KindOpen ||
		got[0].Message.Text != "aws_s3_bucket.a: s3_bucket_public_access_block_present not_evaluable (wildcard)" ||
		got[0].Discriminator != "s3_bucket_public_access_block_present" {
		t.Fatalf("findings %+v", got)
	}
	ctls[0].Action = "warn"
	in.PlanJSON = loadPlan(t, "equal-identity")
	if got, err = (graph.Companion{Controls: ctls}).Analyze(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Level != ctfkit.LevelNote || got[0].Kind != ctfkit.KindPass {
		t.Fatalf("pass findings %+v", got)
	}
	in.PlanJSON = loadPlan(t, "missing")
	if got, err = (graph.Companion{Controls: ctls}).Analyze(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Level != ctfkit.LevelWarning || got[0].Kind != ctfkit.KindFail {
		t.Fatalf("warn findings %+v", got)
	}
	// Two versions of one control id keep their own action.
	deny := ctls[0]
	deny.Version, deny.Action = "2.0.0", "deny"
	if got, err = (graph.Companion{Controls: append(ctls, deny)}).Analyze(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Level != ctfkit.LevelWarning || got[1].Level != ctfkit.LevelError {
		t.Fatalf("per-version action findings %+v", got)
	}
}

// TestUnsupportedControls: a control Evaluate cannot judge is an error, never
// a pass; the deletion guard is left to the verdict builder.
func TestUnsupportedControls(t *testing.T) {
	plan := loadPlan(t, "equal-identity")
	expr := "companion.block_public_acls"
	for name, mutate := range map[string]func(*graph.Control){
		"unknown rule":   func(c *graph.Control) { c.Graph.Rule = "companion_linked" },
		"companion_expr": func(c *graph.Control) { c.Graph.CompanionExpr = &expr },
		"no link_attr":   func(c *graph.Control) { c.Graph.LinkAttr = "" },
		"no companion":   func(c *graph.Control) { c.Graph.CompanionType = "" },
		"no target type": func(c *graph.Control) { c.ResourceType = "" },
	} {
		ctls := controls(t)
		mutate(&ctls[0])
		if _, err := graph.Evaluate(plan, nil, ctls); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	ctls := controls(t)
	got, err := graph.Evaluate(plan, nil, ctls[1:])
	if err != nil || len(got) != 0 {
		t.Fatalf("deletion guard: %v %v", got, err)
	}
}

// TestScopeRegion: a known, differing region means not linked; an unknown
// one means the scope is not established.
func TestScopeRegion(t *testing.T) {
	ctls := controls(t)
	for region, want := range map[string]string{"eu-central-1": "fail", "": "not_evaluable"} {
		plan := loadPlan(t, "equal-identity")
		for _, rc := range plan.ResourceChanges {
			if rc.Type != "aws_s3_bucket_public_access_block" {
				continue
			}
			after := rc.Change.After.(map[string]any)
			unknown := rc.Change.AfterUnknown.(map[string]any)
			if region == "" {
				delete(after, "region")
				unknown["region"] = true
			} else {
				after["region"] = region
			}
		}
		got, err := graph.Evaluate(plan, nil, ctls)
		if err != nil || len(got) != 1 || got[0].Result != want || want == "not_evaluable" && got[0].Reason != "ambiguous_reference" {
			t.Errorf("region %q: %+v %v, want %s", region, got, err, want)
		}
	}
}

// TestBucketVersioningLinks: a versioning resource names its bucket like a
// public access block does, so the equal-identity pair links with it as the
// companion, and the arn-name-alias pair is identity_alias.
func TestBucketVersioningLinks(t *testing.T) {
	ctl := controls(t)[0]
	ctl.ID, ctl.Graph.CompanionType = "s3_bucket_versioning_present", "aws_s3_bucket_versioning"
	for c, want := range map[string]string{"equal-identity": "pass", "arn-name-alias": "not_evaluable"} {
		plan := loadPlan(t, c)
		for _, rc := range plan.ResourceChanges {
			if rc.Type == "aws_s3_bucket_public_access_block" {
				rc.Type = "aws_s3_bucket_versioning"
			}
		}
		got, err := graph.Evaluate(plan, nil, []graph.Control{ctl})
		if err != nil || len(got) != 1 || got[0].Result != want || want == "not_evaluable" && got[0].Reason != graph.ReasonIdentityAlias {
			t.Errorf("%s: %+v %v, want %s", c, got, err, want)
		}
	}
}

// TestIdentityCatalogInSchema holds every attribute the identity catalog and
// its scope name to the pack's provider schema snapshot.
func TestIdentityCatalogInSchema(t *testing.T) {
	for _, p := range rulepack.Embedded().Packs() {
		if p.Identities == nil {
			continue
		}
		snap, err := rulepack.ReadSnapshot(os.DirFS("../rulepack"), p.Name)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range p.Identities.Attributes() {
			typ, attr, _ := strings.Cut(key, ".")
			if kind, ok := snap.Kind(typ, attr); !ok || kind != rulepack.KindString {
				t.Errorf("%s: %s is not a string attribute of %s %s", p.Name, key, snap.Provider, snap.Version)
			}
			for _, s := range p.Identities.Scope {
				if kind, ok := snap.Kind(typ, s); !ok || kind != rulepack.KindString {
					t.Errorf("%s: scope attribute %s.%s is not a string", p.Name, typ, s)
				}
			}
		}
	}
}

// TestInstanceKeys: a string instance key holding "]" or an escaped quote
// still maps the instance to its configuration block, so the pair links.
func TestInstanceKeys(t *testing.T) {
	ctls := controls(t)
	for _, key := range []string{`[0]`, `["logs]prod"]`, `["a\"]b"]`} {
		plan := loadPlan(t, "equal-identity")
		for _, rc := range plan.ResourceChanges {
			rc.Address += key
		}
		got, err := graph.Evaluate(plan, nil, ctls)
		if err != nil || len(got) != 1 || got[0].Result != "pass" {
			t.Errorf("key %s: %+v %v", key, got, err)
		}
	}
}

// TestIteratedNestedOnly: an each.* reference only inside a nested provider
// block (assume_role) still marks the configuration iterated, and a constant
// top-level region does not make it one configuration.
func TestIteratedNestedOnly(t *testing.T) {
	plan := loadPlan(t, "cross-module/iterated-provider")
	exprs := plan.Config.ProviderConfigs["aws.by_region"].Expressions
	exprs["region"] = &tfjson.Expression{ExpressionData: &tfjson.ExpressionData{ConstantValue: "eu-west-1"}}
	if len(exprs["assume_role"].NestedBlocks) == 0 {
		t.Fatal("fixture lost its nested assume_role block")
	}
	got, err := graph.Evaluate(plan, nil, controls(t))
	if err != nil || len(got) != 1 || got[0].Reason != graph.ReasonAmbiguousReference {
		t.Errorf("%+v %v", got, err)
	}
	delete(exprs, "assume_role")
	if got, err = graph.Evaluate(plan, nil, controls(t)); err != nil || len(got) != 1 || got[0].Result != "pass" {
		t.Errorf("without each.*: %+v %v", got, err)
	}
}
