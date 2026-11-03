package sensitivechange_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/internal/analyzer/sensitivechange"
	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

const fixtureRoot = "../../../testdata/fixtures/plan"

// rulePrefix is the prefix every rule id of the family shares.
const rulePrefix = "ctf.risk.sensitive_change"

// The two secrets fixture 16 plants, named in the fixture README.
var canaries = []string{"CANARY-50c488e396915cedcc5b650db695f0d2", "canary-pass-8fdf8eaa189601fd"}

// TestFixtures runs the family over every recorded plan fixture. 11 to 15
// must equal their expected results for this family, less ctf.evidence, which
// the command adds after the analyzers have run. Every other fixture, the
// secret canary included, must produce no finding from this family: the
// analyzer stays inside its five classes.
func TestFixtures(t *testing.T) {
	cat := fixtureCatalog(t)
	entries, err := os.ReadDir(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			got := analyze(t, loadInput(t, name, cat))
			want := []any{}
			if name >= "11" && name < "16" {
				want = expectedResults(t, name)
				if len(want) == 0 {
					t.Fatalf("%s records no result for this family", name)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("findings do not match expected/findings.sarif\n got: %s\nwant: %s", indent(t, got), indent(t, want))
			}
		})
	}
}

// TestDescriptorsMatchFixtures checks every rule descriptor a fixture records
// against Descriptors, and that the family covers all five rule ids.
func TestDescriptorsMatchFixtures(t *testing.T) {
	byID := map[string]string{}
	for _, d := range sensitivechange.Descriptors() {
		byID[d.ID] = d.ShortDescription + "|" + d.Level
	}
	if len(byID) != 5 {
		t.Errorf("got %d descriptors, want 5", len(byID))
	}

	seen := map[string]bool{}
	for _, name := range []string{
		"11-sensitive-public-exposure", "12-sensitive-wildcard-iam", "13-sensitive-audit-log-removal",
		"14-sensitive-encryption-disablement", "15-sensitive-destructive-stateful",
	} {
		for _, r := range recorded(t, name).Runs[0].Tool.Driver.Rules {
			seen[r.ID] = true
			if got, want := byID[r.ID], r.ShortDescription.Text+"|"+r.DefaultConfiguration.Level; got != want {
				t.Errorf("%s: descriptor %s = %q, want %q", name, r.ID, got, want)
			}
		}
	}
	if len(seen) != 5 {
		t.Errorf("fixtures record %d of the five descriptors", len(seen))
	}
}

// TestCanaryAbsentFromSARIF renders what the family finds in fixture 16
// through the SARIF renderer and greps the bytes for both planted secrets.
// Fixture 16 alone produces no finding from this family, so the same plan is
// run again with the canary database made public, which fires a finding on
// the very resource that holds the password: the positive control that proves
// the grep ran over a document with something in it.
func TestCanaryAbsentFromSARIF(t *testing.T) {
	in := loadInput(t, "16-secret-canary", fixtureCatalog(t))
	if n := len(run(t, in)); n != 0 {
		t.Fatalf("fixture 16 produced %d findings from this family, want 0", n)
	}
	assertNoCanary(t, render(t, in))

	raw, err := os.ReadFile(filepath.Join(fixtureRoot, "16-secret-canary", "input", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range canaries {
		if !strings.Contains(string(raw), c) {
			t.Fatalf("plan.json no longer holds the canary %s", c)
		}
	}
	for _, rc := range in.PlanJSON.ResourceChanges {
		if rc.Address != "aws_db_instance.app" {
			continue
		}
		after := rc.Change.After.(map[string]any)
		after["publicly_accessible"] = true
	}
	findings := run(t, in)
	if len(findings) != 1 || findings[0].RuleID != rulePrefix+"_public_exposure" {
		t.Fatalf("positive control: got %d findings, want the one public exposure", len(findings))
	}
	assertNoCanary(t, render(t, in))
}

func assertNoCanary(t *testing.T, doc []byte) {
	t.Helper()
	for _, c := range canaries {
		if strings.Contains(string(doc), c) {
			t.Errorf("rendered SARIF carries the canary %s", c)
		}
	}
}

func render(t *testing.T, in ctfkit.AnalyzerInput) []byte {
	t.Helper()
	findings := run(t, in)
	ctfkit.SortFindings(findings)
	doc, err := sarif.Render(sarif.Input{
		Tool:     sarif.Tool{Name: "ctfkit", Version: "1.0.0"},
		Rules:    sensitivechange.Descriptors(),
		Findings: findings,
		Metadata: ctfkit.RunMetadata{RunID: "ctfkit-fixture-run", Commit: strings.Repeat("0", 40), Now: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatalf("sarif.Render: %v", err)
	}
	return doc
}

func loadInput(t *testing.T, name string, cat ctfkit.ControlCatalog) ctfkit.AnalyzerInput {
	t.Helper()
	dir := filepath.Join(fixtureRoot, name, "input")
	plan, err := loader.LoadPlan(filepath.Join(dir, "plan.json"))
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}
	config, err := loader.LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, Config: config, PlanJSON: plan, Catalog: cat}
}

// fixtureCatalog is the release catalog embedded in the binary, the one the
// fixtures are recorded against.
func fixtureCatalog(t *testing.T) ctfkit.ControlCatalog {
	t.Helper()
	return catalog.Embedded()
}

// run executes the family in registration order and checks each finding the
// way the runner does.
func run(t *testing.T, in ctfkit.AnalyzerInput) ctfkit.Findings {
	t.Helper()
	registry := ctfkit.NewRegistry()
	sensitivechange.Register(registry)

	var findings ctfkit.Findings
	for _, a := range registry.ByStage(ctfkit.PostPlan) {
		produced, err := a.Analyze(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: %v", a.ID(), err)
		}
		for _, f := range produced {
			checked, validateErr := f.ValidateFor(a.ID(), ctfkit.PostPlan, in.Catalog)
			if validateErr != nil {
				t.Fatalf("%s: %v", a.ID(), validateErr)
			}
			findings = append(findings, checked)
		}
	}
	return findings
}

// analyze returns the family's findings, sorted, as decoded result objects.
func analyze(t *testing.T, in ctfkit.AnalyzerInput) []any {
	t.Helper()
	findings := run(t, in)
	ctfkit.SortFindings(findings)

	out := make([]any, 0, len(findings))
	for _, f := range findings {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshaling %s: %v", f.RuleID, err)
		}
		var v any
		if decodeErr := json.Unmarshal(raw, &v); decodeErr != nil {
			t.Fatalf("decoding: %v", decodeErr)
		}
		out = append(out, v)
	}
	return out
}

type recordedDoc struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID               string `json:"id"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []map[string]any `json:"results"`
	} `json:"runs"`
}

func recorded(t *testing.T, name string) recordedDoc {
	t.Helper()
	path := filepath.Join(fixtureRoot, name, "expected", "findings.sarif")
	raw, err := os.ReadFile(path) //nolint:gosec // a committed fixture path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc recordedDoc
	if parseErr := json.Unmarshal(raw, &doc); parseErr != nil {
		t.Fatalf("parsing %s: %v", path, parseErr)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("%s has %d runs, want 1", path, len(doc.Runs))
	}
	return doc
}

// expectedResults is this family's results in a recorded fixture, less
// ctf.evidence.
func expectedResults(t *testing.T, name string) []any {
	t.Helper()
	out := []any{}
	for _, r := range recorded(t, name).Runs[0].Results {
		if !strings.HasPrefix(r["ruleId"].(string), rulePrefix) {
			continue
		}
		delete(r["properties"].(map[string]any), ctfkit.PropertyEvidence)
		// partialFingerprints is written by the SARIF renderer, not the analyzer.
		delete(r, "partialFingerprints")
		out = append(out, any(r))
	}
	return out
}

func indent(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("indenting: %v", err)
	}
	return raw
}
