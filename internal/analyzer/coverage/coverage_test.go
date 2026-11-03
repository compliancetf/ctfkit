package coverage_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/compliancetf/ctfkit/internal/analyzer/coverage"
	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// fixtureRoot is the recorded fixture pack, which is the oracle for every
// rule of this family.
const fixtureRoot = "../../../testdata/fixtures/report"

// runContextKeys are the result-level property keys the command adds after
// the analyzer has run. An analyzer never sets them, so a comparison against
// a recorded projection drops them from the expected side rather than
// inventing them on the produced side.
var runContextKeys = []string{"ctf.evidence"}

// TestFixtures is the table the family is built against: every recorded case
// must produce exactly the results array its expected SARIF records.
func TestFixtures(t *testing.T) {
	cases := []string{
		"served-leaf",
		"delegated-with-sibling",
		"delegated-without-sibling",
		"blueprint-wrapper",
		"degraded-build",
		"missing-manifest",
		"helper-module",
		"example-multi-instance",
		"supporting-clauses",
	}

	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			in := loadFixture(t, name)
			produced := analyze(t, in)
			want := expectedResults(t, name)

			if !reflect.DeepEqual(produced, want) {
				t.Errorf("findings do not match %s/expected/findings.sarif\n got: %s\nwant: %s",
					name, mustIndent(t, produced), mustIndent(t, want))
			}
		})
	}
}

// TestSchemaStubNeverReachesTheAnalyzer records that ctf.coverage.manifest_schema
// is not a finding: the loader refuses an unsupported schema major and the
// command exits 2, so no analyzer of this family ever sees the tree.
func TestSchemaStubNeverReachesTheAnalyzer(t *testing.T) {
	input := filepath.Join(fixtureRoot, "schema-4-stub", "input")

	inv, err := loader.LoadModules(input)
	if err == nil {
		t.Fatalf("LoadModules accepted an unsupported schema major and returned %d instance(s)", len(inv.Instances))
	}

	registry := ctfkit.NewRegistry()
	coverage.Register(registry)
	if a := registry.ByID("ctf.coverage.manifest_schema", ctfkit.PostInit); a != nil {
		t.Errorf("ctf.coverage.manifest_schema is registered as an analyzer; it is the loader's exit 2 path")
	}
}

// loadFixture reads one recorded case the way the command will: configuration,
// module inventory, the imported test document when the case has one, and the
// catalog that holds the control ids the manifests name.
func loadFixture(t *testing.T, name string) ctfkit.AnalyzerInput {
	t.Helper()

	input := filepath.Join(fixtureRoot, name, "input")

	config, err := loader.LoadConfig(input)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", input, err)
	}
	modules, err := loader.LoadModules(input)
	if err != nil {
		t.Fatalf("LoadModules(%s): %v", input, err)
	}

	testsPath := filepath.Join(input, "tests.json")
	if _, statErr := os.Stat(testsPath); statErr == nil {
		run, importErr := loader.ImportTests(testsPath)
		if importErr != nil {
			t.Fatalf("ImportTests(%s): %v", testsPath, importErr)
		}
		modules.Tests = run
	}

	return ctfkit.AnalyzerInput{
		Stage:   ctfkit.PostInit,
		Config:  config,
		Modules: modules,
		Catalog: fixtureCatalog(t),
	}
}

// fixtureCatalog is the catalog the recorded manifests join against: the
// embedded release catalog, which carries every control id the fixtures name
// and spells framework ids the way the manifests do (soc_2).
func fixtureCatalog(t *testing.T) ctfkit.ControlCatalog {
	t.Helper()

	return catalog.Embedded()
}

// analyze runs every rule of the family in registration order, checks each
// finding the way the runner will, and puts the results in the order every
// projection emits them: by level descending, then analyzer emission order.
func analyze(t *testing.T, in ctfkit.AnalyzerInput) []any {
	t.Helper()

	registry := ctfkit.NewRegistry()
	coverage.Register(registry)

	var findings ctfkit.Findings
	for _, a := range registry.ByStage(ctfkit.PostInit) {
		produced, err := a.Analyze(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: %v", a.ID(), err)
		}
		for _, f := range produced {
			checked, validateErr := f.ValidateFor(a.ID(), ctfkit.PostInit, in.Catalog)
			if validateErr != nil {
				t.Fatalf("%s: %v", a.ID(), validateErr)
			}
			findings = append(findings, checked)
		}
	}

	// SortFindings is the stable order the runner sorts a whole run into; the
	// projections then present the findings by level. Applying both here
	// leaves an order that does not depend on which rule ran first.
	ctfkit.SortFindings(findings)
	sort.SliceStable(findings, func(i, j int) bool {
		return levelRank(findings[i].Level) < levelRank(findings[j].Level)
	})

	out := make([]any, 0, len(findings))
	for _, f := range findings {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshaling %s: %v", f.RuleID, err)
		}
		out = append(out, decode(t, raw))
	}
	return out
}

// levelRank orders the SARIF levels the way every projection presents them:
// error first, then warning, then note.
func levelRank(level string) int {
	switch level {
	case ctfkit.LevelError:
		return 0
	case ctfkit.LevelWarning:
		return 1
	default:
		return 2
	}
}

// expectedResults is the results array of a recorded SARIF file with the run
// context the command adds stripped from each result.
func expectedResults(t *testing.T, name string) []any {
	t.Helper()

	path := filepath.Join(fixtureRoot, name, "expected", "findings.sarif")
	raw, err := os.ReadFile(path) //nolint:gosec // a committed fixture path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	var document struct {
		Runs []struct {
			Results []map[string]any `json:"results"`
		} `json:"runs"`
	}
	if unmarshalErr := json.Unmarshal(raw, &document); unmarshalErr != nil {
		t.Fatalf("parsing %s: %v", path, unmarshalErr)
	}
	if len(document.Runs) != 1 {
		t.Fatalf("%s has %d runs, want exactly 1", path, len(document.Runs))
	}

	out := make([]any, 0, len(document.Runs[0].Results))
	for _, result := range document.Runs[0].Results {
		properties, ok := result["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s has a result with no property bag", path)
		}
		for _, key := range runContextKeys {
			delete(properties, key)
		}
		// partialFingerprints is written by the SARIF renderer, not the analyzer.
		delete(result, "partialFingerprints")
		out = append(out, any(result))
	}
	return out
}

// decode turns marshaled JSON back into the generic shape the recorded file
// parses to, so the two sides compare as documents rather than as Go types.
func decode(t *testing.T, raw []byte) any {
	t.Helper()

	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return value
}

func mustIndent(t *testing.T, value any) []byte {
	t.Helper()

	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("indenting: %v", err)
	}
	return raw
}
