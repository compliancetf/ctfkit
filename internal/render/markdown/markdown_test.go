package markdown

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/internal/inventory"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// update rewrites the fixture oracles from the current output. The F1 fixture
// pack is the frozen v1 table, so running this on v1 is a specification
// change rather than a test fix: the appendix and the bytes are cut together,
// or not at all.
var update = flag.Bool("update", false,
	"rewrite the report.md oracles of the fixture pack; cuts a new frozen table, never fixes a test")

// repoRoot is where the fixture pack and the gitignored parity fixtures live,
// relative to this package.
const repoRoot = "../../.."

// fixtureCases are the directories of the F1 pack. schema-4-stub renders
// nothing: the loader exits on its schema major before a projection is reached,
// so the case asserts the absence of an oracle rather than bytes.
var fixtureCases = []string{
	"blueprint-wrapper",
	"degraded-build",
	"delegated-with-sibling",
	"delegated-without-sibling",
	"example-multi-instance",
	"helper-module",
	"missing-manifest",
	"schema-4-stub",
	"served-leaf",
	"supporting-clauses",
}

// TestMarkdownGolden is the byte oracle: every fixture of the F1 pack renders
// to its recorded expected/report.md, unchanged.
func TestMarkdownGolden(t *testing.T) {
	for _, name := range fixtureCases {
		t.Run(name, func(t *testing.T) {
			oracle := filepath.Join(repoRoot, "testdata", "fixtures", "report", name, "expected", "report.md")
			want, err := os.ReadFile(oracle)
			if errors.Is(err, os.ErrNotExist) {
				// schema-4-stub. A case with no rendered oracle is a case the
				// command rejects before rendering, and the renderer owes it
				// nothing; asserting that keeps the case from being forgotten.
				assertNoRenderableInput(t, name)

				return
			}
			if err != nil {
				t.Fatalf("read oracle: %v", err)
			}

			var got bytes.Buffer
			if renderErr := Render(&got, fixtureInput(t, name)); renderErr != nil {
				t.Fatalf("Render() error = %v", renderErr)
			}

			if *update {
				if writeErr := os.WriteFile(oracle, got.Bytes(), 0o600); writeErr != nil {
					t.Fatalf("update oracle: %v", writeErr)
				}

				return
			}

			if !bytes.Equal(got.Bytes(), want) {
				t.Errorf("rendered bytes differ from %s\n--- got ---\n%s\n--- want ---\n%s",
					oracle, got.String(), want)
			}
		})
	}
}

// TestMarkdownSupportingIsAdditive pins that the supporting marker and its
// legend appear only when a clause is marked supporting: a schema 3.4 build
// that classified and hedged nothing renders the same bytes as the 3.3 build
// it came from, and so does a build whose manifest does not classify.
func TestMarkdownSupportingIsAdditive(t *testing.T) {
	render := func(in Input) string {
		t.Helper()
		var out bytes.Buffer
		if err := Render(&out, in); err != nil {
			t.Fatalf("Render() error = %v", err)
		}
		return out.String()
	}

	baseline := render(fixtureInput(t, "delegated-without-sibling"))

	nothingHedged := fixtureInput(t, "delegated-without-sibling")
	for i := range nothingHedged.Inventory.Builds[0].Controls {
		nothingHedged.Inventory.Builds[0].Controls[i].SupportingClausesByFramework = map[string][]string{"soc_2": {}}
	}
	if got := render(nothingHedged); got != baseline {
		t.Errorf("a build that hedged nothing changed the table\n--- got ---\n%s\n--- want ---\n%s", got, baseline)
	}
	if strings.Contains(baseline, "supporting") {
		t.Errorf("a manifest that does not classify renders a supporting marker:\n%s", baseline)
	}
}

// TestMarkdownParity is the parity run against fixtures kept outside this
// repository (testdata/local, gitignored), so the test states why it did
// nothing rather than passing silently on an empty set.
func TestMarkdownParity(t *testing.T) {
	local := filepath.Join(repoRoot, "testdata", "local")
	entries, err := os.ReadDir(local)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("testdata/local absent: the parity fixtures are not in this checkout, so parity was not run")
	}
	if err != nil {
		t.Fatalf("read testdata/local: %v", err)
	}

	cases := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		oracle := filepath.Join(local, entry.Name(), "expected", "report.md")
		if _, statErr := os.Stat(oracle); statErr != nil {
			continue
		}
		cases++

		t.Run(entry.Name(), func(t *testing.T) {
			want, readErr := os.ReadFile(oracle)
			if readErr != nil {
				t.Fatalf("read oracle: %v", readErr)
			}

			root := filepath.Join(local, entry.Name(), "input")
			var got bytes.Buffer
			if renderErr := Render(&got, inputFrom(t, root,
				path.Join("testdata/local", entry.Name(), "input"),
				filepath.Join(local, entry.Name(), "expected", "findings.sarif"))); renderErr != nil {
				t.Fatalf("Render() error = %v", renderErr)
			}

			// The generated-by line carries the run context, which the two
			// generators cannot agree on. It is the one line parity strips.
			if stripGenerated(got.String()) != stripGenerated(string(want)) {
				t.Errorf("parity differs for %s\n--- got ---\n%s\n--- want ---\n%s",
					entry.Name(), got.String(), want)
			}
		})
	}

	if cases == 0 {
		t.Skip("testdata/local holds no case with expected/report.md, so parity was not run")
	}
}

// TestMarkdownNoPercent pins that the report never states coverage as a
// percentage, because a percentage of a control set nobody agreed on is a score
// and this document has none.
func TestMarkdownNoPercent(t *testing.T) {
	for _, name := range []string{"served-leaf", "degraded-build"} {
		t.Run(name, func(t *testing.T) {
			var got bytes.Buffer
			if err := Render(&got, fixtureInput(t, name)); err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			if strings.Contains(got.String(), "%") {
				t.Errorf("rendered report contains a percent sign, which the frozen table has no cell for")
			}
		})
	}
}

// TestRenderWatermarkBanner covers --watermark: with none the context line
// ends at the commit, and a banner follows it verbatim when set.
func TestRenderWatermarkBanner(t *testing.T) {
	cases := map[string]struct {
		watermark string
		want      string
	}{
		"none":   {watermark: "", want: "0000000000000000000000000000000000000000`."},
		"banner": {watermark: "internal use only", want: "0000000000000000000000000000000000000000`. internal use only"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := fixtureInput(t, "served-leaf")
			in.Watermark = tc.watermark

			var got bytes.Buffer
			if err := Render(&got, in); err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			line := contextLineOf(t, got.String())
			if !strings.HasSuffix(line, tc.want) {
				t.Errorf("context line = %q, want it to end with %q", line, tc.want)
			}
		})
	}
}

// contextLineOf returns the one line the parity harness strips.
func contextLineOf(t *testing.T, document string) string {
	t.Helper()

	for _, line := range strings.Split(document, "\n") {
		if strings.HasPrefix(line, "Generated by ctfkit report") {
			return line
		}
	}
	t.Fatalf("no context line in:\n%s", document)

	return ""
}

// TestRenderKeepsUnknownFindingLevel pins the fallback the level order
// documents: a level this release does not know sorts last and is still
// reported, because a finding a renderer cannot rank is still a finding.
func TestRenderKeepsUnknownFindingLevel(t *testing.T) {
	in := fixtureInput(t, "served-leaf")
	in.Findings = ctfkit.Findings{
		{RuleID: "ctf.test.unknown", Level: "critical", Message: ctfkit.Message{Text: "from a later release"}},
		{RuleID: "ctf.test.note", Level: ctfkit.LevelNote, Message: ctfkit.Message{Text: "known"}},
	}

	var got bytes.Buffer
	if err := Render(&got, in); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	want := []string{ctfkit.LevelNote, "critical"}
	if levels := findingLevels(got.String()); !slices.Equal(levels, want) {
		t.Errorf("findings table levels = %v, want %v", levels, want)
	}
}

// TestRenderSortsFindingsByLevel proves the findings table orders by level
// rather than by the order the caller happened to hand them over: the fixture
// SARIF is already in the rendered order, so the golden test alone cannot tell
// a sort from a copy. Within a level the caller's order is kept, which is the
// analyzer's emission order, so this case asserts the level column only.
func TestRenderSortsFindingsByLevel(t *testing.T) {
	in := fixtureInput(t, "degraded-build")
	reversed := make(ctfkit.Findings, 0, len(in.Findings))
	for i := len(in.Findings) - 1; i >= 0; i-- {
		reversed = append(reversed, in.Findings[i])
	}
	in.Findings = reversed

	var got bytes.Buffer
	if err := Render(&got, in); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	want := []string{
		ctfkit.LevelError,
		ctfkit.LevelWarning,
		ctfkit.LevelWarning,
		ctfkit.LevelNote,
	}
	if levels := findingLevels(got.String()); !slices.Equal(levels, want) {
		t.Errorf("findings table levels = %v, want %v", levels, want)
	}
}

// findingLevels reads the Level column back out of the rendered findings
// table.
func findingLevels(document string) []string {
	var levels []string
	inTable := false
	for _, line := range strings.Split(document, "\n") {
		switch {
		case line == "### Findings":
			inTable = true
		case !inTable, !strings.HasPrefix(line, "| "):
			continue
		case strings.HasPrefix(line, "| Level "):
			continue
		default:
			levels = append(levels, strings.Split(strings.TrimPrefix(line, "| "), " |")[0])
		}
	}

	return levels
}

// TestRenderVerdictTracksErrorFindings pins the verdict rule the body states:
// an error-level finding fails the run, a warning or a note does not, and a
// suppressed error does not either.
func TestRenderVerdictTracksErrorFindings(t *testing.T) {
	base := fixtureInput(t, "served-leaf")

	cases := map[string]struct {
		findings ctfkit.Findings
		want     string
	}{
		"none":             {findings: nil, want: "Verdict: pass."},
		"warning":          {findings: ctfkit.Findings{{RuleID: "r", Level: ctfkit.LevelWarning}}, want: "Verdict: pass."},
		"error":            {findings: ctfkit.Findings{{RuleID: "r", Level: ctfkit.LevelError}}, want: "Verdict: fail."},
		"suppressed error": {findings: ctfkit.Findings{suppressed()}, want: "Verdict: pass."},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := base
			in.Findings = tc.findings

			var got bytes.Buffer
			if err := Render(&got, in); err != nil {
				t.Fatalf("Render() error = %v", err)
			}
			if !strings.Contains(got.String(), tc.want) {
				t.Errorf("want %q in:\n%s", tc.want, got.String())
			}
		})
	}
}

func suppressed() ctfkit.Finding {
	f := ctfkit.Finding{RuleID: "r", Level: ctfkit.LevelError}
	f.Props.Exception = &ctfkit.ExceptionProperty{Allowed: true}

	return f
}

// TestInjectReplacesMarkedRegion covers the --readme path: the report replaces
// everything between the markers, and the prose on either side is untouched.
func TestInjectReplacesMarkedRegion(t *testing.T) {
	readme := []byte("# Title\n\nOur own prose.\n\n" +
		DefaultStartMarker + "\nstale\n" + DefaultEndMarker + "\n\nMore prose.\n")
	report := []byte(DefaultStartMarker + "\n## Compliance coverage\n\n" + DefaultEndMarker + "\n")

	got, err := Inject(readme, report, Markers{})
	if err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	want := "# Title\n\nOur own prose.\n\n" +
		DefaultStartMarker + "\n## Compliance coverage\n\n" + DefaultEndMarker + "\n\nMore prose.\n"
	if string(got) != want {
		t.Errorf("Inject() =\n%s\nwant\n%s", got, want)
	}
}

// TestInjectCustomMarkers is custom markers such as
// COMPLIANCE_REPORT_START/END, which keep working through --markers.
func TestInjectCustomMarkers(t *testing.T) {
	markers := Markers{Start: "<!-- COMPLIANCE_REPORT_START -->", End: "<!-- COMPLIANCE_REPORT_END -->"}
	readme := []byte("before\n" + markers.Start + "\nold\n" + markers.End + "\nafter\n")
	report := []byte(markers.Start + "\nnew\n" + markers.End + "\n")

	got, err := Inject(readme, report, markers)
	if err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	want := "before\n" + markers.Start + "\nnew\n" + markers.End + "\nafter\n"
	if string(got) != want {
		t.Errorf("Inject() =\n%s\nwant\n%s", got, want)
	}
}

// TestInjectMarkerErrors: a README the operator named and a marker pair that is
// not there is an environment error, never a silent append at the end of
// somebody's README.
func TestInjectMarkerErrors(t *testing.T) {
	report := []byte(DefaultStartMarker + "\n" + DefaultEndMarker + "\n")

	cases := map[string]struct {
		readme string
		want   error
	}{
		"no markers": {readme: "# Title\n", want: ErrStartMarkerMissing},
		"start only": {readme: DefaultStartMarker + "\n", want: ErrEndMarkerMissing},
		"end before start": {
			readme: DefaultEndMarker + "\n" + DefaultStartMarker + "\n",
			want:   ErrEndMarkerMissing,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Inject([]byte(tc.readme), report, Markers{})
			if !errors.Is(err, tc.want) {
				t.Errorf("Inject() error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestRenderUsesConfiguredMarkers proves the marker pair reaches the rendered
// bytes, so a report written with --markers injects into the region those same
// markers delimit.
func TestRenderUsesConfiguredMarkers(t *testing.T) {
	in := fixtureInput(t, "served-leaf")
	in.Markers = Markers{Start: "<!-- COMPLIANCE_REPORT_START -->", End: "<!-- COMPLIANCE_REPORT_END -->"}

	var got bytes.Buffer
	if err := Render(&got, in); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	if !strings.HasPrefix(got.String(), in.Markers.Start+"\n## Compliance coverage\n") {
		t.Errorf("rendered report does not open with the configured start marker:\n%s", got.String())
	}
	if !strings.HasSuffix(got.String(), "\n"+in.Markers.End+"\n") {
		t.Errorf("rendered report does not close with the configured end marker:\n%s", got.String())
	}
}

// TestRenderRejectsNilInventory: a renderer with nothing to render reports it
// rather than writing a document that reads as an empty configuration.
func TestRenderRejectsNilInventory(t *testing.T) {
	if err := Render(&bytes.Buffer{}, Input{}); !errors.Is(err, ErrNoInventory) {
		t.Errorf("Render() error = %v, want %v", err, ErrNoInventory)
	}
}

// fixtureInput builds the renderer input of one F1 case the way the command
// will: the loaded module inventory and configuration through inventory.Build,
// the findings from the case's own recorded SARIF, and the fixed fixture run
// context the context line records.
func fixtureInput(t *testing.T, name string) Input {
	t.Helper()

	dir := filepath.Join(repoRoot, "testdata", "fixtures", "report", name, "input")

	return inputFrom(t, dir,
		path.Join("testdata/fixtures/report", name, "input"),
		filepath.Join(repoRoot, "testdata", "fixtures", "report", name, "expected", "findings.sarif"))
}

// inputFrom loads one recorded root. subject is the path the context line
// records, which is repository relative and POSIX, not the path this test had
// to walk to reach the directory.
func inputFrom(t *testing.T, dir, subject, sarifPath string) Input {
	t.Helper()

	modules, err := loader.LoadModules(dir)
	if err != nil {
		t.Fatalf("LoadModules(%s): %v", dir, err)
	}
	config, err := loader.LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", dir, err)
	}
	if testsFile := filepath.Join(dir, "tests.json"); fileExists(testsFile) {
		run, importErr := loader.ImportTests(testsFile)
		if importErr != nil {
			t.Fatalf("ImportTests(%s): %v", testsFile, importErr)
		}
		modules.Tests = run
	}

	record, err := inventory.Build(modules, config)
	if err != nil {
		t.Fatalf("inventory.Build: %v", err)
	}

	return Input{
		Inventory:   record,
		Findings:    readSARIFFindings(t, sarifPath),
		Obligations: obligationsOf(modules),
		Tests:       modules.Tests,
		Stage:       ctfkit.PostInit,
		Root:        subject,
		Metadata: ctfkit.RunMetadata{
			RunID:    "ctfkit-fixture-run",
			Platform: "local",
			Commit:   strings.Repeat("0", 40),
			Now:      time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
		},
	}
}

// assertNoRenderableInput states what a case with no rendered oracle means:
// the loader rejects it, so there is no inventory for a renderer to be given.
func assertNoRenderableInput(t *testing.T, name string) {
	t.Helper()

	dir := filepath.Join(repoRoot, "testdata", "fixtures", "report", name, "input")
	if _, err := loader.LoadModules(dir); err == nil {
		t.Errorf("fixture %s has no expected/report.md, but its modules loaded without error", name)
	}
}

// readSARIFFindings reads back the level, rule and message of each recorded
// result. It reads the case's own oracle rather than running the analyzer,
// which is built in a sibling change.
func readSARIFFindings(t *testing.T, sarifPath string) ctfkit.Findings {
	t.Helper()

	raw, err := os.ReadFile(sarifPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read %s: %v", sarifPath, err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Kind    string `json:"kind"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", sarifPath, err)
	}
	if len(doc.Runs) == 0 {
		return nil
	}

	findings := make(ctfkit.Findings, 0, len(doc.Runs[0].Results))
	for _, result := range doc.Runs[0].Results {
		findings = append(findings, ctfkit.Finding{
			RuleID:  result.RuleID,
			Level:   result.Level,
			Kind:    result.Kind,
			Message: ctfkit.Message{Text: result.Message.Text},
		})
	}

	return findings
}

// obligationsOf collects every does-not-prove entry of every manifest read, in
// the order the instances were loaded. The renderer is what de-duplicates and
// sorts them.
func obligationsOf(modules *ctfkit.ModuleInventory) []ctfkit.ManifestObligation {
	var obligations []ctfkit.ManifestObligation
	for _, instance := range modules.Instances {
		if instance.Manifest == nil {
			continue
		}
		obligations = append(obligations, instance.Manifest.Scope.DoesNotProve...)
	}

	return obligations
}

func fileExists(path string) bool {
	info, err := os.Stat(path)

	return err == nil && !info.IsDir()
}

// stripGenerated drops the one line the parity harness does not compare.
func stripGenerated(document string) string {
	lines := strings.Split(document, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, "Generated by ctfkit report") ||
			strings.HasPrefix(line, "Generated by compliance_report") {
			continue
		}
		kept = append(kept, line)
	}

	return strings.Join(kept, "\n")
}

// TestRenderListsZeroControlBuildsWithoutATable covers the section no fixture
// records: a served build whose manifest lists no controls for its scope, such
// as a subtree IAM role, gets no empty table. Its keys are listed once after
// the builds, as not-evidence.
func TestRenderListsZeroControlBuildsWithoutATable(t *testing.T) {
	in := fixtureInput(t, "served-leaf")
	inv := *in.Inventory
	inv.Builds = append(slices.Clone(inv.Builds), inventory.ServedBuild{
		Keys:    []string{"replication_policy", "replication_role"},
		Source:  "bobthecorp.compliance.tf/terraform-aws-modules/iam/aws",
		Version: "6.8.0",
	})
	in.Inventory = &inv

	var got bytes.Buffer
	if err := Render(&got, in); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	document := got.String()

	if strings.Contains(document, "### replication_policy") {
		t.Error("a zero-control build rendered its own build section")
	}
	want := "### Instances whose manifest lists no controls\n\n" +
		"Their manifests list no controls for their scope. This is not evidence of coverage.\n\n" +
		"- `replication_policy, replication_role` (bobthecorp.compliance.tf/terraform-aws-modules/iam/aws 6.8.0)\n"
	if !strings.Contains(document, want) {
		t.Errorf("zero-control section missing; got:\n%s", document)
	}
}

// TestRenderEscapesHostileValues covers values a pull request author controls:
// a module key and source, and a finding message quoting them. The document is
// posted to job summaries and pull request comments, so none of them may close
// a code span, add a table column, open an HTML tag or mention a user.
func TestRenderEscapesHostileValues(t *testing.T) {
	const hostile = "evil` | <img src=x onerror=alert(1)> @octocat & done"
	const escaped = "evil&#96; \\| &lt;img src=x onerror=alert(1)&gt; &#64;octocat &amp; done"

	in := fixtureInput(t, "served-leaf")
	inv := *in.Inventory
	inv.Builds = append(slices.Clone(inv.Builds), inventory.ServedBuild{
		Keys:    []string{hostile},
		Source:  hostile,
		Version: "1.0.0",
	})
	in.Inventory = &inv
	in.Findings = ctfkit.Findings{
		{RuleID: "ctf.test.hostile", Level: ctfkit.LevelWarning, Message: ctfkit.Message{Text: hostile}},
	}

	var got bytes.Buffer
	if err := Render(&got, in); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	document := got.String()

	for _, raw := range []string{"<img", "@octocat", "evil`"} {
		if strings.Contains(document, raw) {
			t.Errorf("document carries %q unescaped:\n%s", raw, document)
		}
	}
	if want := "| warning | `ctf.test.hostile` | " + escaped + " |\n"; !strings.Contains(document, want) {
		t.Errorf("findings row missing or wrong; want %q in:\n%s", want, document)
	}
	if want := "- `" + escaped + "` (" + escaped + " 1.0.0)\n"; !strings.Contains(document, want) {
		t.Errorf("zero-control bullet missing or wrong; want %q in:\n%s", want, document)
	}
}
