// Package markdown renders the Markdown projection of `ctfkit report`: the
// README section a reader opens to see which controls the served modules in
// one configuration enforce, and what this document does not prove.
//
// The table schema is frozen at v1. There is no template language and no
// option that changes a column, because two customers whose reports differ in
// shape cannot be compared, and an auditor reading a second report has to
// learn it again. Per-customer prose lives outside the markers, where this
// package never writes.
//
// Everything here is bytes. The output is compared byte for byte against the
// recorded fixture pack, and against an existing report generator, so a
// change to a separator, a join string or a blank line is a change to the
// frozen table and is made in the specification appendix first.
//
// The renderer decides nothing: it is handed a coverage record, the findings,
// the obligations and the run context, and it orders and formats them. It
// reads no file, calls no clock and produces no finding.
package markdown

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/inventory"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Markers that delimit the generated section by default. Custom markers such
// as a COMPLIANCE_REPORT_START and COMPLIANCE_REPORT_END pair keep working by
// being passed in instead.
const (
	// DefaultStartMarker opens the generated section.
	DefaultStartMarker = "<!-- CTFKIT_REPORT_START -->"
	// DefaultEndMarker closes it.
	DefaultEndMarker = "<!-- CTFKIT_REPORT_END -->"
)

// Errors this package returns. They are the environment errors of the
// command's exit contract: an operator named a README and the region was not
// there to replace.
var (
	// ErrNoInventory is returned when Render is given no coverage record. A
	// document rendered from nothing would read as a configuration that
	// instantiates nothing, which is a different statement.
	ErrNoInventory = errors.New("markdown: no inventory to render")
	// ErrStartMarkerMissing is returned when the README carries no start
	// marker. The section is never appended at the end of a file instead:
	// where the report goes is the README owner's decision.
	ErrStartMarkerMissing = errors.New("markdown: start marker not found in readme")
	// ErrEndMarkerMissing is returned when the start marker has no end marker
	// after it.
	ErrEndMarkerMissing = errors.New("markdown: end marker not found after the start marker in readme")
)

// Markers is the pair that delimits the generated section. A zero value, or a
// field left empty, takes the default for that field.
type Markers struct {
	// Start opens the section.
	Start string
	// End closes it.
	End string
}

// resolve fills in the defaults.
func (m Markers) resolve() Markers {
	if m.Start == "" {
		m.Start = DefaultStartMarker
	}
	if m.End == "" {
		m.End = DefaultEndMarker
	}

	return m
}

// Input is everything the Markdown projection renders. It is the same material
// the receipt renders, which is what keeps the two documents from disagreeing.
type Input struct {
	// Inventory is the coverage record of the root. It may not be nil.
	Inventory *inventory.Inventory
	// Findings are the findings of this run, in analyzer emission order. The
	// renderer orders them by level and keeps that order within a level, so a
	// caller need not sort first.
	Findings ctfkit.Findings
	// Obligations are the does-not-prove entries of every manifest read, in
	// any order and with repeats. The renderer takes the first prose it sees
	// for a token and never re-cases it: the wording is the producer's.
	Obligations []ctfkit.ManifestObligation
	// Metadata is the run context the first line records.
	Metadata ctfkit.RunMetadata
	// Tests is the imported test document, nil when the operator imported
	// none. The imported-tests line is emitted only when it is set.
	Tests *ctfkit.TestRun
	// Stage is the stage the run was made at, recorded in the first line.
	Stage ctfkit.Stage
	// Root is the path of the analyzed root as the document should record it.
	Root string
	// Watermark is the optional banner text of --watermark, empty for none.
	// When set it ends the context line.
	Watermark string
	// Markers delimit the generated section. The zero value is the default
	// pair.
	Markers Markers
}

// levelRank orders the findings table: errors first, then warnings, then
// notes. An unknown level sorts last rather than being dropped, because a
// finding a renderer does not recognize is still a finding.
var levelRank = map[string]int{
	ctfkit.LevelError:   0,
	ctfkit.LevelWarning: 1,
	ctfkit.LevelNote:    2,
}

// Render writes the Markdown projection of in to w.
func Render(w io.Writer, in Input) error {
	if in.Inventory == nil {
		return ErrNoInventory
	}

	markers := in.Markers.resolve()

	blocks := []string{"## Compliance coverage", contextLine(in)}
	var empty []*inventory.ServedBuild
	for i := range in.Inventory.Builds {
		build := &in.Inventory.Builds[i]
		if len(build.Controls) == 0 {
			empty = append(empty, build)
			continue
		}
		blocks = append(blocks, buildBlocks(build)...)
	}
	blocks = append(blocks, zeroControlBlocks(empty)...)
	// The section sits after every build rather than inside one: an instance
	// with no manifest belongs to no build, so repeating it per build would
	// claim each build failed to carry it. No fixture has two builds, so this
	// placement is a decision of this package, recorded in the specification's
	// discrepancy list.
	blocks = append(blocks, missingManifestBlocks(in.Inventory.InstancesWithoutManifest)...)
	blocks = append(blocks, "### Resources declared by this configuration", rootResourceSentence(in.Inventory.RootResources))
	if in.Tests != nil {
		blocks = append(blocks, importedTestsLine(in.Tests))
	}

	findings := sortedFindings(in.Findings)
	blocks = append(blocks, findingsBlocks(findings)...)
	blocks = append(blocks, obligationBlocks(in.Obligations)...)
	blocks = append(blocks, verdictLine(findings), markers.End)

	document := markers.Start + "\n" + strings.Join(blocks, "\n\n") + "\n"

	_, err := io.WriteString(w, document)

	return err
}

// Inject replaces the marked region of readme with report, which carries the
// same markers. Everything outside the region is kept byte for byte: the prose
// around the section belongs to whoever wrote the README.
func Inject(readme, report []byte, markers Markers) ([]byte, error) {
	resolved := markers.resolve()

	start := bytes.Index(readme, []byte(resolved.Start))
	if start < 0 {
		return nil, fmt.Errorf("%w: %s", ErrStartMarkerMissing, resolved.Start)
	}

	after := start + len(resolved.Start)
	end := bytes.Index(readme[after:], []byte(resolved.End))
	if end < 0 {
		return nil, fmt.Errorf("%w: %s", ErrEndMarkerMissing, resolved.End)
	}
	endOfRegion := after + end + len(resolved.End)

	// The region ends at the end marker itself, so the newline that closed
	// that line in the README stays; the report's own trailing newlines would
	// otherwise add a blank line on every run.
	section := bytes.TrimRight(report, "\n")

	out := make([]byte, 0, len(readme)-(endOfRegion-start)+len(section))
	out = append(out, readme[:start]...)
	out = append(out, section...)
	out = append(out, readme[endOfRegion:]...)

	return out, nil
}

// inline escapes a value that comes from the configuration, a manifest or a
// finding before it lands in a code span, a table cell or prose. The report is
// posted to job summaries and pull request comments, where a module key or
// source chosen by a pull request author must not add markdown, HTML, a
// mention or a table column. The characters it rewrites never occur in the
// recorded fixtures, so the frozen bytes are unchanged; a hostile value renders
// as visible entities instead. Inside a code span the entities show as written,
// which is the point: they are inert.
var inline = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	"`", "&#96;",
	"|", `\|`,
	"@", "&#64;",
).Replace

// contextLine is the one line the parity harness strips, because it is the one
// line two generators of the same report cannot agree on.
func contextLine(in Input) string {
	line := fmt.Sprintf(
		"Generated by ctfkit report (stage %s) for `%s` at %s, run `%s` on %s, commit `%s`.",
		in.Stage,
		inline(in.Root),
		in.Metadata.Now.UTC().Format(time.RFC3339),
		inline(in.Metadata.RunID),
		inline(in.Metadata.Platform),
		inline(in.Metadata.Commit),
	)
	if in.Watermark != "" {
		line += " " + inline(in.Watermark)
	}
	return line
}

// supportingMarker follows a clause identifier the manifest marked as
// supporting evidence (manifest schema 3.4), and supportingLegend says once per
// build what it means. A build with no such clause renders neither, so a
// manifest before 3.4 renders the frozen v1 bytes unchanged.
const (
	supportingMarker = " (supporting)"
	supportingLegend = "A clause marked (supporting) is partial or indirect evidence for that clause, not full enforcement of it."
)

// buildBlocks renders one served build: the header, the coverage table, the
// supporting-clause legend when a cell carries the marker, and the superseded
// and degraded records when the build has them.
func buildBlocks(build *inventory.ServedBuild) []string {
	blocks := []string{buildHeader(build), coverageTable(build)}

	if hasSupporting(build) {
		blocks = append(blocks, supportingLegend)
	}

	if len(build.Superseded) > 0 {
		blocks = append(blocks,
			"Superseded controls (a stricter control stood in for a weaker one):",
			supersededBullets(build.Superseded))
	}
	if len(build.Degraded) > 0 {
		blocks = append(blocks, "Degraded posture for this build: "+inline(strings.Join(build.Degraded, ", ")))
	}

	return blocks
}

// buildHeader names the instances, the served build and the three counts.
func buildHeader(build *inventory.ServedBuild) string {
	enforced, delegated := 0, 0
	for _, control := range build.Controls {
		switch control.Status {
		case inventory.ControlEnforced:
			enforced++
		case inventory.ControlDelegated:
			delegated++
		case inventory.ControlNotApplicable, inventory.ControlWaived:
			// Neither is a row of this table: the header counts what the
			// build answers for in this configuration.
		}
	}

	return fmt.Sprintf("### %s - %s %s - %d enforced, %d delegated, %s",
		inline(strings.Join(build.Keys, ", ")), inline(build.Source), inline(build.Version),
		enforced, delegated, notApplicablePhrase(build.NotApplicable))
}

// notApplicablePhrase distinguishes a build that evaluated the catalog and
// found nothing inapplicable from one that never recorded the classification.
// Rendering the second as "0 not applicable" would assert the first.
func notApplicablePhrase(count *int) string {
	if count == nil {
		return "not applicable not recorded"
	}

	return fmt.Sprintf("%d not applicable", *count)
}

// coverageTable is the frozen v1 table: four fixed columns and one column per
// framework the build reports against.
func coverageTable(build *inventory.ServedBuild) string {
	header := []string{"Control", "Requirement enforced", "Satisfied in"}
	for _, id := range build.Frameworks {
		header = append(header, inline(frameworkName(build, id)))
	}

	rows := make([]string, 0, len(build.Controls)+2)
	rows = append(rows, row(header), separator(len(header)))
	for _, control := range build.Controls {
		cells := []string{inline(control.ID), inline(control.Name), inline(satisfiedIn(control))}
		for _, id := range build.Frameworks {
			cells = append(cells, inline(clauseIdentifiers(control.ClausesByFramework[id], control.SupportingClausesByFramework[id])))
		}
		rows = append(rows, row(cells))
	}

	return strings.Join(rows, "\n")
}

// frameworkName is the display name the manifest gave the framework, falling
// back to the id when the manifest named none, so a column always has a head.
func frameworkName(build *inventory.ServedBuild, id string) string {
	if name, ok := build.FrameworkNames[id]; ok {
		return name
	}

	return id
}

// satisfiedIn names where the evidence is, or says plainly that this
// configuration holds none.
func satisfiedIn(control inventory.Control) string {
	if control.Status == inventory.ControlDelegated {
		return "delegated, not in this configuration"
	}

	return strings.Join(control.SatisfiedIn, ", ")
}

// clauseIdentifiers shortens each whole clause sentence to its identifier by
// catalog.ClauseIdentifier, which is what fits a table cell, and marks the
// ones listed in supporting. The receipt keeps the sentence. Two sentences
// that share an identifier render twice, the supporting one marked, which
// never presents the supporting one as full.
//
// A control with no clause in a listed framework renders an empty cell. No
// fixture has one, so the empty cell is a decision of this package rather than
// a frozen byte.
func clauseIdentifiers(clauses, supporting []string) string {
	identifiers := make([]string, 0, len(clauses))
	for _, clause := range clauses {
		id := catalog.ClauseIdentifier(clause)
		if id == "" {
			continue
		}
		if slices.Contains(supporting, clause) {
			id += supportingMarker
		}
		identifiers = append(identifiers, id)
	}

	return strings.Join(identifiers, ", ")
}

// hasSupporting reports whether any cell of the build's table carries the
// supporting marker.
func hasSupporting(build *inventory.ServedBuild) bool {
	for _, control := range build.Controls {
		for _, id := range build.Frameworks {
			for _, clause := range control.SupportingClausesByFramework[id] {
				if catalog.ClauseIdentifier(clause) != "" {
					return true
				}
			}
		}
	}

	return false
}

func row(cells []string) string {
	return "| " + strings.Join(cells, " | ") + " |"
}

func separator(columns int) string {
	return "|" + strings.Repeat("---|", columns)
}

// supersededBullets lists each replaced control under the stricter one that
// stood in for it, ordered by the weaker id.
func supersededBullets(superseded map[string]string) string {
	weaker := make([]string, 0, len(superseded))
	for id := range superseded {
		weaker = append(weaker, id)
	}
	sort.Strings(weaker)

	bullets := make([]string, 0, len(weaker))
	for _, id := range weaker {
		bullets = append(bullets, fmt.Sprintf("- `%s` superseded by `%s`", inline(id), inline(superseded[id])))
	}

	return strings.Join(bullets, "\n")
}

// missingManifestBlocks lists the instances this report does not cover. They
// are never omitted: a reader who cannot see them reads the rest as the whole
// configuration.
func missingManifestBlocks(instances []inventory.Instance) []string {
	if len(instances) == 0 {
		return nil
	}

	bullets := make([]string, 0, len(instances))
	for _, instance := range instances {
		bullets = append(bullets, fmt.Sprintf("- `%s` (%s)", inline(instance.Key), inline(instance.Source)))
	}

	return []string{
		"### Instances without a manifest",
		"These are listed as not-evidence. They are not covered by this report.",
		strings.Join(bullets, "\n"),
	}
}

// zeroControlBlocks lists the served builds whose manifests name no controls
// for their scope, such as a subtree IAM role. An empty table under a build
// header would read as a rendering fault, and a count of zero enforced reads
// as coverage checked and found wanting; neither is what the manifest says.
func zeroControlBlocks(builds []*inventory.ServedBuild) []string {
	if len(builds) == 0 {
		return nil
	}

	bullets := make([]string, 0, len(builds))
	for _, build := range builds {
		bullets = append(bullets, fmt.Sprintf("- `%s` (%s %s)",
			inline(strings.Join(build.Keys, ", ")), inline(build.Source), inline(build.Version)))
	}

	return []string{
		"### Instances whose manifest lists no controls",
		"Their manifests list no controls for their scope. This is not evidence of coverage.",
		strings.Join(bullets, "\n"),
	}
}

// rootResourceSentence says what the root declares on its own account, which
// no served module answers for. It is one sentence, never a table.
func rootResourceSentence(resources inventory.RootResources) string {
	if resources.Declared == 0 {
		return "This configuration declares no resources of its own."
	}

	switch resources.Coverage {
	case inventory.CoverageUnattested:
		return fmt.Sprintf("%d resource block(s), unattested: no imported test run covers them.", resources.Declared)
	case inventory.CoverageTested:
		// No fixture records this branch, so the wording is this package's
		// and parallels the unattested sentence. A test is evidence of
		// behavior, never of a built-in control, and the sentence says so.
		return fmt.Sprintf("%d resource block(s), tested: an imported test run covers them, which is evidence of behavior and not of an enforced control.",
			resources.Declared)
	}

	// attested and not-applicable with resources declared: neither is
	// reachable from the record this package is given, and neither has
	// recorded bytes. The coverage word itself is the honest sentence.
	return fmt.Sprintf("%d resource block(s), %s.", resources.Declared, resources.Coverage)
}

// importedTestsLine reports what the test runner said, and nothing more: the
// counts are the runner's own summary.
func importedTestsLine(tests *ctfkit.TestRun) string {
	return fmt.Sprintf("Imported test results: %d run(s), %d passed, %d failed, %d errored, %d skipped.",
		tests.Runs, tests.Passed, tests.Failed, tests.Errored, tests.Skipped)
}

// sortedFindings orders by level and keeps analyzer emission order within a
// level. It copies rather than sorting the caller's slice, because the same
// findings are rendered again by the other projections.
func sortedFindings(findings ctfkit.Findings) ctfkit.Findings {
	ordered := make(ctfkit.Findings, len(findings))
	copy(ordered, findings)
	sort.SliceStable(ordered, func(i, j int) bool {
		return rankOf(ordered[i].Level) < rankOf(ordered[j].Level)
	})

	return ordered
}

func rankOf(level string) int {
	if rank, ok := levelRank[level]; ok {
		return rank
	}

	return len(levelRank)
}

// findingsBlocks renders the findings table, which is absent when the run
// produced none.
func findingsBlocks(findings ctfkit.Findings) []string {
	if len(findings) == 0 {
		return nil
	}

	rows := make([]string, 0, len(findings)+2)
	rows = append(rows, row([]string{"Level", "Rule", "Detail"}), separator(3))
	for _, finding := range findings {
		rows = append(rows, row([]string{
			inline(finding.Level),
			"`" + inline(finding.RuleID) + "`",
			inline(finding.Message.Text),
		}))
	}

	return []string{"### Findings", strings.Join(rows, "\n")}
}

// obligationBlocks lists what the manifests read explicitly do not prove, one
// bullet per distinct token. The prose is the producer's, including its
// capitalization: re-casing it would edit a statement this document quotes.
func obligationBlocks(obligations []ctfkit.ManifestObligation) []string {
	prose := make(map[string]string, len(obligations))
	tokens := make([]string, 0, len(obligations))
	for _, obligation := range obligations {
		if _, seen := prose[obligation.Token]; seen {
			continue
		}
		prose[obligation.Token] = obligation.ConsumerObligation
		tokens = append(tokens, obligation.Token)
	}
	sort.Strings(tokens)

	blocks := []string{"### Consumer obligations"}
	if len(tokens) == 0 {
		return blocks
	}

	bullets := make([]string, 0, len(tokens))
	for _, token := range tokens {
		bullets = append(bullets, fmt.Sprintf("- `%s`: %s", inline(token), inline(prose[token])))
	}

	return append(blocks, strings.Join(bullets, "\n"))
}

// verdictLine states the verdict of the run: fail when any unsuppressed
// error-level finding exists, pass otherwise. It does not track --fail-on, so
// a shadow-mode run that exits 0 still records what it found.
func verdictLine(findings ctfkit.Findings) string {
	for _, finding := range findings {
		if finding.Level != ctfkit.LevelError {
			continue
		}
		if finding.Suppressed() {
			continue
		}

		return "Verdict: fail."
	}

	return "Verdict: pass."
}
