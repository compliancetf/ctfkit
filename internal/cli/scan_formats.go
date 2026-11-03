package cli

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/internal/render/spacelift"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// scanRun is everything the scan projections read, gathered once.
type scanRun struct {
	stage     ctfkit.Stage
	findings  ctfkit.Findings
	metadata  ctfkit.RunMetadata
	catalog   ctfkit.CatalogVersion
	watermark string
	stale     string
	version   string
}

// writeScan renders every requested projection. SARIF is rendered first
// whatever was asked: it is the contract output, json embeds its results
// array, and a render failure there must stop the run before any file is
// written, so an analyzer defect never leaves a partial set of projections.
func (c *CLI) writeScan(cmd *cobra.Command, plan outputPlan, run scanRun) error {
	in := sarif.Input{
		Tool:      sarif.Tool{Name: "ctfkit", Version: run.version},
		Rules:     scanRules(),
		Findings:  run.findings,
		Metadata:  run.metadata,
		Catalog:   run.catalog,
		Watermark: run.watermark,
	}
	if run.stale != "" {
		in.Notifications = []sarif.Notification{{
			DescriptorID: staleDescriptorID,
			Level:        ctfkit.LevelNote,
			Text:         staleText(run.stale),
		}}
	}
	doc, err := sarif.Render(in)
	if err != nil {
		return categorized(categoryFinding, "%v", err)
	}

	bodies := map[string][]byte{formatSARIF: doc}
	for _, format := range plan.formats {
		var body []byte
		switch format {
		case formatJSON:
			body, err = renderScanJSON(doc, run)
		case formatText:
			body = renderScanText(run, false)
		case formatPretty:
			body = renderScanText(run, true)
		case formatJUnit:
			body, err = renderScanJUnit(run)
		case formatSpacelift:
			body, err = spacelift.Render(spacelift.Input{Stage: run.stage, Findings: run.findings, Watermark: run.watermark})
		}
		if err != nil {
			return categorized(categoryFinding, "%v", err)
		}
		if body != nil {
			bodies[format] = body
		}
	}

	// --out-dir is created, or refused when the path is not a directory,
	// before anything is written, and the Spacelift file goes last, so a run
	// that ends in exit 2 leaves no projection behind for a policy to read as
	// a verdict.
	if plan.dir != "" {
		if err = ensureOutDir(plan.dir); err != nil {
			return err
		}
	}
	for _, format := range plan.formats {
		if format == formatSpacelift {
			continue
		}
		if err = c.emit(cmd, plan, scanFileNames[format], bodies[format]); err != nil {
			return err
		}
	}
	if plan.wants(formatSpacelift) {
		if err = spacelift.WriteNamed(".", spacelift.ScanFileName, bodies[formatSpacelift]); err != nil {
			return inputError("%v", err)
		}
	}

	return nil
}

// renderScanJSON is {"watermark", "catalogVersion", "findingsDigest",
// "findings"} where findings is the CFF result array of the SARIF document,
// byte for byte the same objects, and findingsDigest is findingsDigest over
// the run's findings. watermark is present only when --watermark set a banner
// line.
func renderScanJSON(doc []byte, run scanRun) ([]byte, error) {
	var parsed struct {
		Runs []struct {
			Results json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil || len(parsed.Runs) != 1 {
		return nil, fmt.Errorf("json: reading the SARIF results back: %v", err)
	}
	results := parsed.Runs[0].Results
	if len(results) == 0 || string(results) == "null" {
		results = json.RawMessage("[]")
	}

	digest, err := findingsDigest(run.findings)
	if err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}

	out := struct {
		Watermark      string             `json:"watermark,omitempty"`
		CatalogVersion catalogJSON        `json:"catalogVersion"`
		FindingsDigest findingsDigestJSON `json:"findingsDigest"`
		Findings       json.RawMessage    `json:"findings"`
	}{run.watermark, catalogJSON{run.catalog.Version, run.catalog.Provenance},
		findingsDigestJSON{findingsDigestAlgorithm, digest}, results}

	// HTML escaping off, as in the SARIF document the findings come from.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	return buf.Bytes(), nil
}

type catalogJSON struct {
	Version string `json:"version"`
	Origin  string `json:"origin"`
}

// findingsDigestJSON is the findingsDigest member: the algorithm name first,
// so a reader knows how the value was computed before it compares one.
type findingsDigestJSON struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

// renderScanText is the text and pretty projection: one block per finding,
// the stale-catalog notice, a summary line, and the --watermark banner, when
// set, as the trailing block. Every field passes through clean, which strips escape sequences and
// control characters, so a crafted address or message cannot drive the
// terminal. pretty adds a colored level label and a remediation hint; color
// is off when NO_COLOR or --no-color is set.
func renderScanText(run scanRun, pretty bool) []byte {
	var b strings.Builder
	var errors, warnings, notes, suppressed int

	for _, f := range run.findings {
		switch {
		case f.Suppressed():
			suppressed++
		case f.Level == ctfkit.LevelError:
			errors++
		case f.Level == ctfkit.LevelWarning:
			warnings++
		default:
			notes++
		}

		level := strings.ToUpper(f.Level)
		if f.Suppressed() {
			level = "SUPPRESSED"
		}
		where := clean(findingLocation(f))

		if !pretty {
			fmt.Fprintf(&b, "%s %s %s %s: %s\n", level, clean(f.RuleID), clean(f.Subject()), where, clean(f.Message.Text))
			continue
		}

		fmt.Fprintf(&b, "%s %s\n", levelColor(f.Level, f.Suppressed())(fmt.Sprintf("%-10s", level)), clean(f.RuleID))
		fmt.Fprintf(&b, "  %s (%s)\n", clean(f.Subject()), where)
		fmt.Fprintf(&b, "  %s\n", clean(f.Message.Text))
		if r := f.Props.Remediation; r != nil && r.ModuleSource != "" {
			fix := clean(r.ModuleSource)
			if r.Version != "" {
				fix += " " + clean(r.Version)
			}
			fmt.Fprintf(&b, "  fix: use %s\n", fix)
		}
		if e := f.Props.Exception; e != nil {
			fmt.Fprintf(&b, "  exception: allowed=%t %s\n", e.Allowed, clean(e.Justification))
		}
		b.WriteString("\n")
	}

	if run.stale != "" {
		fmt.Fprintf(&b, "note: %s\n", clean(run.stale))
	}

	if len(run.findings) == 0 && pretty {
		b.WriteString("All checks passed: no findings.\n")
	} else {
		fmt.Fprintf(&b, "%d finding(s): %d error, %d warning, %d note, %d suppressed\n",
			len(run.findings), errors, warnings, notes, suppressed)
	}
	if run.catalog.Version == "" { // verify-lock reads no catalog
		fmt.Fprintf(&b, "stage %s\n", run.stage)
	} else {
		fmt.Fprintf(&b, "stage %s, catalog %s (%s)\n", run.stage, clean(run.catalog.Version), clean(run.catalog.Provenance))
	}

	if run.watermark != "" {
		b.WriteString("\n" + clean(run.watermark) + "\n")
	}

	return []byte(b.String())
}

// levelColor returns the coloring of a level label.
func levelColor(level string, suppressed bool) func(a ...interface{}) string {
	switch {
	case suppressed:
		return color.New(color.FgHiBlack).SprintFunc()
	case level == ctfkit.LevelError:
		return color.New(color.FgRed, color.Bold).SprintFunc()
	case level == ctfkit.LevelWarning:
		return color.New(color.FgYellow).SprintFunc()
	default:
		return color.New(color.FgCyan).SprintFunc()
	}
}

// findingLocation is uri:line of the first physical location, or "-".
func findingLocation(f ctfkit.Finding) string {
	for _, l := range f.Locations {
		if p := l.PhysicalLocation; p != nil {
			if p.Region != nil && p.Region.StartLine > 0 {
				return p.ArtifactLocation.URI + ":" + strconv.Itoa(p.Region.StartLine)
			}
			return p.ArtifactLocation.URI
		}
	}
	return "-"
}

// clean strips escape sequences, control characters and URL userinfo from a
// string bound for a terminal.
func clean(s string) string {
	return ctfkit.StripUserinfo(cleanWatermark(s))
}

// junit document. encoding/xml escapes every attribute and text node.
type junitSuites struct {
	XMLName xml.Name   `xml:"testsuites"`
	Suite   junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name       string          `xml:"name,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Skipped    int             `xml:"skipped,attr"`
	Properties []junitProperty `xml:"properties>property"`
	Cases      []junitCase     `xml:"testcase"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitCase struct {
	ClassName string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr,omitempty"`
}

// renderScanJUnit is one testcase per finding, a suppressed finding as
// skipped, and the catalog version, the stage and the --watermark banner,
// when set, as testsuite properties.
func renderScanJUnit(run scanRun) ([]byte, error) {
	suite := junitSuite{
		Name:  "ctfkit scan",
		Tests: len(run.findings),
		Properties: []junitProperty{
			{Name: "ctf.catalogVersion", Value: run.catalog.Version + " (" + run.catalog.Provenance + ")"},
			{Name: "ctf.stage", Value: string(run.stage)},
		},
	}
	if run.watermark != "" {
		suite.Properties = append(suite.Properties, junitProperty{Name: "ctf.watermark", Value: run.watermark})
	}
	for _, f := range run.findings {
		tc := junitCase{ClassName: f.RuleID, Name: f.Subject()}
		if f.Suppressed() {
			justification := ""
			if f.Props.Exception != nil {
				justification = f.Props.Exception.Justification
			}
			tc.Skipped = &junitSkipped{Message: justification}
			suite.Skipped++
		} else {
			tc.Failure = &junitFailure{Type: f.Level, Message: f.Message.Text, Text: findingLocation(f)}
			suite.Failures++
		}
		suite.Cases = append(suite.Cases, tc)
	}

	body, err := xml.MarshalIndent(junitSuites{Suite: suite}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("junit: %w", err)
	}
	return append([]byte(xml.Header), append(body, '\n')...), nil
}
