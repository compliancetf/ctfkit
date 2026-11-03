package sarif_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// fingerprintBlock matches one result's partialFingerprints object as the
// renderer indents it.
var fingerprintBlock = regexp.MustCompile(`\n *"partialFingerprints": \{\n[^}]*\},`)

const (
	reportFixtures = "../../../testdata/fixtures/report"
	planFixtures   = "../../../testdata/fixtures/plan"
	schemaPath     = "../../../schema/cff-1.schema.json"
)

// toolName and toolVersion are what every recorded fixture carries. The
// version is the generator version, pinned at 1.0.0 in the fixture pack.
const (
	toolName    = "ctfkit"
	toolVersion = "1.0.0"
)

// reportRules is the rule table of the report specification (Appendix C), transcribed from
// the spec rather than read out of the fixture being asserted against. It is
// what makes the golden comparison an assertion about the frozen
// shortDescriptions and levels instead of a round trip through the oracle.
//
// It is deliberately unsorted and holds one rule no report fixture fires, so
// the golden files also pin that Render emits only the rules that fired and
// sorts them by id.
var reportRules = []sarif.RuleDescriptor{
	{
		ID:               "ctf.coverage.resource_unattested",
		ShortDescription: "The configuration declares its own resources and no imported test run covers them",
		Level:            ctfkit.LevelNote,
	},
	{
		ID:               "ctf.coverage.manifest_missing",
		ShortDescription: "An instantiated module has no compliancetf-manifest.json",
		Level:            ctfkit.LevelError,
	},
	{
		ID:               "ctf.coverage.delegation_unresolved",
		ShortDescription: "A delegated control has no instantiated sibling scope enforcing it",
		Level:            ctfkit.LevelWarning,
	},
	{
		ID:               "ctf.coverage.tests_failed",
		ShortDescription: "Imported test results report failed or errored runs",
		Level:            ctfkit.LevelError,
	},
	{
		ID:               "ctf.coverage.obligation_unknown",
		ShortDescription: "A manifest obligation token is not in the shipped list",
		Level:            ctfkit.LevelNote,
	},
	{
		ID:               "ctf.coverage.posture_degraded",
		ShortDescription: "The served build reports a degraded posture",
		Level:            ctfkit.LevelError,
	},
}

// TestRenderGolden renders every report fixture and compares the bytes with
// the recorded findings.sarif.
//
// The findings come from that same recorded document, because the analyzer
// that produces them for real is tested elsewhere. What the comparison therefore
// asserts is the run shape, the rule selection and ordering, the result key
// order, the run-level watermark and the serialization; the message text and
// the locations pass through and assert only that they survive the round trip.
// The watermark is read from the fixture's receipt.json, a different expected
// artifact, so that field does assert something.
func TestRenderGolden(t *testing.T) {
	for _, name := range casesUnder(t, reportFixtures) {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(reportFixtures, name, "expected")

			in := fixtureInput(t, dir)
			in.Rules = reportRules
			in.Watermark = receiptWatermark(t, dir)
			// The recorded report runs read the embedded release catalog, and
			// the run object records which one.
			in.Catalog = catalog.Embedded().Version()

			got, err := sarif.Render(in)
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			// The input is rebuilt from the recorded SARIF, which does not
			// carry an analyzer's fingerprint discriminator, so the
			// fingerprints are left out here. TestReportSARIFParity in
			// internal/cli pins them from a real run, and
			// fingerprint_test.go pins the rule.
			want := fingerprintBlock.ReplaceAll(readFile(t, filepath.Join(dir, sarif.FileName)), nil)
			got = fingerprintBlock.ReplaceAll(got, nil)
			if string(got) != string(want) {
				t.Errorf("rendered bytes do not match %s\n--- want ---\n%s\n--- got ---\n%s",
					filepath.Join(dir, sarif.FileName), want, got)
			}
		})
	}
}

// TestRenderValidatesAgainstSchema is the check the golden files cannot make:
// they pin the bytes ctfkit writes today, and this pins that those bytes are a
// document the published cff-1 schema accepts. The ten plan fixtures are
// included: they belong to the scan family and are produced elsewhere,
// so they are held to parsing and validating rather than to byte parity.
func TestRenderValidatesAgainstSchema(t *testing.T) {
	schema := compileSchema(t)

	for _, root := range []string{reportFixtures, planFixtures} {
		for _, name := range casesUnder(t, root) {
			t.Run(filepath.Base(root)+"/"+name, func(t *testing.T) {
				dir := filepath.Join(root, name, "expected")

				in := fixtureInput(t, dir)
				in.Rules = fixtureRules(t, dir)

				got, err := sarif.Render(in)
				if err != nil {
					t.Fatalf("Render() error = %v", err)
				}

				doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(got))
				if err != nil {
					t.Fatalf("unmarshal rendered document: %v", err)
				}
				if err = schema.Validate(doc); err != nil {
					t.Errorf("rendered document is not valid against cff-1: %v", err)
				}
			})
		}
	}
}

// TestRenderSerialization pins the byte rules Appendix C states outright, so a
// switch to another encoder cannot quietly drop one, and the two empty lists
// that must be [] rather than null.
func TestRenderSerialization(t *testing.T) {
	got, err := sarif.Render(sarif.Input{
		Tool: sarif.Tool{Name: toolName, Version: toolVersion},
	})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	if len(got) == 0 || got[len(got)-1] != '\n' {
		t.Errorf("rendered document does not end with a newline: %q", got)
	}
	if want := "\n  \"version\""; !strings.Contains(string(got), want) {
		t.Errorf("rendered document is not indented with two spaces:\n%s", got)
	}
	for _, want := range []string{`"rules": []`, `"results": []`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("empty list did not render as %s:\n%s", want, got)
		}
	}
	// No --watermark banner and no catalog: the run carries no property bag.
	if strings.Contains(string(got), `"properties"`) {
		t.Errorf("a run with no banner and no catalog carries a property bag:\n%s", got)
	}
}

// TestRenderToolVersion pins that an unknown generator version is omitted
// rather than written as an empty string, which cff-1 refuses.
func TestRenderToolVersion(t *testing.T) {
	data, err := sarif.Render(sarif.Input{
		Tool: sarif.Tool{Name: toolName},
	})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if strings.Contains(string(data), `"version": ""`) {
		t.Errorf("an unknown generator version rendered as an empty string:\n%s", data)
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unmarshal rendered document: %v", err)
	}
	if err = compileSchema(t).Validate(doc); err != nil {
		t.Errorf("rendered document is not valid against cff-1: %v", err)
	}
}

// TestRenderWatermark covers the optional --watermark banner: absent when
// empty, written verbatim as ctf.watermark when set, and refused when it is
// not one printable line, which the cff-1 pattern would reject.
func TestRenderWatermark(t *testing.T) {
	cases := []struct {
		name    string
		mark    string
		want    string
		wantErr bool
	}{
		{name: "empty", mark: ""},
		{name: "one banner line", mark: "rendered for bobthecorp", want: `"ctf.watermark": "rendered for bobthecorp"`},
		{name: "two lines", mark: "one\ntwo", wantErr: true},
		{name: "control character", mark: "one\x1btwo", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sarif.Render(sarif.Input{
				Tool:      sarif.Tool{Name: toolName, Version: toolVersion},
				Watermark: tc.mark,
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Render() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if tc.want == "" && strings.Contains(string(got), "ctf.watermark") {
				t.Errorf("an empty banner rendered a ctf.watermark:\n%s", got)
			}
			if tc.want != "" && !strings.Contains(string(got), tc.want) {
				t.Errorf("rendered document does not carry %s:\n%s", tc.want, got)
			}
		})
	}
}

// TestRenderRejectsBadInput covers the inputs that would put a document
// the cff-1 schema refuses in front of a reader that cannot report a parse
// problem to anyone.
func TestRenderRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		in   sarif.Input
	}{
		{
			name: "no tool name",
			in: sarif.Input{
				Tool: sarif.Tool{Version: toolVersion},
			},
		},
		{
			name: "a finding whose rule id has no descriptor",
			in: sarif.Input{
				Tool:     sarif.Tool{Name: toolName, Version: toolVersion},
				Findings: ctfkit.Findings{finding("ctf.coverage.manifest_missing", ctfkit.LevelError)},
			},
		},
		{
			name: "a finding with a level outside the frozen set",
			in: sarif.Input{
				Tool:     sarif.Tool{Name: toolName, Version: toolVersion},
				Rules:    reportRules,
				Findings: ctfkit.Findings{finding("ctf.coverage.manifest_missing", "critical")},
			},
		},
		{
			name: "a rule id the published schemas refuse",
			in: sarif.Input{
				Tool: sarif.Tool{Name: toolName, Version: toolVersion},
				// ctfkit.Finding.Validate accepts an underscore in the family
				// segment; cff-1 does not. Rendering it would emit a document
				// the schema rejects.
				Rules: []sarif.RuleDescriptor{{
					ID:               "ctf.s3_bucket.enabled",
					ShortDescription: "an id the SDK accepts and cff-1 refuses",
					Level:            ctfkit.LevelError,
				}},
				Findings: ctfkit.Findings{finding("ctf.s3_bucket.enabled", ctfkit.LevelError)},
			},
		},
		{
			name: "two descriptors for one rule id",
			in: sarif.Input{
				Tool: sarif.Tool{Name: toolName, Version: toolVersion},
				Rules: []sarif.RuleDescriptor{
					{
						ID:               "ctf.coverage.manifest_missing",
						ShortDescription: "one text",
						Level:            ctfkit.LevelError,
					},
					{
						ID:               "ctf.coverage.manifest_missing",
						ShortDescription: "another text",
						Level:            ctfkit.LevelWarning,
					},
				},
				Findings: ctfkit.Findings{finding("ctf.coverage.manifest_missing", ctfkit.LevelError)},
			},
		},
		{
			name: "a rule descriptor with a level outside the frozen set",
			in: sarif.Input{
				Tool: sarif.Tool{Name: toolName, Version: toolVersion},
				Rules: []sarif.RuleDescriptor{{
					ID:               "ctf.coverage.manifest_missing",
					ShortDescription: "an entry with no usable level",
					Level:            "critical",
				}},
				Findings: ctfkit.Findings{finding("ctf.coverage.manifest_missing", ctfkit.LevelError)},
			},
		},
		{
			name: "a finding whose ctf.schema is not a version",
			in:   withFinding(func(f *ctfkit.Finding) { f.Props.Schema = "one point zero" }),
		},
		{
			name: "a finding with an empty control id",
			in:   withFinding(func(f *ctfkit.Finding) { f.Props.ControlIDs = []ctfkit.ControlID{""} }),
		},
		{
			name: "a finding with a framework that has no id",
			in: withFinding(func(f *ctfkit.Finding) {
				f.Props.Frameworks = []ctfkit.FrameworkClauses{{Clauses: []string{"CC6.1"}}}
			}),
		},
		{
			name: "a finding with an empty framework clause",
			in: withFinding(func(f *ctfkit.Finding) {
				f.Props.Frameworks = []ctfkit.FrameworkClauses{{ID: "soc_2", Clauses: []string{""}}}
			}),
		},
		{
			name: "a finding with an empty supporting clause",
			in: withFinding(func(f *ctfkit.Finding) {
				f.Props.Frameworks = []ctfkit.FrameworkClauses{
					{ID: "soc_2", Clauses: []string{"CC7.3"}, SupportingClauses: []string{""}},
				}
			}),
		},
		{
			// cff-1 defines supportingClauses as entries of clauses: hedging a
			// clause the entry never lists would add a mapping nothing made.
			name: "a finding with a supporting clause its framework does not list",
			in: withFinding(func(f *ctfkit.Finding) {
				f.Props.Frameworks = []ctfkit.FrameworkClauses{
					{ID: "soc_2", Clauses: []string{"CC7.3"}, SupportingClauses: []string{"CC6.1"}},
				}
			}),
		},
		{
			name: "a finding with an empty attribute name",
			in:   withFinding(func(f *ctfkit.Finding) { f.Props.Attributes = []string{""} }),
		},
		{
			name: "a finding whose remediation names no module",
			in: withFinding(func(f *ctfkit.Finding) {
				f.Props.Remediation = &ctfkit.Remediation{Version: "~> 5.0"}
			}),
		},
		{
			name: "a finding whose exception has a negative ttl",
			in: withFinding(func(f *ctfkit.Finding) {
				f.Props.Exception = &ctfkit.ExceptionProperty{Allowed: true, TTLSeconds: -1}
			}),
		},
		{
			name: "a finding with an empty location uri",
			in: withFinding(func(f *ctfkit.Finding) {
				f.Locations = []ctfkit.Location{{PhysicalLocation: &ctfkit.PhysicalLocation{}}}
			}),
		},
		{
			name: "a finding with a logical location that has no name",
			in: withFinding(func(f *ctfkit.Finding) {
				f.Locations = []ctfkit.Location{{
					LogicalLocations: []ctfkit.LogicalLocation{{Kind: ctfkit.LogicalLocationResource}},
				}}
			}),
		},
		{
			name: "a finding with an empty message",
			in: func() sarif.Input {
				f := finding("ctf.coverage.manifest_missing", ctfkit.LevelError)
				f.Message.Text = ""
				return sarif.Input{
					Tool:     sarif.Tool{Name: toolName, Version: toolVersion},
					Rules:    reportRules,
					Findings: ctfkit.Findings{f},
				}
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sarif.Render(tc.in); err == nil {
				t.Fatal("Render() error = nil, want an error")
			}
		})
	}
}

// TestRenderNormalizesEmptyLists pins the three lists cff-1 requires to be
// arrays. A nil Go slice marshals as null, which the schema refuses, so each
// one is normalized rather than rejected: a finding that maps to no control,
// no framework or a framework with no clause is a real finding, not a broken
// one.
//
// It also pins that the caller's finding is left alone. Every projection of
// one run renders from the same findings, so a renderer that normalized in
// place would make the others depend on which ran first.
func TestRenderNormalizesEmptyLists(t *testing.T) {
	f := finding("ctf.coverage.manifest_missing", ctfkit.LevelError)
	f.Props.Frameworks = []ctfkit.FrameworkClauses{{ID: "soc_2"}}

	data, err := sarif.Render(sarif.Input{
		Tool:     sarif.Tool{Name: toolName, Version: toolVersion},
		Rules:    reportRules,
		Findings: ctfkit.Findings{f},
	})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	for _, want := range []string{`"ctf.controlIds": []`, `"clauses": []`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("an empty list did not render as %s:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), "null") {
		t.Errorf("a nil slice reached the document as null:\n%s", data)
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unmarshal rendered document: %v", err)
	}
	if err = compileSchema(t).Validate(doc); err != nil {
		t.Errorf("rendered document is not valid against cff-1: %v", err)
	}

	if f.Props.Frameworks[0].Clauses != nil {
		t.Error("Render normalized the caller's finding in place")
	}
}

// TestRenderResultOrder pins that Render keeps the order it was given and
// sorts nothing. Ordering findings is the runner's job, through
// ctfkit.SortFindings, so that every projection of one run shows one order; a
// renderer that sorted on its own would put the SARIF results in a different
// order from the Markdown table and the receipt.
//
// tool.driver.rules is the one list Render does order, by id, because it is a
// lookup table rather than a record of what happened.
func TestRenderResultOrder(t *testing.T) {
	doc := render(t, sarif.Input{
		Tool:  sarif.Tool{Name: toolName, Version: toolVersion},
		Rules: reportRules,
		Findings: ctfkit.Findings{
			finding("ctf.coverage.tests_failed", ctfkit.LevelError),
			finding("ctf.coverage.delegation_unresolved", ctfkit.LevelWarning),
			finding("ctf.coverage.manifest_missing", ctfkit.LevelError),
		},
	})

	wantResults := []string{
		"ctf.coverage.tests_failed",
		"ctf.coverage.delegation_unresolved",
		"ctf.coverage.manifest_missing",
	}
	for i, want := range wantResults {
		if got := doc.Runs[0].Results[i].RuleID; got != want {
			t.Errorf("results[%d].ruleId = %q, want %q", i, got, want)
		}
	}

	wantRules := []string{
		"ctf.coverage.delegation_unresolved",
		"ctf.coverage.manifest_missing",
		"ctf.coverage.tests_failed",
	}
	if len(doc.Runs[0].Tool.Driver.Rules) != len(wantRules) {
		t.Fatalf("rules = %d entries, want %d", len(doc.Runs[0].Tool.Driver.Rules), len(wantRules))
	}
	for i, want := range wantRules {
		if got := doc.Runs[0].Tool.Driver.Rules[i].ID; got != want {
			t.Errorf("rules[%d].id = %q, want %q", i, got, want)
		}
	}
}

// TestRenderSuppression pins the exception rule of the scan specification: an allowed
// waiver adds a suppressions entry and leaves the level and the kind alone; an
// expired one is recorded in the property bag and suppresses nothing.
func TestRenderSuppression(t *testing.T) {
	cases := []struct {
		name    string
		prop    *ctfkit.ExceptionProperty
		wantSup bool
	}{
		{name: "no exception"},
		{
			name:    "allowed",
			prop:    &ctfkit.ExceptionProperty{Allowed: true, EntryID: "bobthecorp-1", Justification: "ETL scratch bucket"},
			wantSup: true,
		},
		{
			name: "expired",
			prop: &ctfkit.ExceptionProperty{Allowed: false, EntryID: "bobthecorp-2", Justification: "ETL scratch bucket"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := finding("ctf.coverage.manifest_missing", ctfkit.LevelError)
			f.Props.Exception = tc.prop

			doc := render(t, sarif.Input{
				Tool:     sarif.Tool{Name: toolName, Version: toolVersion},
				Rules:    reportRules,
				Findings: ctfkit.Findings{f},
			})

			got := doc.Runs[0].Results[0]
			if len(got.Suppressions) > 0 != tc.wantSup {
				t.Fatalf("suppressions = %+v, want any = %v", got.Suppressions, tc.wantSup)
			}
			if got.Level != ctfkit.LevelError || got.Kind != ctfkit.KindFail {
				t.Errorf("a waiver moved level or kind: level = %q, kind = %q", got.Level, got.Kind)
			}
			if !tc.wantSup {
				return
			}
			if got.Suppressions[0].Kind != "external" {
				t.Errorf("suppression kind = %q, want external", got.Suppressions[0].Kind)
			}
			if got.Suppressions[0].Justification != tc.prop.Justification {
				t.Errorf("suppression justification = %q, want %q",
					got.Suppressions[0].Justification, tc.prop.Justification)
			}
		})
	}
}

// TestRenderEvidence pins that ctf.evidence appears only when the run context
// is known, and that the OSS signature is always null: this projection states
// what ran, never that anyone vouched for it.
func TestRenderEvidence(t *testing.T) {
	base := sarif.Input{
		Tool:     sarif.Tool{Name: toolName, Version: toolVersion},
		Rules:    reportRules,
		Findings: ctfkit.Findings{finding("ctf.coverage.manifest_missing", ctfkit.LevelError)},
	}

	t.Run("absent without a run context", func(t *testing.T) {
		doc := render(t, base)
		if doc.Runs[0].Results[0].Properties.Evidence != nil {
			t.Errorf("evidence = %+v, want none", doc.Runs[0].Results[0].Properties.Evidence)
		}
	})

	t.Run("present with one", func(t *testing.T) {
		in := base
		in.Metadata = ctfkit.RunMetadata{RunID: "bobthecorp-run-1", Commit: strings.Repeat("a", 40)}

		doc := render(t, in)
		ev := doc.Runs[0].Results[0].Properties.Evidence
		if ev == nil {
			t.Fatal("evidence = nil, want one")
		}
		if ev.RunID != in.Metadata.RunID || ev.Commit != in.Metadata.Commit {
			t.Errorf("evidence = %+v, want runId %q and commit %q", ev, in.Metadata.RunID, in.Metadata.Commit)
		}
		if ev.Signature != nil {
			t.Errorf("signature = %v, want null: open source output is never attested", *ev.Signature)
		}
	})
}

// TestRenderCatalogVersion pins the run-level record of which catalog the run
// read, so a reader can tell a finding produced from the embedded catalog from
// one produced against a vendored file. No fixture carries it yet, which is
// why it is omitted rather than rendered empty.
func TestRenderCatalogVersion(t *testing.T) {
	base := sarif.Input{
		Tool: sarif.Tool{Name: toolName, Version: toolVersion},
	}

	t.Run("omitted when the run recorded none", func(t *testing.T) {
		if got := render(t, base).Runs[0].Properties.CatalogVersion; got != nil {
			t.Errorf("catalogVersion = %+v, want none", got)
		}
	})

	// Half a catalog is a caller bug. Dropping it would lose the half that was
	// recorded without saying so.
	for _, half := range []ctfkit.CatalogVersion{
		{Version: "2026.9.0"},
		{Provenance: "embedded"},
	} {
		t.Run("rejected when only half of it is recorded", func(t *testing.T) {
			in := base
			in.Catalog = half

			if _, err := sarif.Render(in); err == nil {
				t.Fatalf("Render() error = nil for %+v, want an error", half)
			}
		})
	}

	// Every origin cff-1 names, rendered and then validated against the
	// schema. No fixture carries ctf.catalogVersion, so this is the only
	// place the run-level object is checked against the published enum.
	schema := compileSchema(t)
	for _, origin := range []string{"embedded", "file", "home"} {
		t.Run("recorded when the run has one, origin "+origin, func(t *testing.T) {
			in := base
			in.Catalog = ctfkit.CatalogVersion{Version: "2026.9.0", Provenance: origin}

			data, err := sarif.Render(in)
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("unmarshal rendered document: %v", err)
			}
			if err = schema.Validate(doc); err != nil {
				t.Fatalf("rendered document is not valid against cff-1: %v", err)
			}

			var parsed document
			if err = json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("unmarshal rendered document: %v", err)
			}
			got := parsed.Runs[0].Properties.CatalogVersion
			if got == nil {
				t.Fatal("catalogVersion = nil, want one")
			}
			if got.Version != "2026.9.0" || got.Origin != origin {
				t.Errorf("catalogVersion = %+v, want {2026.9.0 %s}", got, origin)
			}
		})
	}

	// ctfkit.CatalogVersion.Provenance is a bare string, so a value outside
	// the cff-1 enum has to fail here or it reaches the file.
	t.Run("rejected when the origin is not one cff-1 names", func(t *testing.T) {
		in := base
		in.Catalog = ctfkit.CatalogVersion{Version: "2026.9.0", Provenance: "vendored"}

		if _, err := sarif.Render(in); err == nil {
			t.Fatal("Render() error = nil, want an error")
		}
	})

	// The version is the semver grammar cff-1 pins.
	t.Run("rejected when the version is not semver", func(t *testing.T) {
		in := base
		in.Catalog = ctfkit.CatalogVersion{Version: "not a version", Provenance: "embedded"}

		if _, err := sarif.Render(in); err == nil {
			t.Fatal("Render() error = nil, want an error")
		}
	})
}

// TestRenderRejectsEverythingTheSchemaRefuses is the check that keeps the
// hand-written guards in checkAgainstSchema honest. Every case of
// TestRenderRejectsBadInput that carries a finding is rendered with the guards
// bypassed in spirit: if Render were to accept it, the document it produced
// would have to fail cff-1. Asserting the second half here means a guard can
// never be dropped without the schema noticing, and a guard that rejects
// something the schema would have accepted is caught as an over-reach.
//
// It is the inverse of the golden test: that one pins what a good input
// renders to, this one pins that a bad input has nowhere to go.
func TestRenderRejectsEverythingTheSchemaRefuses(t *testing.T) {
	schema := compileSchema(t)

	// Each mutation makes the finding invalid under cff-1 in exactly one way.
	mutations := map[string]func(*ctfkit.Finding){
		"ctf.schema":           func(f *ctfkit.Finding) { f.Props.Schema = "one point zero" },
		"empty control id":     func(f *ctfkit.Finding) { f.Props.ControlIDs = []ctfkit.ControlID{""} },
		"framework with no id": func(f *ctfkit.Finding) { f.Props.Frameworks = []ctfkit.FrameworkClauses{{Clauses: []string{"CC6.1"}}} },
		"empty clause": func(f *ctfkit.Finding) {
			f.Props.Frameworks = []ctfkit.FrameworkClauses{{ID: "soc_2", Clauses: []string{""}}}
		},
		"empty attribute name":  func(f *ctfkit.Finding) { f.Props.Attributes = []string{""} },
		"remediation no module": func(f *ctfkit.Finding) { f.Props.Remediation = &ctfkit.Remediation{Version: "~> 5.0"} },
		"negative ttl":          func(f *ctfkit.Finding) { f.Props.Exception = &ctfkit.ExceptionProperty{Allowed: true, TTLSeconds: -1} },
		"empty location uri": func(f *ctfkit.Finding) {
			f.Locations = []ctfkit.Location{{PhysicalLocation: &ctfkit.PhysicalLocation{}}}
		},
		"logical location no name": func(f *ctfkit.Finding) {
			f.Locations = []ctfkit.Location{{
				LogicalLocations: []ctfkit.LogicalLocation{{Kind: ctfkit.LogicalLocationResource}},
			}}
		},
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := sarif.Render(withFinding(mutate)); err == nil {
				t.Fatal("Render() error = nil: the renderer accepted an input cff-1 refuses")
			}

			// The other half: the schema really does refuse it, so the guard
			// is enforcing cff-1 rather than a rule of its own invention.
			doc := mutatedResultDocument(t, mutate)
			if err := schema.Validate(doc); err == nil {
				t.Error("cff-1 accepts this input, so the renderer has no business rejecting it")
			}
		})
	}
}

// mutatedResultDocument builds the document Render would have produced for a
// mutated finding, by rendering the unmutated one and patching the result in
// the decoded JSON. It exists so the test can ask the schema what it thinks of
// a document Render refuses to build.
//
// It marshals the result through ctfkit.Finding, which emits neither
// ctf.evidence nor suppressions. Every mutation above leaves both alone, so
// the two paths agree; a mutation of either would need this helper to build
// the result the renderer's own structs would have, or its schema assertion
// would pass on a document missing the field under test.
func mutatedResultDocument(t *testing.T, mutate func(*ctfkit.Finding)) any {
	t.Helper()

	clean, err := sarif.Render(withFinding(func(*ctfkit.Finding) {}))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	f := finding("ctf.coverage.manifest_missing", ctfkit.LevelError)
	mutate(&f)

	var patched map[string]any
	if err = json.Unmarshal(clean, &patched); err != nil {
		t.Fatalf("unmarshal the clean document: %v", err)
	}

	// The SDK marshals the property bag with the keys cff-1 names, which is
	// all the schema looks at; the key order it uses is not the rendered one
	// and does not matter here.
	resultJSON, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal the mutated finding: %v", err)
	}
	var mutatedResult any
	if err = json.Unmarshal(resultJSON, &mutatedResult); err != nil {
		t.Fatalf("unmarshal the mutated finding: %v", err)
	}

	runs, ok := patched["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("the clean document does not carry exactly one run")
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("the clean run is not an object")
	}
	run["results"] = []any{mutatedResult}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(mustMarshal(t, patched)))
	if err != nil {
		t.Fatalf("unmarshal the patched document: %v", err)
	}
	return doc
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// withFinding is one valid finding with a mutation applied, wrapped in the
// smallest Input that would otherwise render.
func withFinding(mutate func(*ctfkit.Finding)) sarif.Input {
	f := finding("ctf.coverage.manifest_missing", ctfkit.LevelError)
	mutate(&f)

	return sarif.Input{
		Tool:     sarif.Tool{Name: toolName, Version: toolVersion},
		Rules:    reportRules,
		Findings: ctfkit.Findings{f},
	}
}

// --- helpers ---

// document mirrors the rendered file for the tests that assert on fields
// rather than bytes. It is declared here rather than exported from the
// renderer: the document is a wire format, not a Go type anyone should build a
// program around.
type document struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name           string `json:"name"`
				InformationURI string `json:"informationUri"`
				Version        string `json:"version"`
				Rules          []struct {
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
		Properties struct {
			Watermark      string `json:"ctf.watermark"`
			CatalogVersion *struct {
				Version string `json:"version"`
				Origin  string `json:"origin"`
			} `json:"ctf.catalogVersion"`
		} `json:"properties"`
		Results []struct {
			RuleID     string `json:"ruleId"`
			Level      string `json:"level"`
			Kind       string `json:"kind"`
			Properties struct {
				Evidence *struct {
					RunID     string  `json:"runId"`
					Commit    string  `json:"commit"`
					Signature *string `json:"signature"`
				} `json:"ctf.evidence"`
			} `json:"properties"`
			Suppressions []struct {
				Kind          string `json:"kind"`
				Justification string `json:"justification"`
			} `json:"suppressions"`
		} `json:"results"`
	} `json:"runs"`
}

func render(t *testing.T, in sarif.Input) document {
	t.Helper()

	data, err := sarif.Render(in)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	var doc document
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal rendered document: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("rendered %d runs, want exactly 1", len(doc.Runs))
	}
	return doc
}

// finding is the smallest finding that passes ctfkit.Finding.Validate.
func finding(ruleID, level string) ctfkit.Finding {
	f := ctfkit.Finding{
		RuleID:  ruleID,
		Level:   level,
		Kind:    ctfkit.KindFail,
		Message: ctfkit.Message{Text: "a finding at level " + level},
	}
	f.Props.Schema = "1.0"
	f.Props.Stage = ctfkit.PostInit
	return f
}

// casesUnder lists the fixture directories that record an expected SARIF file.
// report/schema-4-stub is not one of them: it is the exit-2 case, where the
// analysis never completes and no projection is written.
func casesUnder(t *testing.T, root string) []string {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, statErr := os.Stat(filepath.Join(root, e.Name(), "expected", sarif.FileName)); statErr == nil {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatalf("no fixture under %s carries an expected %s", root, sarif.FileName)
	}
	return names
}

// recorded is the subset of the expected SARIF the tests read back.
type recorded struct {
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
		Results []struct {
			RuleID     string            `json:"ruleId"`
			Level      string            `json:"level"`
			Kind       string            `json:"kind"`
			Message    ctfkit.Message    `json:"message"`
			Locations  []ctfkit.Location `json:"locations"`
			Properties struct {
				Schema      string                    `json:"ctf.schema"`
				Stage       string                    `json:"ctf.stage"`
				ControlIDs  []ctfkit.ControlID        `json:"ctf.controlIds"`
				Frameworks  []ctfkit.FrameworkClauses `json:"ctf.frameworks"`
				Preventive  bool                      `json:"ctf.preventive"`
				Attributes  []string                  `json:"ctf.attributes"`
				Remediation *ctfkit.Remediation       `json:"ctf.remediation"`
				Exception   *ctfkit.ExceptionProperty `json:"ctf.exception"`
				Evidence    *struct {
					RunID  string `json:"runId"`
					Commit string `json:"commit"`
				} `json:"ctf.evidence"`
			} `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

// fixtureInput rebuilds the renderer input from a fixture's recorded SARIF.
// The analyzer that produces findings for real is tested elsewhere, so the
// findings come from the recorded document rather than from a run.
func fixtureInput(t *testing.T, expectedDir string) sarif.Input {
	t.Helper()

	rec := readRecorded(t, expectedDir)

	in := sarif.Input{Tool: sarif.Tool{Name: toolName, Version: toolVersion}}
	for _, r := range rec.Runs[0].Results {
		stage, err := ctfkit.ParseStage(r.Properties.Stage)
		if err != nil {
			t.Fatalf("stage on result %s of the recorded SARIF: %v", r.RuleID, err)
		}

		f := ctfkit.Finding{
			RuleID:    r.RuleID,
			Level:     r.Level,
			Kind:      r.Kind,
			Message:   r.Message,
			Locations: r.Locations,
		}
		f.Props = ctfkit.Properties{
			Schema:      r.Properties.Schema,
			Stage:       stage,
			ControlIDs:  r.Properties.ControlIDs,
			Frameworks:  r.Properties.Frameworks,
			Preventive:  r.Properties.Preventive,
			Attributes:  r.Properties.Attributes,
			Remediation: r.Properties.Remediation,
			Exception:   r.Properties.Exception,
		}
		in.Findings = append(in.Findings, f)

		if r.Properties.Evidence != nil {
			in.Metadata.RunID = r.Properties.Evidence.RunID
			in.Metadata.Commit = r.Properties.Evidence.Commit
		}
	}
	return in
}

// fixtureRules reads the rule table out of the recorded document. The golden
// test does not use it: there the table is transcribed from Appendix C, so the
// comparison asserts the frozen text. This is for the plan fixtures, whose
// rules belong to the scan family and have no frozen table here yet.
func fixtureRules(t *testing.T, expectedDir string) []sarif.RuleDescriptor {
	t.Helper()

	rec := readRecorded(t, expectedDir)

	rules := make([]sarif.RuleDescriptor, 0, len(rec.Runs[0].Tool.Driver.Rules))
	for _, r := range rec.Runs[0].Tool.Driver.Rules {
		rules = append(rules, sarif.RuleDescriptor{
			ID:               r.ID,
			ShortDescription: r.ShortDescription.Text,
			Level:            r.DefaultConfiguration.Level,
		})
	}
	return rules
}

func readRecorded(t *testing.T, expectedDir string) recorded {
	t.Helper()

	var rec recorded
	if err := json.Unmarshal(readFile(t, filepath.Join(expectedDir, sarif.FileName)), &rec); err != nil {
		t.Fatalf("unmarshal the recorded SARIF in %s: %v", expectedDir, err)
	}
	if len(rec.Runs) != 1 {
		t.Fatalf("the recorded SARIF in %s carries %d runs, want exactly 1", expectedDir, len(rec.Runs))
	}
	return rec
}

// receiptWatermark reads the watermark from the fixture's expected receipt, a
// different artifact than the one the golden test asserts against.
func receiptWatermark(t *testing.T, expectedDir string) string {
	t.Helper()

	var receipt struct {
		Watermark string `json:"watermark"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(expectedDir, "receipt.json")), &receipt); err != nil {
		t.Fatalf("unmarshal the expected receipt in %s: %v", expectedDir, err)
	}
	return receipt.Watermark
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // test-controlled path under testdata/
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(readFile(t, schemaPath)))
	if err != nil {
		t.Fatalf("unmarshal %s: %v", schemaPath, err)
	}

	c := jsonschema.NewCompiler()
	if err = c.AddResource(schemaPath, doc); err != nil {
		t.Fatalf("add %s: %v", schemaPath, err)
	}
	schema, err := c.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile %s: %v", schemaPath, err)
	}
	return schema
}
