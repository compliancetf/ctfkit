package spacelift_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/compliancetf/ctfkit/internal/render/spacelift"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// -update rewrites the golden files from the current renderer output. It is
// never run against testdata/fixtures/report: those files are the oracle the
// renderer is measured by, and a flag that can overwrite an oracle turns every
// later run green by construction. assertGolden refuses to write there.
var update = flag.Bool("update", false, "rewrite golden files from the current renderer output")

const fixtureRoot = "../../../testdata/fixtures/report"

const schemaPath = "../../../schema/spacelift-1.schema.json"

// TestRenderGolden renders every report fixture that has an expected Spacelift
// file and compares the bytes.
//
// Every input comes from a different expected artifact than the one asserted
// against: the findings from expected/findings.sarif, the stage and watermark
// from expected/receipt.json. Reading the stage out of the expected Spacelift
// file would make that field assert nothing.
func TestRenderGolden(t *testing.T) {
	for _, name := range fixtureCases(t) {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(fixtureRoot, name, "expected")

			got, err := spacelift.Render(fixtureInput(t, dir))
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			assertGolden(t, filepath.Join(dir, spacelift.FileName), got)
		})
	}
}

// TestRenderValidatesAgainstSchema is the check the golden files cannot make:
// they pin the bytes ctfkit writes today, and this pins that those bytes are a
// document the published spacelift-1 schema accepts.
func TestRenderValidatesAgainstSchema(t *testing.T) {
	schema := compileSchema(t)

	for _, name := range fixtureCases(t) {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(fixtureRoot, name, "expected")

			got, err := spacelift.Render(fixtureInput(t, dir))
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(got))
			if err != nil {
				t.Fatalf("unmarshal rendered document: %v", err)
			}
			if err = schema.Validate(doc); err != nil {
				t.Errorf("rendered document is not valid against spacelift-1: %v", err)
			}
		})
	}
}

// TestRenderSerialization pins the two byte rules Appendix D states outright,
// so a switch to another encoder cannot quietly drop either.
func TestRenderSerialization(t *testing.T) {
	got, err := spacelift.Render(spacelift.Input{
		Stage: ctfkit.PostInit,
	})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	if len(got) == 0 || got[len(got)-1] != '\n' {
		t.Errorf("rendered document does not end with a newline: %q", got)
	}
	if want := "\n  \"schema\""; !strings.Contains(string(got), want) {
		t.Errorf("rendered document is not indented with two spaces:\n%s", got)
	}
	// findings is required and must be [] rather than null when there is none,
	// so a policy can range over it without a nil check.
	if want := "\"findings\": []"; !strings.Contains(string(got), want) {
		t.Errorf("empty findings did not render as []:\n%s", got)
	}
}

// TestRenderVerdict pins the rule of the 2026-09-20 decision: the verdict is
// fail when any unsuppressed error-level finding exists, and nothing else
// moves it. A warning-only run passes however many warnings it has.
func TestRenderVerdict(t *testing.T) {
	cases := []struct {
		name     string
		findings ctfkit.Findings
		verdict  string
		summary  [3]int // error, warning, note
	}{
		{
			name:    "no findings",
			verdict: "pass",
		},
		{
			name:     "warnings and notes only",
			findings: ctfkit.Findings{level(ctfkit.LevelWarning), level(ctfkit.LevelWarning), level(ctfkit.LevelNote)},
			verdict:  "pass",
			summary:  [3]int{0, 2, 1},
		},
		{
			name:     "one error",
			findings: ctfkit.Findings{level(ctfkit.LevelWarning), level(ctfkit.LevelError)},
			verdict:  "fail",
			summary:  [3]int{1, 1, 0},
		},
		{
			name:     "the only error is suppressed",
			findings: ctfkit.Findings{level(ctfkit.LevelWarning), allowed(level(ctfkit.LevelError))},
			verdict:  "pass",
			summary:  [3]int{0, 1, 0},
		},
		{
			name:     "an expired waiver still counts",
			findings: ctfkit.Findings{expired(level(ctfkit.LevelError))},
			verdict:  "fail",
			summary:  [3]int{1, 0, 0},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decode(t, tc.findings)

			if got.Verdict != tc.verdict {
				t.Errorf("verdict = %q, want %q", got.Verdict, tc.verdict)
			}
			want := struct {
				Error   int `json:"error"`
				Warning int `json:"warning"`
				Note    int `json:"note"`
			}{tc.summary[0], tc.summary[1], tc.summary[2]}
			if got.Summary != want {
				t.Errorf("summary = %+v, want %+v", got.Summary, want)
			}
		})
	}
}

// TestRenderKeepsSuppressedFindingsInTheArray records the split Appendix D
// leaves implicit: an allowed exception takes a finding out of the counts and
// out of the verdict, and never out of the record.
func TestRenderKeepsSuppressedFindingsInTheArray(t *testing.T) {
	got := decode(t, ctfkit.Findings{allowed(level(ctfkit.LevelError))})

	if len(got.Findings) != 1 {
		t.Fatalf("findings = %d entries, want 1", len(got.Findings))
	}
	if got.Findings[0].Level != ctfkit.LevelError {
		t.Errorf("suppressed finding level = %q, want %q", got.Findings[0].Level, ctfkit.LevelError)
	}
	if got.Summary.Error != 0 {
		t.Errorf("summary.error = %d, want 0", got.Summary.Error)
	}
}

// TestRenderRejectsUnrenderableInput covers the inputs that would produce a
// file the schema refuses. The reader is a policy gate with nobody to report a
// parse problem to, so the renderer fails loudly instead.
func TestRenderRejectsUnrenderableInput(t *testing.T) {
	cases := []struct {
		name string
		in   spacelift.Input
	}{
		{
			name: "unknown stage",
			in:   spacelift.Input{Stage: ctfkit.Stage("post_everything")},
		},
		{
			name: "empty stage",
			in:   spacelift.Input{},
		},
		{
			name: "watermark carries two lines",
			in:   spacelift.Input{Stage: ctfkit.PostInit, Watermark: "one\ntwo"},
		},
		{
			name: "rule id outside the frozen format",
			in: spacelift.Input{
				Stage:    ctfkit.PostInit,
				Findings: ctfkit.Findings{ruleID("coverage.manifest_missing")},
			},
		},
		{
			// Both published schemas forbid an underscore in the family
			// segment. ctfkit.Finding.Validate rejects it too now; this case
			// is what proves the renderer still refuses
			// the id after its own copy of the regexp was removed.
			name: "rule id with an underscore in the family segment",
			in: spacelift.Input{
				Stage:    ctfkit.PostInit,
				Findings: ctfkit.Findings{ruleID("ctf.s3_bucket.enabled")},
			},
		},
		{
			name: "unknown finding level",
			in: spacelift.Input{
				Stage:    ctfkit.PostInit,
				Findings: ctfkit.Findings{level("critical")},
			},
		},
		{
			name: "empty finding message",
			in: spacelift.Input{
				Stage:    ctfkit.PostInit,
				Findings: ctfkit.Findings{noMessage()},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := spacelift.Render(tc.in); err == nil {
				t.Fatal("Render() error = nil, want an error")
			}
		})
	}
}

// TestRenderWatermarkBanner covers the optional --watermark banner: no
// watermark key when it is empty, the banner verbatim when it is set, and a
// document the schema accepts either way.
func TestRenderWatermarkBanner(t *testing.T) {
	for _, banner := range []string{"", "Rendered for the bobthecorp pilot"} {
		got, err := spacelift.Render(spacelift.Input{Stage: ctfkit.PostInit, Watermark: banner})
		if err != nil {
			t.Fatalf("Render(%q) error = %v", banner, err)
		}

		var raw map[string]any
		if err = json.Unmarshal(got, &raw); err != nil {
			t.Fatalf("unmarshal rendered document: %v", err)
		}
		mark, present := raw["watermark"]
		if banner == "" && present {
			t.Errorf("an empty banner rendered a watermark key: %v", mark)
		}
		if banner != "" && mark != banner {
			t.Errorf("watermark = %v, want %q", mark, banner)
		}

		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(got))
		if err != nil {
			t.Fatalf("unmarshal rendered document: %v", err)
		}
		if err = compileSchema(t).Validate(doc); err != nil {
			t.Errorf("rendered document is not valid against spacelift-1: %v", err)
		}
	}
}

// TestWriteAlwaysLandsInTheWorkingDirectory is the unit-level half of the
// --out-dir rule: Write has no way to be told anywhere else, so an --out-dir
// pointing elsewhere cannot move the file. The black-box half, which runs the
// binary with --format spacelift --out-dir elsewhere, belongs to the command
// tests because only the command owns the flag wiring.
func TestWriteAlwaysLandsInTheWorkingDirectory(t *testing.T) {
	workingDir := t.TempDir()
	outDir := t.TempDir()

	if err := spacelift.Write(workingDir, []byte("{}\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(workingDir, spacelift.FileName)); err != nil {
		t.Errorf("file is not in the working directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, spacelift.FileName)); !os.IsNotExist(err) {
		t.Errorf("file reached the out dir, stat error = %v, want not-exist", err)
	}

}

// TestWriteOverwrites pins that every run replaces the previous file whole. A
// stale verdict left behind by an earlier run is the one failure mode a plan
// policy cannot detect: it reads a well-formed file that describes a run that
// is not this one.
func TestWriteOverwrites(t *testing.T) {
	workingDir := t.TempDir()
	path := filepath.Join(workingDir, spacelift.FileName)

	if err := os.WriteFile(path, []byte("stale and much longer than what follows\n"), 0o600); err != nil {
		t.Fatalf("seed the stale file: %v", err)
	}
	if err := spacelift.Write(workingDir, []byte("{}\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // test-controlled path under t.TempDir()
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "{}\n" {
		t.Errorf("file = %q, want the new bytes alone", got)
	}
}

// TestWriteDoesNotFollowASymlink is the one placement vector Write's signature
// cannot close on its own. The working directory is the checked-out
// configuration, which on a proposed run is whatever the change author
// committed, and git carries symlinks. A symlink left at the file's name would
// send an in-place write to its target, outside the working directory, and
// leave the plan policy reading whatever already sat at the name.
func TestWriteDoesNotFollowASymlink(t *testing.T) {
	workingDir := t.TempDir()
	elsewhere := filepath.Join(t.TempDir(), "victim.json")

	if err := os.WriteFile(elsewhere, []byte("do not touch\n"), 0o600); err != nil {
		t.Fatalf("seed the victim file: %v", err)
	}
	dest := filepath.Join(workingDir, spacelift.FileName)
	if err := os.Symlink(elsewhere, dest); err != nil {
		t.Fatalf("plant the symlink: %v", err)
	}

	if err := spacelift.Write(workingDir, []byte("{}\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	victim, err := os.ReadFile(elsewhere) //nolint:gosec // test-controlled path under t.TempDir()
	if err != nil {
		t.Fatalf("read the victim file: %v", err)
	}
	if string(victim) != "do not touch\n" {
		t.Errorf("the write followed the symlink: victim file = %q", victim)
	}

	info, err := os.Lstat(dest)
	if err != nil {
		t.Fatalf("lstat the destination: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("the destination is still a symlink, so no file was written for the policy to read")
	}
	written, err := os.ReadFile(dest) //nolint:gosec // test-controlled path under t.TempDir()
	if err != nil {
		t.Fatalf("read the destination: %v", err)
	}
	if string(written) != "{}\n" {
		t.Errorf("destination = %q, want the rendered bytes", written)
	}
}

// TestWriteLeavesNoTempFileBehind pins the other half of the rename: the run's
// working directory is the configuration root, and a leftover temp file there
// is a stray artifact in somebody's repository.
func TestWriteLeavesNoTempFileBehind(t *testing.T) {
	workingDir := t.TempDir()

	if err := spacelift.Write(workingDir, []byte("{}\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	entries, err := os.ReadDir(workingDir)
	if err != nil {
		t.Fatalf("read the working directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != spacelift.FileName {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("working directory holds %v, want only %s", names, spacelift.FileName)
	}
}

// TestWriteSetsTheModeEveryRun pins that the mode does not survive from a file
// an earlier run or another tool left at looser permissions: each run renames a
// freshly created 0600 file into place.
func TestWriteSetsTheModeEveryRun(t *testing.T) {
	workingDir := t.TempDir()
	dest := filepath.Join(workingDir, spacelift.FileName)

	if err := os.WriteFile(dest, []byte("world readable\n"), 0o644); err != nil { //nolint:gosec // the loose mode is the point of the case
		t.Fatalf("seed the loose file: %v", err)
	}
	if err := spacelift.Write(workingDir, []byte("{}\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat the destination: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %04o, want 0600", got)
	}
}

// --- helpers ---

// document mirrors the rendered file for the tests that assert on fields
// rather than bytes. It is declared here rather than exported from the
// renderer: the file is a wire format for a policy, not a Go type anyone
// should build a program around.
type document struct {
	Schema    string `json:"schema"`
	Stage     string `json:"stage"`
	Verdict   string `json:"verdict"`
	Watermark string `json:"watermark"`
	Summary   struct {
		Error   int `json:"error"`
		Warning int `json:"warning"`
		Note    int `json:"note"`
	} `json:"summary"`
	Findings []struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message string `json:"message"`
	} `json:"findings"`
}

func decode(t *testing.T, findings ctfkit.Findings) document {
	t.Helper()

	data, err := spacelift.Render(spacelift.Input{
		Stage:    ctfkit.PostInit,
		Findings: findings,
	})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	var doc document
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal rendered document: %v", err)
	}
	return doc
}

func level(l string) ctfkit.Finding {
	f := ctfkit.Finding{
		RuleID:  "ctf.coverage.delegation_unresolved",
		Level:   l,
		Kind:    ctfkit.KindFail,
		Message: ctfkit.Message{Text: "a finding at level " + l},
	}
	f.Props.Schema = "1.0"
	f.Props.Stage = ctfkit.PostInit
	return f
}

func ruleID(id string) ctfkit.Finding {
	f := level(ctfkit.LevelError)
	f.RuleID = id
	return f
}

func noMessage() ctfkit.Finding {
	f := level(ctfkit.LevelError)
	f.Message.Text = ""
	return f
}

func allowed(f ctfkit.Finding) ctfkit.Finding {
	f.Props.Exception = &ctfkit.ExceptionProperty{Allowed: true, EntryID: "bobthecorp-1"}
	return f
}

func expired(f ctfkit.Finding) ctfkit.Finding {
	f.Props.Exception = &ctfkit.ExceptionProperty{Allowed: false, EntryID: "bobthecorp-2"}
	return f
}

// fixtureCases lists the report fixtures that record an expected Spacelift
// file. schema-4-stub is not one of them: it is the exit-2 case, where the
// analysis never completes and no projection is written.
func fixtureCases(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(fixtureRoot)
	if err != nil {
		t.Fatalf("read fixture root: %v", err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, statErr := os.Stat(filepath.Join(fixtureRoot, e.Name(), "expected", spacelift.FileName)); statErr == nil {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatalf("no report fixture carries an expected %s", spacelift.FileName)
	}
	return names
}

// fixtureInput rebuilds the renderer input from the fixture's other expected
// artifacts. The analyzer that produces findings for real is tested elsewhere,
// so the findings come from the recorded SARIF rather than from a run.
func fixtureInput(t *testing.T, expectedDir string) spacelift.Input {
	t.Helper()

	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Properties struct {
					Schema    string                    `json:"ctf.schema"`
					Stage     string                    `json:"ctf.stage"`
					Exception *ctfkit.ExceptionProperty `json:"ctf.exception"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	readJSON(t, filepath.Join(expectedDir, "findings.sarif"), &sarif)

	var receipt struct {
		Watermark string `json:"watermark"`
		Statement struct {
			Stage string `json:"stage"`
		} `json:"statement"`
	}
	readJSON(t, filepath.Join(expectedDir, "receipt.json"), &receipt)

	stage, err := ctfkit.ParseStage(receipt.Statement.Stage)
	if err != nil {
		t.Fatalf("stage from the expected receipt: %v", err)
	}

	in := spacelift.Input{Stage: stage, Watermark: receipt.Watermark}
	if len(sarif.Runs) == 0 {
		t.Fatalf("expected SARIF carries no run")
	}
	for _, r := range sarif.Runs[0].Results {
		resultStage, stageErr := ctfkit.ParseStage(r.Properties.Stage)
		if stageErr != nil {
			t.Fatalf("stage on result %s of the expected SARIF: %v", r.RuleID, stageErr)
		}

		f := ctfkit.Finding{RuleID: r.RuleID, Level: r.Level, Kind: ctfkit.KindFail}
		f.Message.Text = r.Message.Text
		f.Props.Schema = r.Properties.Schema
		f.Props.Stage = resultStage
		f.Props.Exception = r.Properties.Exception
		in.Findings = append(in.Findings, f)
	}
	return in
}

func readJSON(t *testing.T, path string, into any) {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // test-controlled path under testdata/
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err = json.Unmarshal(data, into); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
}

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	data, err := os.ReadFile(schemaPath) //nolint:gosec // test-controlled path under schema/
	if err != nil {
		t.Fatalf("read %s: %v", schemaPath, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
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

// assertGolden compares got against the recorded bytes. -update refuses to
// touch the report fixtures: they are the oracle, and an oracle a test can
// rewrite proves nothing on the next run.
func assertGolden(t *testing.T, path string, got []byte) {
	t.Helper()

	if *update {
		t.Fatalf("-update refuses to rewrite the report fixture oracle at %s", path)
	}

	want, err := os.ReadFile(path) //nolint:gosec // test-controlled path under testdata/
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("rendered bytes do not match %s\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}
