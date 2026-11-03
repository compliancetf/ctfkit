// Package spacelift renders ctfkit.custom.spacelift.json, the compact metadata
// file a Spacelift plan policy reads as input.third_party_metadata.custom.ctfkit.
//
// The file is deliberately small: a policy, not a human, reads it. It carries
// the verdict, the counts a policy can deny on without walking an array, and a
// findings list with the rule id, level and message of each finding. No
// locations, no property bag, no prose.
package spacelift

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// FileName is the name the file always takes, in the run's working directory
// and nowhere else. --out-dir moves every other projection and never this one,
// because the working directory is where Spacelift looks for a custom metadata
// input. The name is part of the platform contract, so it is a constant rather
// than a caller's choice.
const FileName = "ctfkit.custom.spacelift.json"

// SchemaID is the schema tag every rendered document carries.
const SchemaID = "ctfkit.spacelift/1"

// Verdicts recorded in the file. The verdict follows the exit contract of the
// run, not the finding count and not --fail-on.
const (
	// VerdictPass means the run produced no unsuppressed error-level finding.
	VerdictPass = "pass"
	// VerdictFail means at least one error-level finding stands unsuppressed.
	VerdictFail = "fail"
)

// Input is everything the renderer needs. It takes findings rather than a
// receipt so that the Spacelift file can be written from the same in-memory
// run as every other projection, with no ordering dependency between them.
type Input struct {
	// Stage is the stage the run analyzed at. It is written verbatim and must
	// be one of the frozen stages.
	Stage ctfkit.Stage
	// Findings are the run's findings in the order every projection shows
	// them, suppressed ones included: a waiver hides a finding from the gate,
	// not from the record.
	Findings ctfkit.Findings
	// Watermark is the optional --watermark banner line, empty for none. The
	// watermark key is written only when it is set.
	Watermark string
}

// document is the file itself. Field order is key order: encoding/json writes
// struct fields in declaration order, which is what keeps the rendered bytes
// stable without a hand-rolled encoder.
type document struct {
	Schema    string    `json:"schema"`
	Stage     string    `json:"stage"`
	Verdict   string    `json:"verdict"`
	Watermark string    `json:"watermark,omitempty"`
	Summary   summary   `json:"summary"`
	Findings  []finding `json:"findings"`
}

// summary counts findings by level, after suppression, so that a policy can
// deny on summary.error alone. All three keys are always present.
type summary struct {
	Error   int `json:"error"`
	Warning int `json:"warning"`
	Note    int `json:"note"`
}

// finding is one entry of the findings list: the three fields a policy can act on.
type finding struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// Render returns the bytes of the Spacelift metadata file: two-space indent,
// trailing newline. It rejects an input that would produce a document the
// spacelift-1 schema refuses, because the reader of this file is a policy gate
// that cannot report a parse problem to anyone.
func Render(in Input) ([]byte, error) {
	if in.Stage.Rank() < 0 {
		return nil, fmt.Errorf("spacelift: unknown stage %q", in.Stage)
	}
	if err := checkWatermark(in.Watermark); err != nil {
		return nil, err
	}

	doc := document{
		Schema:    SchemaID,
		Stage:     in.Stage.String(),
		Verdict:   VerdictPass,
		Watermark: in.Watermark,
		Findings:  make([]finding, 0, len(in.Findings)),
	}

	for _, f := range in.Findings {
		// Finding.Validate is the shape check the SDK defines for exactly this
		// boundary: the rule id, the level and the kind against their frozen
		// sets. Its rule id check is ctfkit.RuleIDPattern, which is the
		// published schemas' pattern verbatim, so it is the whole of what this
		// renderer needs; there was a second copy of that regexp here until
		// the SDK followed the schemas. Validate does not look at
		// the message, and the schema wants a non-empty one, so that check
		// stays here.
		if err := f.Validate(); err != nil {
			return nil, fmt.Errorf("spacelift: %w", err)
		}
		if f.Message.Text == "" {
			return nil, fmt.Errorf("spacelift: finding %q has an empty message", f.RuleID)
		}

		doc.Findings = append(doc.Findings, finding{
			RuleID:  f.RuleID,
			Level:   f.Level,
			Message: f.Message.Text,
		})

		// A suppressed finding stays in the array and leaves the counts and
		// the verdict alone: that is the whole of what an allowed exception
		// buys, and a reader can still see what was waived.
		if f.Suppressed() {
			continue
		}

		switch f.Level {
		case ctfkit.LevelError:
			doc.Summary.Error++
			doc.Verdict = VerdictFail
		case ctfkit.LevelWarning:
			doc.Summary.Warning++
		case ctfkit.LevelNote:
			doc.Summary.Note++
		}
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("spacelift: marshal: %w", err)
	}
	return append(data, '\n'), nil
}

// Write puts data at FileName inside workingDir, overwriting whatever a
// previous run left. The destination is not a caller's choice: --out-dir moves
// the other projections and never this one, because Spacelift discovers a
// custom metadata input by name in the run's working directory.
func Write(workingDir string, data []byte) error {
	return WriteNamed(workingDir, FileName, data)
}

// ScanFileName is the name `ctfkit scan` writes. It differs from FileName so
// that an after_plan scan never overwrites the after_init report; the plan
// policy reads each under its own key.
const ScanFileName = "ctfkit-scan.custom.spacelift.json"

// WriteNamed is Write under a caller-chosen fixed name, FileName or
// ScanFileName.
func WriteNamed(workingDir, name string, data []byte) error {
	path := filepath.Join(workingDir, name)

	// Written to a temp file beside the destination and renamed over it, not
	// opened in place. os.WriteFile opens without O_NOFOLLOW, so a symlink
	// left at this name by the checked-out configuration would send the write
	// to the symlink's target, outside workingDir, and the plan policy would
	// read whatever already sat at the name. The configuration under analysis
	// is untrusted input: on a proposed run it is whatever the change author
	// committed. rename(2) replaces the link itself.
	//
	// Two more things follow from the same move. The replacement is atomic, so
	// a policy reading concurrently never sees half a document. And the mode
	// is set fresh every run: os.CreateTemp creates at 0600, where O_TRUNC on
	// an existing file would have kept a looser mode some other tool left.
	// 0600 is right because the file is read by the runner that wrote it, in
	// that runner's own workspace (gosec G306).
	tmp, err := os.CreateTemp(workingDir, name+".tmp-*")
	if err != nil {
		return fmt.Errorf("spacelift: create a temp file in %s: %w", workingDir, err)
	}
	tmpName := tmp.Name()
	// Closing twice and removing a renamed-away name both fail harmlessly, so
	// the cleanup needs no success flag: it is a no-op on the happy path and
	// removes the temp file on every error path.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("spacelift: write %s: %w", tmpName, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("spacelift: close %s: %w", tmpName, err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("spacelift: rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}

// checkWatermark holds the --watermark banner to the one printable line the
// spacelift-1 schema allows.
func checkWatermark(w string) error {
	if strings.ContainsFunc(w, unicode.IsControl) {
		return fmt.Errorf("spacelift: watermark must be one printable line: %q", w)
	}
	return nil
}
