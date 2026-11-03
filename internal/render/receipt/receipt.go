// Package receipt renders the Evidence Receipt of one `ctfkit report`
// run: the schema ctf.evidence.receipt/1 document of kind module-coverage.
//
// The whole file, envelope included, is canonical JSON (RFC 8785): keys
// sorted, no insignificant whitespace, no trailing newline. That is not a
// formatting preference. A later release has the customer's CI sign the
// statement and an enterprise countersigning service from compliance.tf
// countersign it, and a signature covers bytes, so the bytes have to be
// reproducible from the parsed value on any machine. Every
// recorded case under testdata/fixtures/report is compared byte for byte.
//
// The envelope is frozen: attestations is present and empty in open source
// output, so signing (planned) fills it with no schema change. watermark, the
// optional --watermark banner line, is written only when set.
//
// RenderProviderRun renders the same envelope with kind provider-run: the
// receipt of `ctfkit evidence ship`, whose status is the first true row of
// the run status table.
package receipt

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/compliancetf/ctfkit/internal/inventory"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

const (
	// Schema is the receipt schema id, frozen at 1.
	Schema = "ctf.evidence.receipt/1"
	// Kind is what this command's receipt records. Another kind would be
	// another command's receipt, not another version of this one.
	Kind = "module-coverage"
	// Stage is the SDK stage a module-coverage receipt is produced at. The
	// post_apply receipt of a later release is a different document.
	Stage = "post_init"
	// Provenance is the only provenance open source output claims for a
	// manifest: read from disk, countersigned by nobody.
	Provenance = ctfkit.ProvenanceLocalUnverified
)

// ScopeStatement is rendered verbatim into every receipt. It is the sentence
// the evidence pack is read against, so it is a constant here rather than
// prose a caller supplies: a receipt that narrowed its own scope statement
// would claim more than the run can support.
const ScopeStatement = "This receipt records which controls the compliance.tf served modules in this " +
	"configuration enforce at module build time, as read from the manifests written at init, and which " +
	"resources declared by this configuration are covered by its own tests. It is not a live-state " +
	"assertion, not an attestation by compliance.tf, and not computer-system validation."

// Verdicts the receipt records.
const (
	// VerdictPass means the run produced no unsuppressed error-level finding.
	VerdictPass = "pass"
	// VerdictFail means it produced at least one.
	VerdictFail = "fail"
)

// Generator names the build that produced the receipt.
type Generator struct {
	// Name is the tool name, "ctfkit".
	Name string `json:"name"`
	// Version is the release the binary was built from.
	Version string `json:"version"`
}

// Input is everything the receipt records. Every field is read; nothing here
// is fetched, and no clock is read: the run time is Metadata.Now, which is what
// lets a recorded case be an oracle on any day.
type Input struct {
	// Inventory is the coverage record of the root, from the inventory step.
	Inventory *inventory.Inventory
	// Modules is the loaded modules.json with its per-instance manifests and
	// digests. The receipt's inputs block and its obligations come from here.
	Modules *ctfkit.ModuleInventory
	// ModulesJSONSHA256 is the lowercase hex digest of the modules.json bytes
	// that were read. It is an input rather than something this package
	// computes, because the loader is what read those bytes and re-reading the
	// file would digest a document nobody analyzed.
	ModulesJSONSHA256 string
	// Findings are the analyzer's unsuppressed findings, in the order the
	// projections emit them. They are not re-sorted here: the order is the
	// analyzer's, and it is what the recorded cases carry.
	Findings ctfkit.Findings
	// Metadata is the run context, from the run flags or the CI environment.
	Metadata ctfkit.RunMetadata
	// Tests is the imported test document, nil when none was imported. The
	// inputs.tests block is absent rather than zeroed when it is nil, because
	// zero runs and no run are different statements.
	Tests *ctfkit.TestRun
	// Watermark is the operator's optional banner line, empty for none.
	Watermark string
	// Generator names the build that produced the receipt.
	Generator Generator
}

// Render returns the receipt as canonical JSON with no trailing newline.
func Render(in Input) ([]byte, error) {
	if in.Inventory == nil {
		return nil, errors.New("receipt: no inventory, so there is nothing to attest to")
	}
	if in.Modules == nil {
		return nil, errors.New("receipt: no module inventory, so no input can be digested")
	}
	if in.ModulesJSONSHA256 == "" {
		return nil, errors.New("receipt: no modules.json digest, so the receipt could not name what it read")
	}
	if in.Metadata.Now.IsZero() {
		return nil, errors.New("receipt: no run clock, so the receipt would date itself to the zero time")
	}
	if in.Generator.Name == "" || in.Generator.Version == "" {
		return nil, errors.New("receipt: no generator name and version, so nothing would say which build produced this")
	}
	// RunID, Platform and Commit are not checked: RunMetadata documents each
	// as empty when unknown, and a laptop run knows none of the three. A
	// receipt that named no run is still a true receipt; one that named the
	// zero time or no generator is not.

	if err := checkWatermark(in.Watermark); err != nil {
		return nil, err
	}

	doc := document{
		Attestations: attestations{ComplianceTf: []json.RawMessage{}, CustomerCi: []json.RawMessage{}},
		Kind:         Kind,
		Schema:       Schema,
		Statement: statement{
			Builds:                   orEmpty(in.Inventory.Builds),
			Findings:                 findings(in.Findings),
			Generator:                in.Generator,
			Inputs:                   inputsOf(in),
			InstancesWithoutManifest: orEmpty(in.Inventory.InstancesWithoutManifest),
			Obligations:              obligations(in.Modules.Instances),
			RootResources:            in.Inventory.RootResources,
			Run: run{
				Commit:    in.Metadata.Commit,
				ID:        in.Metadata.RunID,
				Platform:  in.Metadata.Platform,
				Timestamp: in.Metadata.Now.UTC().Format(time.RFC3339),
			},
			ScopeStatement: ScopeStatement,
			Stage:          Stage,
			Subject:        subject{Root: in.Modules.Root},
			Verdict:        verdict(in.Findings),
		},
		Watermark: in.Watermark,
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("receipt: %w", err)
	}
	return jcs.Transform(raw)
}

// document is the frozen envelope.
type document struct {
	Attestations attestations `json:"attestations"`
	Kind         string       `json:"kind"`
	Schema       string       `json:"schema"`
	Statement    statement    `json:"statement"`
	Watermark    string       `json:"watermark,omitempty"`
}

// attestations is where signatures land in the hosted tier. Both lists are
// present and empty in open source output, so a reader can tell "nobody signed
// this" from "this document has no place for a signature".
type attestations struct {
	ComplianceTf []json.RawMessage `json:"complianceTf"`
	CustomerCi   []json.RawMessage `json:"customerCi"`
}

// statement is what a signature covers.
type statement struct {
	Builds                   []inventory.ServedBuild `json:"builds"`
	Findings                 []finding               `json:"findings"`
	Generator                Generator               `json:"generator"`
	Inputs                   inputs                  `json:"inputs"`
	InstancesWithoutManifest []inventory.Instance    `json:"instancesWithoutManifest"`
	Obligations              []obligation            `json:"obligations"`
	RootResources            inventory.RootResources `json:"rootResources"`
	Run                      run                     `json:"run"`
	ScopeStatement           string                  `json:"scopeStatement"`
	Stage                    string                  `json:"stage"`
	Subject                  subject                 `json:"subject"`
	Verdict                  string                  `json:"verdict"`
}

type run struct {
	Commit    string `json:"commit"`
	ID        string `json:"id"`
	Platform  string `json:"platform"`
	Timestamp string `json:"timestamp"`
}

type subject struct {
	Root string `json:"root"`
}

// inputs names every document the run read, by digest, so a reader can check
// that the receipt describes the tree they are holding.
type inputs struct {
	Manifests   []manifestInput `json:"manifests"`
	ModulesJSON digestOnly      `json:"modulesJson"`
	Tests       *testsInput     `json:"tests,omitempty"`
}

type digestOnly struct {
	SHA256 string `json:"sha256"`
}

type manifestInput struct {
	Key        string `json:"key"`
	Provenance string `json:"provenance"`
	SHA256     string `json:"sha256"`
	Source     string `json:"source"`
	Version    string `json:"version"`
}

type testsInput struct {
	Errored int    `json:"errored"`
	Failed  int    `json:"failed"`
	Passed  int    `json:"passed"`
	Runs    int    `json:"runs"`
	SHA256  string `json:"sha256"`
	Skipped int    `json:"skipped"`
}

// obligation is one does-not-prove token and what the consumer must do
// instead. The receipt carries the consumer's side only; the statement of what
// the manifest does not assert is the manifest's own text.
type obligation struct {
	ConsumerObligation string `json:"consumerObligation"`
	Token              string `json:"token"`
}

// finding is the three members of a finding the receipt carries. Locations and
// the ctf.* property bag are the SARIF projection's contract; a receipt is read
// by a person and by a control mapper, and neither needs a line number.
type finding struct {
	Level   string `json:"level"`
	Message string `json:"message"`
	RuleID  string `json:"ruleId"`
}

// orEmpty renders a nil slice as [] rather than null. Every list in the
// envelope is required and an empty list is a statement in its own right: no
// build was instantiated, no instance lacked a manifest. A null there would
// read as "this receipt does not say", which is a different claim and one the
// published schema refuses.
func orEmpty[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

// inputsOf digests everything the run read.
func inputsOf(in Input) inputs {
	out := inputs{
		Manifests:   manifests(in.Modules.Instances),
		ModulesJSON: digestOnly{SHA256: in.ModulesJSONSHA256},
	}
	if in.Tests != nil {
		out.Tests = &testsInput{
			Errored: in.Tests.Errored,
			Failed:  in.Tests.Failed,
			Passed:  in.Tests.Passed,
			Runs:    in.Tests.Runs,
			SHA256:  in.Tests.SHA256,
			Skipped: in.Tests.Skipped,
		}
	}
	return out
}

// manifests lists one entry per instance that has a manifest, sorted by key.
// Several instances of one build carry one entry each with the same digest:
// the list names what was read per instance, not per build, so a reader can
// check every file the run opened.
func manifests(instances []ctfkit.ModuleInstance) []manifestInput {
	out := make([]manifestInput, 0, len(instances))
	for _, instance := range instances {
		if instance.Manifest == nil {
			continue
		}
		out = append(out, manifestInput{
			Key:        instance.Key,
			Provenance: Provenance,
			SHA256:     instance.ManifestSHA256,
			Source:     instance.Manifest.Module.RegistrySource,
			Version:    instance.Manifest.Module.Version,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// obligations is the union of every manifest's scope.does_not_prove, sorted by
// token. A token two manifests share keeps the prose of the first manifest
// modules.json lists, which is the producer's own order: the alternative is to
// pick a winner by comparing two sentences, and the receipt is not the place to
// decide which of a producer's two phrasings is right.
func obligations(instances []ctfkit.ModuleInstance) []obligation {
	seen := make(map[string]string)
	for _, instance := range instances {
		if instance.Manifest == nil {
			continue
		}
		for _, entry := range instance.Manifest.Scope.DoesNotProve {
			if _, ok := seen[entry.Token]; !ok {
				seen[entry.Token] = entry.ConsumerObligation
			}
		}
	}

	out := make([]obligation, 0, len(seen))
	for token, prose := range seen {
		out = append(out, obligation{ConsumerObligation: prose, Token: token})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Token < out[j].Token })
	return out
}

// findings carries the analyzer's list in the analyzer's order.
func findings(fs ctfkit.Findings) []finding {
	out := make([]finding, 0, len(fs))
	for _, f := range fs {
		out = append(out, finding{Level: f.Level, Message: f.Message.Text, RuleID: f.RuleID})
	}
	return out
}

// verdict is fail when the run produced any unsuppressed error-level finding,
// and it is independent of --fail-on. A shadow-mode run exits 0 and still
// records fail, which is the whole reason shadow evidence is worth keeping;
// widening the threshold to warning does not turn a warning-only run into fail.
//
// A finding an allowed exception waives does not count: that is the whole of
// what a waiver buys. An exception found but out of its review window is
// recorded with Allowed false and still counts. The report specification makes this one
// value across the receipt, the Spacelift file and the Markdown verdict line,
// and the other two renderers already applied it; this one did not.
func verdict(fs ctfkit.Findings) string {
	for _, f := range fs {
		if f.Level != ctfkit.LevelError {
			continue
		}
		if f.Suppressed() {
			continue
		}
		return VerdictFail
	}
	return VerdictPass
}

// checkWatermark holds the operator's banner to one printable line.
func checkWatermark(extra string) error {
	for _, r := range extra {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("receipt: watermark text %q carries a control character", extra)
		}
	}
	return nil
}
