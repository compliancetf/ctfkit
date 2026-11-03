package receipt

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// KindProviderRun is the receipt of one governed run's evidence, written by
// ctfkit evidence ship. Same envelope as module-coverage.
const KindProviderRun = "provider-run"

// Run receipt statuses, in the order Status tests them: the status is the
// first condition that holds, enforced when none does.
const (
	StatusRecoveryRequired   = "recovery_required"
	StatusFailed             = "failed"
	StatusOverridden         = "overridden"
	StatusEvidenceDegraded   = "evidence-degraded"
	StatusSingleResourceOnly = "single-resource-only"
	StatusEnforced           = "enforced"
)

// statusOrder is the status table; enforced is not a condition.
var statusOrder = []string{StatusRecoveryRequired, StatusFailed, StatusOverridden, StatusEvidenceDegraded, StatusSingleResourceOnly}

// Status is the first of conditions in table order, or enforced.
func Status(conditions []string) string {
	for _, s := range statusOrder {
		if slices.Contains(conditions, s) {
			return s
		}
	}
	return StatusEnforced
}

// Runner classes. The class comes from the producing command, never env.
const (
	RunnerLocal = "local"
	RunnerCI    = "ci"
)

// ProviderRun is everything a provider-run receipt records.
type ProviderRun struct {
	Generator Generator
	Run       RunInfo
	// Conditions are the true status conditions, any order, duplicates
	// allowed; the statement lists them once each in table order.
	Conditions []string
	Chains     []ChainRef
	Sinks      []SinkRef
	Manifest   *ManifestRef
	Alerts     []string
	// Reason is why the run is not enforced when no other member says it,
	// for example chains that failed verification; empty for none.
	Reason string
}

// RunInfo identifies the run. Now is the run clock.
type RunInfo struct {
	ID          string
	OrgID       string
	Workspace   string
	RunnerClass string
	Now         time.Time
}

// SeqRange is a missing span of seqs; To nil is open-ended.
type SeqRange struct {
	From int64  `json:"from"`
	To   *int64 `json:"to,omitempty"`
}

// ChainRef is one process chain as the run manifest records it.
type ChainRef struct {
	Breaks     int        `json:"breaks"`
	Chain      string     `json:"chain"`
	FirstSeq   int64      `json:"firstSeq"`
	LastHash   string     `json:"lastHash"`
	LastSeq    int64      `json:"lastSeq"`
	Missing    []SeqRange `json:"missing"`
	Records    int        `json:"records"`
	Terminated bool       `json:"terminated"`
}

// SinkRef is how many of the run's objects one sink took and how many were
// spooled for a later run.
type SinkRef struct {
	Name    string `json:"name"`
	Shipped int    `json:"shipped"`
	Spooled int    `json:"spooled"`
}

// ManifestRef names the signed run manifest: its object key, signing kid and
// the hex sha256 of its bytes.
type ManifestRef struct {
	Key    string `json:"key"`
	Kid    string `json:"kid"`
	SHA256 string `json:"sha256"`
}

type providerRunDoc struct {
	Attestations attestations         `json:"attestations"`
	Kind         string               `json:"kind"`
	Schema       string               `json:"schema"`
	Statement    providerRunStatement `json:"statement"`
}

type providerRunStatement struct {
	Alerts     []string     `json:"alerts"`
	Chains     []ChainRef   `json:"chains"`
	Conditions []string     `json:"conditions"`
	Generator  Generator    `json:"generator"`
	Manifest   *ManifestRef `json:"manifest,omitempty"`
	Reason     string       `json:"reason,omitempty"`
	Run        providerRun  `json:"run"`
	Sinks      []SinkRef    `json:"sinks"`
	Status     string       `json:"status"`
}

type providerRun struct {
	ID          string `json:"id"`
	OrgID       string `json:"orgId"`
	RunnerClass string `json:"runnerClass"`
	Timestamp   string `json:"timestamp"`
	Workspace   string `json:"workspace"`
}

// RenderProviderRun returns the provider-run receipt as canonical JSON with
// no trailing newline.
func RenderProviderRun(in ProviderRun) ([]byte, error) {
	switch {
	case in.Run.Now.IsZero():
		return nil, errors.New("receipt: no run clock")
	case in.Generator.Name == "" || in.Generator.Version == "":
		return nil, errors.New("receipt: no generator name and version")
	case in.Run.ID == "" || in.Run.OrgID == "" || in.Run.RunnerClass == "":
		return nil, errors.New("receipt: no run id, org id or runner class")
	}
	conditions := []string{}
	for _, s := range statusOrder {
		if slices.Contains(in.Conditions, s) {
			conditions = append(conditions, s)
		}
	}
	for _, c := range in.Conditions {
		if !slices.Contains(statusOrder, c) {
			return nil, fmt.Errorf("receipt: unknown condition %q", c)
		}
	}
	chains := slices.Clone(orEmpty(in.Chains)) // the caller's chains stay as given
	for i := range chains {
		chains[i].Missing = orEmpty(chains[i].Missing)
	}
	doc := providerRunDoc{
		Attestations: attestations{ComplianceTf: []json.RawMessage{}, CustomerCi: []json.RawMessage{}},
		Kind:         KindProviderRun,
		Schema:       Schema,
		Statement: providerRunStatement{
			Alerts:     orEmpty(in.Alerts),
			Chains:     chains,
			Conditions: conditions,
			Generator:  in.Generator,
			Manifest:   in.Manifest,
			Reason:     in.Reason,
			Run: providerRun{ID: in.Run.ID, OrgID: in.Run.OrgID, RunnerClass: in.Run.RunnerClass,
				Timestamp: in.Run.Now.UTC().Format(time.RFC3339), Workspace: in.Run.Workspace},
			Sinks:  orEmpty(in.Sinks),
			Status: Status(conditions),
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("receipt: %w", err)
	}
	return jcs.Transform(raw)
}
