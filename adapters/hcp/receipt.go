package hcp

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"runtime"
	"time"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// Receipt values. The statement follows the receipt-1 provider-run shape of
// findings, inputs and reason are the run task's own members.
// shortcut: rendered here until the provider-run renderer lands in
// internal/render/receipt; then this file calls it and keeps only the extra
// members.
const (
	receiptSchema        = "ctf.evidence.receipt/1"
	receiptKind          = "provider-run"
	runnerClass          = "hcp-advisory"
	statusFailed         = "failed"
	statusSingleResource = "single-resource-only"
	receiptSuffix        = ".receipt.json"
)

// Generator names the build that produced a receipt.
type Generator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type receiptDoc struct {
	Attestations struct {
		ComplianceTf []json.RawMessage `json:"complianceTf"`
		CustomerCi   []json.RawMessage `json:"customerCi"`
	} `json:"attestations"`
	Kind      string           `json:"kind"`
	Schema    string           `json:"schema"`
	Statement receiptStatement `json:"statement"`
}

type receiptStatement struct {
	Alerts     []string         `json:"alerts"`
	Chains     []any            `json:"chains"`
	Conditions []string         `json:"conditions"`
	Findings   []receiptFinding `json:"findings"`
	Generator  Generator        `json:"generator"`
	Inputs     receiptInputs    `json:"inputs"`
	Reason     string           `json:"reason,omitempty"`
	Run        receiptRun       `json:"run"`
	Sinks      []any            `json:"sinks"`
	Status     string           `json:"status"`
}

type receiptInputs struct {
	PlanJSON string `json:"planJson,omitempty"` // sha256:<hex> of the bytes analyzed
	Profile  string `json:"profile,omitempty"`  // verified profile digest
}

type receiptRun struct {
	ID           string `json:"id"`
	OrgID        string `json:"orgId"`
	RunnerClass  string `json:"runnerClass"`
	Speculative  bool   `json:"speculative"`
	Stage        string `json:"stage"`
	TaskResultID string `json:"taskResultId"`
	Timestamp    string `json:"timestamp"`
	Workspace    string `json:"workspace"`
}

type receiptFinding struct {
	Level      string `json:"level"`
	Message    string `json:"message"`
	RuleID     string `json:"ruleId"`
	Suppressed bool   `json:"suppressed"`
}

// renderReceipt returns the run's receipt as canonical JSON (RFC 8785).
func renderReceipt(gen Generator, p *payload, o outcome, now time.Time) ([]byte, error) {
	var d receiptDoc
	d.Attestations.ComplianceTf, d.Attestations.CustomerCi = []json.RawMessage{}, []json.RawMessage{}
	d.Kind, d.Schema = receiptKind, receiptSchema
	d.Statement = receiptStatement{
		Alerts: []string{}, Chains: []any{}, Sinks: []any{},
		Conditions: o.conditions, Findings: receiptFindings(o.findings), Generator: gen,
		Inputs: receiptInputs{PlanJSON: o.planDigest, Profile: o.profile},
		Reason: o.reason, Status: o.status,
		Run: receiptRun{ID: p.RunID, OrgID: p.OrganizationName, RunnerClass: runnerClass, Speculative: p.IsSpeculative,
			Stage: p.Stage, TaskResultID: p.TaskResultID, Timestamp: now.UTC().Format(time.RFC3339), Workspace: p.WorkspaceName},
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

func receiptFindings(fs ctfkit.Findings) []receiptFinding {
	out := make([]receiptFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, receiptFinding{Level: f.Level, Message: f.Message.Text, RuleID: f.RuleID, Suppressed: f.Suppressed()})
	}
	return out
}

// writeReceipt writes <task_result_id>.receipt.json in the receipt dir,
// exclusively and 0600, and makes it and the dir durable. The id was checked
// against idPattern, and the os.Root refuses any path out of the dir anyway.
func (h *Handler) writeReceipt(p *payload, o outcome, now time.Time) error {
	body, err := renderReceipt(h.cfg.Generator, p, o, now)
	if err != nil {
		return err
	}
	f, err := h.receipts.OpenFile(p.TaskResultID+receiptSuffix, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		// A partial receipt must not read as evidence; the id stays
		// refused for this process by the seen-set.
		return errors.Join(err, h.receipts.Remove(p.TaskResultID+receiptSuffix))
	}
	return h.syncReceiptDir()
}

func (h *Handler) syncReceiptDir() error {
	if runtime.GOOS == "windows" {
		return nil // a directory handle cannot be synced there
	}
	d, err := h.receipts.Open(".")
	if err != nil {
		return err
	}
	err = d.Sync()
	return errors.Join(err, d.Close())
}

// receiptExists reports a receipt for the task result; a receipt that
// survived a restart still makes its request a replay.
func (h *Handler) receiptExists(id string) bool {
	_, err := h.receipts.Lstat(id + receiptSuffix)
	return !errors.Is(err, fs.ErrNotExist)
}
