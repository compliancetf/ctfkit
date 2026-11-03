// Package spacelift holds the offline check of policy.rego: it must load under
// the OPA 1.x defaults and under Rego v0, since the mode a Spacelift account
// evaluates plan policies in is not ours to choose, and it must render the
// metadata ctfkit report writes the way the README says.
package spacelift

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const policy = "policy.rego"

const taskApproval = "task-approval.rego"

func TestPolicyLoadsInV1AndV0(t *testing.T) {
	opa := lookOPA(t)
	for _, file := range []string{policy, taskApproval} {
		for _, mode := range [][]string{{}, {"--v0-v1"}, {"--v0-compatible"}} {
			args := append([]string{"check"}, mode...)
			out, err := exec.Command(opa, append(args, file)...).CombinedOutput() // #nosec G204 -- fixed arguments
			if err != nil {
				t.Errorf("opa %v %s: %v\n%s", args, file, err, out)
			}
		}
	}
}

// TestPolicyRendersReportFixtures feeds every committed Spacelift projection of
// ctfkit report to the policy under the ctfkit key, next to a passing
// ctfkit-scan file, and checks shadow mode: a failing verdict is warned with
// its totals, a passing one is silent, and nothing is denied.
func TestPolicyRendersReportFixtures(t *testing.T) {
	opa := lookOPA(t)
	fixtures, err := filepath.Glob("../../testdata/fixtures/report/*/expected/ctfkit.custom.spacelift.json")
	if err != nil || len(fixtures) == 0 {
		t.Fatalf("no Spacelift fixtures found (%v)", err)
	}
	const scanPass = `{"schema":"ctfkit.spacelift/1","stage":"post_plan","verdict":"pass","summary":{"error":0,"warning":0,"note":0},"findings":[]}`
	var sawFail, sawPass bool
	for _, fixture := range fixtures {
		name := filepath.Base(filepath.Dir(filepath.Dir(fixture)))
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(fixture) // #nosec G304 -- committed fixture
			if err != nil {
				t.Fatal(err)
			}
			var meta struct {
				Verdict string                       `json:"verdict"`
				Summary struct{ Error, Warning int } `json:"summary"`
			}
			if err = json.Unmarshal(data, &meta); err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(t.TempDir(), "input.json")
			wrapped := `{"third_party_metadata":{"custom":{"ctfkit":` + string(data) + `,"ctfkit-scan":` + scanPass + `}}}`
			if err = os.WriteFile(input, []byte(wrapped), 0o600); err != nil {
				t.Fatal(err)
			}
			got := evalPolicy(t, opa, input)
			var want []string
			switch meta.Verdict {
			case "pass":
				sawPass = true
			case "fail":
				sawFail = true
				want = []string{fmt.Sprintf("ctfkit: verdict fail (%d error, %d warning)", meta.Summary.Error, meta.Summary.Warning)}
			default:
				t.Fatalf("fixture verdict %q is neither pass nor fail", meta.Verdict)
			}
			if !slices.Equal(got.warn, want) || len(got.deny) != 0 {
				t.Errorf("warn %q, deny %q; want warn %q and nothing denied", got.warn, got.deny, want)
			}
		})
	}
	if !sawFail || !sawPass {
		t.Errorf("fixtures must include a failing and a passing run (fail %v, pass %v)", sawFail, sawPass)
	}
}

// TestPolicyStackLabel checks the per-stack flip, with enforce left false: the
// ctfkit:enforce label, in any case, turns every fail-closed condition into a
// deny, no label leaves shadow mode, and any other ctfkit: label is denied
// even in shadow mode and enforces nothing. Each row adds labels to a
// committed test input.
func TestPolicyStackLabel(t *testing.T) {
	opa := lookOPA(t)
	const (
		enforceLabel = "ctfkit:enforce"
		scanFail     = "ctfkit-scan: verdict fail (2 error, 0 warning)"
		scanMissing  = "ctfkit metadata is missing from this run under key ctfkit-scan"
		badSchema    = "ctfkit metadata under key ctfkit-scan is in unknown schema ctfkit.spacelift/9"
		nearMiss     = "unrecognized ctfkit label ctfkit:enforce-later; the known labels are ctfkit:enforce and ctfkit:gate"
		gate2        = "unrecognized ctfkit label ctfkit:gate2; the known labels are ctfkit:enforce and ctfkit:gate"
		upperNear    = "unrecognized ctfkit label CTFKIT:Enforced; the known labels are ctfkit:enforce and ctfkit:gate"
	)
	for _, tc := range []struct {
		name, fixture string
		labels        []string
		warn, deny    []string
	}{
		{"failing verdict, label", "scan-verdict-fail", []string{"team:platform", enforceLabel}, []string{scanFail}, []string{scanFail}},
		{"failing verdict, no label", "scan-verdict-fail", nil, []string{scanFail}, nil},
		{"missing scan key, label", "scan-key-missing", []string{enforceLabel}, []string{scanMissing}, []string{scanMissing}},
		{"unknown schema, label", "unknown-schema", []string{enforceLabel}, nil, []string{badSchema}},
		{"both pass, label", "clean", []string{enforceLabel}, nil, nil},
		{"label in upper case", "scan-verdict-fail", []string{"CTFKIT:Enforce"}, []string{scanFail}, []string{scanFail}},
		{"near-miss label", "clean", []string{"team:platform", "ctfkit:enforce-later"}, nil, []string{nearMiss}},
		{"near-miss label in upper case", "clean", []string{"CTFKIT:Enforced"}, nil, []string{upperNear}},
		{"ctfkit:gate2", "clean", []string{"ctfkit:gate2"}, nil, []string{gate2}},
		{"near-miss label, enforcing", "scan-verdict-fail", []string{"ctfkit:enforce-later", enforceLabel},
			[]string{scanFail}, []string{scanFail, nearMiss}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := evalPolicy(t, opa, withLabels(t, "test/"+tc.fixture+".json", tc.labels))
			if !slices.Equal(got.warn, tc.warn) || !slices.Equal(got.deny, tc.deny) {
				t.Errorf("warn %q, deny %q; want warn %q, deny %q", got.warn, got.deny, tc.warn, tc.deny)
			}
		})
	}
}

// TestPolicyGate checks the governed-apply rules against the committed
// test/gate-*.json inputs, with the shipped policy and with a copy that sets
// verdict_required. A ctfkit:gate stack is refused without the ctfkit-gate
// metadata even in shadow mode; a stack without the label is allowed, with no
// verdict and single-resource checks only, unless verdict_required is set; an
// absent or unknown gate schema is refused everywhere. Rows with labels
// replace the fixture's stack labels.
func TestPolicyGate(t *testing.T) {
	opa := lookOPA(t)
	src, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	const off, on = "verdict_required := false", "verdict_required := true"
	if strings.Count(string(src), off) != 1 {
		t.Fatalf("%s must set %q exactly once", policy, off)
	}
	required := filepath.Join(t.TempDir(), "policy-verdict-required.rego")
	if err = os.WriteFile(required, []byte(strings.Replace(string(src), off, on, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	const (
		missing    = "ctfkit metadata is missing from this run under key ctfkit-gate; the stack's plan command must be ctfkit gate plan"
		badSchema9 = "ctfkit metadata under key ctfkit-gate is in unknown schema ctfkit.spacelift-gate/9"
	)
	for _, tc := range []struct {
		name, fixture      string
		labels             []string
		verdictRequired    bool
		wantWarn, wantDeny []string
	}{
		{name: "gate stack with metadata", fixture: "gate-clean"},
		{name: "gate stack with metadata, verdict_required", fixture: "gate-clean", verdictRequired: true},
		{name: "gate stack without metadata", fixture: "gate-missing", wantDeny: []string{missing}},
		{name: "gate label in mixed case without metadata", fixture: "gate-missing", labels: []string{"Ctfkit:Gate"}, wantDeny: []string{missing}},
		{name: "ctfkit:gate2 is not a gate stack", fixture: "gate-missing", labels: []string{"ctfkit:gate2"},
			wantDeny: []string{"unrecognized ctfkit label ctfkit:gate2; the known labels are ctfkit:enforce and ctfkit:gate"}},
		{name: "enforced gate stack with metadata", fixture: "gate-clean", labels: []string{"ctfkit:gate", "ctfkit:enforce"}},
		{name: "enforced gate stack without metadata", fixture: "gate-missing", labels: []string{"ctfkit:gate", "ctfkit:enforce"},
			wantDeny: []string{missing}},
		{name: "unknown gate schema", fixture: "gate-unknown-schema", wantDeny: []string{badSchema9}},
		{name: "unknown gate schema, verdict_required", fixture: "gate-unknown-schema", verdictRequired: true, wantDeny: []string{badSchema9}},
		{name: "absent gate schema", fixture: "gate-schema-absent",
			wantDeny: []string{"ctfkit metadata under key ctfkit-gate is in unknown schema absent"}},
		{name: "plain stack: single-resource-only", fixture: "gate-not-gate-stack"},
		{name: "plain stack, verdict_required", fixture: "gate-not-gate-stack", verdictRequired: true, wantDeny: []string{missing}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := policy
			if tc.verdictRequired {
				p = required
			}
			got := evalPolicyFile(t, opa, p, withLabels(t, "test/"+tc.fixture+".json", tc.labels))
			if !slices.Equal(got.warn, tc.wantWarn) || !slices.Equal(got.deny, tc.wantDeny) {
				t.Errorf("warn %q, deny %q; want warn %q, deny %q", got.warn, got.deny, tc.wantWarn, tc.wantDeny)
			}
		})
	}
}

// TestTaskApproval checks the sample approval policy: a task on a ctfkit:gate
// stack, in any case of the label, is rejected; every other run is approved.
func TestTaskApproval(t *testing.T) {
	opa := lookOPA(t)
	for _, tc := range []struct {
		name, runType string
		labels        []string
		wantReject    bool
	}{
		{"task on a gate stack", "TASK", []string{"team:platform", "ctfkit:gate"}, true},
		{"task on a gate stack, label in upper case", "TASK", []string{"CTFKIT:GATE"}, true},
		{"tracked run on a gate stack", "TRACKED", []string{"ctfkit:gate"}, false},
		{"task on a plain stack", "TASK", []string{"ctfkit:enforce"}, false},
		{"task on a stack without labels", "TASK", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := json.Marshal(map[string]any{
				"run":   map[string]any{"type": tc.runType, "command": "tofu state rm aws_s3_bucket.logs"},
				"stack": map[string]any{"labels": tc.labels},
			})
			if err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(t.TempDir(), "input.json")
			if err = os.WriteFile(input, doc, 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(opa, "eval", "--format", "json", // #nosec G204 -- test-owned paths
				"--data", taskApproval, "--input", input, "data.spacelift").Output()
			if err != nil {
				t.Fatalf("opa eval %s: %v", taskApproval, err)
			}
			var res struct {
				Result []struct {
					Expressions []struct {
						Value struct{ Approve, Reject bool } `json:"value"`
					} `json:"expressions"`
				} `json:"result"`
			}
			if err = json.Unmarshal(out, &res); err != nil || len(res.Result) != 1 || len(res.Result[0].Expressions) != 1 {
				t.Fatalf("unexpected opa output (%v):\n%s", err, out)
			}
			v := res.Result[0].Expressions[0].Value
			if v.Reject != tc.wantReject || v.Approve == tc.wantReject {
				t.Errorf("approve %v, reject %v; want reject %v and approve the opposite", v.Approve, v.Reject, tc.wantReject)
			}
		})
	}
}

// withLabels returns the path of a copy of the input fixture whose stack
// carries labels, or the fixture itself when there are none.
func withLabels(t *testing.T, fixture string, labels []string) string {
	t.Helper()
	if labels == nil {
		return fixture
	}
	data, err := os.ReadFile(fixture) // #nosec G304 -- committed fixture
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["spacelift"] = map[string]any{"stack": map[string]any{"labels": labels}}
	if data, err = json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "input.json")
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func lookOPA(t *testing.T) string {
	t.Helper()
	opa, err := exec.LookPath("opa")
	if err != nil {
		t.Skip("opa is not installed: the policy check is skipped")
	}
	return opa
}

type verdicts struct{ warn, deny []string }

func evalPolicy(t *testing.T, opa, input string) verdicts {
	t.Helper()
	return evalPolicyFile(t, opa, policy, input)
}

func evalPolicyFile(t *testing.T, opa, file, input string) verdicts {
	t.Helper()
	out, err := exec.Command(opa, "eval", "--format", "json", // #nosec G204 -- test-owned paths
		"--data", file, "--input", input, "data.spacelift").Output()
	if err != nil {
		t.Fatalf("opa eval %s: %v", file, err)
	}
	var res struct {
		Result []struct {
			Expressions []struct {
				Value struct {
					Warn []string `json:"warn"`
					Deny []string `json:"deny"`
				} `json:"value"`
			} `json:"expressions"`
		} `json:"result"`
	}
	if err = json.Unmarshal(out, &res); err != nil || len(res.Result) != 1 || len(res.Result[0].Expressions) != 1 {
		t.Fatalf("unexpected opa output (%v):\n%s", err, out)
	}
	v := res.Result[0].Expressions[0].Value
	return verdicts{warn: v.Warn, deny: v.Deny}
}
