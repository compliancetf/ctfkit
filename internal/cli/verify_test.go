package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/internal/sign"
	"github.com/compliancetf/ctfkit/pkg/verdict"
)

// signNow is the clock of gate plan and gate sign in these tests; the
// valid inputs' floor statement was issued at 06:00 that day.
var signNow = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// applyCLI is a CLI at now whose Evidence API answers evidence.
func applyCLI(t *testing.T, inputs string, now, evidence time.Time) *CLI {
	t.Helper()
	c := gateCLI(t, inputs)
	c.now = func() time.Time { return now }
	c.evidenceTime = func(context.Context) (time.Time, error) { return evidence, nil }
	return c
}

func applyArgs(inputs, tf, set string, cmd ...string) []string {
	return append(cmd, "--artifacts", set, "--dir", signConfig,
		"--workspace", "default", "--environment", "prod", "--tf-bin", tf, "--org", "bobthecorp",
		"--profile", filepath.Join(inputs, "profile.dsse.json"), "--floor", filepath.Join(inputs, "floor.dsse.json"),
		"--bundle-dir", filepath.Join(inputs, "bundles"))
}

// signedSet runs gate plan and gate sign over plan; gate sign may exit 1
// (the verdict is written all the same).
func signedSet(t *testing.T, inputs, plan string) (fakeTF, string) {
	t.Helper()
	f := newFakeTFSchema(t, plan, filepath.Join(gateCases, "schema.json"), 0)
	set := planCandidate(t, inputs, f)
	if code, msg := runGate(signCLI(t, inputs, verdictKeyL), signArgs(inputs, f.bin, set)); code == ExitEnvironment {
		t.Fatalf("gate sign: exit 2: %s", msg)
	}
	return f, set
}

// resign edits the verdict and signs it again with the profile's key.
func resign(t *testing.T, inputs, set string, edit func(d *verdict.Document)) {
	t.Helper()
	_, doc := readVerdict(t, set)
	edit(doc)
	s, err := parseSignSettings(mustVerified(t, inputs).Profile)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sign.Verdict(context.Background(), newLabelSigner(verdictKeyL), doc, s.keys, nil, signNow)
	if err == nil {
		err = os.WriteFile(filepath.Join(set, artifactVerdict), raw, 0o600)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// refusal is one artifact set ctfkit apply and verdict verify refuse
// (exit 2) without running terraform apply.
type refusal struct {
	inputs, plan string
	mutate       func(t *testing.T, set string)
	swapTF       func(cand map[string]any, digest string) // edits candidate.json for a swapped --tf-bin
	c            func(t *testing.T) *CLI
	want         string
	consumed     bool // ctfkit apply read the exact set, so the refusal consumes it
	terraform    bool // terraform ran (show) before the refusal
}

func refusals() map[string]refusal {
	valid := filepath.Join(gateInputs, "valid")
	linked := filepath.Join(gateCases, "linked-create", "plan.json")
	replace := filepath.Join(gateCases, "replace", "plan.json")
	at := func(now, evidence time.Time) func(*testing.T) *CLI {
		return func(t *testing.T) *CLI { return applyCLI(t, valid, now, evidence) }
	}
	return map[string]refusal{
		"missing-companion": {plan: filepath.Join(gateCases, "missing-companion", "plan.json"),
			want: "aws_s3_bucket.logs create s3_bucket_public_access_block_present fail", consumed: true},
		"companion-delete": {plan: filepath.Join(gateCases, "companion-delete", "plan.json"),
			want: "aws_s3_bucket_public_access_block.logs delete s3_bucket_public_access_block_kept fail", consumed: true},
		"replace-create-half": {plan: replace, mutate: func(t *testing.T, s string) {
			resign(t, valid, s, func(d *verdict.Document) { d.Instances[0].Decisions[0].Result = "fail" })
		}, want: "aws_s3_bucket.logs create s3_bucket_public_access_block_present fail", consumed: true},
		"replace-delete-half": {plan: replace, mutate: func(t *testing.T, s string) {
			resign(t, valid, s, func(d *verdict.Document) { d.Instances[1].DeleteDecisions[0].Result = "fail" })
		}, want: "aws_s3_bucket_public_access_block.logs delete s3_bucket_public_access_block_kept fail", consumed: true},
		"missing-instance": {plan: linked, mutate: func(t *testing.T, s string) {
			resign(t, valid, s, func(d *verdict.Document) { d.Instances = d.Instances[:1] })
		}, want: "aws_s3_bucket_public_access_block.logs is missing", consumed: true, terraform: true},
		"extra-instance": {plan: linked, mutate: func(t *testing.T, s string) {
			resign(t, valid, s, func(d *verdict.Document) {
				x := d.Instances[1]
				x.Address = "aws_s3_bucket_public_access_block.extra"
				d.Instances = append(d.Instances, x)
			})
		}, want: "aws_s3_bucket_public_access_block.extra is not in the plan", consumed: true, terraform: true},
		"deposed": {plan: linked, mutate: func(t *testing.T, s string) {
			resign(t, valid, s, func(d *verdict.Document) { d.Instances[1].Deposed = "00000001" })
		}, want: "aws_s3_bucket_public_access_block.logs is missing", consumed: true, terraform: true},
		"other-key": {plan: linked, mutate: func(t *testing.T, s string) {
			resign(t, valid, s, func(d *verdict.Document) { d.Instances[0].InstanceKey = "sha256:" + strings.Repeat("a", 64) })
		}, want: "aws_s3_bucket.logs differs from the plan", consumed: true, terraform: true},
		"unsigned-edit": {plan: linked, mutate: func(t *testing.T, s string) {
			p := filepath.Join(s, artifactVerdict)
			b, _ := os.ReadFile(p)
			if err := os.WriteFile(p, bytes.Replace(b, []byte(`"result":"pass"`), []byte(`"result":"fail"`), 1), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "signature does not verify", consumed: true},
		"planfile-swapped": {plan: linked, mutate: func(t *testing.T, s string) {
			if err := os.WriteFile(filepath.Join(s, artifactPlanfile), []byte("other planfile"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "planfile does not match its digest"},
		"planfile-and-candidate-swapped": {plan: linked, mutate: func(t *testing.T, s string) {
			other := []byte("other planfile")
			if err := os.WriteFile(filepath.Join(s, artifactPlanfile), other, 0o600); err != nil {
				t.Fatal(err)
			}
			rewriteCandidate(t, s, func(m map[string]any) {
				m["plan_digest"] = rawDigest(other)
				m["artifacts"].(map[string]any)[artifactPlanfile] = rawDigest(other)
			})
		}, want: "plan_digest differs", consumed: true},
		// The terraform binary is swapped after gate sign and candidate.json
		// names its digest: the digest gate plan recorded is signed.
		"terraform-swapped": {plan: linked, swapTF: func(m map[string]any, d string) { m["terraform_digest"] = d },
			want: "terraform_digest differs", consumed: true},
		"terraform-and-provenance-swapped": {plan: linked, swapTF: func(m map[string]any, d string) {
			m["terraform_digest"] = d
			m["provenance"].(map[string]any)["terraform_digest"] = d
		}, want: "provenance differs", consumed: true},
		"incomplete-set": {plan: linked, mutate: func(t *testing.T, s string) {
			if err := os.Remove(filepath.Join(s, artifactFindings)); err != nil {
				t.Fatal(err)
			}
		}, want: "candidate.json lists"},
		"no-verdict": {plan: linked, mutate: func(t *testing.T, s string) {
			if err := os.Remove(filepath.Join(s, artifactVerdict)); err != nil {
				t.Fatal(err)
			}
		}, want: "holds no verdict.json"},
		"tf-cli-args": {plan: linked, mutate: func(t *testing.T, _ string) { t.Setenv("TF_CLI_ARGS_apply", "-target=x") },
			want: "TF_CLI_ARGS_apply is set"},
		"evidence-api-unreachable": {plan: linked, c: func(t *testing.T) *CLI {
			c := applyCLI(t, valid, signNow, signNow)
			c.evidenceTime = noEvidenceAPI
			return c
		}, want: "needs Evidence API time at apply start", consumed: true},
		"evidence-api-zero-time": {plan: linked, c: at(signNow, time.Time{}), want: "no server time in the answer", consumed: true},
		// Expired by Evidence API time, not by the runner clock.
		"exception-expired-online": {plan: linked, mutate: func(t *testing.T, s string) {
			resign(t, valid, s, func(d *verdict.Document) {
				d.Exceptions = []verdict.ExceptionRef{{Digest: "sha256:" + strings.Repeat("e", 64), Source: "grant", Expires: "2026-10-19T11:00:00Z"}}
			})
		}, c: at(signNow.Add(-2*time.Hour), signNow.Add(-30*time.Minute)), want: "expired at \"2026-10-19T11:00:00Z\" by Evidence API time", consumed: true},
		// Expired at the airgap time (the floor's issued_at, 06:00), not by
		// the runner clock (05:56).
		"exception-expired-airgap": {inputs: "airgap", plan: linked, mutate: func(t *testing.T, s string) {
			resign(t, filepath.Join(gateInputs, "airgap"), s, func(d *verdict.Document) {
				d.Exceptions = []verdict.ExceptionRef{{Digest: "sha256:" + strings.Repeat("e", 64), Source: "grant", Expires: "2026-10-19T05:58:00Z"}}
			})
		}, c: func(t *testing.T) *CLI {
			c := applyCLI(t, filepath.Join(gateInputs, "airgap"), time.Date(2026, 10, 19, 5, 56, 0, 0, time.UTC), time.Time{})
			c.evidenceTime = noEvidenceAPI // never read under airgap
			return c
		}, want: "by the floor statement's issued_at (floor_mode airgap)", consumed: true},
		// D3: advisory run mode, but the control floor makes the control
		// blocking: wildcard and catalog_miss refuse like fail.
		"permissive-wildcard": {inputs: "permissive", plan: filepath.Join(gateCases, "alias-wildcard", "plan.json"),
			want: "aws_s3_bucket.w create s3_bucket_public_access_block_present not_evaluable", consumed: true},
		"permissive-catalog-miss": {inputs: "permissive", plan: "catalog-miss",
			want: "aws_s3_bucket.a create s3_bucket_public_access_block_present not_evaluable", consumed: true},
	}
}

// refuse runs cmd on the signed set of tc and asserts exit 2 for tc.want
// with no terraform apply; it returns the set.
func refuse(t *testing.T, tc refusal, cmd ...string) string {
	t.Helper()
	inputs := filepath.Join(gateInputs, "valid")
	if tc.inputs != "" {
		inputs = filepath.Join(gateInputs, tc.inputs)
	}
	plan := tc.plan
	if plan == "catalog-miss" {
		plan = governedPlan(t, filepath.Join("..", "..", "testdata", "fixtures", "graph", "catalog-miss", "plan.json"))
	}
	f, set := signedSet(t, inputs, plan)
	if tc.mutate != nil {
		tc.mutate(t, set)
	}
	if tc.swapTF != nil {
		b, err := os.ReadFile(f.bin)
		if err == nil {
			b = append(b, "# other bytes\n"...)
			err = os.WriteFile(f.bin, b, 0o700) //nolint:gosec // G306: an executable test fake
		}
		if err != nil {
			t.Fatal(err)
		}
		d, err := fileDigest(f.bin)
		if err != nil {
			t.Fatal(err)
		}
		rewriteCandidate(t, set, func(m map[string]any) { tc.swapTF(m, d) })
	}
	c := applyCLI(t, inputs, signNow, signNow)
	if tc.c != nil {
		c = tc.c(t)
	}
	before := len(f.calls(t))
	code, msg := runGate(c, applyArgs(inputs, f.bin, set, cmd...))
	if code != ExitEnvironment || !strings.Contains(msg, tc.want) {
		t.Fatalf("exit %d (%s), want 2 (%s)", code, msg, tc.want)
	}
	calls := f.calls(t)[before:]
	if slices.ContainsFunc(calls, func(l string) bool { return strings.Contains(l, " apply ") }) {
		t.Fatal("terraform apply ran")
	}
	if ran := len(calls) > 0; ran != tc.terraform {
		t.Errorf("terraform ran: %v, want %v", ran, tc.terraform)
	}
	return set
}

// TestVerdictVerify: a signed linked plan verifies (exit 0) and the set is
// left as it is, terraform apply never run.
func TestVerdictVerify(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	f, set := signedSet(t, inputs, filepath.Join(gateCases, "linked-create", "plan.json"))
	before := len(f.calls(t))
	if code, msg := runGate(applyCLI(t, inputs, signNow, signNow), applyArgs(inputs, f.bin, set, "verdict", "verify")); code != ExitOK {
		t.Fatalf("verdict verify: exit %d: %s", code, msg)
	}
	if slices.ContainsFunc(f.calls(t)[before:], func(l string) bool { return strings.Contains(l, " apply ") }) {
		t.Fatal("verdict verify ran terraform apply")
	}
	unchanged(t, set)
}

// unchanged asserts the set holds its run key and no result or tombstone.
func unchanged(t *testing.T, set string) {
	t.Helper()
	for _, n := range []string{artifactResult, artifactTombstone} {
		if _, err := os.Lstat(filepath.Join(set, n)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the set got %s", n)
		}
	}
	if _, err := os.Stat(filepath.Join(set, artifactRunKey)); err != nil {
		t.Errorf("ctfkit-run.key: %v", err)
	}
}

// TestVerdictVerifyRefuses: each refusal exits 2 and changes nothing.
func TestVerdictVerifyRefuses(t *testing.T) {
	for name, tc := range refusals() {
		t.Run(name, func(t *testing.T) {
			unchanged(t, refuse(t, tc, "verdict", "verify"))
		})
	}
}

// governedPlan copies a hashicorp/aws plan with the compliance.tf provider
// address, so a governed gate sign decides it, keeping only the attributes
// of the gate schema.
func governedPlan(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.ReplaceAll(b, []byte("registry.terraform.io/hashicorp/aws"), []byte("registry.compliance.tf/compliancetf/aws"))
	var plan map[string]any
	if err = json.Unmarshal(b, &plan); err != nil {
		t.Fatal(err)
	}
	keep := []string{"id", "bucket", "region", "block_public_acls"}
	for _, rc := range plan["resource_changes"].([]any) {
		change := rc.(map[string]any)["change"].(map[string]any)
		for _, k := range []string{"after", "after_unknown"} {
			if m, ok := change[k].(map[string]any); ok {
				maps.DeleteFunc(m, func(a string, _ any) bool { return !slices.Contains(keep, a) })
			}
		}
	}
	b, _ = json.Marshal(plan)
	out := filepath.Join(t.TempDir(), "plan.json")
	if err = os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}
