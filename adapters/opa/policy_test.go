// Package opa checks the OPA example: policy.rego loads as Rego v1 and decides
// on the committed output of ctfkit scan --format json. ctfkit produces the
// findings; the policy is where the decision lives.
package opa

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

const policy = "policy.rego"

func TestPolicyIsRegoV1(t *testing.T) {
	opa := lookOPA(t)
	out, err := exec.Command(opa, "check", "--v1-compatible", policy).CombinedOutput() // #nosec G204 -- fixed arguments
	if err != nil {
		t.Fatalf("opa check --v1-compatible %s: %v\n%s", policy, err, out)
	}
}

func TestPolicyDecidesOnScanOutput(t *testing.T) {
	opa := lookOPA(t)
	const errorDeny = "ctf.coverage.module_source at aws_s3_bucket.logs: " +
		"Raw aws_s3_bucket where the compliance.tf module soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws exists"
	for _, tc := range []struct {
		input string
		want  []string
	}{
		{"test/error.json", []string{errorDeny}},
		{"test/clean.json", nil},
		// The same error finding under an accepted exception: suppressed, so allowed.
		{"test/suppressed.json", nil},
		// An empty suppressions array suppresses nothing, a finding with no
		// location still denies, and a warning never does.
		{edgeCase(t), []string{"ctf.x at configuration: no location"}},
	} {
		t.Run(filepath.Base(tc.input), func(t *testing.T) {
			out, err := exec.Command(opa, "eval", "--format", "json", // #nosec G204 -- test-owned paths
				"--data", policy, "--input", tc.input, "data.ctfkit.deny").Output()
			if err != nil {
				t.Fatalf("opa eval: %v", err)
			}
			var res struct {
				Result []struct {
					Expressions []struct {
						Value []string `json:"value"`
					} `json:"expressions"`
				} `json:"result"`
			}
			if err = json.Unmarshal(out, &res); err != nil || len(res.Result) != 1 || len(res.Result[0].Expressions) != 1 {
				t.Fatalf("unexpected opa output (%v):\n%s", err, out)
			}
			if got := res.Result[0].Expressions[0].Value; !slices.Equal(got, tc.want) {
				t.Errorf("deny = %q, want %q", got, tc.want)
			}
		})
	}
}

func edgeCase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "edge.json")
	body := `{"findings":[
		{"ruleId":"ctf.x","level":"error","message":{"text":"no location"},"suppressions":[]},
		{"ruleId":"ctf.y","level":"warning","message":{"text":"only a warning"}}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func lookOPA(t *testing.T) string {
	t.Helper()
	opa, err := exec.LookPath("opa")
	if err != nil {
		t.Skip("opa is not installed: the example check is skipped")
	}
	return opa
}
