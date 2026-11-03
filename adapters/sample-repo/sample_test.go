// Package samplerepo holds the check that the sample repository shows one
// finding in three places: the terminal, the GitHub Security tab (SARIF) and a
// Spacelift plan policy. Every surface is produced by the built binary from the
// committed plan.json, with an empty HOME and no CI or cloud environment, which
// is the launch promise: a plan file and the binary, nothing else.
package samplerepo

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	ruleID       = "ctf.coverage.module_source"
	address      = "aws_s3_bucket.raw"
	moduleSource = "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws"
	message      = "Raw aws_s3_bucket where the compliance.tf module " + moduleSource + " exists"
	repoRoot     = "../.."
	policyPath   = repoRoot + "/adapters/spacelift/policy.rego"
	schemaPath   = repoRoot + "/schema/cff-1.schema.json"
)

type run struct {
	stdout, stderr string
	code           int
}

// buildBinary builds cmd/ctfkit once for this test, the same main package a
// release ships.
func buildBinary(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "ctfkit")
	cmd := exec.Command("go", "build", "-o", exe, "./cmd/ctfkit") // #nosec G204 -- fixed arguments
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/ctfkit: %v\n%s", err, out)
	}
	return exe
}

// ctfkit runs the binary from dir with an environment of PATH, an empty HOME
// and NO_COLOR only: no CI variables, no credentials, no settings file.
func ctfkit(t *testing.T, exe, dir string, args ...string) run {
	t.Helper()
	cmd := exec.Command(exe, args...) // #nosec G204 -- test-owned binary and arguments
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "NO_COLOR=1"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	r := run{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		r.code = exitErr.ExitCode()
	default:
		t.Fatalf("ctfkit %v: %v", args, err)
	}
	return r
}

func TestOneFindingInThreePlaces(t *testing.T) {
	exe := buildBinary(t)
	here, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	plan := filepath.Join(here, "plan.json")

	t.Run("terminal", func(t *testing.T) {
		r := ctfkit(t, exe, here, "scan", "plan.json", "--format", "pretty")
		if r.code != 1 {
			t.Fatalf("exit %d, want 1\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
		}
		for _, want := range []string{
			"ERROR      " + ruleID,
			address + " (main.tf:69)",
			message,
			"fix: use " + moduleSource,
			"1 finding(s): 1 error, 0 warning, 0 note, 0 suppressed",
			"stage post_plan",
		} {
			if !strings.Contains(r.stdout, want) {
				t.Errorf("pretty output lacks %q\n%s", want, r.stdout)
			}
		}
	})

	t.Run("security tab", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "findings.sarif")
		r := ctfkit(t, exe, here, "scan", "plan.json", "--format", "sarif", "--out", out)
		if r.code != 1 {
			t.Fatalf("exit %d, want 1\nstderr:\n%s", r.code, r.stderr)
		}
		data, err := os.ReadFile(out) // #nosec G304 -- test temp file
		if err != nil {
			t.Fatal(err)
		}
		validate(t, data)

		var doc struct {
			Runs []struct {
				Properties map[string]any `json:"properties"`
				Results    []struct {
					RuleID  string `json:"ruleId"`
					Level   string `json:"level"`
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
					Locations []struct {
						PhysicalLocation struct {
							ArtifactLocation struct {
								URI string `json:"uri"`
							} `json:"artifactLocation"`
						} `json:"physicalLocation"`
						LogicalLocations []struct {
							FullyQualifiedName string `json:"fullyQualifiedName"`
						} `json:"logicalLocations"`
					} `json:"locations"`
					Properties struct {
						Remediation struct {
							ModuleSource string `json:"moduleSource"`
						} `json:"ctf.remediation"`
					} `json:"properties"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err = json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
			t.Fatalf("want one run with one result, got %s", data)
		}
		if got, ok := doc.Runs[0].Properties["ctf.watermark"]; ok {
			t.Errorf("ctf.watermark = %v, want it absent without --watermark", got)
		}
		res := doc.Runs[0].Results[0]
		if res.RuleID != ruleID || res.Level != "error" || res.Message.Text != message {
			t.Errorf("result = %s %s %q, want %s error %q", res.RuleID, res.Level, res.Message.Text, ruleID, message)
		}
		if len(res.Locations) != 1 || res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "main.tf" ||
			len(res.Locations[0].LogicalLocations) != 1 ||
			res.Locations[0].LogicalLocations[0].FullyQualifiedName != address {
			t.Errorf("location is not %s in main.tf: %+v", address, res.Locations)
		}
		if res.Properties.Remediation.ModuleSource != moduleSource {
			t.Errorf("remediation.moduleSource = %q, want %q", res.Properties.Remediation.ModuleSource, moduleSource)
		}
	})

	t.Run("spacelift plan policy", func(t *testing.T) {
		work := t.TempDir()
		r := ctfkit(t, exe, work, "scan", "--plan", plan, "--format", "spacelift")
		if r.code != 0 {
			t.Fatalf("exit %d, want 0 (a format list of exactly spacelift never fails the hook)\nstderr:\n%s", r.code, r.stderr)
		}
		data, err := os.ReadFile(filepath.Join(work, "ctfkit-scan.custom.spacelift.json")) // #nosec G304 -- test temp file
		if err != nil {
			t.Fatal(err)
		}
		var meta struct {
			Schema   string `json:"schema"`
			Verdict  string `json:"verdict"`
			Findings []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message string `json:"message"`
			} `json:"findings"`
		}
		if err = json.Unmarshal(data, &meta); err != nil {
			t.Fatal(err)
		}
		if meta.Schema != "ctfkit.spacelift/1" || meta.Verdict != "fail" || len(meta.Findings) != 1 ||
			meta.Findings[0].RuleID != ruleID || meta.Findings[0].Level != "error" || meta.Findings[0].Message != message {
			t.Fatalf("spacelift metadata does not carry the finding:\n%s", data)
		}

		opa, err := exec.LookPath("opa")
		if err != nil {
			t.Skip("opa is not installed: the metadata file is checked, the policy evaluation is skipped")
		}
		input := filepath.Join(work, "input.json")
		wrapped := `{"third_party_metadata":{"custom":{"ctfkit-scan":` + string(data) + `}}}`
		if err = os.WriteFile(input, []byte(wrapped), 0o600); err != nil {
			t.Fatal(err)
		}
		const msg = "ctfkit-scan: verdict fail (1 error, 0 warning)"

		shadow := evalPolicy(t, opa, policyPath, input)
		if !slices.Contains(shadow.warn, msg) || len(shadow.deny) != 0 {
			t.Errorf("shadow mode: warn %q, deny %q; want %q warned and nothing denied", shadow.warn, shadow.deny, msg)
		}

		src, err := os.ReadFile(policyPath)
		if err != nil {
			t.Fatal(err)
		}
		flipped := strings.Replace(string(src), "enforce := false", "enforce := true", 1)
		if flipped == string(src) {
			t.Fatal("policy.rego no longer carries the line enforce := false")
		}
		enforcedPath := filepath.Join(work, "policy-enforced.rego")
		if err = os.WriteFile(enforcedPath, []byte(flipped), 0o600); err != nil {
			t.Fatal(err)
		}
		enforced := evalPolicy(t, opa, enforcedPath, input)
		if !slices.Contains(enforced.deny, msg) {
			t.Errorf("enforced mode: deny %q, want %q", enforced.deny, msg)
		}
	})
}

func validate(t *testing.T, data []byte) {
	t.Helper()
	schemaFile, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaFile))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err = c.AddResource(schemaPath, schemaDoc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err = schema.Validate(doc); err != nil {
		t.Fatalf("SARIF does not validate against %s: %v", schemaPath, err)
	}
}

type verdicts struct{ warn, deny []string }

func evalPolicy(t *testing.T, opa, policy, input string) verdicts {
	t.Helper()
	cmd := exec.Command(opa, "eval", "--format", "json", // #nosec G204 -- test-owned paths
		"--data", policy, "--input", input, "data.spacelift")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("opa eval %s: %v", policy, err)
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
