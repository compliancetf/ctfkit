package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/sign"
	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

const (
	gateCases   = "../../testdata/fixtures/gate"
	signConfig  = "testdata/gate-sign/config"
	verdictKeyL = "compliancetf.test-verdict-key/bobthecorp" // the inputs profile's verdict key
)

// labelSigner signs with the P-256 key of a public label, the key the
// inputs generator lists in the profile.
type labelSigner struct{ key *ecdsa.PrivateKey }

func newLabelSigner(label string) labelSigner {
	d := sha256.Sum256([]byte(label))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		panic(err)
	}
	return labelSigner{k}
}

func (l labelSigner) Public() *ecdsa.PublicKey { return &l.key.PublicKey }

func (l labelSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, l.key, digest)
}

func signCLI(t *testing.T, inputs, label string) *CLI {
	t.Helper()
	c := gateCLI(t, inputs)
	c.openSigner = func(string) (sign.Signer, error) { return newLabelSigner(label), nil }
	return c
}

func planArgs(inputs, tf, out string) []string {
	args := gateArgs(inputs, tf, out)
	args[3] = signConfig // --dir
	return args
}

func signArgs(inputs, tf, cand string, extra ...string) []string {
	return append([]string{"gate", "sign", "--candidate", cand, "--dir", signConfig,
		"--workspace", "default", "--environment", "prod", "--tf-bin", tf, "--org", "bobthecorp",
		"--profile", filepath.Join(inputs, "profile.dsse.json"), "--floor", filepath.Join(inputs, "floor.dsse.json"),
		"--bundle-dir", filepath.Join(inputs, "bundles"), "--signer", "test:bobthecorp"}, extra...)
}

// planCandidate runs gate plan over show and returns the candidate dir.
func planCandidate(t *testing.T, inputs string, f fakeTF) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "candidate")
	if code, msg := runGate(gateCLI(t, inputs), planArgs(inputs, f.bin, out)); code != ExitOK {
		t.Fatalf("gate plan: exit %d: %s", code, msg)
	}
	return out
}

func readVerdict(t *testing.T, cand string) ([]byte, *verdict.Document) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(cand, artifactVerdict))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := verdict.Parse(raw)
	if err != nil {
		t.Fatalf("verdict.json does not parse: %v", err)
	}
	return raw, doc
}

// TestGateSign runs gate plan then gate sign over the fake terraform: a
// linked plan exits 0 and a missing companion exits 1, both with a signed
// verdict bound to the candidate and verifying under the profile's key.
func TestGateSign(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	for name, tc := range map[string]struct {
		plan string
		code int
		want string
	}{
		"linked":  {"linked-create", ExitOK, "pass"},
		"missing": {"missing-companion", ExitFindings, "fail"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeTFSchema(t, filepath.Join(gateCases, tc.plan, "plan.json"), filepath.Join(gateCases, "schema.json"), 0)
			cand := planCandidate(t, inputs, f)
			code, msg := runGate(signCLI(t, inputs, verdictKeyL), signArgs(inputs, f.bin, cand))
			if code != tc.code {
				t.Fatalf("gate sign: exit %d (%s), want %d", code, msg, tc.code)
			}
			raw, doc := readVerdict(t, cand)
			st, _ := os.Stat(filepath.Join(cand, artifactVerdict))
			if st.Mode().Perm() != 0o600 {
				t.Errorf("verdict.json mode %v", st.Mode().Perm())
			}
			key := newLabelSigner(verdictKeyL).Public()
			set, err := parseSignSettings(mustVerified(t, inputs).Profile)
			if err != nil {
				t.Fatal(err)
			}
			if err = verdict.Verify(raw, doc.Signature, set.keys, nil, "verdict", gateCLI(t, inputs).now()); err != nil || !key.Equal(set.keys[0].Key) {
				t.Fatalf("signature: %v", err)
			}
			candRaw, _ := os.ReadFile(filepath.Join(cand, artifactCandidate))
			c, _ := parseCandidate(candRaw)
			secret, _ := os.ReadFile(filepath.Join(cand, artifactRunKey))
			s, _ := instancekey.ParseSecret(secret)
			_, check, _ := instancekey.Keys(s)
			switch {
			case doc.PlanDigest != c.PlanDigest || doc.ContentDigest != gateContentDigest(t, inputs) || doc.FloorEpoch != "7":
				t.Errorf("binding %s %s %s", doc.PlanDigest, doc.ContentDigest, doc.FloorEpoch)
			case doc.ProfileDigest != c.ProfileDigest || doc.BundleDigest != c.BundleDigest || doc.Workspace != "default" || doc.Environment != "prod":
				t.Errorf("scope %s %s", doc.ProfileDigest, doc.BundleDigest)
			case doc.InstanceKeyCheck != instancekey.KeyCheck(check):
				t.Error("instance_key_check is not the run key's")
			case doc.ProviderVersions["compliancetf/aws"] != "2.0.0" || doc.ProviderVersions["hashicorp/aws"] != "6.20.0":
				t.Errorf("provider_versions %v", doc.ProviderVersions)
			case doc.Instances[0].InstanceKey != c.Instances[0].Keys[0].Key || doc.Instances[0].Decisions[0].Result != tc.want:
				t.Errorf("instance %+v", doc.Instances[0])
			}
			// A candidate is signed once.
			code, msg = runGate(signCLI(t, inputs, verdictKeyL), signArgs(inputs, f.bin, cand))
			if code != ExitEnvironment || !strings.Contains(msg, "already holds a verdict.json; use that verdict, or run ctfkit gate plan for a new candidate") {
				t.Errorf("second sign: exit %d (%s)", code, msg)
			}
		})
	}
}

// TestGateSignFormatSpaced: a --format value with spaces around the name
// renders that format, as on every other command, rather than text.
func TestGateSignFormatSpaced(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	f := newFakeTFSchema(t, filepath.Join(gateCases, "linked-create", "plan.json"), filepath.Join(gateCases, "schema.json"), 0)
	cand := planCandidate(t, inputs, f)
	c := signCLI(t, inputs, verdictKeyL)
	var stdout bytes.Buffer
	c.rootCmd.SetArgs(signArgs(inputs, f.bin, cand, "-f", " sarif "))
	c.rootCmd.SetOut(&stdout)
	c.rootCmd.SetErr(io.Discard)
	if err := c.Execute(); err != nil {
		t.Fatalf("gate sign: %v", err)
	}
	var doc struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil || doc.Version != "2.1.0" {
		t.Errorf("gate sign -f \" sarif \" printed no SARIF (%v):\n%s", err, stdout.String())
	}
}

func mustVerified(t *testing.T, inputs string) *verdict.Verified {
	t.Helper()
	in, err := verdict.ReadInputs(os.DirFS(inputs), "bobthecorp", "keyring.json", "profile.dsse.json", "floor.dsse.json", "bundles")
	if err != nil {
		t.Fatal(err)
	}
	v, err := verdict.VerifyInputs(in, gateCLI(t, inputs).now())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// rewriteCandidate changes candidate.json through edit, keeping it JCS.
func rewriteCandidate(t *testing.T, cand string, edit func(m map[string]any)) {
	t.Helper()
	p := filepath.Join(cand, artifactCandidate)
	raw, _ := os.ReadFile(p)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, _ := json.Marshal(m)
	b, err := jcs.Transform(b)
	if err == nil {
		err = os.WriteFile(p, b, 0o600)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// TestGateSignRefuses: each refusal exits 2 with no verdict written.
func TestGateSignRefuses(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	plan := filepath.Join(gateCases, "linked-create", "plan.json")
	for name, tc := range map[string]struct {
		mutate func(t *testing.T, cand string) []string
		want   string
	}{
		"break-glass":   {func(*testing.T, string) []string { return []string{"--break-glass", "o.json"} }, "--break-glass is not supported yet"},
		"fail-on-never": {func(*testing.T, string) []string { return []string{"--fail-on", "never"} }, "unknown --fail-on"},
		"incomplete-format": {func(t *testing.T, c string) []string {
			rewriteCandidate(t, c, func(m map[string]any) { m["format"] = "compliancetf.candidate/v1-incomplete" })
			return nil
		}, "gate sign accepts only compliancetf.candidate/v1"},
		"content-digest": {func(t *testing.T, c string) []string {
			rewriteCandidate(t, c, func(m map[string]any) { m["content_digest"] = "sha256:" + strings.Repeat("c", 64) })
			return nil
		}, "content digest mismatch"},
		"floor-epoch": {func(t *testing.T, c string) []string {
			rewriteCandidate(t, c, func(m map[string]any) { m["floor_epoch"] = "6" })
			return nil
		}, "floor epoch 6"},
		"instance-key": {func(t *testing.T, c string) []string {
			rewriteCandidate(t, c, func(m map[string]any) {
				m["instances"].([]any)[0].(map[string]any)["keys"].([]any)[0].(map[string]any)["key"] = "sha256:" + strings.Repeat("a", 64)
			})
			return nil
		}, "instances are not the keys of the sealed plan"},
		"planfile": {func(t *testing.T, c string) []string {
			if err := os.WriteFile(filepath.Join(c, artifactPlanfile), []byte("other planfile"), 0o600); err != nil {
				t.Fatal(err)
			}
			return nil
		}, "planfile does not match its digest"},
		"extra-file": {func(t *testing.T, c string) []string {
			if err := os.WriteFile(filepath.Join(c, "extra"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return nil
		}, "candidate.json lists"},
		"wide-mode": {func(t *testing.T, c string) []string {
			if err := os.Chmod(filepath.Join(c, artifactRunKey), 0o644); err != nil {
				t.Fatal(err)
			}
			return nil
		}, "must be a 0600 regular file"},
		"workspace": {func(*testing.T, string) []string { return []string{"--workspace", "other"} }, "the candidate is for org"},
		"tf-bin": {func(t *testing.T, c string) []string {
			other := filepath.Join(t.TempDir(), "terraform")
			if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // test fake
				t.Fatal(err)
			}
			return []string{"--tf-bin", other}
		}, "--tf-bin is not the terraform binary gate plan ran"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeTFSchema(t, plan, filepath.Join(gateCases, "schema.json"), 0)
			cand := planCandidate(t, inputs, f)
			args := signArgs(inputs, f.bin, cand)
			for extra := tc.mutate(t, cand); len(extra) == 2; extra = nil {
				if i := slices.Index(args, extra[0]); i > 0 {
					args[i+1] = extra[1]
				} else {
					args = append(args, extra...)
				}
			}
			c := signCLI(t, inputs, verdictKeyL)
			code, msg := runGate(c, args)
			if code != ExitEnvironment || !strings.Contains(msg, tc.want) {
				t.Fatalf("exit %d (%s), want 2 (%s)", code, msg, tc.want)
			}
			if _, err := os.Lstat(filepath.Join(cand, artifactVerdict)); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("a refused gate sign wrote a verdict")
			}
		})
	}
}

// TestGateSignNoSigner: a release build opens no test: signer, so gate sign
// refuses before terraform runs; an untrusted signer key never signs.
func TestGateSignNoSigner(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	f := newFakeTFSchema(t, filepath.Join(gateCases, "linked-create", "plan.json"), filepath.Join(gateCases, "schema.json"), 0)
	cand := planCandidate(t, inputs, f)
	before := len(f.calls(t))
	code, msg := runGate(gateCLI(t, inputs), signArgs(inputs, f.bin, cand))
	if code != ExitEnvironment || !strings.Contains(msg, `--signer scheme "test" is not supported; use awskms:KEY_ARN`) || len(f.calls(t)) != before {
		t.Fatalf("release signer: exit %d (%s), terraform calls %d -> %d", code, msg, before, len(f.calls(t)))
	}
	code, msg = runGate(signCLI(t, inputs, "compliancetf.test-other-key/bobthecorp"), signArgs(inputs, f.bin, cand))
	if code != ExitEnvironment || !strings.Contains(msg, "kid unknown") {
		t.Fatalf("untrusted key: exit %d (%s)", code, msg)
	}
	if _, err := os.Lstat(filepath.Join(cand, artifactVerdict)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("an untrusted key wrote a verdict")
	}
}

// TestGateSignBypass: a governed plan holding an AWS resource of any provider
// other than the compliance.tf one (hashicorp/aws of either registry, a fork
// in another namespace, awscc), matched in any case, fails the gate (exit 1)
// and is never signed (A29). It is the compensating control for the
// verify-lock exemption of the hashicorp/aws lock entries (boundUpstream).
func TestGateSignBypass(t *testing.T) {
	for _, hashi := range []string{"registry.terraform.io/hashicorp/aws", "registry.opentofu.org/hashicorp/aws", "Registry.OpenTofu.org/HashiCorp/AWS",
		"registry.terraform.io/bobthecorp/aws", "registry.terraform.io/hashicorp/awscc", "registry.terraform.io/bobthecorp/amazon"} {
		t.Run(hashi, func(t *testing.T) { gateSignBypass(t, hashi) })
	}
}

func gateSignBypass(t *testing.T, hashi string) {
	inputs := filepath.Join(gateInputs, "valid")
	dir := t.TempDir()
	plan, _ := os.ReadFile(filepath.Join(gateCases, "linked-create", "plan.json"))
	plan = bytes.Replace(plan, []byte("registry.compliance.tf/compliancetf/aws"), []byte(hashi), 1)
	var schema map[string]any
	raw, _ := os.ReadFile(filepath.Join(gateCases, "schema.json"))
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	ps := schema["provider_schemas"].(map[string]any)
	ps[hashi] = ps["registry.compliance.tf/compliancetf/aws"]
	raw, _ = json.Marshal(schema)
	for n, b := range map[string][]byte{"plan.json": plan, "schema.json": raw} {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f := newFakeTFSchema(t, filepath.Join(dir, "plan.json"), filepath.Join(dir, "schema.json"), 0)
	cand := planCandidate(t, inputs, f)
	code, msg := runGate(signCLI(t, inputs, verdictKeyL), signArgs(inputs, f.bin, cand))
	if code != ExitFindings || !strings.Contains(msg, "outside the compliance.tf provider for aws_s3_bucket.logs") {
		t.Fatalf("exit %d (%s), want 1", code, msg)
	}
	if _, err := os.Lstat(filepath.Join(cand, artifactVerdict)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a bypassed plan was signed")
	}
}

// TestBypassed: only AWS resource changes of a provider outside the
// compliance.tf namespace are listed; other providers (random, null) are not.
func TestBypassed(t *testing.T) {
	for _, tc := range []struct {
		provider, typ string
		want          bool
	}{
		{"registry.compliance.tf/compliancetf/aws", "aws_s3_bucket", false},
		{"Registry.Compliance.TF/CompliancETF/aws", "aws_s3_bucket", false},
		{"registry.terraform.io/hashicorp/aws", "aws_s3_bucket", true},
		{"registry.opentofu.org/hashicorp/aws", "aws_s3_bucket", true},
		{"registry.terraform.io/bobthecorp/aws", "aws_s3_bucket", true},
		{"registry.terraform.io/hashicorp/awscc", "awscc_s3_bucket", true},
		{"registry.terraform.io/bobthecorp/amazon", "aws_s3_bucket", true},
		{"registry.terraform.io/hashicorp/random", "random_id", false},
		{"registry.terraform.io/hashicorp/null", "null_resource", false},
		{"registry.terraform.io/bobthecorp/awsome", "awsome_thing", false},
	} {
		plan := &tfjson.Plan{ResourceChanges: []*tfjson.ResourceChange{nil, {Address: tc.typ + ".x", Type: tc.typ, ProviderName: tc.provider}}}
		if got := len(bypassed(plan)) == 1; got != tc.want {
			t.Errorf("%s %s: bypassed %v, want %v", tc.provider, tc.typ, got, tc.want)
		}
	}
}

// TestCheckScope: a workspace or environment the signed profile does not
// allow is refused.
func TestCheckScope(t *testing.T) {
	s := &signSettings{}
	s.scope.Workspace, s.scope.Environment = "default", "prod"
	s.modeFloor.Environments = map[string]string{"prod": "hard_fail", "dev": "soft_fail"}
	for _, tc := range []struct {
		ws, env string
		ok      bool
	}{{"default", "prod", true}, {"other", "prod", false}, {"default", "dev", false}} {
		if err := s.checkScope(tc.ws, tc.env); (err == nil) != tc.ok {
			t.Errorf("%s/%s: %v", tc.ws, tc.env, err)
		}
	}
	s.scope.Environment = ""
	if s.checkScope("default", "dev") != nil || s.checkScope("default", "qa") == nil {
		t.Error("an environment outside mode_floor.environments must be refused, one inside allowed")
	}
	if got := s.modeTable().RunMode; got != "hard_fail" {
		t.Errorf("no fixed environment: run mode %s, want the strongest environment floor", got)
	}
}

// TestBundleControlsNeedCIS: a bundle set without the provider's CIS
// bundle is refused.
func TestBundleControlsNeedCIS(t *testing.T) {
	v := mustVerified(t, filepath.Join(gateInputs, "valid"))
	if _, err := bundleControls(v); err != nil {
		t.Fatal(err)
	}
	for i := range v.Bundles {
		if v.Bundles[i].Manifest.BundleID == cisBundleID {
			v.Bundles = append(v.Bundles[:i], v.Bundles[i+1:]...)
			break
		}
	}
	if _, err := bundleControls(v); err == nil || !strings.Contains(err.Error(), "no cis-aws bundle") {
		t.Fatalf("no CIS bundle: %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

// TestPublishVerdict: a report that cannot be printed removes the verdict it
// wrote (exit 2 leaves nothing), and a verdict already present is untouched.
func TestPublishVerdict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, artifactVerdict)
	if err := publishVerdict(failWriter{}, dir, []byte("{}"), []byte("report")); err == nil {
		t.Fatal("print failure accepted")
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("verdict left behind: %v", err)
	}
	if err := os.WriteFile(path, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishVerdict(io.Discard, dir, []byte("{}"), nil); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("existing verdict: %v", err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "other" {
		t.Fatalf("existing verdict changed: %q %v", b, err)
	}
}
