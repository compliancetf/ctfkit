package gate_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/gate"
	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/resolve"
	keyjson "github.com/compliancetf/ctfkit/pkg/verdict/tfjson"
)

var update = flag.Bool("update", false, "rewrite testdata/fixtures/gate/*/expected.verdict.json")

const fixtures = "../../testdata/fixtures/gate"

// cases is every gate fixture; a directory not listed fails TestFixtureList.
var cases = []string{"alias-wildcard", "companion-delete", "deposed", "exemptions", "linked-create", "missing-companion", "replace", "state-actions"}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// build runs Build on a fixture plan with a fixed leaf key, the fixture
// controls under hard_fail, and the case's exemptions.json when present.
func build(t *testing.T, planRaw []byte, exemptions []gate.Exemption) (*gate.Output, error) {
	t.Helper()
	controls, err := gate.ParseControls(read(t, filepath.Join(fixtures, "controls.json")))
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := keyjson.ParseSchemas(read(t, filepath.Join(fixtures, "schema.json")))
	if err != nil {
		t.Fatal(err)
	}
	leaf := sha256.Sum256([]byte("ctfkit gate fixtures"))
	keys, err := keyjson.Instances(leaf, planRaw, schemas)
	if err != nil {
		t.Fatal(err)
	}
	var plan tfjson.Plan
	if err = json.Unmarshal(planRaw, &plan); err != nil {
		t.Fatal(err)
	}
	cov := map[string][]string{}
	for _, c := range controls {
		cov[c.ID] = c.ExemptionCoverable
	}
	return gate.Build(gate.Input{Plan: &plan, Keys: keys, Controls: controls, Mode: resolve.ModeTable{RunMode: resolve.HardFail},
		Coverable: func(id string) []string { return cov[id] }, Exemptions: exemptions})
}

// document is a verdict with fixed header fields and a placeholder
// signature around out, so the fixture is byte-stable and schema-valid.
func document(out *gate.Output) *verdict.Document {
	z := "sha256:" + strings.Repeat("0", 64)
	return &verdict.Document{Format: verdict.Format, OrgID: "bobthecorp", Workspace: "default", Environment: "prod", RunID: "run-fixture",
		Caller: json.RawMessage(`{"account_id":"","role_arn":"","region":""}`), PlanDigest: z, Provenance: json.RawMessage(`{}`), PlanFormatVersion: "1.2",
		ProfileDigest: z, BundleDigest: z, ContentDigest: z, FloorEpoch: "7",
		ProviderVersions: map[string]string{"compliancetf/aws": "2.0.0", "hashicorp/aws": "6.0.0"}, TerraformVersion: "1.16.3",
		Nonce: "AAAAAAAAAAAAAAAAAAAAAA", IssuedAt: "2026-10-19T12:00:00Z", ExpiresAt: "2026-10-20T12:00:00Z",
		InstanceKeyCheck: strings.Repeat("0", 64), Instances: out.Instances, Exceptions: out.Exceptions,
		Baselines: []verdict.BaselineRef{}, BreakGlassReceipts: []json.RawMessage{},
		Signature: verdict.Signature{Kid: z, Alg: verdict.AlgES256, Value: "AA"}}
}

// TestFixtures builds each fixture plan and compares the verdict with
// expected.verdict.json byte for byte.
func TestFixtures(t *testing.T) {
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			dir := filepath.Join(fixtures, c)
			var ex []gate.Exemption
			if raw, err := os.ReadFile(filepath.Join(dir, "exemptions.json")); err == nil {
				if err = json.Unmarshal(raw, &ex); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, fs.ErrNotExist) {
				t.Fatal(err)
			}
			out, err := build(t, read(t, filepath.Join(dir, "plan.json")), ex)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(document(out), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			if _, err = verdict.Parse(got); err != nil {
				t.Fatalf("built verdict does not parse: %v", err)
			}
			path := filepath.Join(dir, "expected.verdict.json")
			if *update {
				if err = os.WriteFile(path, got, 0o644); err != nil { //nolint:gosec // public test data
					t.Fatal(err)
				}
			}
			if want := read(t, path); !bytes.Equal(got, want) {
				t.Errorf("verdict:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestFixtureList(t *testing.T) {
	entries, err := os.ReadDir(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if !slices.Equal(dirs, cases) {
		t.Errorf("fixture directories %v, cases %v", dirs, cases)
	}
}

// TestDeposedNonDelete: a deposed object with any action but delete is
// refused, whatever gate plan keyed.
func TestDeposedNonDelete(t *testing.T) {
	raw := bytes.Replace(read(t, filepath.Join(fixtures, "deposed", "plan.json")),
		[]byte(`"deposed": "00000001"`), []byte(`"deposed": "00000001", "x": 1`), 1)
	var plan tfjson.Plan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	for _, rc := range plan.ResourceChanges {
		if rc.DeposedKey != "" {
			rc.Change.Actions = tfjson.Actions{tfjson.ActionUpdate}
		}
	}
	_, err := gate.Build(gate.Input{Plan: &plan})
	if err == nil || !strings.Contains(err.Error(), "a deposed object takes only a delete entry") {
		t.Fatalf("deposed update: %v", err)
	}
}

// TestKeysBindPlan: a mutation gate plan did not key, and a key for a change
// the plan does not hold, are refused.
func TestKeysBindPlan(t *testing.T) {
	raw := read(t, filepath.Join(fixtures, "missing-companion", "plan.json"))
	var plan tfjson.Plan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Build(gate.Input{Plan: &plan}); err == nil || !strings.Contains(err.Error(), "did not key") {
		t.Errorf("unkeyed create: %v", err)
	}
	extra := []keyjson.Instance{{Address: "aws_s3_bucket.ghost", Keys: []keyjson.KeyInput{{Field: "instance_key", Key: "sha256:" + strings.Repeat("a", 64)}}}}
	var empty tfjson.Plan
	if _, err := gate.Build(gate.Input{Plan: &empty, Keys: extra}); err == nil || !strings.Contains(err.Error(), "not in the plan") {
		t.Errorf("extra key: %v", err)
	}
}

// TestParseControlsUnknownKind: a control of a kind or graph rule the
// provider does not know refuses the run instead of dropping out of the
// verdict.
func TestParseControlsUnknownKind(t *testing.T) {
	if _, err := gate.ParseControls([]byte(`[{"id":"c","version":"1.0.0","kind":"Graph","resource_type":"aws_s3_bucket"}]`)); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, err := gate.ParseControls([]byte(`[{"id":"c","version":"1.0.0","kind":"graph","resource_type":"aws_s3_bucket","graph":{"rule":"companion_maybe"}}]`)); err == nil {
		t.Fatal("unknown graph rule accepted")
	}
	if _, err := gate.ParseControls([]byte(`[{"id":"c","version":"1.0.0","kind":"data_source","resource_type":"aws_s3_bucket"}]`)); err != nil {
		t.Fatal(err)
	}
}
