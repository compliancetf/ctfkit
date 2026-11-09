package disabledcontrol_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/analyzer/disabledcontrol"
	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// fixtureRoot is the recorded plan fixture pack, the oracle for this family.
const fixtureRoot = "../../../testdata/fixtures/plan"

// ownRulePrefix selects the results of this family from a recorded SARIF
// document, which also holds the results of other analyzers.
const ownRulePrefix = "ctf.policy.disabled_"

// runnerKeys are the result-level property keys the runner adds after
// Analyze: the run identity and the exception verdict. An analyzer never sets
// them, so the comparison drops them from the recorded side.
var runnerKeys = []string{"ctf.evidence", "ctf.exception"}

// TestFixtures runs the family over every plan fixture and compares its
// findings with the recorded results of this family's rule ids. 03 is the one
// case with a disable; every other case, 06 and 07 included, records none.
func TestFixtures(t *testing.T) {
	entries, err := os.ReadDir(fixtureRoot)
	if err != nil {
		t.Fatalf("reading %s: %v", fixtureRoot, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			config, loadErr := loader.LoadConfig(filepath.Join(fixtureRoot, name, "input"))
			if loadErr != nil {
				t.Fatalf("LoadConfig: %v", loadErr)
			}
			produced := analyze(t, config)
			want := expectedResults(t, name)

			if !reflect.DeepEqual(produced, want) {
				t.Errorf("findings do not match %s/expected/findings.sarif\n got: %s\nwant: %s",
					name, mustIndent(t, produced), mustIndent(t, want))
			}
		})
	}
}

// TestFixture03ControlIDs is the acceptance line of this analyzer, stated on its
// own so a regression names it. Fixture 03 disables s3_bucket_mfa_delete_enabled,
// a control outside the embedded CIS v6.0 catalog, so it is reported as an
// unknown disable: an error like a known one, with no control id.
func TestFixture03ControlIDs(t *testing.T) {
	config, err := loader.LoadConfig(filepath.Join(fixtureRoot, "03-ctf-module-disabled-control", "input"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	findings := run(t, config)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.RuleID != "ctf.policy.disabled_control_unknown" || f.Level != ctfkit.LevelError || len(f.Props.ControlIDs) != 0 {
		t.Errorf("got %s %s %v, want ctf.policy.disabled_control_unknown error with no control id",
			f.RuleID, f.Level, f.Props.ControlIDs)
	}
}

func TestCases(t *testing.T) {
	cases := []struct {
		name string
		hcl  string
		want []string // "ruleId level controlId subject", one per finding
	}{
		{
			name: "multiple ids in one parameter",
			hcl: `module "b" {
  source = "https://soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws?version=5.16.1&disable=s3_bucket_mfa_delete_enabled,s3_bucket_enforces_ssl"
}`,
			want: []string{
				"ctf.policy.disabled_control error s3_bucket_enforces_ssl module.b",
				"ctf.policy.disabled_control error s3_bucket_mfa_delete_enabled module.b",
			},
		},
		{
			name: "repeated parameter",
			hcl: `module "b" {
  source = "https://bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws?disable=s3_bucket_enforces_ssl&disable=s3_bucket_mfa_delete_enabled"
}`,
			want: []string{
				"ctf.policy.disabled_control error s3_bucket_enforces_ssl module.b",
				"ctf.policy.disabled_control error s3_bucket_mfa_delete_enabled module.b",
			},
		},
		{
			name: "duplicate id reported once",
			hcl: `module "b" {
  source = "https://soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws?disable=s3_bucket_enforces_ssl,s3_bucket_enforces_ssl"
}`,
			want: []string{"ctf.policy.disabled_control error s3_bucket_enforces_ssl module.b"},
		},
		{
			name: "unknown id",
			hcl: `module "b" {
  source = "https://soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws?disable=s3_bucket_mfa_delet_enabled,s3_bucket_enforces_ssl"
}`,
			want: []string{
				"ctf.policy.disabled_control error s3_bucket_enforces_ssl module.b",
				"ctf.policy.disabled_control_unknown error - module.b",
			},
		},
		{
			name: "non compliance.tf host ignored",
			hcl: `module "b" {
  source = "https://example.com/terraform-aws-modules/s3-bucket/aws?disable=s3_bucket_mfa_delete_enabled"
}
module "c" {
  source = "https://compliance.tf.example.com/x/y/aws?disable=s3_bucket_mfa_delete_enabled"
}`,
		},
		{
			name: "clean compliance.tf source",
			hcl: `module "b" {
  source  = "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"
}`,
		},
		{
			name: "dropped keyword heuristic",
			hcl: `module "b" {
  source           = "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  no_public_access = true
  disable_logging  = true
  skip_versioning  = true
}`,
		},
		{
			name: "empty disable value",
			hcl: `module "b" {
  source = "https://soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws?disable="
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := &ctfkit.ConfigArchive{
				Root:  ".",
				Files: []ctfkit.ConfigFile{{Path: "main.tf", Bytes: []byte(tc.hcl)}},
			}
			var got []string
			for _, f := range run(t, config) {
				id := "-"
				if len(f.Props.ControlIDs) == 1 {
					id = string(f.Props.ControlIDs[0])
				}
				got = append(got, strings.Join([]string{f.RuleID, f.Level, id, f.Subject()}, " "))
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestUnknownIDCarriesNoControlID keeps the unknown finding free of any
// control id: ValidateFor would refuse one the catalog does not hold.
func TestUnknownIDCarriesNoControlID(t *testing.T) {
	config := &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{{Path: "main.tf", Bytes: []byte(`module "b" {
  source = "https://soc2.compliance.tf/m/aws?disable=typo_control"
}`)}}}
	findings := run(t, config)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if len(f.Props.ControlIDs) != 0 || f.Props.Preventive || f.Props.Remediation != nil {
		t.Errorf("unknown finding props = %+v, want no control id, not preventive, no remediation", f.Props)
	}
	if !strings.Contains(f.Message.Text, "typo_control") {
		t.Errorf("message %q does not name the token", f.Message.Text)
	}
}

func TestSubdirectoryAndJSONFilesRead(t *testing.T) {
	config := &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{
		{Path: "envs/prod/main.tf", Bytes: []byte(`module "b" {
  source = "https://soc2.compliance.tf/m/aws?disable=s3_bucket_mfa_delete_enabled"
}`)},
		{Path: "json.tf.json", Bytes: []byte(`{"module": {"j": {"source": "https://soc2.compliance.tf/m/aws?disable=s3_bucket_enforces_ssl"}}}`)},
	}}
	var got []string
	for _, f := range run(t, config) {
		got = append(got, f.Locations[0].PhysicalLocation.ArtifactLocation.URI+" "+f.Subject())
	}
	want := []string{"envs/prod/main.tf module.b", "json.tf.json module.j"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestDoubleColonInQueryDoesNotBlind guards the forced-getter strip: a "::"
// inside a query value must not truncate the source and hide the block.
func TestDoubleColonInQueryDoesNotBlind(t *testing.T) {
	config := &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{{Path: "main.tf", Bytes: []byte(`module "b" {
  source = "https://soc2.compliance.tf/m/aws?disable=s3_bucket_mfa_delete_enabled&disable=a::b"
}
module "g" {
  source = "git::https://soc2.compliance.tf/m/aws?disable=s3_bucket_enforces_ssl"
}`)}}}
	var got []string
	for _, f := range run(t, config) {
		got = append(got, f.RuleID+" "+f.Subject())
	}
	want := []string{
		"ctf.policy.disabled_control module.b",
		"ctf.policy.disabled_control module.g",
		"ctf.policy.disabled_control_unknown module.b",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestDescriptorsMatchFixture checks the rule text fixture 03 records.
func TestDescriptorsMatchFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixtureRoot, "03-ctf-module-disabled-control", "expected", "findings.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID               string `json:"id"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	byID := map[string]string{}
	for _, d := range disabledcontrol.Descriptors() {
		byID[d.ID] = d.ShortDescription + "|" + d.Level
	}
	rules := document.Runs[0].Tool.Driver.Rules
	if len(rules) == 0 {
		t.Fatal("fixture 03 records no rule descriptor")
	}
	for _, r := range rules {
		if got, want := byID[r.ID], r.ShortDescription.Text+"|"+r.DefaultConfiguration.Level; got != want {
			t.Errorf("descriptor %s = %q, want %q", r.ID, got, want)
		}
	}
}

func TestUserinfoStripped(t *testing.T) {
	config := &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{{Path: "main.tf", Bytes: []byte(`module "b" {
  source = "https://user:secret@soc2.compliance.tf/m/aws?disable=nope"
}`)}}}
	findings := run(t, config)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	for _, f := range findings {
		if strings.Contains(f.Message.Text, "secret") {
			t.Errorf("message leaks userinfo: %q", f.Message.Text)
		}
	}
}

func TestInvalidHCLIsAnError(t *testing.T) {
	registry := ctfkit.NewRegistry()
	disabledcontrol.Register(registry)
	in := ctfkit.AnalyzerInput{
		Stage:   ctfkit.PrePlan,
		Config:  &ctfkit.ConfigArchive{Files: []ctfkit.ConfigFile{{Path: "main.tf", Bytes: []byte(`module "b" {`)}}},
		Catalog: fixtureCatalog(t),
	}
	for _, a := range registry.ByStage(ctfkit.PrePlan) {
		if _, err := a.Analyze(context.Background(), in); err == nil {
			t.Errorf("%s accepted unparseable configuration", a.ID())
		}
	}
}

func TestNilConfigHasNoFindings(t *testing.T) {
	if findings := run(t, nil); len(findings) != 0 {
		t.Errorf("got %d findings with no configuration, want 0", len(findings))
	}
}

// run executes every rule of the family and checks each finding the way the
// runner will.
func run(t *testing.T, config *ctfkit.ConfigArchive) ctfkit.Findings {
	t.Helper()

	registry := ctfkit.NewRegistry()
	disabledcontrol.Register(registry)
	in := ctfkit.AnalyzerInput{Stage: ctfkit.PrePlan, Config: config, Catalog: fixtureCatalog(t)}

	var out ctfkit.Findings
	for _, a := range registry.ByStage(ctfkit.PrePlan) {
		produced, err := a.Analyze(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: %v", a.ID(), err)
		}
		for _, f := range produced {
			checked, validateErr := f.ValidateFor(a.ID(), ctfkit.PrePlan, in.Catalog)
			if validateErr != nil {
				t.Fatalf("%s: %v", a.ID(), validateErr)
			}
			out = append(out, checked)
		}
	}
	ctfkit.SortFindings(out)
	return out
}

func analyze(t *testing.T, config *ctfkit.ConfigArchive) []any {
	t.Helper()

	out := make([]any, 0)
	for _, f := range run(t, config) {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshaling %s: %v", f.RuleID, err)
		}
		out = append(out, decode(t, raw))
	}
	return out
}

// fixtureCatalog is the release catalog embedded in the binary, the one the
// fixtures are recorded against.
func fixtureCatalog(t *testing.T) ctfkit.ControlCatalog {
	t.Helper()
	return catalog.Embedded()
}

// expectedResults is this family's results from a recorded SARIF file, with
// what the runner adds after Analyze removed.
func expectedResults(t *testing.T, name string) []any {
	t.Helper()

	path := filepath.Join(fixtureRoot, name, "expected", "findings.sarif")
	raw, err := os.ReadFile(path) //nolint:gosec // a committed fixture path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	var document struct {
		Runs []struct {
			Results []map[string]any `json:"results"`
		} `json:"runs"`
	}
	if unmarshalErr := json.Unmarshal(raw, &document); unmarshalErr != nil {
		t.Fatalf("parsing %s: %v", path, unmarshalErr)
	}
	if len(document.Runs) != 1 {
		t.Fatalf("%s has %d runs, want exactly 1", path, len(document.Runs))
	}

	out := make([]any, 0)
	for _, result := range document.Runs[0].Results {
		ruleID, _ := result["ruleId"].(string)
		if !strings.HasPrefix(ruleID, ownRulePrefix) {
			continue
		}
		properties, ok := result["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s has a result with no property bag", path)
		}
		for _, key := range runnerKeys {
			delete(properties, key)
		}
		delete(result, "suppressions")
		// partialFingerprints is written by the SARIF renderer, not the analyzer.
		delete(result, "partialFingerprints")
		out = append(out, any(result))
	}
	return out
}

func decode(t *testing.T, raw []byte) any {
	t.Helper()

	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return value
}

func mustIndent(t *testing.T, value any) []byte {
	t.Helper()

	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("indenting: %v", err)
	}
	return raw
}
