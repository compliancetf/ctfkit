package modulesource_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/analyzer/modulesource"
	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// fixtureRoot is the recorded plan fixture pack, which is the oracle for this
// analyzer.
const fixtureRoot = "../../../testdata/fixtures/plan"

// runContextKeys are the result-level property keys the command adds after the
// analyzer has run. An analyzer never sets them, so the comparison drops them
// from the expected side rather than inventing them on the produced side.
var runContextKeys = []string{"ctf.evidence", "ctf.exception"}

// TestFixtures is the table this analyzer is built against. Every recorded
// plan case must produce exactly the ctf.coverage.module_source results its
// expected SARIF records, at the stage its scan argv runs. Cases 06 and
// 07 carry an exception decision; the analyzer's part of those results is
// everything but the runner's exception property and suppression.
func TestFixtures(t *testing.T) {
	cases := map[string]ctfkit.Stage{
		"01-raw-s3-no-ctf":               ctfkit.PostPlan,
		"02-ctf-module-intact":           ctfkit.PostPlan,
		"03-ctf-module-disabled-control": ctfkit.PrePlan,
		"04-floating-ref":                ctfkit.PrePlan,
		"05-mixed-origin":                ctfkit.PrePlan,
		"06-sentinel-exception":          ctfkit.PostPlan,
		"07-expired-exception":           ctfkit.PostPlan,
	}

	for name, stage := range cases {
		t.Run(name, func(t *testing.T) {
			in := loadFixture(t, name, stage)
			produced := analyze(t, in)
			want := expectedResults(t, name)

			if !reflect.DeepEqual(produced, want) {
				t.Errorf("findings do not match %s/expected/findings.sarif\n got: %s\nwant: %s",
					name, mustIndent(t, produced), mustIndent(t, want))
			}
		})
	}
}

// TestPrePlanReadsModuleBlocksOnly records the stage split: the pre_plan value
// classifies the module blocks of the configuration and never a resource, so
// the mixed case reports the upstream module call and not the raw queue the
// same case reports at post_plan.
func TestPrePlanReadsModuleBlocksOnly(t *testing.T) {
	in := loadFixture(t, "05-mixed-origin", ctfkit.PrePlan)
	findings := analyze(t, in)

	if len(findings) != 1 {
		t.Fatalf("pre_plan produced %d finding(s), want 1: %s", len(findings), mustIndent(t, findings))
	}

	result, ok := findings[0].(map[string]any)
	if !ok {
		t.Fatalf("finding is not an object: %s", mustIndent(t, findings[0]))
	}
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		t.Fatalf("finding carries no property bag: %s", mustIndent(t, result))
	}
	if got := properties["ctf.stage"]; got != string(ctfkit.PrePlan) {
		t.Errorf("ctf.stage is %v, want %s", got, ctfkit.PrePlan)
	}
	message, ok := result["message"].(map[string]any)
	if !ok {
		t.Fatalf("finding carries no message: %s", mustIndent(t, result))
	}
	if text, _ := message["text"].(string); !strings.Contains(text, "terraform-aws-modules/iam/aws") {
		t.Errorf("message is %q, want the upstream module call", text)
	}
}

// TestPrePlanIsQuietOnServedAndNonRegistrySources records the other three
// pre_plan cases: a served module, a served module carrying a disable query
// and a git:: source each produce nothing from this analyzer.
func TestPrePlanIsQuietOnServedAndNonRegistrySources(t *testing.T) {
	for _, name := range []string{
		"02-ctf-module-intact",
		"03-ctf-module-disabled-control",
		"04-floating-ref",
	} {
		t.Run(name, func(t *testing.T) {
			in := loadFixture(t, name, ctfkit.PrePlan)
			if findings := analyze(t, in); len(findings) != 0 {
				t.Errorf("pre_plan produced %d finding(s), want none: %s",
					len(findings), mustIndent(t, findings))
			}
		})
	}
}

// TestClassificationRows walks the classification table one module source at a
// time. The fixture pack pins four of the rows; this pins all six, including
// the two no recorded plan carries.
func TestClassificationRows(t *testing.T) {
	cases := []struct {
		name         string
		source       string
		version      string
		endpoints    []string
		wantRule     string
		wantText     string
		wantLevel    string
		wantModule   string
		wantPreventi bool
	}{
		{
			name:     "served module is not a finding",
			source:   "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws",
			wantRule: "",
		},
		{
			name:     "served module carrying a disable query is handed to disabled_control",
			source:   "https://soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws?disable=s3_bucket_versioning_enabled",
			wantRule: "",
		},
		{
			name:         "upstream registry module is a migration candidate",
			source:       "terraform-aws-modules/iam/aws//modules/iam-policy",
			version:      "~> 6.0",
			wantRule:     "ctf.coverage.module_source",
			wantLevel:    ctfkit.LevelError,
			wantModule:   "soc2.compliance.tf/terraform-aws-modules/iam/aws//modules/iam-policy",
			wantPreventi: true,
		},
		{
			name:       "upstream module behind the public registry host is the same row",
			source:     "registry.terraform.io/terraform-aws-modules/vpc/aws",
			version:    "~> 5.0",
			wantRule:   "ctf.coverage.module_source",
			wantLevel:  ctfkit.LevelError,
			wantModule: "soc2.compliance.tf/terraform-aws-modules/vpc/aws",

			wantPreventi: true,
		},
		{
			name:         "the upstream namespace matches case-insensitively",
			source:       "Terraform-AWS-Modules/iam/aws",
			version:      "~> 6.0",
			wantRule:     "ctf.coverage.module_source",
			wantLevel:    ctfkit.LevelError,
			wantModule:   "soc2.compliance.tf/Terraform-AWS-Modules/iam/aws",
			wantPreventi: true,
		},
		{
			name:      "third-party registry module is inventory only",
			source:    "cloudposse/s3-bucket/aws",
			version:   "~> 4.0",
			wantRule:  "ctf.coverage.module_source",
			wantLevel: ctfkit.LevelNote,
			wantText: "Third-party module cloudposse/s3-bucket/aws has no compliance.tf equivalent; " +
				"it is listed for inventory only",
		},
		{
			name:      "registry host outside the allowlist is an unknown registry",
			source:    "registry.example.internal/platform/s3-bucket/aws",
			endpoints: []string{"bobthecorp.compliance.tf"},
			wantRule:  "ctf.coverage.module_source_unknown_registry",
			wantLevel: ctfkit.LevelWarning,
			wantText: "Module source registry.example.internal/platform/s3-bucket/aws resolves to the " +
				"registry host registry.example.internal, which the endpoint allowlist does not name",
		},
		{
			name:      "an endpoint allowlist replaces the compliance.tf suffix rule",
			source:    "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws",
			endpoints: []string{"soc2.compliance.tf"},
			wantRule:  "ctf.coverage.module_source_unknown_registry",
			wantLevel: ctfkit.LevelWarning,
		},
		{
			name:     "a git source is the origin rules' subject, not this one",
			source:   "git::https://github.com/terraform-aws-modules/terraform-aws-iam.git//modules/iam-policy",
			wantRule: "",
		},
		{
			name:     "an https archive URL with three path segments is not a registry address",
			source:   "https://artifacts.example.com/team/service/archive.zip",
			wantRule: "",
		},
		{
			name:     "an https URL to the public registry is an archive, not a registry address",
			source:   "https://registry.terraform.io/terraform-aws-modules/vpc/aws",
			wantRule: "",
		},
		{
			name:     "the bare compliance.tf host is served",
			source:   "compliance.tf/terraform-aws-modules/s3-bucket/aws",
			wantRule: "",
		},
		{
			name:     "a local path is not a registry address",
			source:   "./modules/network",
			wantRule: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := ctfkit.AnalyzerInput{
				Stage:    ctfkit.PostPlan,
				PlanJSON: planWithModuleCall("candidate", tc.source, tc.version),
				Catalog:  fixtureCatalog(t),
				Settings: ctfkit.Settings{Endpoints: tc.endpoints},
			}

			findings := analyzeTyped(t, in)
			if tc.wantRule == "" {
				if len(findings) != 0 {
					t.Fatalf("produced %d finding(s), want none: %+v", len(findings), findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("produced %d finding(s), want 1: %+v", len(findings), findings)
			}

			got := findings[0]
			if got.RuleID != tc.wantRule {
				t.Errorf("rule id is %s, want %s", got.RuleID, tc.wantRule)
			}
			if got.Level != tc.wantLevel {
				t.Errorf("level is %s, want %s", got.Level, tc.wantLevel)
			}
			if tc.wantText != "" && got.Message.Text != tc.wantText {
				t.Errorf("message is %q, want %q", got.Message.Text, tc.wantText)
			}
			if got.Props.Preventive != tc.wantPreventi {
				t.Errorf("ctf.preventive is %v, want %v", got.Props.Preventive, tc.wantPreventi)
			}
			if tc.wantModule == "" {
				if got.Props.Remediation != nil {
					t.Errorf("ctf.remediation is %+v, want none", got.Props.Remediation)
				}
				return
			}
			if got.Props.Remediation == nil {
				t.Fatalf("ctf.remediation is absent, want %s", tc.wantModule)
			}
			if got.Props.Remediation.ModuleSource != tc.wantModule {
				t.Errorf("moduleSource is %s, want %s", got.Props.Remediation.ModuleSource, tc.wantModule)
			}
			if got.Props.Remediation.Version != tc.version {
				t.Errorf("remediation version is %q, want the carried-over %q",
					got.Props.Remediation.Version, tc.version)
			}
		})
	}
}

// TestRemediationNeedsACatalogEntry records the other half of the remediation
// rule: a raw resource is a finding only where the catalog names a module for
// its type, and a type the catalog does not cover is never guessed at.
func TestRemediationNeedsACatalogEntry(t *testing.T) {
	in := ctfkit.AnalyzerInput{
		Stage:    ctfkit.PostPlan,
		PlanJSON: planWithResources("aws_kinesis_stream.events", "aws_kinesis_stream"),
		Catalog:  fixtureCatalog(t),
	}

	if findings := analyzeTyped(t, in); len(findings) != 0 {
		t.Errorf("produced %d finding(s) for an uncovered resource type, want none: %+v",
			len(findings), findings)
	}
}

// TestResourcesInsideAServedModuleAreNotClassified records the subtree rule.
// The served module of 02-ctf-module-intact plans an aws_s3_bucket the catalog
// covers; it is the module's resource, not the configuration's, so it is not a
// migration candidate and the recorded case has no results at all.
func TestResourcesInsideAServedModuleAreNotClassified(t *testing.T) {
	in := loadFixture(t, "02-ctf-module-intact", ctfkit.PostPlan)

	plan := in.PlanJSON
	if plan == nil || plan.PlannedValues == nil || plan.PlannedValues.RootModule == nil {
		t.Fatal("the fixture plan carries no planned values")
	}
	var planned int
	for _, child := range plan.PlannedValues.RootModule.ChildModules {
		planned += len(child.Resources)
	}
	if planned == 0 {
		t.Fatal("the served module planned no resources, so this case proves nothing")
	}

	if findings := analyzeTyped(t, in); len(findings) != 0 {
		t.Errorf("produced %d finding(s) inside a served module, want none: %+v",
			len(findings), findings)
	}
}

// TestResourcesInsideAnIndexedServedModuleAreNotClassified records that the
// subtree rule survives count and for_each: the planned values name the
// instance, module.s3_bucket[0], while the configuration names the call.
func TestResourcesInsideAnIndexedServedModuleAreNotClassified(t *testing.T) {
	for _, instance := range []string{`module.served[0]`, `module.served["logs"]`, `module.served["a]b"]`} {
		t.Run(instance, func(t *testing.T) {
			plan := planWithModuleCall("served", "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws", "~> 5.0")
			plan.PlannedValues.RootModule.ChildModules = []*tfjson.StateModule{{
				Address: instance,
				Resources: []*tfjson.StateResource{{
					Address: instance + ".aws_s3_bucket.this[0]",
					Mode:    tfjson.ManagedResourceMode,
					Type:    "aws_s3_bucket",
					Name:    "this",
				}},
			}}

			in := ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, PlanJSON: plan, Catalog: fixtureCatalog(t)}
			if findings := analyzeTyped(t, in); len(findings) != 0 {
				t.Errorf("produced %d finding(s) inside an indexed served module, want none: %+v",
					len(findings), findings)
			}
		})
	}
}

// TestResourcesInsideAnUnservedModuleAreClassified is the other side of the
// subtree rule: a third-party module's own raw resource is still the
// configuration's risk, because instantiating that module is the choice that
// created it.
func TestResourcesInsideAnUnservedModuleAreClassified(t *testing.T) {
	plan := planWithModuleCall("vendor", "cloudposse/s3-bucket/aws", "~> 4.0")
	plan.PlannedValues.RootModule.ChildModules = []*tfjson.StateModule{{
		Address: "module.vendor",
		Resources: []*tfjson.StateResource{{
			Address: "module.vendor.aws_s3_bucket.this",
			Mode:    tfjson.ManagedResourceMode,
			Type:    "aws_s3_bucket",
			Name:    "this",
		}},
	}}

	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, PlanJSON: plan, Catalog: fixtureCatalog(t)}

	findings := analyzeTyped(t, in)
	if len(findings) != 2 {
		t.Fatalf("produced %d finding(s), want the module note and the resource error: %+v",
			len(findings), findings)
	}
	if got := findings[1].Subject(); got != "module.vendor.aws_s3_bucket.this" {
		t.Errorf("second finding is about %s, want the vendored bucket", got)
	}
}

// TestRawResourceCarriesOnlyTheModulesControls records that a raw-resource
// finding names only the controls the replacement module enforces. The catalog
// places s3_bucket_enforces_ssl on aws_s3_bucket, but the s3-bucket module
// does not claim it, so the finding must not say the module closes it.
func TestRawResourceCarriesOnlyTheModulesControls(t *testing.T) {
	cat := fixtureCatalog(t)
	if !slices.Contains(cat.ControlsFor("aws_s3_bucket"), "s3_bucket_enforces_ssl") {
		t.Fatal("the catalog no longer places s3_bucket_enforces_ssl on aws_s3_bucket; pick another unclaimed control")
	}
	module, _ := cat.ModuleFor("aws_s3_bucket")

	in := ctfkit.AnalyzerInput{
		Stage:    ctfkit.PostPlan,
		PlanJSON: planWithResources("aws_s3_bucket.raw", "aws_s3_bucket"),
		Catalog:  cat,
	}
	findings := analyzeTyped(t, in)
	if len(findings) != 1 {
		t.Fatalf("produced %d finding(s), want the raw-resource error", len(findings))
	}
	ids := findings[0].Props.ControlIDs
	if slices.Contains(ids, "s3_bucket_enforces_ssl") {
		t.Errorf("finding carries s3_bucket_enforces_ssl, which the s3-bucket module does not claim: %v", ids)
	}
	for _, id := range ids {
		if !slices.Contains(module.Controls, id) {
			t.Errorf("finding carries %s, which the s3-bucket module does not enforce", id)
		}
	}
}

// TestDataSourcesAndNonAWSResourcesAreNotClassified records what the rule does
// not read: a data source is not a planned resource, and the launch catalog
// only covers aws_* types.
func TestDataSourcesAndNonAWSResourcesAreNotClassified(t *testing.T) {
	plan := planWithResources("local_file.notes", "local_file")
	plan.PlannedValues.RootModule.Resources = append(plan.PlannedValues.RootModule.Resources,
		&tfjson.StateResource{
			Address: "data.aws_s3_bucket.existing",
			Mode:    tfjson.DataResourceMode,
			Type:    "aws_s3_bucket",
			Name:    "existing",
		})

	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, PlanJSON: plan, Catalog: fixtureCatalog(t)}

	if findings := analyzeTyped(t, in); len(findings) != 0 {
		t.Errorf("produced %d finding(s), want none: %+v", len(findings), findings)
	}
}

// TestRegistrationIsFourValues records the registry contract: one rule id runs
// at two stages, which is two registered values, and the family registers two
// ids. ctf.coverage.module_source_disabled is deliberately absent: the
// recorded disabled-control case carries no result under it, and the finding
// belongs to ctf.policy.disabled_control.
func TestRegistrationIsFourValues(t *testing.T) {
	registry := ctfkit.NewRegistry()
	modulesource.Register(registry)

	for _, id := range []string{"ctf.coverage.module_source", "ctf.coverage.module_source_unknown_registry"} {
		for _, stage := range []ctfkit.Stage{ctfkit.PrePlan, ctfkit.PostPlan} {
			if registry.ByID(id, stage) == nil {
				t.Errorf("%s is not registered at %s", id, stage)
			}
		}
	}
	for _, stage := range []ctfkit.Stage{ctfkit.PrePlan, ctfkit.PostPlan} {
		if a := registry.ByID("ctf.coverage.module_source_disabled", stage); a != nil {
			t.Errorf("ctf.coverage.module_source_disabled is registered at %s; "+
				"the recorded fixture carries no such result", stage)
		}
	}
	if got := len(registry.All()); got != 4 {
		t.Errorf("the family registered %d values, want 4", got)
	}
}

// TestRemediationHostFollowsTheRunFramework records the host rule: the first
// run framework the catalog hosts picks the host label, a framework the
// catalog does not host is passed over, and no framework falls back to the
// catalog default, which fixture 01-raw-s3-no-ctf pins.
func TestRemediationHostFollowsTheRunFramework(t *testing.T) {
	cases := map[string]struct {
		frameworks []string
		want       string
	}{
		"catalog default":            {nil, "soc2.compliance.tf/terraform-aws-modules/sqs/aws"},
		"first hosted framework":     {[]string{"pci_dss_v40", "soc_2"}, "pcidss.compliance.tf/terraform-aws-modules/sqs/aws"},
		"unhosted framework skipped": {[]string{"iso27001", "pci_dss_v40"}, "pcidss.compliance.tf/terraform-aws-modules/sqs/aws"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := ctfkit.AnalyzerInput{
				Stage:    ctfkit.PostPlan,
				PlanJSON: planWithResources("aws_sqs_queue.events", "aws_sqs_queue"),
				Catalog:  fixtureCatalog(t),
				Metadata: ctfkit.RunMetadata{Frameworks: tc.frameworks},
			}

			findings := analyzeTyped(t, in)
			if len(findings) != 1 || findings[0].Props.Remediation == nil {
				t.Fatalf("produced %+v, want one finding with a remediation", findings)
			}
			if got := findings[0].Props.Remediation.ModuleSource; got != tc.want {
				t.Errorf("moduleSource is %s, want %s", got, tc.want)
			}
		})
	}
}

// TestPlanWithoutConfigurationClassifiesRootResourcesOnly records that a plan
// document with no configuration tree cannot say which child module is served,
// so a child module's resources are left alone rather than all reported raw.
func TestPlanWithoutConfigurationClassifiesRootResourcesOnly(t *testing.T) {
	plan := planWithResources("aws_sqs_queue.events", "aws_sqs_queue")
	plan.Config = nil
	plan.PlannedValues.RootModule.ChildModules = []*tfjson.StateModule{{
		Address: "module.served",
		Resources: []*tfjson.StateResource{{
			Address: "module.served.aws_s3_bucket.this",
			Mode:    tfjson.ManagedResourceMode,
			Type:    "aws_s3_bucket",
			Name:    "this",
		}},
	}}

	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, PlanJSON: plan, Catalog: fixtureCatalog(t)}
	findings := analyzeTyped(t, in)
	if len(findings) != 1 || findings[0].Subject() != "aws_sqs_queue.events" {
		t.Errorf("produced %+v, want only the root queue", findings)
	}
}

// TestNullModuleCallIsSkipped records that a malformed plan document with a
// null module_calls entry is read past rather than crashing the run.
func TestNullModuleCallIsSkipped(t *testing.T) {
	plan := planWithModuleCall("upstream", "terraform-aws-modules/iam/aws", "~> 6.0")
	plan.Config.RootModule.ModuleCalls["broken"] = nil

	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, PlanJSON: plan, Catalog: fixtureCatalog(t)}
	if findings := analyzeTyped(t, in); len(findings) != 1 {
		t.Errorf("produced %d finding(s), want the one for the well-formed call: %+v", len(findings), findings)
	}
}

// TestEmptyInputIsNotAnError records that a stage the analyzer has nothing to
// read at reports nothing rather than failing the run.
func TestEmptyInputIsNotAnError(t *testing.T) {
	cases := map[string]ctfkit.AnalyzerInput{
		"pre_plan without configuration": {Stage: ctfkit.PrePlan, Catalog: fixtureCatalog(t)},
		"post_plan without a plan":       {Stage: ctfkit.PostPlan, Catalog: fixtureCatalog(t)},
		"post_plan without a catalog": {
			Stage:    ctfkit.PostPlan,
			PlanJSON: planWithResources("aws_s3_bucket.logs", "aws_s3_bucket"),
		},
	}

	registry := ctfkit.NewRegistry()
	modulesource.Register(registry)

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			for _, a := range registry.ByStage(in.Stage) {
				produced, err := a.Analyze(context.Background(), in)
				if err != nil {
					t.Fatalf("%s: %v", a.ID(), err)
				}
				if len(produced) != 0 {
					t.Errorf("%s produced %d finding(s), want none", a.ID(), len(produced))
				}
			}
		})
	}
}

// loadFixture reads one recorded plan case the way the command will:
// configuration for the file anchor, the plan document at post_plan, and the
// catalog the recorded findings join against.
func loadFixture(t *testing.T, name string, stage ctfkit.Stage) ctfkit.AnalyzerInput {
	t.Helper()

	input := filepath.Join(fixtureRoot, name, "input")

	config, err := loader.LoadConfig(input)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", input, err)
	}

	in := ctfkit.AnalyzerInput{Stage: stage, Config: config, Catalog: fixtureCatalog(t)}
	if stage == ctfkit.PostPlan {
		plan, planErr := loader.LoadPlan(filepath.Join(input, "plan.json"))
		if planErr != nil {
			t.Fatalf("LoadPlan(%s): %v", input, planErr)
		}
		in.PlanJSON = plan
	}

	return in
}

// fixtureCatalog is the catalog the recorded plan findings join against: the
// release catalog embedded in the binary.
func fixtureCatalog(t *testing.T) ctfkit.ControlCatalog {
	t.Helper()
	return catalog.Embedded()
}

// analyzeTyped runs every rule of the family for the input's stage, in
// registration order, and checks each finding the way the runner will.
func analyzeTyped(t *testing.T, in ctfkit.AnalyzerInput) ctfkit.Findings {
	t.Helper()

	registry := ctfkit.NewRegistry()
	modulesource.Register(registry)

	var findings ctfkit.Findings
	for _, a := range registry.ByStage(in.Stage) {
		produced, err := a.Analyze(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: %v", a.ID(), err)
		}
		for _, f := range produced {
			checked, validateErr := f.ValidateFor(a.ID(), in.Stage, in.Catalog)
			if validateErr != nil {
				t.Fatalf("%s: %v", a.ID(), validateErr)
			}
			findings = append(findings, checked)
		}
	}

	return findings
}

// analyze is analyzeTyped rendered as the generic JSON the recorded documents
// parse to, so the two sides compare as documents rather than as Go types.
func analyze(t *testing.T, in ctfkit.AnalyzerInput) []any {
	t.Helper()

	findings := analyzeTyped(t, in)

	out := make([]any, 0, len(findings))
	for _, f := range findings {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshaling %s: %v", f.RuleID, err)
		}
		out = append(out, decode(t, raw))
	}
	return out
}

// expectedResults is the results array of a recorded SARIF file, reduced to
// this family's rules and with the run context the command adds stripped from
// each result. Another rule's result in the same document belongs to another
// analyzer and is not this analyzer's to produce.
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

	out := make([]any, 0, len(document.Runs[0].Results))
	for _, result := range document.Runs[0].Results {
		ruleID, _ := result["ruleId"].(string)
		if !strings.HasPrefix(ruleID, "ctf.coverage.module_source") {
			continue
		}
		properties, ok := result["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s has a result with no property bag", path)
		}
		for _, key := range runContextKeys {
			delete(properties, key)
		}
		// A suppression is the runner's verdict on an exception, never the
		// analyzer's output.
		delete(result, "suppressions")
		// partialFingerprints is written by the SARIF renderer, not the analyzer.
		delete(result, "partialFingerprints")
		out = append(out, any(result))
	}
	return out
}

// planWithModuleCall is the smallest plan document that declares one root
// module call and plans nothing.
func planWithModuleCall(name, source, version string) *tfjson.Plan {
	return &tfjson.Plan{
		FormatVersion: "1.2",
		Config: &tfjson.Config{
			RootModule: &tfjson.ConfigModule{
				ModuleCalls: map[string]*tfjson.ModuleCall{
					name: {Source: source, VersionConstraint: version},
				},
			},
		},
		PlannedValues: &tfjson.StateValues{RootModule: &tfjson.StateModule{}},
	}
}

// planWithResources is the smallest plan document that plans one managed
// resource in the root module and calls no module.
func planWithResources(address, resourceType string) *tfjson.Plan {
	name := address
	if i := strings.LastIndex(address, "."); i >= 0 {
		name = address[i+1:]
	}

	return &tfjson.Plan{
		FormatVersion: "1.2",
		Config:        &tfjson.Config{RootModule: &tfjson.ConfigModule{}},
		PlannedValues: &tfjson.StateValues{RootModule: &tfjson.StateModule{
			Resources: []*tfjson.StateResource{{
				Address: address,
				Mode:    tfjson.ManagedResourceMode,
				Type:    resourceType,
				Name:    name,
			}},
		}},
	}
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
