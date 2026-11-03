package origin_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"
	"gopkg.in/yaml.v3"

	"github.com/compliancetf/ctfkit/internal/analyzer/origin"
	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

const fixtureRoot = "../../../testdata/fixtures/plan"

// runContextKeys are result-level keys the command adds after analysis.
var runContextKeys = []string{"ctf.evidence"}

var planCases = []string{
	"01-raw-s3-no-ctf",
	"02-ctf-module-intact",
	"03-ctf-module-disabled-control",
	"04-floating-ref",
	"05-mixed-origin",
	"06-sentinel-exception",
	"07-expired-exception",
	"08-missing-tags",
	"09-unknown-provider",
	"10-post-apply-state",
}

// TestPrePlanFixtures runs every pre_plan rule of both families over every
// recorded plan case. The expected SARIF of each case is the oracle for the
// rule ids this package owns: 04 records one floating_ref, 09 one
// origin.provider, and every other case none.
func TestPrePlanFixtures(t *testing.T) {
	for _, name := range planCases {
		t.Run(name, func(t *testing.T) {
			input := filepath.Join(fixtureRoot, name, "input")
			config, err := loader.LoadConfig(input)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			in := ctfkit.AnalyzerInput{
				Stage:    ctfkit.PrePlan,
				Config:   config,
				Catalog:  catalog.Embedded(),
				Settings: fixtureSettings(t, input),
			}

			got := run(t, in)
			want := expectedResults(t, name)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("findings do not match %s/expected/findings.sarif\n got: %s\nwant: %s",
					name, indent(t, got), indent(t, want))
			}
		})
	}
}

// TestPostPlanFixtures runs the post_plan rules over every recorded plan. Only
// 09 configures a provider outside its allowlist, and it is reported once per
// provider instance.
func TestPostPlanFixtures(t *testing.T) {
	for _, name := range planCases {
		t.Run(name, func(t *testing.T) {
			input := filepath.Join(fixtureRoot, name, "input")
			plan, err := loader.LoadPlan(filepath.Join(input, "plan.json"))
			if err != nil {
				t.Fatalf("LoadPlan: %v", err)
			}
			findings := analyze(t, ctfkit.AnalyzerInput{
				Stage:    ctfkit.PostPlan,
				PlanJSON: plan,
				Catalog:  catalog.Embedded(),
				Settings: fixtureSettings(t, input),
			})

			if name != "09-unknown-provider" {
				if len(findings) != 0 {
					t.Fatalf("got %d finding(s), want none: %v", len(findings), findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("got %d finding(s), want 1: %v", len(findings), findings)
			}
			f := findings[0]
			if f.RuleID != "ctf.origin.provider" || f.Props.Stage != ctfkit.PostPlan {
				t.Errorf("got %s at %s, want ctf.origin.provider at post_plan", f.RuleID, f.Props.Stage)
			}
			if !strings.Contains(f.Message.Text, "registry.opentofu.org/hashicorp/random") {
				t.Errorf("message %q does not name the random provider", f.Message.Text)
			}
			wantLoc := `provider["registry.opentofu.org/hashicorp/random"]`
			if got := f.Locations[0].LogicalLocations[0]; got.FullyQualifiedName != wantLoc || got.Kind != ctfkit.LogicalLocationProvider {
				t.Errorf("location = %+v, want %s of kind provider", got, wantLoc)
			}
		})
	}
}

// TestSyntheticConfigs covers the cases no recorded fixture holds.
func TestSyntheticConfigs(t *testing.T) {
	awsLocked := &ctfkit.Lockfile{Providers: []ctfkit.LockedProvider{{
		Source: "registry.terraform.io/hashicorp/aws", Version: "6.2.0", Hashes: []string{"h1:abc="},
	}}}
	requiredAWS := `terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
`
	cases := []struct {
		name     string
		files    map[string]string
		lock     *ctfkit.Lockfile
		settings ctfkit.Settings
		want     []string // "ruleId|level|subject" per finding, in sorted order
	}{
		{
			name: "pinned references produce nothing",
			files: map[string]string{
				"providers.tf": requiredAWS,
				"main.tf": `module "sha" {
  source = "git::https://github.com/bobthecorp/tf-s3.git?ref=0123456789abcdef0123456789abcdef01234567"
}
module "registry" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"
}
module "local" {
  source = "./modules/local"
}
resource "aws_s3_bucket" "b" {}
`,
			},
			lock:     awsLocked,
			settings: ctfkit.Settings{AllowedProviders: []string{"registry.terraform.io/hashicorp/aws"}},
		},
		{
			name: "allowed by namespace produces nothing",
			files: map[string]string{
				"providers.tf": requiredAWS,
				"main.tf":      `resource "random_pet" "p" {}` + "\n" + `resource "aws_sqs_queue" "q" {}`,
			},
			settings: ctfkit.Settings{AllowedProviders: []string{"registry.terraform.io/hashicorp"}},
		},
		{
			name: "branch, tag and unbounded refs",
			files: map[string]string{
				"main.tf": `module "branch" {
  source = "git::https://github.com/bobthecorp/tf-s3.git?ref=main"
}
module "tag" {
  source = "github.com/bobthecorp/tf-s3?ref=v4.6.0"
}
module "noversion" {
  source = "terraform-aws-modules/s3-bucket/aws"
}
module "open" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 5.0"
}
`,
			},
			want: []string{
				"ctf.policy.floating_ref|warning|module.branch",
				"ctf.policy.floating_ref|warning|module.tag",
				"ctf.policy.floating_ref_unbounded|warning|module.noversion",
				"ctf.policy.floating_ref_unbounded|warning|module.open",
			},
		},
		{
			name: "unpinned provider and a lock entry without hashes",
			files: map[string]string{
				"providers.tf": `terraform {
  required_providers {
    aws    = { source = "hashicorp/aws" }
    random = { source = "hashicorp/random", version = ">= 3.0" }
    local  = { source = "hashicorp/local", version = "~> 2.0" }
  }
}
`,
			},
			lock: &ctfkit.Lockfile{Providers: []ctfkit.LockedProvider{
				{Source: "registry.terraform.io/hashicorp/aws", Version: "6.2.0", Hashes: []string{"h1:abc="}},
				{Source: "registry.terraform.io/hashicorp/random", Version: "3.6.0"},
			}},
			want: []string{
				`ctf.origin.provider_unpinned|warning|provider["registry.terraform.io/hashicorp/aws"]`,
				`ctf.origin.provider_unpinned|warning|provider["registry.terraform.io/hashicorp/random"]`,
				// Same file, so line order: random is declared above local.
				`ctf.origin.provider_unverified|warning|provider["registry.terraform.io/hashicorp/random"]`,
				`ctf.origin.provider_unverified|warning|provider["registry.terraform.io/hashicorp/local"]`,
			},
		},
		{
			name: "unapproved provider declared in required_providers and aliased",
			files: map[string]string{
				"providers.tf": `terraform {
  required_providers {
    aws  = { source = "hashicorp/aws", version = "~> 6.0" }
    evil = { source = "example.com/bobthecorp/evil", version = "~> 1.0" }
  }
}
provider "evil" {
  alias = "second"
}
`,
				"main.tf": `resource "evil_thing" "a" {
  provider = evil.second
}
`,
			},
			settings: ctfkit.Settings{AllowedProviders: []string{"hashicorp/aws"}},
			want: []string{
				`ctf.origin.provider|warning|provider["example.com/bobthecorp/evil"]`,
			},
		},
		{
			name: "allowed_resources once per type",
			files: map[string]string{
				"main.tf": `resource "aws_s3_bucket" "a" {}
resource "aws_instance" "one" {}
resource "aws_instance" "two" {}
`,
			},
			settings: ctfkit.Settings{AllowedResources: []string{"aws_s3_bucket"}},
			want: []string{
				"ctf.origin.provider_resource_type|error|aws_instance",
			},
		},
		{
			name:  "credentials in a module source never reach a finding",
			files: map[string]string{"main.tf": `module "x" { source = "git::https://user:s3cr3t@github.com/bobthecorp/x.git" }`},
			want:  []string{"ctf.policy.floating_ref|warning|module.x"},
		},
		{
			name:  "an sshkey query argument never reaches a finding",
			files: map[string]string{"main.tf": `module "k" { source = "git::ssh://git@example.com/bobthecorp/k.git?sshkey=s3cr3t" }`},
			want:  []string{"ctf.policy.floating_ref|warning|module.k"},
		},
		{
			name:  "a dotless private registry host is a registry source",
			files: map[string]string{"main.tf": `module "p" { source = "tfe/bobthecorp/vpc/aws" }`},
			want:  []string{"ctf.policy.floating_ref_unbounded|warning|module.p"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive := &ctfkit.ConfigArchive{Root: ".", Lockfile: tc.lock}
			for _, path := range []string{"main.tf", "providers.tf"} {
				if body, ok := tc.files[path]; ok {
					archive.Files = append(archive.Files, ctfkit.ConfigFile{Path: path, Bytes: []byte(body)})
				}
			}
			findings := analyze(t, ctfkit.AnalyzerInput{
				Stage:    ctfkit.PrePlan,
				Config:   archive,
				Catalog:  catalog.Embedded(),
				Settings: tc.settings,
			})

			got := make([]string, 0, len(findings))
			for _, f := range findings {
				got = append(got, f.RuleID+"|"+f.Level+"|"+subject(f))
				raw, _ := json.Marshal(f)
				if strings.Contains(string(raw), "s3cr3t") {
					t.Errorf("finding carries the credential: %s", raw)
				}
			}
			if !reflect.DeepEqual(got, nonNil(tc.want)) {
				t.Errorf("got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestPostPlanResourceTypes reports a planned type outside allowed_resources
// once, however many instances the plan creates, and ignores data sources.
func TestPostPlanResourceTypes(t *testing.T) {
	plan := &tfjson.Plan{ResourceChanges: []*tfjson.ResourceChange{
		{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Mode: tfjson.ManagedResourceMode},
		{Address: "aws_instance.x[0]", Type: "aws_instance", Mode: tfjson.ManagedResourceMode},
		{Address: "aws_instance.x[1]", Type: "aws_instance", Mode: tfjson.ManagedResourceMode},
		{Address: "data.aws_ami.ubuntu", Type: "aws_ami", Mode: tfjson.DataResourceMode},
	}}
	findings := analyze(t, ctfkit.AnalyzerInput{
		Stage:    ctfkit.PostPlan,
		PlanJSON: plan,
		Catalog:  catalog.Embedded(),
		Settings: ctfkit.Settings{AllowedResources: []string{"aws_s3_bucket"}},
	})
	if len(findings) != 1 || findings[0].RuleID != "ctf.origin.provider_resource_type" ||
		subject(findings[0]) != "aws_instance" {
		t.Fatalf("got %v, want one provider_resource_type finding for aws_instance", findings)
	}
}

// TestRegistration pins which (id, stage) pairs the family registers.
func TestRegistration(t *testing.T) {
	r := ctfkit.NewRegistry()
	origin.Register(r)

	want := map[ctfkit.Stage][]string{
		ctfkit.PrePlan: {
			"ctf.origin.provider", "ctf.origin.provider_unpinned", "ctf.origin.provider_unverified",
			"ctf.origin.provider_resource_type", "ctf.policy.floating_ref", "ctf.policy.floating_ref_unbounded",
		},
		ctfkit.PostPlan: {"ctf.origin.provider", "ctf.origin.provider_resource_type"},
	}
	for stage, ids := range want {
		var got []string
		for _, a := range r.ByStage(stage) {
			got = append(got, a.ID())
		}
		if !reflect.DeepEqual(got, ids) {
			t.Errorf("%s: got %v, want %v", stage, got, ids)
		}
	}
	if n := len(r.All()); n != 8 {
		t.Errorf("registered %d analyzers, want 8", n)
	}
}

// TestWrongStageInputIsEmpty: a rule handed an input its stage does not
// populate reports nothing rather than failing.
func TestWrongStageInputIsEmpty(t *testing.T) {
	r := ctfkit.NewRegistry()
	origin.Register(r)
	for _, a := range r.All() {
		fs, err := a.Analyze(context.Background(), ctfkit.AnalyzerInput{Stage: a.Stage()})
		if err != nil || len(fs) != 0 {
			t.Errorf("%s at %s on an empty input: %v, %v", a.ID(), a.Stage(), fs, err)
		}
	}
}

func analyze(t *testing.T, in ctfkit.AnalyzerInput) ctfkit.Findings {
	t.Helper()
	r := ctfkit.NewRegistry()
	origin.Register(r)

	var out ctfkit.Findings
	for _, a := range r.ByStage(in.Stage) {
		produced, err := a.Analyze(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: %v", a.ID(), err)
		}
		for _, f := range produced {
			checked, err := f.ValidateFor(a.ID(), in.Stage, in.Catalog)
			if err != nil {
				t.Fatalf("%s: %v", a.ID(), err)
			}
			out = append(out, checked)
		}
	}
	ctfkit.SortFindings(out)
	return out
}

func run(t *testing.T, in ctfkit.AnalyzerInput) []any {
	t.Helper()
	out := []any{}
	for _, f := range analyze(t, in) {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshaling: %v", err)
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("decoding: %v", err)
		}
		out = append(out, v)
	}
	return out
}

// fixtureSettings reads the allowlists a case's .ctfkit.yaml carries, the
// part of settings resolution this family depends on.
func fixtureSettings(t *testing.T, input string) ctfkit.Settings {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(input, ".ctfkit.yaml")) //nolint:gosec // committed fixture path
	if os.IsNotExist(err) {
		return ctfkit.Settings{}
	}
	if err != nil {
		t.Fatalf("reading .ctfkit.yaml: %v", err)
	}
	var doc struct {
		AllowedProviders []string `yaml:"allowed_providers"`
		AllowedResources []string `yaml:"allowed_resources"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing .ctfkit.yaml: %v", err)
	}
	return ctfkit.Settings{AllowedProviders: doc.AllowedProviders, AllowedResources: doc.AllowedResources}
}

// expectedResults is the recorded results array, reduced to this package's
// rule ids and stripped of run context.
func expectedResults(t *testing.T, name string) []any {
	t.Helper()
	path := filepath.Join(fixtureRoot, name, "expected", "findings.sarif")
	raw, err := os.ReadFile(path) //nolint:gosec // committed fixture path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc struct {
		Runs []struct {
			Results []map[string]any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Runs) != 1 {
		t.Fatalf("parsing %s: %v", path, err)
	}
	out := []any{}
	for _, result := range doc.Runs[0].Results {
		id, _ := result["ruleId"].(string)
		if !strings.HasPrefix(id, "ctf.origin.") && !strings.HasPrefix(id, "ctf.policy.floating_ref") {
			continue
		}
		if props, ok := result["properties"].(map[string]any); ok {
			for _, k := range runContextKeys {
				delete(props, k)
			}
		}
		// partialFingerprints is written by the SARIF renderer, not the analyzer.
		delete(result, "partialFingerprints")
		out = append(out, any(result))
	}
	return out
}

func subject(f ctfkit.Finding) string {
	if s := f.Subject(); s != "" {
		return s
	}
	if len(f.Locations) > 0 && len(f.Locations[0].LogicalLocations) > 0 {
		return f.Locations[0].LogicalLocations[0].FullyQualifiedName
	}
	return ""
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func indent(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("indenting: %v", err)
	}
	return raw
}
