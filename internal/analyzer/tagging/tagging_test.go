package tagging_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/analyzer/tagging"
	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

const fixtureRoot = "../../../testdata/fixtures/plan"

// fixture08Policy is the tag policy the 08-missing-tags input records in its
// .ctfkit.yaml: Environment and Owner are required on every resource. The
// settings loader resolves that file into Settings.Tags; this test states the
// resolved value directly so the analyzer is tested on its own input.
var fixture08Policy = []ctfkit.TagRule{
	{Key: "Environment", Required: true},
	{Key: "Owner", Required: true},
}

// TestFixture08MissingTags asserts the findings equal the results array of
// 08-missing-tags/expected/findings.sarif, less ctf.evidence, which the
// command adds after the analyzer has run.
func TestFixture08MissingTags(t *testing.T) {
	input := filepath.Join(fixtureRoot, "08-missing-tags", "input")

	plan, err := loader.LoadPlan(filepath.Join(input, "plan.json"))
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}
	config, err := loader.LoadConfig(input)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	got := analyze(t, ctfkit.AnalyzerInput{
		Stage:    ctfkit.PostPlan,
		Config:   config,
		PlanJSON: plan,
		Catalog:  catalog.Embedded(),
		Settings: ctfkit.Settings{Tags: fixture08Policy},
	})
	want := expectedResults(t, filepath.Join(fixtureRoot, "08-missing-tags", "expected", "findings.sarif"))

	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings do not match expected/findings.sarif\n got: %s\nwant: %s", indent(t, got), indent(t, want))
	}
}

func TestFullyTaggedPlanHasNoFindings(t *testing.T) {
	plan := buildPlan(t, `{"aws": {"name": "aws", "expressions": {"default_tags": [{"tags": {"constant_value": {"Owner": "platform"}}}]}}}`,
		// Own tags carry both keys.
		change("aws_sqs_queue.own", "aws_sqs_queue", "create",
			`{"tags": {"Environment": "prod", "Owner": "platform"}}`, `{}`),
		// The provider's own merge, tags_all, carries both keys.
		change("aws_s3_bucket.merged", "aws_s3_bucket", "update",
			`{"tags": null, "tags_all": {"Environment": "prod", "Owner": "platform"}}`, `{}`),
		// Owner comes from provider default_tags, tags_all is not known yet.
		change("module.data.aws_sns_topic.this[0]", "aws_sns_topic", "create",
			`{"tags": {"Environment": "prod"}}`, `{"tags_all": true}`),
		// A resource with no tags attribute is out of scope.
		change("aws_iam_role_policy_attachment.x", "aws_iam_role_policy_attachment", "create",
			`{"role": "r"}`, `{}`),
		// A deleted resource produces no tagging finding.
		change("aws_sqs_queue.gone", "aws_sqs_queue", "delete", `null`, `{}`),
	)

	got := analyze(t, input(plan, fixture08Policy))
	if len(got) != 0 {
		t.Errorf("want zero findings, got %s", indent(t, got))
	}
}

func TestValueRules(t *testing.T) {
	policy := []ctfkit.TagRule{
		{Key: "DataClassification", Required: true, AllowedValues: []string{"internal", "public"}},
		{Key: "CostCenter", Pattern: `^cc-[0-9]{4}$`},
	}
	plan := buildPlan(t, `{}`,
		change("aws_s3_bucket.bad", "aws_s3_bucket", "create",
			`{"tags": {"DataClassification": "secret-value-1", "CostCenter": "secret-value-2"}}`, `{}`),
		change("aws_s3_bucket.good", "aws_s3_bucket", "create",
			`{"tags": {"DataClassification": "internal", "CostCenter": "cc-0042"}}`, `{}`),
		// An optional tag that is absent is not judged.
		change("aws_s3_bucket.optional", "aws_s3_bucket", "create",
			`{"tags": {"DataClassification": "public"}}`, `{}`),
		change("aws_s3_bucket.later", "aws_s3_bucket", "create",
			`{"tags": {"CostCenter": "cc-0001"}}`, `{"tags": {"DataClassification": true}}`),
		// A tags map unknown as a whole cannot be judged either.
		change("aws_s3_bucket.opaque", "aws_s3_bucket", "create",
			`{}`, `{"tags": true}`),
	)

	got := summarize(t, input(plan, policy))
	want := []string{
		"ctf.policy.tagging_unresolved|note|open|aws_s3_bucket.later|" +
			"aws_s3_bucket.later has tags whose values are not known until apply: DataClassification",
		"ctf.policy.tagging_unresolved|note|open|aws_s3_bucket.opaque|" +
			"aws_s3_bucket.opaque has tags whose values are not known until apply: CostCenter, DataClassification",
		"ctf.policy.tagging_value|warning|fail|aws_s3_bucket.bad|" +
			"aws_s3_bucket.bad has tag values the policy does not allow: " +
			"CostCenter (must match ^cc-[0-9]{4}$), DataClassification (must be one of internal, public)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got: %q\nwant: %q", got, want)
	}
	for _, line := range got {
		if strings.Contains(line, "secret-value") {
			t.Errorf("a finding carries a tag value: %s", line)
		}
	}
}

func TestResourceTypesFilter(t *testing.T) {
	policy := []ctfkit.TagRule{
		{Key: "Backup", Required: true, ResourceTypes: []string{"aws_db_instance"}},
		{Key: "Owner", Required: true},
	}
	plan := buildPlan(t, `{}`,
		change("aws_db_instance.main", "aws_db_instance", "create", `{"tags": {}}`, `{}`),
		change("aws_sqs_queue.q", "aws_sqs_queue", "create", `{"tags": {}}`, `{}`),
	)

	got := summarize(t, input(plan, policy))
	want := []string{
		"ctf.policy.tagging|warning|fail|aws_db_instance.main|aws_db_instance.main is missing required tags Backup, Owner",
		"ctf.policy.tagging|warning|fail|aws_sqs_queue.q|aws_sqs_queue.q is missing required tags Owner",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got: %q\nwant: %q", got, want)
	}
}

func TestNoPolicyNoFindings(t *testing.T) {
	plan := buildPlan(t, `{}`, change("aws_sqs_queue.q", "aws_sqs_queue", "create", `{"tags": {}}`, `{}`))
	if got := analyze(t, input(plan, nil)); len(got) != 0 {
		t.Errorf("want zero findings without a tag policy, got %s", indent(t, got))
	}
}

func input(plan *tfjson.Plan, rules []ctfkit.TagRule) ctfkit.AnalyzerInput {
	return ctfkit.AnalyzerInput{
		Stage:    ctfkit.PostPlan,
		PlanJSON: plan,
		Catalog:  catalog.Embedded(),
		Settings: ctfkit.Settings{Tags: rules},
	}
}

// change is one resource_changes entry.
func change(address, typ, action, after, afterUnknown string) string {
	return `{"address": "` + address + `", "mode": "managed", "type": "` + typ + `", "name": "x",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {"actions": ["` + action + `"], "before": null, "after": ` + after +
		`, "after_unknown": ` + afterUnknown + `}}`
}

// buildPlan assembles a plan document. Every resource uses the root "aws"
// provider configuration, which is what Terraform records for a child module
// that inherits its provider.
func buildPlan(t *testing.T, providerConfig string, changes ...string) *tfjson.Plan {
	t.Helper()

	configResources := make([]string, 0, len(changes))
	for _, c := range changes {
		var rc struct {
			Address string `json:"address"`
		}
		if err := json.Unmarshal([]byte(c), &rc); err != nil {
			t.Fatalf("change %s: %v", c, err)
		}
		if !strings.HasPrefix(rc.Address, "module.") {
			configResources = append(configResources,
				`{"address": "`+strings.SplitN(rc.Address, "[", 2)[0]+`", "provider_config_key": "aws"}`)
		}
	}
	doc := `{"format_version": "1.2", "resource_changes": [` + strings.Join(changes, ",") + `],
		"configuration": {"provider_config": ` + providerConfig + `,
		"root_module": {"resources": [` + strings.Join(configResources, ",") + `],
		"module_calls": {"data": {"module": {"resources": [
			{"address": "aws_sns_topic.this", "provider_config_key": "aws"}]}}}}}}`

	var plan tfjson.Plan
	if err := json.Unmarshal([]byte(doc), &plan); err != nil {
		t.Fatalf("plan: %v\n%s", err, doc)
	}
	return &plan
}

// analyze runs the family in registration order, checks each finding the way
// the runner does, and returns the marshaled results.
func analyze(t *testing.T, in ctfkit.AnalyzerInput) []any {
	t.Helper()

	registry := ctfkit.NewRegistry()
	tagging.Register(registry)

	var findings ctfkit.Findings
	for _, a := range registry.ByStage(ctfkit.PostPlan) {
		produced, err := a.Analyze(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: %v", a.ID(), err)
		}
		for _, f := range produced {
			checked, validateErr := f.ValidateFor(a.ID(), ctfkit.PostPlan, in.Catalog)
			if validateErr != nil {
				t.Fatalf("%s: %v", a.ID(), validateErr)
			}
			findings = append(findings, checked)
		}
	}
	ctfkit.SortFindings(findings)

	out := make([]any, 0, len(findings))
	for _, f := range findings {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshaling %s: %v", f.RuleID, err)
		}
		var v any
		if decodeErr := json.Unmarshal(raw, &v); decodeErr != nil {
			t.Fatalf("decoding: %v", decodeErr)
		}
		out = append(out, v)
	}
	return out
}

// summarize reduces each finding to rule|level|kind|subject|message and checks
// the property bag every rule of the family shares.
func summarize(t *testing.T, in ctfkit.AnalyzerInput) []string {
	t.Helper()

	var out []string
	for _, v := range analyze(t, in) {
		r := v.(map[string]any)
		props := r["properties"].(map[string]any)
		if props["ctf.preventive"] != false || len(props["ctf.controlIds"].([]any)) != 0 ||
			len(props["ctf.frameworks"].([]any)) != 0 || props["ctf.stage"] != "post_plan" {
			t.Errorf("unexpected property bag %v", props)
		}
		if _, ok := props["ctf.attributes"]; ok {
			t.Errorf("tagging findings carry no ctf.attributes, got %v", props)
		}
		loc := r["locations"].([]any)[0].(map[string]any)
		subject := loc["logicalLocations"].([]any)[0].(map[string]any)["fullyQualifiedName"]
		out = append(out, strings.Join([]string{
			r["ruleId"].(string), r["level"].(string), r["kind"].(string),
			subject.(string), r["message"].(map[string]any)["text"].(string),
		}, "|"))
	}
	return out
}

func expectedResults(t *testing.T, path string) []any {
	t.Helper()

	raw, err := os.ReadFile(path) //nolint:gosec // a committed fixture path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc struct {
		Runs []struct {
			Results []map[string]any `json:"results"`
		} `json:"runs"`
	}
	if parseErr := json.Unmarshal(raw, &doc); parseErr != nil {
		t.Fatalf("parsing %s: %v", path, parseErr)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("%s has %d runs, want 1", path, len(doc.Runs))
	}
	out := make([]any, 0, len(doc.Runs[0].Results))
	for _, r := range doc.Runs[0].Results {
		// Another analyzer's result in the same document is not this one's.
		if id, _ := r["ruleId"].(string); !strings.HasPrefix(id, "ctf.policy.tagging") {
			continue
		}
		delete(r["properties"].(map[string]any), ctfkit.PropertyEvidence)
		// partialFingerprints is written by the SARIF renderer, not the analyzer.
		delete(r, "partialFingerprints")
		out = append(out, any(r))
	}
	return out
}

func indent(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("indenting: %v", err)
	}
	return raw
}
