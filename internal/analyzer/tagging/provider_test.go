package tagging_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/analyzer/tagging"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// TestPackTagAttributes records that the tag attributes come from the rule
// pack of each resource's provider: the google pack keeps tags in labels,
// merges the provider's default_labels and reads effective_labels, and a
// google resource's tags attribute is not its tags.
func TestPackTagAttributes(t *testing.T) {
	doc := `{"format_version": "1.2", "resource_changes": [
		{"address": "google_storage_bucket.labeled", "mode": "managed", "type": "google_storage_bucket", "name": "labeled",
		 "provider_name": "registry.terraform.io/hashicorp/google",
		 "change": {"actions": ["create"], "before": null, "after": {"labels": {"owner": "data"}}, "after_unknown": {"effective_labels": true}}},
		{"address": "google_storage_bucket.unlabeled", "mode": "managed", "type": "google_storage_bucket", "name": "unlabeled",
		 "provider_name": "registry.terraform.io/hashicorp/google",
		 "change": {"actions": ["create"], "before": null, "after": {"labels": {}}, "after_unknown": {}}},
		{"address": "google_compute_instance.tagged", "mode": "managed", "type": "google_compute_instance", "name": "tagged",
		 "provider_name": "registry.terraform.io/hashicorp/google",
		 "change": {"actions": ["create"], "before": null, "after": {"tags": ["web"]}, "after_unknown": {}}}],
		"configuration": {
		 "provider_config": {"google": {"name": "google", "full_name": "registry.terraform.io/hashicorp/google",
		   "expressions": {"default_labels": {"constant_value": {"team": "platform"}}}}},
		 "root_module": {"resources": [
		   {"address": "google_storage_bucket.labeled", "provider_config_key": "google"},
		   {"address": "google_storage_bucket.unlabeled", "provider_config_key": "google"},
		   {"address": "google_compute_instance.tagged", "provider_config_key": "google"}]}}}`
	var plan tfjson.Plan
	if err := json.Unmarshal([]byte(doc), &plan); err != nil {
		t.Fatal(err)
	}
	in := input(&plan, []ctfkit.TagRule{{Key: "owner", Required: true}, {Key: "team", Required: true}})

	registry := ctfkit.NewRegistry()
	tagging.Register(registry)
	var got []string
	for _, a := range registry.ByStage(ctfkit.PostPlan) {
		findings, err := a.Analyze(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			got = append(got, f.Message.Text)
		}
	}
	want := []string{"google_storage_bucket.unlabeled is missing required tags owner"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings %q, want %q", got, want)
	}
}
