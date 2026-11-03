package sensitivechange_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// TestSecondProviderPack runs the google proof pack: its rules fire for
// resources of that provider with no Go of their own, and a resource is
// judged by its own provider's pack only.
//
// The pack has no firewall rule. Telling an open allow rule from a deny rule
// or a disabled one needs conditions the generic predicates do not express,
// and reporting a deny-all-from-anywhere rule, a standard hardening, as open
// ingress would fail the scans of exactly the configurations that got it
// right. The deny, disabled and allow cases below pin that no firewall
// finding comes back unnoticed.
func TestSecondProviderPack(t *testing.T) {
	const google, aws = "registry.terraform.io/hashicorp/google", "registry.terraform.io/hashicorp/aws"
	change := func(address, provider, actions, before, after string) string {
		typ := strings.Split(address, ".")[0]
		return `{"address": "` + address + `", "mode": "managed", "type": "` + typ + `", "name": "x",
			"provider_name": "` + provider + `", "change": {"actions": ` + actions + `, "before": ` + before +
			`, "after": ` + after + `, "after_unknown": {}}}`
	}
	doc := `{"format_version": "1.2", "resource_changes": [` + strings.Join([]string{
		change("google_compute_firewall.deny_all", google, `["create"]`, `null`,
			`{"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "deny": [{"protocol": "all"}], "allow": [], "disabled": false}`),
		change("google_compute_firewall.disabled", google, `["create"]`, `null`,
			`{"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["22"]}], "disabled": true}`),
		change("google_compute_firewall.allow_ssh", google, `["create"]`, `null`,
			`{"direction": "INGRESS", "source_ranges": ["0.0.0.0/0", "::/0"], "allow": [{"protocol": "tcp", "ports": ["22"]}], "disabled": false}`),
		change("google_sql_database_instance.db", google, `["update"]`, `{"deletion_protection": true}`, `{"deletion_protection": false}`),
		change("google_storage_bucket.logs", google, `["delete"]`, `{"name": "bobthecorp-logs"}`, `null`),
		// The aws pack has no rule for a google type.
		change("google_storage_bucket.misfiled", aws, `["delete"]`, `{"name": "bobthecorp-misfiled"}`, `null`),
	}, ",") + `]}`
	var plan tfjson.Plan
	if err := json.Unmarshal([]byte(doc), &plan); err != nil {
		t.Fatal(err)
	}

	findings := run(t, ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, PlanJSON: &plan, Catalog: fixtureCatalog(t)})
	ctfkit.SortFindings(findings)
	got := []string{}
	for _, f := range findings {
		got = append(got, strings.Join([]string{strings.TrimPrefix(f.RuleID, rulePrefix+"_"), f.Level,
			strings.Join(f.Props.Attributes, ","), f.Message.Text}, "|"))
	}
	want := []string{
		"destructive_stateful|warning|deletion_protection|google_sql_database_instance.db turns deletion_protection from true to false",
		"destructive_stateful|error||google_storage_bucket.logs is deleted, which destroys the bucket and the data it holds",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got: %q\nwant: %q", got, want)
	}
}
