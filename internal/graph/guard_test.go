package graph_test

import (
	"encoding/json"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/graph"
)

// rc is one managed change in a guard test plan; nil before or after is null.
type rc struct {
	addr, typ, deposed string
	actions            []string
	before, after      map[string]any
}

func guardPlan(t *testing.T, provider string, changes ...rc) *tfjson.Plan {
	t.Helper()
	var rcs, res []map[string]any
	for _, c := range changes {
		m := map[string]any{"address": c.addr, "mode": "managed", "type": c.typ, "name": strings.SplitN(c.addr, ".", 2)[1],
			"provider_name": provider, "change": map[string]any{"actions": c.actions, "before": c.before, "after": c.after, "after_unknown": map[string]any{}}}
		if c.deposed != "" {
			m["deposed"] = c.deposed
		}
		rcs = append(rcs, m)
		res = append(res, map[string]any{"address": c.addr, "mode": "managed", "type": c.typ, "name": m["name"], "provider_config_key": "aws"})
	}
	raw, err := json.Marshal(map[string]any{"format_version": "1.2", "resource_changes": rcs, "configuration": map[string]any{
		"provider_config": map[string]any{"aws": map[string]any{"name": "aws", "full_name": provider}},
		"root_module":     map[string]any{"resources": res}}})
	if err != nil {
		t.Fatal(err)
	}
	var p tfjson.Plan
	if err = json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

var (
	bucket = map[string]any{"id": "bobthecorp-logs", "bucket": "bobthecorp-logs", "region": "eu-west-1"}
	pab    = map[string]any{"id": "bobthecorp-logs", "bucket": "bobthecorp-logs", "region": "eu-west-1"}
	pabARN = map[string]any{"id": "x", "bucket": "arn:aws:s3:::bobthecorp-logs", "region": "eu-west-1"}
)

func kept(t *testing.T) []graph.Control {
	t.Helper()
	var c []graph.Control
	err := json.Unmarshal([]byte(`[{"id":"pab_kept","version":"1.0.0","kind":"graph","resource_type":"aws_s3_bucket","action":"deny",
		"graph":{"rule":"companion_absent_forbidden","companion_type":"aws_s3_bucket_public_access_block","link_attr":"bucket","target_attrs":["id","bucket"]}}]`), &c)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestEvaluateGuards: a deletion guard is decided on the deleted companion's
// prior values against every target the plan keeps, for both the
// hashicorp/aws and the compliance.tf provider names.
func TestEvaluateGuards(t *testing.T) {
	del, noop, repl := []string{"delete"}, []string{"no-op"}, []string{"delete", "create"}
	for name, tc := range map[string]struct {
		changes []rc
		want    string
	}{
		"companion-deleted-target-kept": {[]rc{{"aws_s3_bucket.a", "aws_s3_bucket", "", noop, bucket, bucket},
			{"aws_s3_bucket_public_access_block.a", "aws_s3_bucket_public_access_block", "", del, pab, nil}}, "fail"},
		"both-deleted": {[]rc{{"aws_s3_bucket.a", "aws_s3_bucket", "", del, bucket, nil},
			{"aws_s3_bucket_public_access_block.a", "aws_s3_bucket_public_access_block", "", del, pab, nil}}, "pass"},
		"companion-replaced": {[]rc{{"aws_s3_bucket.a", "aws_s3_bucket", "", noop, bucket, bucket},
			{"aws_s3_bucket_public_access_block.a", "aws_s3_bucket_public_access_block", "", repl, pab, pab}}, "pass"},
		"another-companion-kept": {[]rc{{"aws_s3_bucket.a", "aws_s3_bucket", "", noop, bucket, bucket},
			{"aws_s3_bucket_public_access_block.a", "aws_s3_bucket_public_access_block", "", del, pab, nil},
			{"aws_s3_bucket_public_access_block.b", "aws_s3_bucket_public_access_block", "", noop, pab, pab}}, "pass"},
		"deposed-companion": {[]rc{{"aws_s3_bucket.a", "aws_s3_bucket", "", noop, bucket, bucket},
			{"aws_s3_bucket_public_access_block.a", "aws_s3_bucket_public_access_block", "00000001", del, pab, nil}}, "fail"},
		"arn-alias": {[]rc{{"aws_s3_bucket.a", "aws_s3_bucket", "", noop, bucket, bucket},
			{"aws_s3_bucket_public_access_block.a", "aws_s3_bucket_public_access_block", "", del, pabARN, nil}}, "not_evaluable identity_alias"},
	} {
		for _, provider := range []string{"registry.terraform.io/hashicorp/aws", "registry.compliance.tf/compliancetf/aws"} {
			got, err := graph.EvaluateGuards(guardPlan(t, provider, tc.changes...), nil, kept(t))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Address != "aws_s3_bucket_public_access_block.a" || strings.TrimSpace(got[0].Result+" "+got[0].Reason) != tc.want {
				t.Errorf("%s (%s): %+v, want one %s decision on the deleted companion", name, provider, got, tc.want)
			}
		}
	}
}

func TestEvaluateGuardsCompanionExpr(t *testing.T) {
	c := kept(t)
	expr := "true"
	c[0].Graph.CompanionExpr = &expr
	if _, err := graph.EvaluateGuards(guardPlan(t, "registry.terraform.io/hashicorp/aws"), nil, c); err == nil {
		t.Fatal("companion_expr guard: want an error")
	}
}
