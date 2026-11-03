package sensitivechange_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// rc is one resource_changes entry. before, after and unknown are JSON.
type rc struct {
	address, actions, before, after, unknown, replacePaths string
}

func plan(t *testing.T, changes ...rc) *tfjson.Plan {
	t.Helper()
	parts := make([]string, 0, len(changes))
	for _, c := range changes {
		typ := strings.Split(strings.TrimPrefix(c.address, "module.m."), ".")[0]
		unknown, replacePaths := c.unknown, c.replacePaths
		if unknown == "" {
			unknown = "{}"
		}
		if replacePaths == "" {
			replacePaths = "null"
		}
		parts = append(parts, `{"address": "`+c.address+`", "mode": "managed", "type": "`+typ+`", "name": "x",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {"actions": `+c.actions+`, "before": `+c.before+`, "after": `+c.after+`,
			"after_unknown": `+unknown+`, "replace_paths": `+replacePaths+`}}`)
	}
	var p tfjson.Plan
	doc := `{"format_version": "1.2", "resource_changes": [` + strings.Join(parts, ",") + `]}`
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatalf("plan: %v\n%s", err, doc)
	}
	return &p
}

// summarize reduces each finding to
// rule suffix|level|address|attributes|control ids|message.
func summarize(t *testing.T, changes ...rc) []string {
	t.Helper()
	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, PlanJSON: plan(t, changes...), Catalog: fixtureCatalog(t)}
	findings := run(t, in)
	ctfkit.SortFindings(findings)
	out := []string{}
	for _, f := range findings {
		controls := make([]string, 0, len(f.Props.ControlIDs))
		for _, id := range f.Props.ControlIDs {
			controls = append(controls, string(id))
		}
		if f.Props.Preventive != (len(controls) > 0) {
			t.Errorf("%s: ctf.preventive %v with control ids %v", f.Message.Text, f.Props.Preventive, controls)
		}
		out = append(out, strings.Join([]string{
			strings.TrimPrefix(f.RuleID, rulePrefix+"_"), f.Level, f.Locations[0].LogicalLocations[0].FullyQualifiedName,
			strings.Join(f.Props.Attributes, ","), strings.Join(controls, ","), f.Message.Text,
		}, "|"))
	}
	return out
}

const (
	openPolicy        = `"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"*\"]},\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}"`
	conditionalPolicy = `"{\"Statement\":{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"true\"}}}}"`
	adminPolicy       = `"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"*\"],\"Resource\":[\"*\"]}]}"`
	adminWithCond     = `"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":\"10.0.0.0/8\"}}}]}"`
)

func TestRules(t *testing.T) {
	tests := []struct {
		name    string
		changes []rc
		want    []string
	}{
		{
			name: "class 1 public exposure",
			changes: []rc{
				{"aws_s3_bucket_public_access_block.gone", `["delete"]`, `{"block_public_acls": true}`, `null`, ``, ``},
				{"aws_s3_bucket_acl.site", `["update"]`, `{"acl": "private"}`, `{"acl": "public-read"}`, ``, ``},
				{"aws_sqs_queue_policy.open", `["create"]`, `null`, `{"policy": ` + openPolicy + `}`, ``, ``},
				{"aws_sns_topic_policy.conditional", `["create"]`, `null`, `{"policy": ` + conditionalPolicy + `}`, ``, ``},
				{"aws_iam_role.trust", `["create"]`, `null`, `{"assume_role_policy": ` + openPolicy + `, "inline_policy": []}`, ``, ``},
				{"aws_lambda_permission.any", `["create"]`, `null`, `{"principal": "*", "source_arn": null}`, ``, ``},
				{"aws_lambda_permission.scoped", `["create"]`, `null`, `{"principal": "*", "source_arn": "arn:aws:s3:::bobthecorp"}`, ``, ``},
				{"aws_db_instance.db", `["update"]`, `{"publicly_accessible": false}`, `{"publicly_accessible": true}`, ``, ``},
				{"aws_instance.web", `["create"]`, `null`, `{"associate_public_ip_address": true}`, ``, ``},
				{"aws_security_group_rule.ssh", `["create"]`, `null`, `{"type": "ingress", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}`, ``, ``},
				{"aws_security_group_rule.egress", `["create"]`, `null`, `{"type": "egress", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}`, ``, ``},
				{"aws_vpc_security_group_ingress_rule.https", `["create"]`, `null`, `{"from_port": 443, "to_port": 443, "cidr_ipv6": "::/0"}`, ``, ``},
				{"aws_security_group.mixed", `["create"]`, `null`, `{"ingress": [{"from_port": 80, "to_port": 80, "cidr_blocks": ["0.0.0.0/0"]}, {"from_port": 5432, "to_port": 5432, "cidr_blocks": ["10.0.0.0/8"]}]}`, ``, ``},
			},
			want: []string{
				"public_exposure|error|aws_db_instance.db|publicly_accessible|rds_db_instance_prohibit_public_access|aws_db_instance.db turns publicly_accessible from false to true",
				"public_exposure|error|aws_iam_role.trust|assume_role_policy||aws_iam_role.trust allows any principal with no Condition in assume_role_policy",
				"public_exposure|warning|aws_instance.web|associate_public_ip_address|ec2_instance_not_publicly_accessible|aws_instance.web turns associate_public_ip_address from false to true",
				"public_exposure|error|aws_lambda_permission.any|principal||aws_lambda_permission.any lets any principal invoke it with no source_arn, through principal",
				"public_exposure|error|aws_s3_bucket_acl.site|acl||aws_s3_bucket_acl.site sets a public canned ACL in acl",
				"public_exposure|error|aws_s3_bucket_public_access_block.gone|||aws_s3_bucket_public_access_block.gone is deleted, which lifts the public access block on its bucket",
				"public_exposure|note|aws_security_group.mixed|ingress||aws_security_group.mixed opens ingress to any address in ingress",
				"public_exposure|error|aws_security_group_rule.ssh|cidr_blocks||aws_security_group_rule.ssh opens ingress to any address in cidr_blocks",
				"public_exposure|error|aws_sqs_queue_policy.open|policy||aws_sqs_queue_policy.open allows any principal with no Condition in policy",
				"public_exposure|note|aws_vpc_security_group_ingress_rule.https|cidr_ipv6||aws_vpc_security_group_ingress_rule.https opens ingress to any address in cidr_ipv6",
			},
		},
		{
			name: "class 2 wildcard IAM",
			changes: []rc{
				{"aws_iam_role_policy.admin", `["update"]`, `{"policy": ""}`, `{"policy": ` + adminPolicy + `}`, ``, ``},
				{"aws_iam_user_policy.conditional", `["create"]`, `null`, `{"policy": ` + adminWithCond + `}`, ``, ``},
				{"aws_iam_role.inline", `["create"]`, `null`, `{"assume_role_policy": "", "inline_policy": [{"name": "a", "policy": ` + adminPolicy + `}]}`, ``, ``},
				{"aws_iam_group_policy.later", `["create"]`, `null`, `{}`, `{"policy": true}`, ``},
			},
			want: []string{
				"wildcard_iam|error|aws_iam_role.inline|inline_policy||aws_iam_role.inline allows every action on every resource with no Condition in inline_policy",
				"wildcard_iam|error|aws_iam_role_policy.admin|policy||aws_iam_role_policy.admin allows every action on every resource with no Condition in policy",
			},
		},
		{
			name: "class 3 audit-logging removal",
			changes: []rc{
				{"aws_cloudtrail.main", `["update"]`, `{"enable_logging": true, "is_multi_region_trail": true}`, `{"enable_logging": false, "is_multi_region_trail": false}`, ``, ``},
				{"aws_flow_log.vpc", `["delete"]`, `{"traffic_type": "ALL"}`, `null`, ``, ``},
				{"aws_guardduty_detector.main", `["update"]`, `{"enable": true}`, `{"enable": false}`, ``, ``},
				{"aws_rds_cluster.db", `["update"]`, `{"enabled_cloudwatch_logs_exports": ["audit", "error"]}`, `{"enabled_cloudwatch_logs_exports": ["error"]}`, ``, ``},
				{"aws_rds_cluster.same", `["update"]`, `{"enabled_cloudwatch_logs_exports": ["audit"]}`, `{"enabled_cloudwatch_logs_exports": ["audit"]}`, ``, ``},
				{"aws_cloudwatch_log_group.short", `["update"]`, `{"retention_in_days": 365}`, `{"retention_in_days": 30}`, ``, ``},
				{"aws_cloudwatch_log_group.forever", `["update"]`, `{"retention_in_days": 0}`, `{"retention_in_days": 30}`, ``, ``},
				{"aws_cloudwatch_log_group.never", `["update"]`, `{"retention_in_days": 30}`, `{"retention_in_days": 0}`, ``, ``},
				{"aws_eks_cluster.later", `["update"]`, `{"enabled_cluster_log_types": ["api", "audit"]}`, `{"enabled_cluster_log_types": ["api", null]}`, `{"enabled_cluster_log_types": [false, true]}`, ``},
			},
			want: []string{
				// One finding: neither attribute maps to a control in this catalog.
				"audit_log_removal|error|aws_cloudtrail.main|enable_logging|cloudtrail_trail_enabled|aws_cloudtrail.main turns enable_logging from true to false",
				"audit_log_removal|error|aws_cloudtrail.main|is_multi_region_trail||aws_cloudtrail.main turns is_multi_region_trail from true to false",
				"audit_log_removal|warning|aws_cloudwatch_log_group.forever|retention_in_days|cloudwatch_log_group_retention_period_365|aws_cloudwatch_log_group.forever shortens retention_in_days",
				"audit_log_removal|warning|aws_cloudwatch_log_group.short|retention_in_days|cloudwatch_log_group_retention_period_365|aws_cloudwatch_log_group.short shortens retention_in_days",
				"audit_log_removal|error|aws_flow_log.vpc|||aws_flow_log.vpc is deleted, which stops the audit trail it records",
				"audit_log_removal|error|aws_guardduty_detector.main|enable||aws_guardduty_detector.main turns enable from true to false",
				"audit_log_removal|error|aws_rds_cluster.db|enabled_cloudwatch_logs_exports||aws_rds_cluster.db narrows enabled_cloudwatch_logs_exports to a strict subset of its prior value",
			},
		},
		{
			name: "class 4 encryption disablement",
			changes: []rc{
				{"aws_ebs_volume.data", `["update"]`, `{"encrypted": true}`, `{"encrypted": null}`, ``, ``},
				{"aws_sqs_queue.jobs", `["update"]`, `{"kms_master_key_id": "alias/bobthecorp"}`, `{"kms_master_key_id": ""}`, ``, ``},
				{"aws_sns_topic.later", `["update"]`, `{"kms_master_key_id": "alias/bobthecorp"}`, `{"kms_master_key_id": null}`, `{"kms_master_key_id": true}`, ``},
				{"aws_kms_key.main", `["update"]`, `{"enable_key_rotation": true}`, `{"enable_key_rotation": false}`, ``, ``},
				{"aws_eks_cluster.main", `["update"]`, `{"encryption_config": [{"resources": ["secrets"]}]}`, `{"encryption_config": []}`, ``, ``},
				{"aws_dynamodb_table.orders", `["update"]`, `{"server_side_encryption": [{"enabled": true}]}`, `{"server_side_encryption": [{"enabled": false}]}`, ``, ``},
				{"aws_db_instance.kept", `["update"]`, `{"storage_encrypted": true}`, `{"storage_encrypted": true}`, ``, ``},
			},
			want: []string{
				"encryption_disablement|error|aws_dynamodb_table.orders|server_side_encryption||aws_dynamodb_table.orders removes server_side_encryption",
				"encryption_disablement|error|aws_ebs_volume.data|encrypted|ebs_volume_encryption_at_rest_enabled|aws_ebs_volume.data removes encrypted",
				"encryption_disablement|error|aws_eks_cluster.main|encryption_config|eks_cluster_secrets_encrypted|aws_eks_cluster.main removes encryption_config",
				"encryption_disablement|error|aws_kms_key.main|enable_key_rotation|kms_cmk_rotation_enabled|aws_kms_key.main turns enable_key_rotation from true to false",
				"encryption_disablement|error|aws_sqs_queue.jobs|kms_master_key_id|sqs_queue_encrypted_with_kms_cmk|aws_sqs_queue.jobs removes kms_master_key_id",
			},
		},
		{
			name: "class 5 destructive stateful",
			changes: []rc{
				{"aws_s3_bucket.logs", `["delete"]`, `{"bucket": "bobthecorp-logs"}`, `null`, ``, ``},
				{"module.m.aws_rds_cluster.db", `["create", "delete"]`, `{"engine": "aurora"}`, `{"engine": "aurora-postgresql"}`, ``, `[["engine"]]`},
				{"aws_db_instance.snap", `["update"]`, `{"skip_final_snapshot": false}`, `{"skip_final_snapshot": true}`, ``, ``},
				{"aws_db_instance.replaced", `["delete", "create"]`, `{"deletion_protection": true}`, `{"deletion_protection": false}`, ``, `[["identifier"]]`},
				{"aws_sqs_queue.gone", `["delete"]`, `{"name": "q"}`, `null`, ``, ``},
			},
			want: []string{
				"destructive_stateful|error|aws_db_instance.replaced|identifier||aws_db_instance.replaced is replaced, which deletes the existing instance before the new one is created",
				"destructive_stateful|warning|aws_db_instance.snap|skip_final_snapshot||aws_db_instance.snap turns skip_final_snapshot from false to true",
				"destructive_stateful|error|aws_s3_bucket.logs|||aws_s3_bucket.logs is deleted, which destroys the bucket and the data it holds",
				"destructive_stateful|error|module.m.aws_rds_cluster.db|engine||module.m.aws_rds_cluster.db is replaced, which deletes the existing cluster after the new one is created",
			},
		},
		{
			name: "outside the five classes",
			changes: []rc{
				// A rename through a moved block is a no-op with a previous address.
				{"aws_db_instance.renamed", `["no-op"]`, `{"publicly_accessible": true}`, `{"publicly_accessible": true}`, ``, ``},
				{"aws_s3_bucket.read", `["read"]`, `null`, `{"bucket": "b"}`, ``, ``},
				{"aws_sqs_queue.q", `["update"]`, `{"visibility_timeout_seconds": 30}`, `{"visibility_timeout_seconds": 60}`, ``, ``},
				{"aws_db_instance.unknown", `["update"]`, `{"publicly_accessible": false}`, `{}`, `{"publicly_accessible": true}`, ``},
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summarize(t, tt.changes...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findings\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// TestNoValuesInFindings plants a secret in every value the rules read and
// checks it reaches no finding.
func TestNoValuesInFindings(t *testing.T) {
	const secret = "CANARY-unit-4f7a"
	policy := `"{\"Statement\":[{\"Sid\":\"` + secret + `\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"`
	changes := []rc{
		{"aws_s3_bucket_policy.p", `["create"]`, `null`, `{"policy": ` + policy + `}`, ``, ``},
		{"aws_iam_policy.p", `["create"]`, `null`, `{"policy": ` + policy + `}`, ``, ``},
		{"aws_sqs_queue.q", `["update"]`, `{"kms_master_key_id": "` + secret + `"}`, `{"kms_master_key_id": ""}`, ``, ``},
		{"aws_dynamodb_table.t", `["delete", "create"]`, `{"hash_key": "` + secret + `"}`, `{"hash_key": "id"}`, ``, `[["hash_key"]]`},
	}
	got := summarize(t, changes...)
	if len(got) != 4 {
		t.Fatalf("got %d findings, want 4: %q", len(got), got)
	}
	in := ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, PlanJSON: plan(t, changes...), Catalog: fixtureCatalog(t)}
	for _, f := range run(t, in) {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), secret) {
			t.Errorf("finding carries a value: %s", raw)
		}
	}
}

// TestV6AttributeRules records the rules that read the v6 attribute where the
// original rule named one v6 does not have: each fires on the
// real attribute, and the near misses beside it do not.
func TestV6AttributeRules(t *testing.T) {
	got := summarize(t,
		rc{"aws_opensearch_domain_policy.open", `["create"]`, `null`, `{"access_policies": ` + openPolicy + `}`, ``, ``},
		rc{"aws_opensearch_domain_policy.conditional", `["create"]`, `null`, `{"access_policies": ` + conditionalPolicy + `}`, ``, ``},
		rc{"aws_rds_cluster_instance.public", `["update"]`, `{"publicly_accessible": false}`, `{"publicly_accessible": true}`, ``, ``},
		rc{"aws_rds_cluster_instance.private", `["update"]`, `{"publicly_accessible": false}`, `{"publicly_accessible": false}`, ``, ``},
		rc{"aws_dynamodb_table.unprotected", `["update"]`, `{"deletion_protection_enabled": true}`, `{"deletion_protection_enabled": false}`, ``, ``},
		rc{"aws_dynamodb_table.protected", `["update"]`, `{"deletion_protection_enabled": true}`, `{"deletion_protection_enabled": true}`, ``, ``},
		rc{"aws_redshift_cluster.off", `["update"]`, `{"encrypted": "true"}`, `{"encrypted": "false"}`, ``, ``},
		rc{"aws_redshift_cluster.gone", `["update"]`, `{"encrypted": "true"}`, `{"encrypted": null}`, ``, ``},
		rc{"aws_redshift_cluster.kept", `["update"]`, `{"encrypted": "true"}`, `{"encrypted": "true"}`, ``, ``},
		rc{"aws_redshift_cluster.later", `["update"]`, `{"encrypted": "true"}`, `{}`, `{"encrypted": true}`, ``},
		rc{"aws_redshift_cluster.bool", `["update"]`, `{"encrypted": true}`, `{"encrypted": false}`, ``, ``},
	)
	want := []string{
		"destructive_stateful|warning|aws_dynamodb_table.unprotected|deletion_protection_enabled|dynamodb_table_deletion_protection_enabled|aws_dynamodb_table.unprotected turns deletion_protection_enabled from true to false",
		// The v5 bool form, judged by aws/v6 when the lock file pins 5.x.
		"encryption_disablement|error|aws_redshift_cluster.bool|encrypted||aws_redshift_cluster.bool turns encrypted from true to false",
		"encryption_disablement|error|aws_redshift_cluster.gone|encrypted||aws_redshift_cluster.gone removes encrypted",
		"encryption_disablement|error|aws_redshift_cluster.off|encrypted||aws_redshift_cluster.off turns encrypted from true to false",
		"public_exposure|error|aws_opensearch_domain_policy.open|access_policies||aws_opensearch_domain_policy.open allows any principal with no Condition in access_policies",
		"public_exposure|error|aws_rds_cluster_instance.public|publicly_accessible||aws_rds_cluster_instance.public turns publicly_accessible from false to true",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got: %q\nwant: %q", got, want)
	}
}
