# Compliance evidence pack

**Unsigned. Not independently attested.** This pack records what ctfkit by compliance.tf read from the module manifests installed by `terraform init`. compliance.tf does not sign, attest or verify it.

| | |
|---|---|
| Release | input |
| Commit | `0000000000000000000000000000000000000000` |
| Generated | 2026-09-20T00:00:00Z by ctfkit 1.0.0 |
| Control catalog | 2026.11.1, the catalog embedded in ctfkit, which holds the CIS v6.0 controls only; `ctfkit catalog pull` fetches the full catalog |
| Frameworks | SOC 2 |

## 1 Summary

Counts are taken from the module manifests and the control catalog named above.

| | |
|---|---|
| Modules in scope | 2, 1 with a compliance.tf manifest |
| Controls enforced | 10 |
| Controls delegated to another scope | 2 |
| With a SOC 2 clause | 12 of 12 |
| Framework gaps with a recorded reason | 0 of 0 |
| Catalog controls for these resource types not enforced here | 5 |
| Control enforcement tests | No tests supplied |
| Findings at error level | None |

## 2 Scope

The modules `terraform init` installed for this release. A module without a compliance.tf manifest is listed in the report findings.

| Module | Source | Version | Manifest sha256 |
|---|---|---|---|
| `naming` | `./modules/naming` | Not set | None, declares no resources |
| `s3_bucket` | `bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws` | 5.16.1-1e4b692ae5e0a847 | `561d28c33b3778847004ceec25f125c2a3dbbfccbd947742dbd050dd001a5c39` |

## 3 What this pack shows, and what it does not

It shows:

- Which compliance controls each installed compliance.tf module enforced when it was built, as the module manifest records them.
- The framework clauses each control is mapped to, with supporting clauses marked as partial or indirect evidence.
- Catalog controls for the same resource types that these modules do not enforce, and the layer that owns each one.
- The results of the enforcement tests supplied with this release, when tests were supplied.

It does not show:

- The state of resources running in AWS. Check that with AWS Config or Audit Manager.
- Organizational or process controls.
- Operation after deployment.
- Computer system validation: no CSV, IQ, OQ or PQ activities, e-signature logic or audit-trail business logic.

## 4 Control-to-clause mapping

Every control each module manifest lists, with the clauses it gives evidence for. A clause marked (supporting) is partial or indirect evidence. None means no clause in that framework; section 5 gives the reason. Clause titles are in annex A.

### Module `s3_bucket`

| Control | Status | SOC 2 |
|---|---|---|
| `s3_bucket_cross_region_replication_enabled` S3 buckets should have cross-region replication enabled | enforced | A1.2 |
| `s3_bucket_default_encryption_enabled_kms` S3 buckets should have default encryption enabled using KMS | enforced | PI1.4, PI1.5 |
| `s3_bucket_event_notifications_enabled` S3 buckets should have event notifications enabled | delegated | CC7.3 |
| `s3_bucket_logging_enabled` S3 buckets should have logging enabled | enforced | A1.2, CC7.2, CC7.3 |
| `s3_bucket_not_accessible_to_all_authenticated_user` S3 buckets should not be accessible to all authenticated users | enforced | CC6.1 |
| `s3_bucket_object_lock_enabled` S3 buckets should have object lock enabled | enforced | C1.1, PI1.5 |
| `s3_bucket_policy_restrict_public_access` S3 buckets should have policies that prohibit public access | enforced | CC6.1, CC6.6 |
| `s3_bucket_restrict_public_read_access` S3 buckets should prohibit public read access | enforced | CC6.1, CC6.6 |
| `s3_bucket_restrict_public_write_access` S3 buckets should prohibit public write access | enforced | CC6.1, CC6.6 |
| `s3_bucket_versioning_and_lifecycle_policy_enabled` S3 buckets with versioning enabled should have lifecycle policies configured | enforced | C1.1 |
| `s3_bucket_versioning_enabled` S3 buckets should have versioning enabled | enforced | A1.2, C1.2, CC7.4, PI1.5 |
| `s3_public_access_block_account` S3 public access should be blocked at account level | delegated | CC6.6 |

## 5 Controls with no clause in a framework

A control can have no matching clause in a framework. The reason comes from the control catalog.

None.

## 6 Catalog controls not enforced by these modules

Controls the catalog lists for the resource types of these modules that no module manifest lists, and the layer that owns each one. The catalog is the embedded one, which holds the CIS v6.0 controls only, so this list is not complete.

| Control | Resource types | Layer | Reason |
|---|---|---|---|
| `cloudtrail_s3_logging_enabled` CloudTrail S3 buckets should have access logging enabled | `aws_cloudtrail`, `aws_s3_bucket`, `aws_s3_bucket_logging` | Not set | Not set |
| `cloudtrail_s3_object_read_events_audit_enabled` S3 buckets should have object-level read event logging enabled in CloudTrail | `aws_s3_bucket` | Not set | Not set |
| `cloudtrail_s3_object_write_events_audit_enabled` S3 buckets should have object-level write event logging enabled in CloudTrail | `aws_s3_bucket` | Not set | Not set |
| `s3_bucket_enforces_ssl` S3 buckets should enforce SSL | `aws_s3_bucket` | Not set | Not set |
| `s3_public_access_block_bucket_account` S3 public access should be blocked at account and bucket levels | `aws_s3_bucket` | Not set | Not set |

## 7 Enforcement tests

No tests supplied. Pass `--tests-json` to `ctfkit report` to include the results of `tofu test -json` or `terraform test -json`.

## Annex A Clause register

Every clause cited in this pack, as the module manifests name it, and the clauses the catalog records no control applies to.

### SOC 2

| Clause | Title | Controls |
|---|---|---|
| A1.2 | The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data back-up processes, and recovery infrastructure to meet its objectives | `s3_bucket_cross_region_replication_enabled`, `s3_bucket_logging_enabled`, `s3_bucket_versioning_enabled` |
| C1.1 | The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality | `s3_bucket_object_lock_enabled`, `s3_bucket_versioning_and_lifecycle_policy_enabled` |
| C1.2 | The entity disposes of confidential information to meet the entity's objectives related to confidentiality | `s3_bucket_versioning_enabled` |
| CC6.1 | The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives | `s3_bucket_not_accessible_to_all_authenticated_user`, `s3_bucket_policy_restrict_public_access`, `s3_bucket_restrict_public_read_access`, `s3_bucket_restrict_public_write_access` |
| CC6.6 | The entity implements logical access security measures to protect against threats from sources outside its system boundaries. | `s3_bucket_policy_restrict_public_access`, `s3_bucket_restrict_public_read_access`, `s3_bucket_restrict_public_write_access`, `s3_public_access_block_account` |
| CC7.2 | The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events. | `s3_bucket_logging_enabled` |
| CC7.3 | The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives (security incidents) and, if so, takes actions to prevent or address such failures | `s3_bucket_event_notifications_enabled`, `s3_bucket_logging_enabled` |
| CC7.4 | The entity responds to identified security incidents by executing a defined incident response program to understand, contain, remediate, and communicate security incidents, as appropriate | `s3_bucket_versioning_enabled` |
| PI1.4 | System outputs are complete, accurate, distributed only to intended parties, and retained to meet the entity's processing integrity commitments and system requirements | `s3_bucket_default_encryption_enabled_kms` |
| PI1.5 | Stored data is maintained complete, accurate, and protected from unauthorized modification to meet the entity's processing integrity commitments and system requirements | `s3_bucket_default_encryption_enabled_kms`, `s3_bucket_object_lock_enabled`, `s3_bucket_versioning_enabled` |

Clauses with no applicable control: None.

---

Unsigned. Not independently attested.
