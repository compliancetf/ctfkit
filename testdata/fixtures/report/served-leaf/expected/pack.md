# Compliance evidence pack

**Unsigned. Not independently attested.** This pack records what ctfkit by compliance.tf read from the module manifests installed by `terraform init`. compliance.tf does not sign, attest or verify it.

| | |
|---|---|
| Release | testdata/fixtures/report/served-leaf/input |
| Commit | `0000000000000000000000000000000000000000` |
| Generated | 2026-09-20T00:00:00Z by ctfkit 1.0.0 |
| Control catalog | 2026.11.1, the catalog embedded in ctfkit, which holds the CIS v6.0 controls only; `ctfkit catalog pull` fetches the full catalog |
| Frameworks | SOC 2 |

## 1 Summary

Counts are taken from the module manifests and the control catalog named above.

| | |
|---|---|
| Modules in scope | 1, 1 with a compliance.tf manifest |
| Controls enforced | 1 |
| Controls delegated to another scope | 0 |
| With a SOC 2 clause | 1 of 1 |
| Framework gaps with a recorded reason | 0 of 0 |
| Catalog controls for these resource types not enforced here | 0 |
| Control enforcement tests | No tests supplied |
| Findings at error level | None |

## 2 Scope

The modules `terraform init` installed for this release. A module without a compliance.tf manifest is listed in the report findings.

| Module | Source | Version | Manifest sha256 |
|---|---|---|---|
| `s3_bucket_notification` | `bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws//modules/notification` | 5.16.1-1e4b692ae5e0a847 | `bd6add96ced9ccad50c15d3e6e68d0a90efc227f4a23ae8fe5b909eac4e2ce95` |

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

### Module `s3_bucket_notification`

| Control | Status | SOC 2 |
|---|---|---|
| `s3_bucket_event_notifications_enabled` S3 buckets should have event notifications enabled | enforced | CC7.3 |

## 5 Controls with no clause in a framework

A control can have no matching clause in a framework. The reason comes from the control catalog.

None.

## 6 Catalog controls not enforced by these modules

Controls the catalog lists for the resource types of these modules that no module manifest lists, and the layer that owns each one. The catalog is the embedded one, which holds the CIS v6.0 controls only, so this list is not complete.

None.

## 7 Enforcement tests

No tests supplied. Pass `--tests-json` to `ctfkit report` to include the results of `tofu test -json` or `terraform test -json`.

## Annex A Clause register

Every clause cited in this pack, as the module manifests name it, and the clauses the catalog records no control applies to.

### SOC 2

| Clause | Title | Controls |
|---|---|---|
| CC7.3 | The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives (security incidents) and, if so, takes actions to prevent or address such failures | `s3_bucket_event_notifications_enabled` |

Clauses with no applicable control: None.

---

Unsigned. Not independently attested.
