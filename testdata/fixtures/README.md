# Fixture pack

The oracle every ctfkit by compliance.tf analyzer and renderer is built against.
Three families:

- `report/<case>/` - recorded `.terraform/modules` trees for `ctfkit report`
  (stage `post_init`), one directory per report acceptance case.
- `plan/<NN-name>/` - the 16 canonical plan documents from the findings format
  conformance suite and the scan specification, one directory per fixture.
- `graph/<case>/` - hand-written plan documents for the `ctf.graph.companion`
  analyzer: `plan.json` and `expected.json`, the decisions for the graph
  controls in `graph/controls.json`. `internal/graph` runs them.
  `graph/cross-module/<case>/` holds the cases whose target and companion
  sit in different modules or reach their provider configuration through a
  module call.
- `migrate/behaviour/<B#>/<cli>-<version>.golden` - recorded transcripts of
  the Terraform and OpenTofu behaviours B1-B7 that `ctfkit migrate` relies
  on, one per CLI version. `internal/migrate/behaviour_test.go` replays them
  and holds the re-record recipe (live mode). These are not `input/` plus
  `expected/` cases.
- `migrate/<NN-name>/` - the 18 `ctfkit migrate` rewrite cases. Today most are a
  README stub naming what it covers and the task that fills it; that task adds
  `input/` and `expected/migrate-plan.json` (schema `migrate-plan-1`) plus
  `expected/files/`. No empty placeholder is committed: `make schemacheck` fails
  on an empty expected file. Example migration records (`journal.json`) and WAL
  records (`*.wal.json`) live in `schema/testdata/migrate/`.

Every case is `input/` (what the command reads) plus `expected/` (what it must
produce). Nothing here is generated at test time; the expected files are
committed bytes.

## Provenance rule

**Fixtures come from the `bobthecorp` test organisation or from a public
framework host. Never from a real customer organisation.** No customer name,
organisation alias, account id, bucket name, role ARN or file path from a real
estate appears in this directory, and none may be added. A parity run against
fixtures kept outside this repository (`testdata/local`, gitignored) uses them
locally and commits nothing here.

Every account id in this pack is `111111111111`, every region is `eu-west-1`,
every AWS credential is the literal string `mock_access_key` /
`mock_secret_key`, and no fixture was ever applied against AWS.

## How these were produced

The trees under `report/` were **recorded**, not hand-written:

```bash
cd <scratch dir>
# main.tf calls bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws
tofu init -backend=false
```

and then `.terraform/modules/modules.json` plus the `compliancetf-manifest.json`
of each directory `modules.json` points at were copied into `input/`. The module
source itself is not copied: the report reads the manifests, not the HCL of the
served module. The manifests are schema 3.3 as served on 2026-09-20 and are
byte-identical to what the registry wrote, with the exceptions named below.

The plan documents under `plan/` were recorded with `tofu plan -out` followed by
`tofu show -json`, against a provider configured with a mock key, a skipped
credential check and (where the served module reads `aws_caller_identity`) a
local STS stub. Two normalisations are applied to the recorded document and
nothing else: the `timestamp` field is frozen to `2026-09-20T00:00:00Z`, and the
absolute scratch path is rewritten to `.`, so the bytes are stable across
machines.

### The synthesized inputs, and why

| Case | What was injected | Why it could not be recorded |
|---|---|---|
| `report/degraded-build` | `posture.degraded` set to `["org-rules-unavailable", "baseline-not-authored"]`, and one unrecognised `does_not_prove` token, `org_baseline_not_evidenced` | Both are producer-side conditions. A healthy registry never emits them on request, and the fixture pack must not depend on breaking the registry to regenerate |
| `report/schema-4-stub` | `schema_version` raised to `4.0` on an otherwise recorded manifest | Schema 4 does not exist. The case asserts that an unsupported major is an environment error (exit 2), not a finding |
| `report/supporting-clauses` | the `delegated-without-sibling` manifest with `schema_version` raised to `3.4` and `supporting_clauses_by_framework` added to every control: `CC7.3` marked supporting on `s3_bucket_logging_enabled` and `s3_bucket_event_notifications_enabled`, `[]` on every other control; the bucket name in `main.tf` changed. `manifest_set_hash` is left as recorded, which ctfkit does not verify | The 3.4 field is newer than every recorded tree, and which clauses a curation marks supporting is producer-side data. Everything else is the recorded `delegated-without-sibling` tree |

Each of the three is a transform of the recorded `delegated-without-sibling`
tree, named in `report/PIN.json` (`degraded-posture`, `schema-major-4`,
`supporting-clauses`) and written in Go in `internal/fixturepin/transform.go`.
`degraded-build` and `supporting-clauses` also rename the bucket in `main.tf`.
Everything else in those cases is the base tree byte for byte, and the pin
check holds every synthesized input to its transform ("Pinning and
re-recording" below).

`plan/10-post-apply-state` records real drift, but from the `local` provider:
drift needs an apply, and no fixture is applied against AWS. Only the shape of
`resource_drift[]` in the plan document is what the case asserts.

`report/example-multi-instance/input/tests.json` is real `tofu test -json`
output from the test file kept beside it at `input/tests/buckets.tftest.hcl`
(two runs pass, one asserts a deliberately wrong region and fails).

## Naming contract

Other tests and tools depend on these exact paths. Do not rename a case or a file.

```
report/<case>/input/.terraform/modules/modules.json
report/<case>/input/.terraform/modules/<dir>/compliancetf-manifest.json
report/<case>/input/*.tf                      root configuration
report/<case>/input/tests.json                optional, tofu test -json output
report/<case>/expected/report.md
report/<case>/expected/receipt.json
report/<case>/expected/findings.sarif
report/<case>/expected/ctfkit.custom.spacelift.json
report/<case>/expected/exit-code

plan/<NN-name>/input/plan.json
plan/<NN-name>/input/*.tf                     config the analyzer needs
plan/<NN-name>/input/.ctfkit.yaml             where the case needs org config
plan/<NN-name>/input/.ctf-exceptions.yaml     where the case needs an exception
plan/<NN-name>/expected/findings.sarif
plan/<NN-name>/expected/exit-code             11- to 16- only

evidence/<status>/input/chains/<chain>.jsonl   provider evidence chain of run bobthecorp-run-1
evidence/<status>/input/artifacts/             verdict.json, result.json and ctfkit-run.tombstone (runner class ci)
evidence/<status>/expected/receipt.json        provider-run receipt
evidence/<status>/expected/exit-code
```

One naming rule for a new or re-recorded case: a module instance key becomes a
directory name under `.terraform/modules/`, so it must not collide with a common
ignore pattern. A key of `logs` is silently dropped by any checkout whose global
or repository ignore file carries the usual `logs` line, which is why the
multi-instance case names its first bucket `archive`.

`report/schema-4-stub` is the one exception: it carries `expected/exit-code` and
`expected/stderr.txt` and no projection at all, because the command stops before
it renders one.

### Report cases

| Case | What the tree holds | Expected verdict | Rules fired |
|---|---|---|---|
| `served-leaf` | one instance of a served leaf module (the `notification` subtree) | pass, exit 0 | none |
| `blueprint-wrapper` | a served package root plus three resources the root declares itself, no tests | pass, exit 0 | `delegation_unresolved` x2, `resource_unattested` |
| `example-multi-instance` | three instances of one served build, with imported test results | fail, exit 1 | `tests_failed`, `delegation_unresolved` x2 |
| `degraded-build` | a served build reporting a degraded posture and an unknown obligation token | fail, exit 1 | `posture_degraded`, `delegation_unresolved` x2, `obligation_unknown` |
| `missing-manifest` | a served build plus a local module with no manifest | fail, exit 1 | `manifest_missing`, `delegation_unresolved` x2 |
| `helper-module` | a served build plus a local helper module (data, locals and outputs only) with no manifest | pass, exit 0 | `delegation_unresolved` x2 |
| `delegated-with-sibling` | the package root plus the two subtrees its delegated controls point at | pass, exit 0 | none |
| `delegated-without-sibling` | the package root alone, so both delegated controls are unresolved | pass, exit 0 | `delegation_unresolved` x2 |
| `supporting-clauses` | `delegated-without-sibling` at manifest schema 3.4, two controls with a clause marked supporting | pass, exit 0 | `delegation_unresolved` x2, one carrying `supportingClauses: ["CC7.3"]`, the other `[]` |
| `schema-4-stub` | a manifest declaring an unsupported schema major | environment error, exit 2 | none, the command stops |

Exit codes assume the default `--fail-on error`: a warning or note does not
change the exit code, which is why `blueprint-wrapper` and
`delegated-without-sibling` carry findings and still exit 0.

### Evidence cases

`ctfkit evidence ship` cases, one per provider-run receipt status (phase 3 F13),
run by `internal/cli/evidence_ship_test.go` against a fake S3 Object Lock bucket,
a fake Evidence API and the signed inputs `pkg/verdict/testdata/inputs/evidence`
(`evidence-advisory`: no `verdict_required`). The chains are the provider goldens
of `schema/testdata/provider-evidence`; the break-glass chain is `chain-good.jsonl`
with `break_glass_id` on one result and its later `prev` links recomputed.
`input/artifacts/verdict.json` is `pkg/verdict/testdata/sig/valid/verdict.json`
rebound to org `bobthecorp`, workspace `default`, run `bobthecorp-run-1` and the
plan digest of `result.json`, under the `evidence` profile's verdict key, so the
set authenticates and the runner class is ci. Rewrite `expected/` and those
verdicts with `go test ./internal/cli/ -run TestEvidenceShipFixtures
-update-evidence`.

| Case | Input | Status, exit |
|---|---|---|
| `enforced` | terminated chain, apply outcome enforced, every sink takes every object | enforced, 0 |
| `evidence-degraded` | chain cut by a crash after seq 1 (missing from seq 2) | evidence-degraded, 1 |
| `overridden` | a record with `break_glass_id`, apply outcome overridden | overridden, 1 |
| `overridden-degraded` | `overridden` with the S3 sink failing every put (objects spooled) | overridden, 1, alert raised |
| `single-resource-only` | no artifact set (runner class local), profile without `verdict_required` | single-resource-only, 1 |
| `failed` | apply outcome failed | failed, 1 |
| `tampered` | `chain-edited.jsonl`, an edited line; nothing is uploaded, the receipt records the reason and the run of the authenticated verdict | failed, 1, alert `evidence_tampered` |

### Plan cases

The 10 conformance fixtures, in the order the findings format lists them, each
asserting the finding named there. `02-ctf-module-intact` is the negative case:
a document with zero results.

Every plan case runs with the argv of the scan specification's fixture table from its
`input/` directory and joins the catalog embedded in the binary; no case pins a
catalog of its own. The recorded `expected/findings.sarif` is what `ctfkit
scan` renders, so the pack and the command cannot disagree. The findings the
case is named for are still there; where the embedded catalog covers another
raw resource in the same plan (the `aws_sqs_queue` in `08-` and `16-`), its
`ctf.coverage.module_source` error is recorded too and the case exits 1.

### Plan cases 11 to 16

`11-` to `15-` are `ctf.risk.sensitive_change`, one per class of
analyzers/sensitive-change.md, each with a clean counterpart in the same plan
that must produce no finding. `16-secret-canary` proves that no value from a
plan reaches any output; its `input/.ctfkit.yaml` approves only the `aws`
provider, so the `random` instance is the unapproved one. All six run as
`scan plan.json` at `post_plan`.

| Case | Resources in the plan | Expected findings | Exit |
|---|---|---|---|
| `11-sensitive-public-exposure` | public access block updated (`block_public_policy`, `restrict_public_buckets` true to false); bucket policy created with `Principal: "*"` and no condition; clean: a second public access block, no-op | 2 x `_public_exposure` error | 1 |
| `12-sensitive-wildcard-iam` | four `aws_iam_policy` created: `*` on `*`, `s3:*` on `*`, a `Deny` with both wildcards; clean: named actions on a named bucket | `_wildcard_iam` error (admin), warning (s3_admin); nothing for the `Deny` | 1 |
| `13-sensitive-audit-log-removal` | `aws_cloudtrail.org` destroyed (removed from config); `aws_eks_cluster.platform` log types `[api, audit, authenticator]` to `[api]`; clean: a second trail, no-op | 2 x `_audit_log_removal` error | 1 |
| `14-sensitive-encryption-disablement` | `aws_db_instance.primary` `storage_encrypted` true to false, which the provider can only do by replacement; bucket encryption configuration destroyed; clean: a second instance keeps encryption, in-place retention change | 2 x `_encryption_disablement` error, plus 1 x `_destructive_stateful` error for the replacement | 1 |
| `15-sensitive-destructive-stateful` | `aws_dynamodb_table.sessions` replaced (hash key change); `aws_db_instance.ledger` `deletion_protection` true to false in place; clean: a second table, in-place tag change | `_destructive_stateful` error (sessions), warning (ledger) | 1 |
| `16-secret-canary` | `aws_db_instance.app` with the canary password; a module from a `git::https://user:pass@` source; providers `aws`, `aws.replica`, `random` (two resources on `random`) | 1 x `ctf.origin.provider` warning, on the `random` provider instance; 1 x `ctf.coverage.module_source` error on the raw `aws_sqs_queue.replica_events` | 1 |

`14-` carries one more finding than the analyzer spec's fixture line names: the
spec's own class 5 rule fires on the replacement that turning off
`storage_encrypted` forces, and a recorded plan cannot avoid it.

**What was recorded live.** Every `input/plan.json` is real `tofu plan -out`
plus `tofu show -json` output (OpenTofu 1.12.6, hashicorp/aws 6.65.0), with the
two normalisations above. The plan step ran with `HTTPS_PROXY` and `HTTP_PROXY`
pointed at a closed local port, so any request to AWS would have failed the
recording; none did. `11-`, `13-`, `14-` and `15-` need a prior state, because
their rules compare `before` with `after`. That state was seeded, not applied:
the prior configuration was planned as a create, its planned values were written
out as a local state file (unknown computed values filled with fixed fakes such
as `bobthecorp-<name>` ids and `111111111111` ARNs), and the committed
configuration was then planned against it with `-refresh=false`. The seeded
state is visible in each plan's `prior_state`; the state file itself is not
committed. `15-` also needs a local DynamoDB stub on `127.0.0.1:15516`, named
in its `providers.tf`, because the provider calls `DescribeTable` while
planning a table update. In `16-` the module is fetched through a git
`url.<base>.insteadOf` rule that maps the credentialed URL to a local bare
repository, so the source string in the plan is exactly what the configuration
states and nothing was cloned over the network.

**What the expected files record.** Every `expected/findings.sarif` is the
output of `ctfkit scan` (see "Regenerating"), checked against
analyzers/sensitive-change.md and analyzers/origin-and-floating-ref.md. The
judgement calls those specs leave open:

- A control id is attached only when the embedded catalog covers the changed
  resource's own type and a control on that type is about the changed
  attribute (for example `eks_cluster_control_plane_audit_logging_enabled`,
  `rds_db_instance_encryption_at_rest_enabled`,
  `rds_db_instance_deletion_protection_enabled`). A whole-resource delete or
  replace names no attribute, so those findings carry `ctf.controlIds: []`.
- `ctf.preventive` is true exactly when a control id is attached, and
  `ctf.frameworks` lists every framework the catalog maps that control to,
  by catalog id, with clause identifiers (decision 2 below).
- No finding carries `ctf.remediation`: the catalog's module entries (S3
  bucket, SQS queue) list none of these control ids.
- `ctf.attributes` names the changed attributes; a replacement names the
  attributes in the plan's `replace_paths`. Messages are constants with the
  address and attribute names filled in, never a value.
- `16-` keeps the bare rule id and warning level of `09-unknown-provider`. At
  `post_plan` the finding is reported per provider instance, so its one
  location is the logical provider instance address; `ctf.origin.provider`
  emits no physical location for it.

**The canary.** Two fake, unique secrets are planted in `16-secret-canary`,
for a test to grep for in every output format, on stderr and in exit-2
diagnostics:

| Secret | Where it is in the input |
|---|---|
| `CANARY-50c488e396915cedcc5b650db695f0d2` | `aws_db_instance.app` `password`, three times in `plan.json` |
| `canary-pass-8fdf8eaa189601fd` | the password in the module source `git::https://canary-user:canary-pass-8fdf8eaa189601fd@git.bobthecorp.example/...` |

Both are recorded in the plan (the layout test checks that, so the canary
cannot pass by being absent) and neither is in `expected/`.

### Plan case 17

`17-exec-pre-plan` runs `scan --stage pre_plan .` over a configuration with no
compliance.tf module: a `terraform_data` resource with a `local-exec`
provisioner and a `check` block with a scoped `data "external"` in `main.tf`,
and a local module whose `main.tf.json` declares a `data "external"` block. It
records one `ctf.exec.provisioner` and two `ctf.exec.external_data` errors (the
scoped one as `check.health.data.external.probe`, the module's as
`module.hook.data.external.probe`, the address its call gives it) and exits 1. The command and the program carry
`CANARY-` markers that no expected file may hold. The case never reads its
`input/plan.json`: that file is a minimal hand-written plan document, not a
recorded one, present only because every plan case carries one.

## Run context

Every expected projection was rendered with a frozen run context, and a
regeneration has to pass the same flags or the bytes will differ:

```
--run-id ctfkit-fixture-run
--commit 0000000000000000000000000000000000000000
--platform local
```

with the generator reporting itself as `ctfkit 1.0.0` and the timestamp
`2026-09-20T00:00:00Z`.

## Serialisation

- `receipt.json` is canonical JSON (RFC 8785 rules: keys sorted, no insignificant
  whitespace, UTF-8, no escaping of non-ASCII) with **no trailing newline**. The
  whole file is the bytes a signature will one day cover, so it is compared
  byte for byte and never reformatted.
- `findings.sarif` and `ctfkit.custom.spacelift.json` are indented two spaces
  with a trailing newline, because a human reads them in a pull request.
- `report.md` is compared after stripping the `Generated by ...` line, which is
  the same comparison the Python parity harness uses.

## Framework ids

Framework ids are the control catalog's ids everywhere: `soc_2`,
`pci_dss_v40`, `hipaa`, and so on, spelled as the manifest and the catalog
spell them. The catalog `hosts` map turns an id into its registry host label
(`soc_2` to `soc2`), which appears only in module sources such as
`soc2.compliance.tf/...`. Receipts (`frameworks`, `clausesByFramework`) and
SARIF `ctf.frameworks[].id` carry the catalog id. The Markdown column headers
keep the manifest display name (`SOC 2`). No layer normalises the spelling.

- 2026-09-21: the report cases were re-recorded under this rule by running
  `ctfkit report` with the argv below against the embedded release catalog.
  Every `receipt.json` and `findings.sarif` changed `soc2` to `soc_2`, and every
  `findings.sarif` gained the run-level `ctf.catalogVersion` block (2026.11.0,
  embedded) the earlier recording predates. `report.md`,
  `ctfkit.custom.spacelift.json` and every exit code are unchanged. Before this
  date the receipts carried `soc2`, normalised from the manifests' `soc_2` by
  an alias in the inventory package.
- 2026-09-24: a `ctf.coverage.manifest_missing` result now
  carries a module logical location, `module.<key>` (a nested key `a.b` is
  `module.a.module.b`), so a rule-keyed exception entry can be scoped to the
  instance. `report/missing-manifest/expected/findings.sarif` was re-recorded
  with the argv below (`--format sarif`); it is the only case with that rule.
  Its receipt, Markdown, Spacelift file and exit code are unchanged, because
  none of them carries locations. The other coverage rules are about a build,
  a token or the run rather than one instance, and keep no logical location.
- 2026-09-26: `ctf.coverage.manifest_missing` no longer
  fires for a manifest-less instance whose own directory declares no
  `resource` block, such as a helper of data sources, locals and outputs:
  it creates nothing, so it leaves no evidence gap. The instance stays
  listed under "Instances without a manifest". Each instance is judged on
  its own directory, so a child module with resources under a
  resource-free wrapper is still reported. `report/helper-module` was
  recorded in process at the fixture clock with the argv below;
  `report/missing-manifest` is unchanged and still proves the error for a
  module that declares resources.

## Regenerating

Until `ctfkit report` and `ctfkit scan` exist, the expected files are derived
from the report specification and the findings format by hand and are the specification in
executable form. Once the commands exist, the loop is:

```bash
# report cases
ctfkit report --path testdata/fixtures/report/<case>/input \
  --tests-json testdata/fixtures/report/<case>/input/tests.json \
  --format markdown,receipt,sarif,spacelift \
  --out-dir testdata/fixtures/report/<case>/expected \
  --run-id ctfkit-fixture-run --platform local \
  --commit 0000000000000000000000000000000000000000 \
  --catalog embedded
# ctfkit.custom.spacelift.json lands in the working directory; move it into
# expected/. Run from the repository root with an empty HOME.

# plan cases: the scan-spec argv of each case, run from its input directory
# from a clean HOME at the fixture clock, written over expected/findings.sarif
CTFKIT_RERECORD=1 go test ./internal/cli -run TestScanFixtureParity

# report cases, findings.sarif only: the in-process report run at the fixture
# clock and version, when a change touches the SARIF and nothing else
CTFKIT_RERECORD=1 go test ./internal/cli -run TestReportSARIFParity

# report cases, every expected file (report.md, receipt.json, findings.sarif,
# ctfkit.custom.spacelift.json, exit-code, and schema-4-stub's stderr.txt)
CTFKIT_RERECORD=1 go test -count=1 ./internal/cli -run \
  '^(TestReportProjections|TestReportSARIFParity|TestReportSpaceliftParity|TestReportRecordedExitCodes|TestReportEnvironmentDiagnostic)$'
```

Those five are the named report golden tests. With `CTFKIT_RERECORD=1` each
writes what it renders over the expected file and then compares, and renders
every case directory whether or not the expected file exists yet, so an empty
`expected/` is filled completely. `CTFKIT_FIXTURE_ROOT=<absolute dir>` points
them at another tree holding `testdata/fixtures/report` instead of this
repository; the recorder uses it so a re-record regenerates its fresh tree and
never the live pack. No other test reads either variable for the report pack.

The plan cases are re-recorded through the parity test rather than a built
binary because `06-sentinel-exception` records `ctf.exception.ttlSeconds`,
which counts from the run clock; the test runs the command at the fixture
clock. The run-level `ctf.catalogVersion` block and the stale-catalog
`invocations` block are left out of the recorded file (the parity test asserts
them separately), so a catalog release does not by itself change every case.

### Plan pack decisions

- 2026-09-21: `ctf.frameworks[].id` is the
  control catalog's framework id (`soc_2`, `pci_dss_v40`), never the host
  label (`soc2`). Every plan case joins the embedded release catalog; the
  analyzer packages keep no pinned catalog copy.
- 2026-09-21: every analyzer that joins the catalog writes
  `ctf.frameworks` the same way: every framework the catalog maps the control
  to, each clause shortened to its identifier by the coverage analyzer's rule
  (first whitespace-delimited token, trailing colon dropped, each once),
  `catalog.ClauseIdentifiers`. A clause title that does not start with an
  identifier shortens to its first word; that is a catalog content issue,
  tracked separately.
- 2026-09-24: superseding the first-word fallback above,
  `catalog.ClauseIdentifier` is the one rule for catalog clauses, manifest
  clauses and markdown cells. A title with no leading identifier keeps a
  trailing parenthesized control id (`Denial Of Service Protection (SC-5)` is
  `SC-5`), else its words through a number in the first three
  (`Article 25 ...` is `Article 25`), else the whole title (`Data protection`).
  Plan cases 01, 03, 06-08 and 14-16 were re-recorded. Titles the catalog
  stores with no identifier at all, such as most `pci_dss_v321` clauses, stay
  whole until the catalog carries one.
- 2026-09-21: `ctf.exception` is exactly what
  `ctfkit.Decide` returns: no matching entry, no property. `06-` and `07-`
  carry one entry per control id on the raw-bucket finding (under the embedded
  catalog, one: `s3_bucket_object_lock_enabled`), so `06-` is suppressed with
  the entry's justification and exits 0, and `07-` carries the expired entry's
  metadata and exits 1.
- 2026-09-21: `03-`'s `disabled_control` message and rule
  description do not mention exceptions; the verdict is in `ctf.exception`.
- 2026-09-21: results are in `SortFindings` order. `05-`
  runs at `pre_plan` as its scan argv says, where `module_source` reads
  module blocks only, so it records the upstream module call and not the raw
  queue; the raw-resource row is asserted at `post_plan` by `01-`.
- 2026-09-24: `08-missing-tags` and `16-secret-canary` keep
  their raw `aws_sqs_queue` and the `ctf.coverage.module_source` error it
  raises, and that error is the whole reason both exit 1: the finding each case
  is named for is a warning (`ctf.policy.tagging`, `ctf.origin.provider`), so
  each would exit 0 on its own. The coupling is accepted because the inputs are
  live recordings. Removing the queue, or routing it through the served SQS
  module, means a new `tofu plan` recording, and editing `plan.json` by hand
  breaks the provenance rule. In `16-` the queue is also the only resource on
  the `aws.replica` provider instance. Each case's own assertion does not
  depend on the exit code: `08-` is checked on its tagging result, `16-` on the
  absence of both canaries. A catalog release that stops listing the SQS
  module drops the extra result and turns both exit codes to 0, and the parity
  test reports that as a diff.
- 2026-09-25: a result whose block ctfkit read from a
  configuration file carries `physicalLocation.region` with `startLine` and
  `endLine`: the whole block, or the `required_providers` entry for a provider
  rule. In a `.tf.json` file the region is the block header only, because a
  JSON body carries no range of its own. Results are sorted by rule id, then
  uri, then start line, then address (`ctfkit.SortFindings`), so results of one
  rule in one file now follow line order; `11-`, `14-` and `15-` reorder for
  that reason alone.
  A resource whose block the plan deleted keeps the `main.tf` fallback with no
  region. Every plan case with a result was re-recorded with
  `CTFKIT_RERECORD=1`; `02-` has none and `10-` is the post_apply case.
- 2026-09-25: every result carries
  `partialFingerprints["ctfkitFindingHash/v1"]`, the SHA-256 of rule id,
  artifact uri, subject, sorted control ids and an analyzer discriminator,
  with no line and no message text in it; `docs/cff.md` "Fingerprint" has the
  rule. The plan cases were re-recorded with `CTFKIT_RERECORD=1 go test
  ./internal/cli -run TestScanFixtureParity` and the report cases'
  `findings.sarif` with `CTFKIT_RERECORD=1 go test ./internal/cli -run
  TestReportSARIFParity`. `TestRenderGolden` rebuilds its input from the
  recorded SARIF, which has no discriminator, so it compares everything but
  the fingerprints.
  Each diff adds the key and nothing else. The binary command above records
  the run clock and the build version, so it is not the tool for this change;
  receipts, markdown and Spacelift files carry no fingerprint and are
  unchanged. `10-post-apply-state` records the planned post_apply stage, which
  scan refuses with exit 2, so no renderer writes it and it keeps no
  fingerprint until that stage ships.

A diff against the committed bytes is the failure. Changing an expected file is
a specification change and needs the owning spec changed in the same pull
request.

Re-recording an input tree means re-running `tofu init` against the
`bobthecorp` host and copying `modules.json` and the manifests back in. The
served module version moves, so a re-record changes `version`, every manifest
`sha256` and the control set, and therefore every expected file in that case.
For the report pack that is done only by `scripts/record-report-fixtures.sh`
(next section), never by hand.

## Pinning and re-recording

**Decision (2026-09-27).** The report pack (`report/*`; `plan/` is
out of scope) is pinned. The committed bytes are the oracle, no test touches
the network, and the pack changes only through a scripted re-record opened as a
reviewed pull request. There are two triggers: once before the 1 Nov 2026
cutover, and a manifest schema change the product must support. Nothing is
scheduled, and the registry credential never goes into CI.

These goldens are the ctfkit oracle: they say what ctfkit renders for a pinned
set of served modules. They are not the parity oracle for fixtures kept outside
this repository, which is compared there (see "Provenance rule").

### PIN.json

`report/PIN.json` is canonical JSON (keys sorted, no whitespace, no trailing
newline):

| Field | Meaning |
|---|---|
| `pin_format` | `1` |
| `registry_host` | the host every registry module is served from, `bobthecorp.compliance.tf` |
| `tofu_version` | the tofu that recorded the pack, or `unknown` |
| `recorded_on` | UTC date of the recording |
| `cases.<name>.role` | `recorded` or `synthesized` |
| `cases.<name>.base_case`, `.transform` | synthesized cases only: the recorded case and the named Go transform the inputs are derived from |
| `cases.<name>.modules[]` | every registry module of the case's `modules.json`: `key`, `source`, `version`, `manifest_schema_version` (must equal the manifest's `schema_version`), `manifest_sha256` (of the committed bytes). The root entry and `./` / `../` sources are not pinned |

The current pin was written from the pack as committed, recorded on
2026-09-20 at manifest schema 3.3. Its `tofu_version` is `unknown`: this README
names OpenTofu 1.12.6 for the plan recordings only and never named the tofu
that ran `init` for the report trees. The next re-record writes the real
version, which `mise.toml` now pins.

`pin_test.go` (`TestReportPackMatchesItsPin`, run by `make conformance`) holds
the pack to its pin offline: `pin_format`; the registry grammar
`host/namespace/name/system` with an optional contained `//subdir` on the
pinned host; the pinned cases equal the case directories and the pinned modules
equal each `modules.json`, both ways; every `Dir` is relative and its real path
stays under `.terraform/modules/` with a manifest in it; each manifest's
sha256 and `schema_version` match the pin; one version per package address
across the pack; every synthesized input equals its transform of the base case
byte for byte, file set included; and a raw-bytes scan of the whole pack finds
no token shape, signed URL or absolute path (a symlink is refused).

### The recorder

```bash
TF_TOKEN_bobthecorp_compliance_tf=<token> scripts/record-report-fixtures.sh          # re-record and swap in
TF_TOKEN_bobthecorp_compliance_tf=<token> scripts/record-report-fixtures.sh --check  # compare only
```

Maintainer-only; it refuses to run when `CI` is set, and `--check` also
refuses when `CTFKIT_UPDATE_GOLDEN` is set. It uses the tofu `mise.toml` pins
and refuses any other version. What it does:

1. Sweeps and recreates one fixed 0700 scratch parent outside the repository,
   `$TMPDIR/ctfkit-report-rerecord`, holding `HOME`, `TMPDIR`, `TF_DATA_DIR`
   and a 0600 CLI config with the token (read from `TF_TOKEN_<host>` before
   anything runs under `env -i`) and `provider_installation` limited to
   `registry.opentofu.org/hashicorp/*`.
2. For each recorded case, copies the committed configuration (everything in
   `input/` but `.terraform`) into scratch, validates every module source
   before `init` (a local path whose real path stays in the case, or the
   registry grammar on the pinned host), runs `tofu -chdir=<case> init
   -backend=false` under `env -i`, and validates every `modules.json` entry
   again before anything is copied.
3. Assembles a fresh tree under `testdata/.report-rerecord/` (gitignored):
   the configuration, `modules.json` with every `Dir` relative, and each
   manifest byte for byte; nothing else tofu fetched. Synthesized cases are
   written by their transforms, whose post-conditions stop the run when a new
   base no longer fits. `PIN.json` is written from the result.
4. Regenerates every expected file with the named report golden tests
   (`CTFKIT_RERECORD=1`, `CTFKIT_FIXTURE_ROOT` at the fresh tree,
   `GOPROXY=off`, `GOFLAGS='-mod=readonly -buildvcs=false'`, `-count=1`, the maintainer's module
   and build caches), then once more; the second pass must change nothing.
5. Scans the whole fresh tree: the literal token or a signed URL exits 3,
   any other pattern hit exits 2. Nothing is compared, printed or swapped on
   either.
6. Runs the pin check on the fresh tree, then swaps: live to
   `testdata/.report-rerecord/backup`, fresh to live, backup deleted. It
   refuses to start while a backup exists, and a trap restores the live pack
   if the swap is interrupted.

`--check` runs the same pipeline into scratch and compares the fresh tree
with the live pack, every file, `PIN.json` included except its `recorded_on`;
an added or removed file is drift.

| Exit | Record | `--check` |
|---|---|---|
| 0 | re-recorded and swapped in | no drift |
| 1 | - | drift: the served modules differ from the pin |
| 2 | tooling error, refused source, failed check or pattern hit | same |
| 3 | the token or a signed URL is in the tree: rotate the credential | same |

A residual the recorder cannot close: tofu may fetch a transitive module from
outside the registry before the post-init check sees it. That happens on the
maintainer's machine against the first-party registry, and such a module is
never copied or committed.

The first live re-record drops the trailing newline of `helper-module`'s
`modules.json`, which was assembled in process rather than written by tofu, so
that case's receipt changes its `modulesJson` sha256 too.

`cmd/fixturepin/record_test.go` runs the recorder end to end against a fake
tofu that serves the committed modules: the re-record reproduces every
committed file except those two and `PIN.json`, `--check` then exits 0, and
the drift, token, absolute-path, refused-source, interrupted-swap and refusal
paths exit as the table says.

### Recovery

- The live pack is missing and `testdata/.report-rerecord/backup` exists:
  `mv testdata/.report-rerecord/backup testdata/fixtures/report`.
- Both exist: the swap finished; delete `testdata/.report-rerecord/`.
- A run killed with SIGKILL leaves the 0700 scratch parent, CLI config and
  token included, and can leave `testdata/.report-rerecord/fresh`, which may
  hold recorded bytes the scan never saw. The next run sweeps both; if no run
  follows, delete `$TMPDIR/ctfkit-report-rerecord` and
  `testdata/.report-rerecord/fresh` by hand.

### Cutover checklist (1 Nov 2026)

The release owner holds the registry credential and runs every step.

Until the first live re-record lands, `--check` exits 1 whatever the
registry serves: the pinned `tofu_version` is `unknown` and the recorder
writes the real one, and `helper-module`'s `modules.json` loses its trailing
newline (above). An exit 1 before that re-record is expected, not a sign the
served modules moved; run the re-record.

1. T-14d (18 Oct 2026) and T-48h (30 Oct 2026):
   `scripts/record-report-fixtures.sh --check`.
   - 0: nothing to do.
   - 1: run `scripts/record-report-fixtures.sh`, review the diff (`PIN.json`
     shows the recorded manifest schema, 3.4 expected), run `make check`, and
     open the re-record pull request.
   - 2: fix the cause and rerun.
   - 3: rotate the credential, then rerun.
2. After a re-record is merged, `--check` exits 0.
3. The live parity comparison against fixtures kept outside this repository
   runs outside it.
4. Record each result in the cutover notes.

## Layout test

`pin_test.go` is the pin check above. `fixtures_test.go` guards the layout
contract only: the files each case must
carry, that the case lists match the directories, that every JSON file parses,
and that no projection carries a watermark, since every case is recorded
without `--watermark`. It asserts nothing about
what the expected outputs say - that is the analyzer and renderer tests' job.

Go excludes `testdata` from wildcard package patterns, so run it by path:

```bash
go test ./testdata/fixtures/
```
