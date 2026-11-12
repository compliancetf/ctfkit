# CFF: the ctfkit findings format

Status: **draft**. CFF version `1.0`, schema `schema/cff-1.schema.json`.

CFF is the findings format of ctfkit by compliance.tf. It is a profile of
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html): a
normal SARIF log plus a `ctf.*` property bag on the run and on every result.
Any SARIF 2.1.0 reader can load a CFF file; a reader that does not know the
profile sees ordinary SARIF.

`ctfkit scan --format sarif` writes it, as does `ctfkit report --format sarif`.
The file name inside `--out-dir` is `findings.sarif`.

Draft means the field names and rules below are what ctfkit emits today and
what the schema checks, and they can still change before the profile is
declared stable. The machine-checkable contract is the schema; where this page
and the schema disagree, the schema wins.

## Sources of truth

| What | Where |
|---|---|
| JSON Schema (draft 2020-12) | `schema/cff-1.schema.json` |
| Property key constants, levels, kinds | `pkg/ctfkit/finding.go` |
| Stage names | `pkg/ctfkit/analyzer.go` |
| Exception decision | `pkg/ctfkit/exceptions.go` |
| Renderer | `internal/render/sarif/sarif.go` |
| Conformance fixtures | `testdata/fixtures/*/*/expected/findings.sarif` |

The schema constrains the subset ctfkit emits and the profile on top of it.
SARIF objects stay open (no `additionalProperties: false`), so anything SARIF
allows and the profile does not name still validates. Full structural SARIF
validation is the job of the official schema at
`https://json.schemastore.org/sarif-2.1.0.json`, which `cff-1` does not `$ref`
so that validation can run offline.

## Document

| Key | Required | Value |
|---|---|---|
| `$schema` | no | if present, `https://json.schemastore.org/sarif-2.1.0.json` (ctfkit always writes it) |
| `version` | yes | `2.1.0` |
| `runs` | yes | at least one run; ctfkit writes exactly one |

## Run

| Key | Required | Value |
|---|---|---|
| `tool.driver.name` | yes | non-empty; ctfkit writes `ctfkit` |
| `tool.driver.version` | no | non-empty when present; omitted when the generator version is unknown |
| `tool.driver.informationUri` | no | a URI |
| `tool.driver.rules` | yes | one entry per rule id that fired, sorted by id; `[]` on a clean run |
| `properties` | yes | the run-level property bag below |
| `results` | yes | the results, sorted by rule id, then the first location's uri, then its start line, then the address; `[]` on a clean run |
| `invocations` | no | plain SARIF; ctfkit uses it only for run-level notices such as `ctf.catalog.stale`, written as `toolExecutionNotifications` of one invocation |

Each `tool.driver.rules` entry needs `id` (a rule id, pattern below),
`shortDescription.text` (non-empty) and `defaultConfiguration.level`. ctfkit also writes the
plain SARIF members GitHub code scanning shows on an alert:

| Member | Value |
|---|---|
| `name` | the rule id without `ctf.`, for example `coverage.module_source`; the rule filter |
| `fullDescription.text` | the same text as `shortDescription.text` |
| `help.text`, `help.markdown` | what the rule reports, the rule's own help where it has one (`ctf.origin.provider_unpinned`), how to waive an intended finding with an exception entry, and the documentation link |
| `helpUri` | the rule's section of the [analyzer reference](https://compliance.tf/docs/ctfkit/analyzers/) |
| `properties.tags` | `compliance`, `terraform` and the rule family (the second id segment: `coverage`, `policy`, `origin`, ...) |
| `properties.precision` | `very-high`: the analyzers are deterministic reads |
| `properties.security-severity` | from the default level: `error` 7.5 (GitHub shows high), `warning` 5.0 (medium), `note` 2.0 (low) |

### Run-level property bag

| Key | Required | Value |
|---|---|---|
| `ctf.watermark` | no | one line of banner text, present only when `--watermark TEXT` is set |
| `ctf.catalogVersion` | no | `{ "version": <semver>, "origin": "embedded" \| "file" \| "home" }`: which control catalog the run read |
| `ctf.settings` | no | defined by the schema (`endpoints`, `fail_on`, `allowed_resources`); ctfkit does not emit it yet |

The run property bag is optional: a run with no banner and no catalog version
carries none. Nothing in the format claims the output is signed or attested.

`ctf.catalogVersion.origin` is `embedded` for the catalog built into the
binary, `file` for one named by `--catalog`, and `home` for one found at the
home path (`~/.ctf/control-requirements.yaml`).

## Result

| Key | Required | Value |
|---|---|---|
| `ruleId` | yes | matches `^ctf\.[a-z0-9]+(\.[a-z0-9_]+)+$`, for example `ctf.coverage.module_source` |
| `level` | yes | see [Levels](#levels) |
| `kind` | yes | see [Kinds](#kinds) |
| `message.text` | yes | non-empty, one sentence |
| `locations` | no | where the finding applies; omitted when it is about the run as a whole |
| `suppressions` | no | present when an approved exception covers the finding, see [Exceptions](#exceptions-and-suppressions) |
| `partialFingerprints` | no | ctfkit writes `ctfkitFindingHash/v1`, see [Fingerprint](#fingerprint) |
| `properties` | yes | the `ctf.*` bag below |

A location may carry:

- `physicalLocation.artifactLocation.uri`: non-empty, the path relative to the
  analysis root, POSIX separated.
- `physicalLocation.region`: `startLine`, `startColumn`, `endLine`,
  `endColumn`, each counted from 1 and omitted when unknown. ctfkit writes
  `startLine` and `endLine`, the first and last line of the block or
  `required_providers` entry the finding is about, whenever it read that
  block from a configuration file. In a `.tf.json` or `.tofu.json` file the
  region runs from the block's key to the closing brace of its object, and a
  `required_providers` entry spans its key and value. A finding anchored to
  `modules.json`, or to a file whose block the plan deleted, carries no
  region. Exceptions match on the address, never on a line.
- `logicalLocations[]`: `fullyQualifiedName` (non-empty), for example
  `aws_s3_bucket.logs`, and `kind`. ctfkit uses the kinds `resource`,
  `module` and `provider`.

### Fingerprint

`partialFingerprints["ctfkitFindingHash/v1"]` is 64 lowercase hex characters:
the SHA-256 of these fields joined with NUL bytes:

1. the rule id;
2. the first `artifactLocation.uri`;
3. the finding's subject, the resource, module or provider address an
   exception names;
4. `ctf.controlIds`, sorted and comma-joined;
5. a discriminator the analyzer sets when the fields above do not tell two
   findings apart: the served module source without its version for
   `ctf.coverage.posture_degraded` and `ctf.coverage.delegation_unresolved`,
   the obligation token for `ctf.coverage.obligation_unknown`, empty
   otherwise. The discriminator is never written to any output.

No line, column or message text goes in, so a block that moves, a test count
that changes or a served build that bumps its version keeps its value, and a
consumer such as GitHub code scanning keeps the same alert. The value is
stable only for the same file path: moving a block to another file, or
scanning from a different `--chdir` so the uri changes, gives a new value.

When two findings in one run still share that input, the second and later
ones, in result order, append their occurrence number (NUL, then `2`, `3`,
...), so every value in a run is distinct. Adding or removing such a colliding
sibling renumbers the ones after it. A change to what the hash covers ships as
a new key (`/v2`), never as a new value under `/v1`.

### Levels

| Level | Meaning | In ctfkit |
|---|---|---|
| `error` | a compliance failure | emitted |
| `warning` | a problem that does not fail the run by default | emitted |
| `note` | informational | emitted |
| `none` | SARIF's no-level value | schema only; the SDK (`pkg/ctfkit`) refuses it |

A compliance failure is a finding at `error`, never a runtime error. The exit
code compares levels against `--fail-on`.

### Kinds

| Kind | Meaning | In ctfkit |
|---|---|---|
| `fail` | the check ran and the subject did not satisfy it | emitted |
| `open` | the check could not decide | emitted, for example `ctf.policy.tagging_unresolved` |
| `pass` | the check ran and the subject satisfied it | accepted by the SDK; no built-in analyzer emits it today |
| `review` | a human must decide | accepted by the SDK; no built-in analyzer emits it today |
| `informational`, `notApplicable` | SARIF kinds | schema only; the SDK refuses them |

### Result property bag

Keys are flat dotted names (`"ctf.stage"`), not a nested `ctf` object.

| Key | Required | Value |
|---|---|---|
| `ctf.schema` | yes | the CFF version the result conforms to, `MAJOR.MINOR`; `1.0` today |
| `ctf.stage` | yes | `pre_plan`, `post_init`, `post_plan`, `pre_apply` or `post_apply`; see [stages](stages.md) |
| `ctf.controlIds` | yes | control catalog ids, sorted; `[]` when the finding maps to no single control |
| `ctf.frameworks` | yes | `[{ "id": <framework id>, "clauses": [<clause>...], "supportingClauses": [<clause>...] }]`, sorted by id; `[]` means framework agnostic. `supportingClauses` is optional, see below |
| `ctf.preventive` | yes | `true` when a compliance.tf module would have prevented the finding at source |
| `ctf.attributes` | no | resource attribute names the finding concerns, never their values; omitted rather than empty |
| `ctf.remediation` | no | the module that would have prevented the finding, see below |
| `ctf.exception` | no | what the exception registry decided, see below |
| `ctf.evidence` | no | `{ "runId", "commit", "signature" }`: the run the finding came from |

`ctf.controlIds` is the join key between the preventive module, the finding and
the evidence receipt. Framework ids use the catalog spelling, for example
`soc_2` or `pci_dss_v40`.

`supportingClauses` lists the entries of `clauses` that a module manifest at
schema 3.4 or later marks as supporting evidence: partial or indirect, never full
enforcement of the clause. It is tri-state. Absent means unknown: the source does
not classify (a manifest before 3.4, or a finding built from the control
catalog), and a reader must not take it as "nothing is hedged". An empty list
means the manifest classified and hedged nothing in that framework.

Plan and configuration values never enter a finding. `ctf.attributes` carries
names only, messages are analyzer constants formatted with names and
addresses, and URL credentials are stripped from every string.

`ctf.evidence.signature` is `null` in ctfkit output. The schema allows a
string there so a signature added later keeps existing output valid; ctfkit
does not sign today, and signing is planned. ctfkit writes `ctf.evidence` only
when it knows a run id or a commit (`--run-id`, `--commit` or the CI
environment).

### ctf.remediation

| Key | Required | Value |
|---|---|---|
| `moduleSource` | yes | the compliance.tf module source, host already substituted, for example `soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws` |
| `version` | no | the version constraint to write beside it, for example `~> 5.0` |
| `diff` | no | defined by the schema; ctfkit does not emit it yet |

`--remediation-host` picks the framework whose registry host goes into
`moduleSource`. Settings files cannot change remediation.

## Exceptions and suppressions

An exception is an entry in the registry file (`--exceptions`, default
`.ctf-exceptions.yaml` in the configuration directory) that waives one control
or one rule id on one resource until a review date. Only the runner applies it;
an analyzer cannot set `ctf.exception`.

`ctf.exception`:

| Key | Required | Value |
|---|---|---|
| `allowed` | yes | `true` when a valid exception covers the finding; `false` when the entry matched but its review date has passed |
| `ttlSeconds` | no | seconds until the review date; omitted once it has passed |
| `requiresJustification` | no | `true` when the entry carries no reason |
| `entryId` | no | the registry entry that matched (emitted by ctfkit, not named by the schema) |
| `justification` | no | the reason recorded on that entry (emitted by ctfkit, not named by the schema) |

When `allowed` is `true`, ctfkit also writes the SARIF member a SARIF reader
already acts on:

```json
"suppressions": [
  { "kind": "external", "justification": "<the entry's reason>" }
]
```

The schema allows `kind` `inSource` or `external`; ctfkit writes `external`,
because the waiver lives in the registry, not in the source. A suppressed
finding is still reported. It stops counting toward the exit code. An expired
exception gets `ctf.exception` with `allowed: false` and no `suppressions`
entry, so it counts and a reader can see the lapse.

Suppression is advisory at the format level. Approval strings are recorded
metadata, not authenticated approvals; enforcing who may approve an exception
is the job of the platform that owns the workflow.

## JSON projection and findings digest

`ctfkit scan --format json` (and `ctfkit verify-lock --format json`) writes
`findings.json`, which wraps the SARIF results array:

```json
{
  "watermark": "<present only with --watermark>",
  "catalogVersion": { "version": "<semver>", "origin": "embedded" },
  "findingsDigest": { "algorithm": "jcs-sha256/v1", "digest": "sha256:<64 hex>" },
  "findings": [ "<the SARIF result objects, byte for byte>" ]
}
```

`findingsDigest` lets a later job scan the same plan again and compare one
value instead of two documents. It hashes what the run found, never which run
found it, so two scans of the same plan give the same digest on any runner, OS
or day. It is a content digest: it does not sign the output or vouch for it.

`jcs-sha256/v1` is computed as follows:

1. For every finding, suppressed ones included, build the entry
   `{ "ruleId", "level", "kind", "message", "locations", "suppressed" }`.
   `message` is `message.text`; `locations` is the result's `locations` with
   every `\` in an artifact `uri` replaced by `/` (`[]` when there are none);
   `suppressed` is `true` when an approved exception covers the finding.
2. Write each entry in its RFC 8785 (JCS) form.
3. Sort the entries by rule id, then the first physical location's `uri`,
   then its `region.startLine`, then message text, then the canonical bytes
   of the entry.
4. Join them into one JSON array and take its SHA-256, written as
   `sha256:<lowercase hex>`. A run with no findings has the digest of `[]`.

Not in the digest: `ctf.evidence` (run id and commit), timestamps, the waiver's
`ttlSeconds`, `entryId` and `justification`, the tool and catalog versions,
`ctf.controlIds`, `ctf.frameworks`, `ctf.remediation` and `partialFingerprints`.
A pipeline that compares digests records the ctfkit version, catalog and
policy beside them. Any change to the entry fields, their normalization or the
order is a new algorithm name, never a new value under `jcs-sha256/v1`.

## Taxonomy

The schema defines `$defs/taxonomy`, a SARIF taxonomy that lists every control
id with its `framework:clause` pairs (for example `soc_2:CC6.1`), rebuilt from
the control catalog. Status: planned. No ctfkit output carries one yet.

## Versioning

- `ctf.schema` on every result carries the CFF version as `MAJOR.MINOR`.
- The schema file name carries the major: `cff-1.schema.json` validates every
  `1.x` document. Its `$id` is
  `https://compliance.tf/schema/cff-1.schema.json`.
- The property keys in `pkg/ctfkit/finding.go` are fixed for major 1; a key is
  named in the format before any implementation emits it.
- Readers should ignore properties they do not know. SARIF objects are open,
  so a later `1.x` that adds an optional key still validates against `cff-1`.

## Validating another implementation

Two checks cover a CFF file from any generator.

1. Validate against the official SARIF 2.1.0 schema with any JSON Schema
   validator.
2. Validate against `schema/cff-1.schema.json`. Any draft 2020-12 validator
   works. This repository ships one, `cmd/schemacheck`, which runs offline.

`schemacheck` walks a directory and picks the schema by file name, so put each
document at `<dir>/<case>/findings.sarif` and run it from the repository root
(it reads `schema/` relative to the working directory; `-schema-dir` changes
that):

```bash
git clone https://github.com/compliancetf/ctfkit
cd ctfkit
mkdir -p /tmp/cff/case1
cp /path/to/your/output.sarif /tmp/cff/case1/findings.sarif
go run ./cmd/schemacheck /tmp/cff
```

It exits `0` when every file validates, `1` when a file does not (each failure
names the file and the JSON pointer), and `2` when it cannot run. Besides your
files it also validates the control catalog embedded in the binary, so the
count it prints is higher than the number of files you added.

To check behavior and not just shape, run your generator on the inputs under
`testdata/fixtures/*/*/input/` and compare with the `expected/findings.sarif`
next to them. `go run ./cmd/schemacheck testdata/fixtures` is what
`make schemacheck` runs over the fixture pack itself.
