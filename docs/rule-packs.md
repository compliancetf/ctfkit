# Rule packs

ctfkit by compliance.tf keeps Terraform provider knowledge in data, not in analyzer code. A
rule pack describes one provider major version: its resource type prefix, which attributes
hold tags, and the sensitive-change rules for its resources. Packs are embedded in the binary
at build time, the way the release catalog is; a run never reads a pack from disk or the
network, and a scanned repository cannot supply one.

Five analyzers read packs:

| Analyzer | Reads |
|---|---|
| `ctf.risk.sensitive_change_*` | the rules and `controls.yaml` of the pack for each changed resource's provider |
| `ctf.policy.tagging` | the tag attributes of the pack for each changed resource's provider |
| `ctf.coverage.module_source` | the resource prefix of every pack: only those resources are migration candidates |
| `ctf.graph.companion` | `identities.yaml`: which identity form each resource attribute holds |
| `ctf.exec.external_data` | `program_data_sources` in `defaults.yaml`: the data source types that run a local program |

A test in `internal/analyzer` fails on any string literal in analyzer code that holds a
pack's resource prefix, so a provider fact written into Go is caught in CI.

| Pack | Status | Covers |
|---|---|---|
| `aws/v6` | available | the five sensitive-change classes, controls, tags |
| `google/v8` | available | a proof pack: Cloud SQL instance deletion protection, bucket and instance deletion or replacement, labels for tagging |

## Layout

```
internal/rulepack/rules/
  defaults.yaml                  tag attributes for a provider no pack describes, providers
                                 with no rules, data source types that run a program
  aws/v6/
    provider.yaml                provider facts
    controls.yaml                catalog controls per type and attribute (optional)
    identities.yaml              identity catalog for graph controls (optional)
    public_exposure.yaml         the rules of one class
    wildcard_iam.yaml
    audit_log_removal.yaml
    encryption_disablement.yaml
    destructive_stateful.yaml
    schema.json                  trimmed provider schema the pack is validated against
```

The directory under `rules/` is the provider, the one below it is `v<major>`. Only the YAML
files are embedded; `schema.json` is read by the tests and the generator. Every YAML file
is read strictly: an unknown key is an error, so a misspelled argument fails the build's tests
instead of switching a rule off.

## Pack selection

Each resource change in a plan records its provider address, such as
`registry.opentofu.org/hashicorp/aws`. The pack is the one whose `source` equals the last two
segments of that address, whatever the registry host. When the configuration has a
`.terraform.lock.hcl` entry for the provider, the pack for the locked major version is used;
with no entry, or no pack for that major, the newest pack of the provider is used. When the
lock file pins a major that has no pack, `scan` says so in one stderr line, for example
`ctfkit: hashicorp/aws 5.x has no rule pack; checked with aws/v6`, since attribute names
differ between majors.

A provider no pack describes has no sensitive-change rules. That is not an error: `scan`
prints one stderr line naming the providers concerned, and its tags are read from the
attributes `defaults.yaml` names. Providers that manage no infrastructure, such as
`hashicorp/random`, `hashicorp/null` or the built-in `terraform` provider of
`terraform_data`, are listed under `no_rules` in `defaults.yaml` and left out of that line.

`program_data_sources` in `defaults.yaml` lists the data source types that run a program on
the machine that plans the configuration, as a `data` block writes the type: today
`external`, from `hashicorp/external`. `ctfkit scan --stage pre_plan` and `ctfkit report`
report every such block with `ctf.exec.external_data`. The type is listed here rather than in a provider pack because the
rule does not depend on the provider version.

## provider.yaml

```yaml
source: hashicorp/aws          # namespace/type, lower case, no registry host
resource_prefix: aws_          # every resource type of the provider starts with it
dialect: aws                   # optional: a Go plug-in with provider-specific predicates
tags:
  attribute: tags              # the resource's own tag map
  effective: tags_all          # optional: the provider-computed map with defaults merged in
  provider_default: default_tags.tags   # optional: provider-level defaults, dot path
```

`provider_default` walks the provider configuration: every step but the last is a nested
block, the last is the attribute that holds the map. A value that is not a constant is left
out, since the effective map carries it once the provider resolves it.

## Rule files

A rule file declares one class and lists its rules:

```yaml
class: encryption_disablement
rules:
  - types: [aws_ebs_volume, aws_efs_file_system]
    attribute: encrypted
    predicate: turned_off
    or_removed: true
    level: error
```

The class is one of `public_exposure`, `wildcard_iam`, `audit_log_removal`,
`encryption_disablement` and `destructive_stateful`, the suffix of the rule id
`ctf.risk.sensitive_change_<class>`.

| Field | Meaning |
|---|---|
| `types` | resource types the rule applies to, each starting with the pack's `resource_prefix` |
| `kinds` | instead of `types`: a map from type to the word a message uses for it (`{kind}`) |
| `attribute` | the attribute the predicate reads |
| `attributes` | shorthand for one rule per attribute, in list order |
| `predicate` | the check, from the table below |
| `level` | `error`, `warning` or `note` |
| `message` | optional template; `{address}`, `{attributes}` and `{kind}` are its placeholders |
| `when` | optional map of attribute to string value the planned object must have |

For one resource, the rules of a class run in file order. A whole-resource predicate
(`deleted`, `replaced`) that fires ends the class for that resource, which is why a delete of
a public access block is reported once, as a delete. A message never carries a value from the
plan, only the address, attribute names and the rule's own words.

### Predicates

Every predicate but the dialect ones reads `change.before`, `change.after` and
`change.after_unknown` only, and an attribute unknown at plan time never fires.

| Predicate | Fires when | Arguments |
|---|---|---|
| `turned_off` | the attribute is true before and false after | `or_removed: true` also reports true before and absent after, as a removal; `as_string: true` also reads the strings `"true"` and `"false"`, for an attribute that became a string in this major (a plan from the previous major, judged by this pack, still has the bool) |
| `turned_on` | the attribute is not true before and true after | |
| `removed` | the attribute is set before and empty after | |
| `block_removed` | the nested block is present before and absent after | `flag`: instead, the first block's flag is true before and not after |
| `narrowed` | the list after is a strict subset of the list before | |
| `shortened` | the number decreases | `zero_is_unlimited: true`: 0 means no limit |
| `deleted` | the plan deletes or replaces the resource | `message`, or `kinds` for the default message |
| `replaced` | the plan replaces the resource; names the attributes forcing it | `kinds` (required) |
| `value_in` | the planned string value is one of `values` | `values`, `message` (required); `unset`: attributes that must be empty and known |
| `open_cidr` | ingress is open to `0.0.0.0/0` or `::/0` | `ipv4`, `ipv6`; `attribute` for a nested block list of rules; `ports: [from, to]` with `note_ports` lowers the level to note for a single listed port |

The `aws` dialect adds the IAM policy predicates:

| Predicate | Fires when | Arguments |
|---|---|---|
| `policy_any_principal` | the policy document allows any principal with no Condition | |
| `policy_wildcard_action` | the policy allows `*` on every resource with no Condition (at `level`), or a service-wide wildcard such as `s3:*` (at `service_level`) | `service_level` (required); `field`: the attribute is a block list and each element's field is a document |

## controls.yaml

```yaml
controls:
  aws_ebs_volume:
    encrypted: [ebs_volume_encryption_at_rest_enabled]
```

A finding about an attribute carries a control id only when the pack names one for that type
and attribute and the loaded catalog covers the type with it.

## identities.yaml

The identity catalog `ctf.graph.companion` reads to decide whether a companion resource,
such as a bucket's public access block, belongs to its target. Two resources link only
when the companion's link attribute and a target attribute hold known, equal values in
the same form, through the same provider configuration, with equal `scope` attributes.
The provider configuration is the plan's `provider_config_key`, which Terraform resolves
through module calls (inherited defaults and `providers = {...}` maps, at any depth and for
every `count` or `for_each` instance of a module). A key missing from `provider_config`, a
configuration whose arguments reference `each.*` (an OpenTofu provider `for_each`) and two
different keys, even with identical arguments, are `ambiguous_reference`.

```yaml
scope: [region]                  # attributes two linked resources must agree on
forms:                           # anchored patterns; a value is in the first form it matches
  arn: {pattern: '^arn:[a-z0-9-]+:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:.+$'}
  s3_bucket_name: {pattern: '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'}
attributes:                      # per type and attribute, its forms in match order
  aws_s3_bucket: {id: [s3_bucket_name], bucket: [s3_bucket_name], arn: [arn]}
```

A value is classified by its attribute's own forms first, then by every other form whose
pattern starts with a literal (`arn:`, `vpc-`). A form with no literal prefix, such as a bucket
name, also matches ids of other kinds, so it is never matched outside the attributes that
declare it. A value in another form than the target holds (an ARN against a name) is an
alias, a value in no form it may be read as is a catalog miss, and an attribute the catalog does not name is a catalog miss
too: when a candidate companion exists, each makes the decision `not_evaluable`, never
a pass or a fail (with no candidate of the companion type the target fails). Every attribute named
here must be a string attribute in the pack's schema snapshot, which a test checks.

## Schema snapshots

`schema.json` is a trimmed `terraform providers schema -json` of the provider version the pack
was last checked against: every attribute of each resource type a rule, `controls.yaml` or
`identities.yaml` names (nested blocks and objects one level down), and, for every other type, only the
attributes whose names match the tracked patterns (`encrypted`, `*encryption*`, `kms_key_id`,
`publicly_accessible`, `deletion_protection*`, `*logging*`, `retention_*`).

`TestSchemaSnapshots` in `internal/analyzer/sensitivechange` holds every pack to its snapshot.
Each resource type and attribute a rule reads, each nested field (`flag`, `field`, `ipv4`,
`ipv6`, `ports`), each `unset` and `when` attribute, and each `controls.yaml` entry must exist,
with a kind the predicate reads: `turned_off` reads a bool, `shortened` a number, and so on. A
failure names the pack, the file, the predicate and the resource type. It runs in `make check`
like every other test, so a rule that names an attribute the provider does not have fails CI
instead of never firing.

## Weekly refresh

`.github/workflows/rule-pack-schemas.yml` runs every Monday and on demand. It runs
`scripts/refresh-rule-pack-schemas.sh`, which for each pack installs the newest provider
release within the pack's major, regenerates `schema.json` with `cmd/rulepackgen`, and writes
draft rules for tracked attributes that are new since the previous snapshot and that no rule
reads yet. It then runs the snapshot test and opens or updates one pull request,
`chore/rule-pack-schemas`, with the snapshots, the validation result and the drafts. A pull
request opened with the job token does not start the Test workflow, so the `pull-request` job runs
the rule pack and analyzer tests on the files it commits. When validation and those tests pass and
every changed file is a `schema.json` snapshot, the job squash-merges the pull request; snapshots
are not embedded, so the binary does not change and the `chore` commit opens no release. Anything
else, including a validation or test failure, stays open for a person and fails the run. Draft
rules are never merged: each one changes findings, so a person checks the attribute in the
provider documentation and adds it in a `feat(rulepack)` pull request.

The workflow pins the Terraform release it generates with (`TERRAFORM_VERSION`) and runs in two
jobs. `generate` installs the providers and runs their binaries with a read-only token, then
uploads the rules directory and the pull request body as an artifact. `pull-request` holds the
write scopes, copies only that directory in, and opens the pull request.

When a provider's newest release has a major version no pack covers, the script first copies
the provider's newest pack to `v<major>`, so the pull request shows what the new major broke.
Fix the rules the validation names, then merge.

The same refresh runs locally with Terraform and network access:

```bash
scripts/refresh-rule-pack-schemas.sh /tmp/proposals
go test ./internal/analyzer/sensitivechange/ -run Schema
```

## Adding a provider

1. Create `internal/rulepack/rules/<provider>/v<major>/provider.yaml` with the source,
   resource prefix and tag attributes.
2. Add rule files using the generic predicates. A provider needs Go only for semantics a rule
   file cannot express, such as a policy language: add a dialect file beside
   `internal/analyzer/sensitivechange/dialect_aws.go` that registers its predicates, and name
   it in `dialect`.
3. Run `scripts/refresh-rule-pack-schemas.sh` to write `schema.json`, then
   `go test ./internal/analyzer/sensitivechange/ ./internal/rulepack/`.
4. Add a test with a plan of that provider, as `provider_test.go` does for `google/v8`.

Nothing else changes: pack selection, `ctf.coverage.module_source` and `ctf.policy.tagging`
pick the new provider up from its pack.
