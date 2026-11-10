# Configuration

ctfkit by compliance.tf reads two optional files: the settings file `.ctfkit.yaml` and the
exception registry `.ctf-exceptions.yaml`. With neither, every command runs on built-in
defaults.

## Settings discovery

`--config FILE` names the settings file. Without it, these commands look in one directory:

| Command | Looks for `.ctfkit.yaml` in |
|---|---|
| `scan` | the configuration directory: `--chdir` or the directory argument, else the working directory |
| `report` | the working directory |
| `verify-lock` | the `DIR` argument (default: the working directory) |
| `gate plan` | the `--dir` directory |
| `runtask serve` | the working directory |

Of the commands not in this table, only `config validate` reads a settings file: the one you name.
`gate plan` and `runtask serve` use the settings for the post_plan rules they run. `scan` does the
same on a plan.

If no file is provided, the program uses built-in defaults. That's not an error. When `scan`
falls back to the working directory, it prints the directory name on one stderr line. It does
this once, after the run completes. Stdout stays the same.

`report` reads the settings file even when `--fail-on` is given, because `allowed_endpoints`
decides `ctf.exec.module_endpoint`; a settings file that does not load is exit 2.

The settings file is part of the scanned repository, so anyone who can open a pull request can
edit it. A run whose settings a pull request must not change passes `--config`, `--exceptions`,
`--catalog` and `--fail-on` from outside the repository. The
[Spacelift hooks](../adapters/spacelift/README.md) do this.

## Keys

| Key | Read by | Default | Meaning |
|---|---|---|---|
| `allowed_endpoints` | `scan`, `report`, `gate plan`, `runtask serve` | absent | the hosts a compliance.tf module source may use; see [below](#allowed_endpoints) |
| `allowed_resources` | `scan`, `gate plan`, `runtask serve` | empty: every type | resource types `ctf.origin.provider` allows |
| `allowed_providers` | `scan`, `gate plan`, `runtask serve` | empty: every provider | provider sources `ctf.origin.provider` allows: full sources such as `registry.terraform.io/hashicorp/aws`, namespaces or registry hosts |
| `tags` | `scan` (post_plan), `gate plan`, `runtask serve` | none | tag rules `ctf.policy.tagging` checks on planned resources |
| `required_tags` | `scan` (post_plan), `gate plan`, `runtask serve` | none | shorthand: each key becomes a required `tags` rule with no value constraint |
| `wrapped_providers` | `verify-lock`, `scan --stage pre_plan` | `aws` for `verify-lock`; unset for `scan` | provider types compliance.tf wraps here: `aws`, `azurerm`, `google`. `verify-lock` checks them, and `scan --stage pre_plan` runs the [lock file rules](analyzers.md#lock-file-rules) when the key is set |
| `fail_on` | `scan`, `report` | `error` | the exit-1 threshold when neither `--fail-on` nor `CTFKIT_FAIL_ON` is set |

### allowed_endpoints

Leave the key out, and any module source host that ends in `.compliance.tf` counts as a
compliance.tf endpoint. This works the same as running with no settings file. If you set the
key, only the hosts you list count. For example, a module from `bobthecorp.compliance.tf` needs
its own entry. Entries are host names, and the comparison is case-insensitive. A leading
`https://` and a trailing `/` are ignored. An empty list - `allowed_endpoints: []` - is a
configuration error. That exits with code 2.

`ctf.coverage.module_source` and `ctf.exec.module_endpoint` judge module sources against it;
ctfkit makes no request with it.

### tags

Each `tags` entry has a `key` and at most one value constraint:

| Field | Meaning |
|---|---|
| `key` | required; the tag key |
| `required` | `true` when a planned resource must carry the tag |
| `allowed_values` | the values the tag may take |
| `pattern` | an RE2 pattern the value must match; the alternative to `allowed_values` |
| `resource_types` | the resource types the rule applies to; empty means every taggable resource |

Rules on `hashicorp/google` resources check labels. See [analyzers.md](analyzers.md#rule-packs).

### fail_on precedence

The `--fail-on` flag accepts four values: `error`, `warning`, `note`, or `never`. For `scan` and
`report`, precedence runs like this: the flag wins over the `CTFKIT_FAIL_ON` environment variable.
That variable wins over `fail_on` in the settings file. And the settings file wins over the built-in
`error`.

### Unused keys

`fail_on_control_disable`, `disable_patterns` and `fail_fast` are accepted in a settings
file but not used: `scan` and `report` ignore them and `ctfkit config init` does not write them;
`config validate -f json` prints them. An empty `disable_patterns: []` is a
configuration error, exit 2.

## Example

```yaml
# Leave allowed_endpoints out to admit any host ending in .compliance.tf.
# List hosts to admit only those:
# allowed_endpoints:
#   - soc2.compliance.tf
#   - bobthecorp.compliance.tf

# Optional allowlists. Empty means everything is allowed.
allowed_resources: []
allowed_providers:
  - registry.terraform.io/hashicorp/aws

# Tag policy for planned resources.
tags:
  - key: Owner
    required: true
    resource_types: [aws_s3_bucket]     # empty means every taggable resource
  - key: CostCentre
    pattern: "^CC-[0-9]{4}$"            # RE2; allowed_values is the alternative
required_tags: [Environment]            # shorthand for required tags entries

# Provider types compliance.tf wraps here: aws, azurerm, google. verify-lock checks them
# (default aws); scan --stage pre_plan runs its rules when this is set.
wrapped_providers: [aws]

# Exit-1 threshold when neither --fail-on nor CTFKIT_FAIL_ON is set.
fail_on: error
```

## config init and config validate

Run `ctfkit config init` and it drops a starter `.ctfkit.yaml` into the current directory. The
`allowed_endpoints` line stays commented out, with the explanation above it. A fresh file
therefore gives the same findings as no file. If a `.ctfkit.yaml` already exists, the command
won't overwrite it. To overwrite it, pass `--force`.

`ctfkit config validate .ctfkit.yaml` loads a settings file and reports the first error. When the
file loads, it prints `allowed_endpoints` and `fail_on` as ctfkit reads them; `-f json` prints
every key. A file that does not load is exit 2.

## Exceptions

An exception waives a finding for one resource, with an approver and a review date. The registry
is a YAML file: `--exceptions FILE`, or else `.ctf-exceptions.yaml` in the same discovery root as
the settings file. For `scan` that is the configuration directory, and for `report` the working
directory. No file means no exceptions, which is not an error. `verify-lock` reads no exception
registry.

```yaml
schema_version: "1.0"

exceptions:
  - rule: ctf.coverage.module_source
    resource: aws_s3_bucket.logs
    justification: "Scratch bucket for ETL output; it stays a raw aws_s3_bucket on purpose."
    approved_by: compliance@bobthecorp.example
    approval_ticket: SEC-4711
    review_date: "2027-06-01"
```

| Key | Rule |
|---|---|
| `control` or `rule` | exactly one per entry: a control id, or a rule id such as `ctf.policy.floating_ref`. Findings with no control id, such as the provider and pinning checks, need a `rule` entry. A `control` entry matches only ids the loaded catalog holds; the embedded catalog holds the CIS v6.0 controls only ([catalog](#catalog)) |
| `resource` | required; the address of the resource the exception covers |
| `approved_by`, `approvals` | at least one approver across the two; `approvals` is a list |
| `review_date` | required, `YYYY-MM-DD` in UTC; the exception holds through the end of that day |
| `id` | entry id; falls back to `approval_ticket` |
| `justification` | free text, kept with the entry |
| `schema_version` | optional; when present its major version must be `1` |

An entry without an approver or without a review date never suppresses anything. An expired
entry stops suppressing the day after its review date, and the finding comes back. These are
errors, exit 2: an entry that names both `control` and `rule`, or neither; an entry with no
`resource`; two entries for the same control or rule and the same resource; a file that does not
parse. Keys ctfkit does not read, such as `organization` or `compensating_controls`, are allowed
and kept for your own records.

A suppressed finding still appears in the output with its `suppressions` entry and counts as
`suppressed` in the summary line; it does not affect the exit code or the Spacelift verdict.
An exception matches one address exactly, and no exception covers an address that holds
`<unresolved>` ([analyzers.md](analyzers.md#where-a-module-directory-may-be)).

## Catalog

Control ids and replacement module sources come from a control catalog. The catalog embedded in
the binary holds the CIS AWS Benchmark v6.0 controls only, each with its CIS v6.0 clauses, and the
compliance.tf module entries. It needs no network or token, so every run has a catalog. The full
catalog, with every control and every framework, is a separate file: name it with
`--catalog FILE`, or place it at `~/.ctf/control-requirements.yaml`, which
[`ctfkit catalog pull`](commands.md#ctfkit-catalog-pull) writes. `--catalog embedded` pins the embedded catalog and ignores the
home file; the GitHub Action and Spacelift configurations pass it by default. With the full
catalog, set the action's `catalog` input to `pull`, or give either adapter the file. `--remediation-host ID` picks the framework whose
registry host goes into the suggested module source.

With the embedded catalog, a control outside CIS v6.0 is a control the catalog does not hold:

- `ctf.coverage.delegation_unresolved` names the id in its message and carries no
  `ctf.controlIds`; `report` still completes. When a catalog holding the id is loaded, the
  finding carries it again and its fingerprint changes.
- `?disable=` of such a control is `ctf.policy.disabled_control_unknown`, an error like
  `ctf.policy.disabled_control`, with no control id.
- `ctf.risk.sensitive_change_*` findings still fire, without a control id or frameworks.
- An exception entry keyed by `control` matches only ids the loaded catalog holds; use a `rule`
  entry to waive such a finding.

A `ctf.coverage.module_source` finding on a raw resource lists only the controls the suggested
module enforces. The catalog can place more controls on the same resource type, and those are
left off, because the finding does not claim the module closes them.
