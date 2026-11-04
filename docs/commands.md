# Commands

Reference for every command of ctfkit by compliance.tf, with its flags, outputs and exit codes.
`ctfkit COMMAND --help` prints the same flags for the binary you have.

## Invocation

```
ctfkit COMMAND [flags]
ctfkit PATH... [flags]
```

- `ctfkit` with no path prints the grouped help on stdout and exits 0, also when the only
  arguments are flags (`ctfkit -f json`). `ctfkit --version` prints the version instead.
- `ctfkit PATH...` is a shortcut for `ctfkit scan --stage pre_plan PATH...`. The output is the
  same. It takes `--format`/`-f` and the global flags. For any other scan flag, use
  `ctfkit scan`.
- If the first argument is a command name, that command runs. If not, every argument is a
  path. When a path doesn't exist and looks close to a command name, it exits 2 and gives a
  suggestion: `ctfkit: no file or directory "scna"; did you mean "ctfkit scan"?`.

Commands, in the order `ctfkit --help` groups them:

| Group | Command | Does |
|---|---|---|
| Check configurations and plans | `scan` | Check a configuration (pre_plan) or a plan JSON (post_plan) |
| | `report` | Report the controls compliance.tf modules enforce, after init (preview) |
| | `verify-lock` | Check that lock files install the compliance.tf provider wrappers (preview) |
| Governed apply (preview) | `gate plan` | Run terraform plan and write a candidate artifact set (preview) |
| | `gate sign` | Decide a candidate and write `verdict.json`, signed with the AWS KMS key `--signer` names (preview) |
| | `verdict verify` | Run every check of apply on an artifact set, apply nothing (preview) |
| | `apply` | Apply the sealed plan of a checked artifact set (preview) |
| | `evidence ship` | Upload a run's evidence chains and write its receipt (preview) |
| Run tasks (preview) | `runtask serve` | Serve an advisory run task: findings and a receipt, no verdict (preview) |
| Settings and help | `config init` | Write a starter .ctfkit.yaml in the working directory |
| | `config validate` | Check a settings file and print what it sets |
| | `version` | Print the version, commit, build date, Go version and platform |
| | `completion` | Print a shell completion script |
| | `help` | Help about any command |

## Network and credentials

| Command | Network and credentials |
|---|---|
| `scan`, `report`, `verify-lock`, `config`, `version`, `completion`, `help` | offline: they never run terraform or tofu, open no network connection and need no credentials |
| `gate plan` | runs terraform `version`, `init`, `providers schema`, `plan` and `show`; terraform may use the network and your cloud credentials |
| `gate sign` | calls AWS KMS through `--signer` (network, AWS credentials); runs terraform `version`, `init` and `show -json` on a sealed copy of the planfile, no plan or apply |
| `verdict verify` | runs terraform `version`, `init` and `show -json` on the sealed planfile, as `apply` does; applies nothing and leaves the artifact set as it is |
| `apply` | runs terraform `version`, `init`, `show -json` and `apply` on the sealed plan (network, cloud credentials) |
| `evidence ship` | uploads to S3 and signs the run manifest with the AWS KMS key `--signer` names (network, AWS credentials); the receipt is not signed; runs no terraform |
| `runtask serve` | listens for HCP Terraform or Terraform Enterprise requests, downloads plan JSON from the configured host and posts the task result back (network) |

terraform `init` configures the backend, so with a remote backend the commands that run it use
the network and your backend credentials.

`gate sign` writes `verdict.json` signed with the key named by `--signer` (your AWS KMS key), and
`evidence ship` signs the run manifest with its `--signer` key. Findings, SARIF, JSON and
receipts are not signed. compliance.tf does not sign, attest or verify anything for you. Receipt
signing is planned.

## Global flags

| Flag | Meaning |
|---|---|
| `--config FILE` | settings file; see [configuration.md](configuration.md#settings-discovery) |
| `-v`, `--verbose` | verbose output |
| `--no-color` | disable colored output |
| `-h`, `--help` | help for the command |
| `--version` | the same text as `ctfkit version` |

Commands that have output formats each get a `--format`/`-f` flag. The list of formats it
accepts belongs to that command.

## ctfkit scan

Check a configuration (pre_plan) or a plan JSON (post_plan).

```bash
ctfkit scan ./infra                                   # pre_plan, no init or credentials
ctfkit scan --stage pre_plan main.tf vpc.tf           # a file list, as the pre-commit hook passes
ctfkit scan plan.json                                 # post_plan
ctfkit scan --plan out/plan.json --chdir ./infra      # anchor findings to ./infra
ctfkit scan plan.json -f sarif,json,junit --out-dir out/
ctfkit scan plan.json -f json --fail-on never > findings.json   # for OPA
ctfkit scan plan.json -f spacelift                    # writes ctfkit-scan.custom.spacelift.json
```

Positional arguments: a directory is the configuration directory; `.tf`, `.tf.json`, `.tofu`
and `.tofu.json` files are an explicit pre_plan file list; any other `.json` file is the plan.
scan never runs terraform; produce the plan JSON yourself with
`terraform show -json tfplan > plan.json` (or `tofu show -json`).

| Flag | Meaning |
|---|---|
| `--stage STAGE` | `auto` (default), `pre_plan` or `post_plan`. `auto` picks `post_plan` when a plan is given and `pre_plan` otherwise; `post_init` and `post_apply` exit 2 ([stages.md](stages.md)) |
| `--plan FILE` | plan JSON from `terraform show -json` or `tofu show -json`; also accepted as a positional `.json` file |
| `--chdir DIR` | Terraform configuration directory (default `.`); a directory positional means the same |
| `-f`, `--format LIST` | `sarif`, `json`, `text`, `pretty` (default), `junit`, `spacelift` |
| `--out FILE` | output for exactly one format; `-` is stdout |
| `--out-dir DIR` | directory for `findings.sarif`, `findings.json`, `findings.txt`, `findings.pretty.txt`, `findings.junit.xml` |
| `--fail-on LEVEL` | exit 1 at or above this level: `error` (default), `warning`, `note` or `never` |
| `--catalog FILE` | control catalog YAML, or `embedded` for the catalog built into this release ([configuration.md](configuration.md#catalog)) |
| `--exceptions FILE` | exception registry (default: `.ctf-exceptions.yaml` in the configuration directory) |
| `--remediation-host ID` | framework id whose registry host goes into the suggested module source |
| `--commit SHA`, `--run-id ID`, `--platform NAME` | run context; detected from the CI environment by default |
| `--watermark TEXT` | an optional banner line added to every output |

Outputs:

- One format goes to stdout or `--out FILE`; several need `--out-dir DIR`.
- `spacelift` writes `ctfkit-scan.custom.spacelift.json` in the working directory, always.
- The SARIF output uses [CFF](cff.md). CFF is the ctfkit findings format and a draft profile
  of SARIF 2.1.0.
- The `json` output carries `findingsDigest`, `{"algorithm": "jcs-sha256/v1", "digest":
  "sha256:<hex>"}`: the SHA-256 of the RFC 8785 form of the findings, sorted by rule id,
  location and message, with POSIX paths and no run id, commit or timestamp. Two scans of the
  same plan give the same digest, so a later job can scan again and compare one value. It is a
  content digest; ctfkit does not sign it. What it covers is in
  [CFF](cff.md#json-projection-and-findings-digest).

The rules scan runs are contained within the [analyzers.md](analyzers.md) file.

## ctfkit report

Report the controls compliance.tf modules enforce, after init (preview since v0.2.0).

```bash
terraform init
ctfkit report                                         # markdown to stdout
ctfkit report --readme README.md                      # rewrite the section between the markers
ctfkit report -f receipt,sarif,markdown --out-dir out/
ctfkit report --tests-json tests.json                 # from: tofu test -json > tests.json
```

`report` reads `.terraform/modules` after `init` and writes the Compliance coverage table, the
evidence receipt, SARIF and Spacelift metadata. It also runs the `ctf.exec.*` rules over every
module `init` installed ([analyzers.md](analyzers.md#code-that-runs-before-plan)). A module
directory it cannot read is exit 2, and so is a configuration with no compliance.tf module
manifest.

| Flag | Meaning |
|---|---|
| `--path DIR` | module root or example directory (repeatable; default `.`) |
| `-f`, `--format LIST` | `markdown` (default), `receipt`, `sarif`, `spacelift` |
| `--out FILE` | output for a single format; `-` is stdout |
| `--out-dir DIR` | directory for `report.md`, `receipt.json` and `findings.sarif` |
| `--readme FILE` | inject the markdown section between the markers in this file |
| `--markers START,END` | marker pair (default `<!-- CTFKIT_REPORT_START -->,<!-- CTFKIT_REPORT_END -->`) |
| `--tests-json FILE` | `tofu test -json` or `terraform test -json` output for this root, written by an earlier step; report runs no tests |
| `--fail-on LEVEL` | `error` (default), `warning`, `note` or `never` |
| `--catalog FILE`, `--exceptions FILE` | as for scan; `--exceptions` defaults to `.ctf-exceptions.yaml` in the working directory, when present |
| `--commit SHA`, `--run-id ID`, `--platform NAME`, `--watermark TEXT` | as for scan |

`spacelift` writes `ctfkit.custom.spacelift.json` in the working directory, a different name
from scan's, so an after_plan scan never overwrites the after_init report.

Supporting clauses: a module manifest of schema 3.4 or later can mark a framework clause as
supporting, meaning the module gives partial or indirect evidence for it. For such a clause the
table cell shows `CC7.3 (supporting)` with a one-line legend under the table, the receipt lists
the clause in `supportingClausesByFramework`, and the SARIF `ctf.frameworks` entry lists it in
`supportingClauses`. A manifest before 3.4 does not classify its clauses, so none of these marks
appears, and its clauses may still be partial. The Markdown table shows an unclassified clause
and a fully evidenced one the same way; the receipt and SARIF keep the difference.

The receipt keeps the schema id `ctf.evidence.receipt/1` while ctfkit is before 1.0, and a
release may add optional properties within `/1`. Validate a receipt against the
`schema/receipt-1.schema.json` shipped with the ctfkit release that wrote it: the schema closes
its objects, so an older copy rejects a property added later. The receipt is not signed; receipt
signing is planned.

## ctfkit verify-lock

Check that lock files install the compliance.tf provider wrappers (preview since
v0.3.0).

```bash
ctfkit verify-lock                                    # every root under ., provider aws
ctfkit verify-lock infra --provider aws --provider google
ctfkit verify-lock -f sarif --out lock.sarif
```

`ctfkit verify-lock [DIR]` checks the `.terraform.lock.hcl` of every deployable root under DIR
(default the working directory) for the wrapped provider types: `--provider` (repeatable: `aws`,
`azurerm`, `google`), else `wrapped_providers` in `.ctfkit.yaml`, else `aws`. It takes
`-f`/`--format` (the scan formats without `spacelift`), `--out` and `--out-dir`. No exception
registry applies. The rules are in [analyzers.md](analyzers.md#lock-file-rules).

verify-lock has no `--fail-on`. It exits 0 when it finds nothing and 1 on any finding, the
`ctf.lock.unwrapped` warning included. It exits 2 when it could not run, for example on a lock
file that does not parse.

## Governed apply commands

`gate plan`, `gate sign`, `verdict verify` and `apply` (preview since v0.3.0) take the
same signed inputs (`--org`, `--profile`, `--floor`, `--bundle-dir`) and run identity (`--dir`,
`--workspace`, `--environment`, `--tf-bin`). Each one's flags, checks and exit codes are in
[governed-apply.md](governed-apply.md). `gate sign` takes `-f sarif` to print its graph decisions
as SARIF, and `--fail-on` with `error`, `warning` or `note` (no `never`).

## ctfkit evidence ship

Upload a run's evidence chains and write its receipt (preview since v0.3.0). Flags,
runner class, receipt status and exit codes: [evidence.md](evidence.md).

## ctfkit runtask serve

Serve an advisory run task: findings and a receipt, no verdict (preview since
v0.3.0). It checks each request's HMAC-SHA512 signature and replay window, downloads
the run's plan JSON within a size and time limit, runs the `post_plan` analyzers, writes a
receipt per run and posts the findings back as the task result. Setup, flags and the threat
handling: [adapters/hcp](../adapters/hcp/README.md).

## ctfkit config

```bash
ctfkit config init                    # write a starter .ctfkit.yaml
ctfkit config init --force            # overwrite an existing one
ctfkit config validate .ctfkit.yaml   # check it and print what it sets
ctfkit config validate .ctfkit.yaml -f json
```

What `config init` writes and what `config validate` checks: [configuration.md](configuration.md#config-init-and-config-validate).

## ctfkit version

```
ctfkit version <version>
  commit:   <full commit sha>
  built:    2026-10-27T14:02:11Z
  go:       go1.27.3
  platform: linux/amd64
```

The commit carries a `-dirty` suffix when the binary was built from a modified tree.
`ctfkit version -f json` prints the same fields as one JSON object: `version`, `commit`, `date`,
`go_version`, `os` and `arch`. A binary built with `make build` or `go install` reads the commit
from the Go build information and shows `built: unknown`. `-f` takes `text`, `pretty` or `json`;
any other value exits 2.

## ctfkit completion

`ctfkit completion bash|zsh|fish|powershell` prints a completion script for that shell;
`ctfkit completion zsh --help` shows how to load it.

## Exit codes

The exit codes are `0`, `1` and `2`. What `1` means depends on the command; a command the `1`
row does not name never returns it.

| Code | Meaning |
|---|---|
| `0` | the command succeeded; for `scan` and `report`, nothing is at or above `--fail-on` (default `error`) |
| `1` | `scan`, `report`: unsuppressed findings at or above `--fail-on`. `verify-lock`: any finding. `gate plan`: terraform plan failed; its findings never change the exit code. `gate sign`: the plan does not pass, or a graph finding reaches `--fail-on`. `apply`: terraform apply failed, a decision is pending or a break-glass receipt was used. `evidence ship`: a receipt status other than `enforced` |
| `2` | could not run, or refused: an unreadable or invalid plan, configuration, catalog, settings, exceptions or lock file, an invalid flag, or a refused input. A refusal applies nothing; `apply` and `verdict verify` refuse a verdict that blocks a change. `apply` also exits 2 when any step of closing the set fails (writing `result.json`, writing the tombstone or removing `ctfkit-run.key`), which can happen after terraform apply has run |

A scan whose format list is exactly `spacelift` returns `0`, because the plan policy reads the
file's verdict. For `scan` and `report`, `--fail-on` precedence is the flag, then
`CTFKIT_FAIL_ON`, then `fail_on` in the settings file, then `error`. Each command's own exit codes
are in its section above and in its `--help`.
