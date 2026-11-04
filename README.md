# ctfkit

**Run the same Terraform and OpenTofu checks across your pipelines.**

ctfkit by compliance.tf is an Apache-2.0 analyzer runtime for Terraform and OpenTofu. It
turns configuration, plans and module manifests into consistent SARIF findings and an
evidence receipt, and hands its results to the policy workflow you already have. Its checks
(`scan`, `report`, `verify-lock`) run offline in your CI: no network connection and no cloud
or Terraform credentials. When a compliance.tf module would have prevented a finding, it names
the exact module source.

Try it on a directory of `.tf` files, before `terraform init`:

```bash
ctfkit scan ./infra
```

Release archives, Linux packages and checksums: [Install](#install).

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go)](https://go.dev/)

## What it does and does not do

ctfkit produces findings. OPA, tfpolicy or your own CI logic decide what to do with them, and
it runs alongside Sentinel. Tools like Checkov, Trivy and tfsec tell you a resource is
misconfigured. ctfkit tells you what your estate requires, and which module closes each gap.

- `scan`, `report`, `verify-lock` and `config` run offline: they never run terraform or tofu
  and need no network or credentials. `report --readme` and `config init` write files.
- The preview commands reach further ([per command](docs/commands.md#network-and-credentials)):
  `gate plan` and `apply` run terraform; `gate sign` and `verdict verify` run only terraform
  `version`, `init` and `show -json` on the sealed plan; `gate sign` and `evidence ship` call
  AWS KMS; `evidence ship` uploads to S3; `runtask serve` downloads plan JSON from HCP Terraform
  and posts results back.
- `gate sign` writes `verdict.json` signed with the key named by `--signer` (your AWS KMS key),
  and `evidence ship` signs the run manifest with its `--signer` key. Findings, SARIF, JSON and
  receipts are not signed. compliance.tf does not sign, attest or verify anything for you.
- There is no IDE integration.

## Status

This is pre-1.0. Everything below is labeled available, preview or planned; nothing labeled
planned has code behind it today. Releases before v0.3.0-preview.3 were not published here.

| Capability | Status | Since |
|---|---|---|
| `scan`: credential-free analysis of a configuration (`pre_plan`) or its plan JSON (`post_plan`) | available | v0.1.0 |
| SARIF ([CFF](docs/cff.md)), JSON, text, pretty, JUnit and Spacelift metadata output | available | v0.1.0 |
| Pre-commit hook `ctfkit` | available | v0.1.0 |
| Pre-commit hook `ctfkit-scan-dir`, for module repositories | available | v0.3.0-preview.1 |
| Resource-type, provider and tag allowlists | available | v0.1.0 |
| [OPA example](adapters/opa/README.md): a Rego policy that decides on `scan -f json` output | available | v0.2.0 |
| `report`: reads the module cache after `init` and writes README markdown, an evidence receipt, SARIF and Spacelift metadata; reports code that runs before plan in modules at any depth | preview | v0.2.0 |
| Analyzer SDK (`pkg/ctfkit`) and conformance harness | preview | v0.2.0 |
| [GitHub Action](adapters/github/README.md) and [Spacelift](adapters/spacelift/README.md) adapters | preview | v0.2.0 |
| `verify-lock`: lock files install the compliance.tf provider wrappers, not the upstream providers | preview | v0.3.0-preview.1 |
| [Governed apply](docs/governed-apply.md): `gate plan`, `gate sign`, `verdict verify`, `apply`; `floor_mode: online` refuses, as release builds have no Evidence API client yet | preview | v0.3.0-preview.1 |
| [Spacelift governed apply](adapters/spacelift/README.md#governed-apply) | preview | v0.3.0-preview.1 |
| [env0 custom flow](adapters/env0/README.md); run only against stubs, not yet on a live env0 account | preview | v0.3.0-preview.1 |
| [`evidence ship`](docs/evidence.md): provider evidence chains to S3 Object Lock and the provider-run receipt; `--api` always spools | preview | v0.3.0-preview.1 |
| [`runtask serve`](adapters/hcp/README.md): an advisory HCP Terraform and Terraform Enterprise run task | preview | v0.3.0-preview.1 |
| Container images (`ghcr.io/compliancetf/ctfkit`), SBOMs and build provenance attestations for release files | preview | v0.3.0-preview.3 |
| Homebrew cask, receipt signing | planned | |

## Install

Every release on [GitHub Releases](https://github.com/compliancetf/ctfkit/releases) has
archives for Linux, macOS and Windows, Linux packages and `checksums.txt`:

```bash
V=0.3.0-preview.4 # x-release-please-version
gh release download "v$V" --repo compliancetf/ctfkit \
    --pattern "ctfkit_${V}_Linux_x86_64.tar.gz" --pattern checksums.txt &&
  awk -v f="ctfkit_${V}_Linux_x86_64.tar.gz" '$2 == f' checksums.txt | sha256sum -c - &&
  tar -xzf "ctfkit_${V}_Linux_x86_64.tar.gz" ctfkit &&
  sudo install -m 0755 ctfkit /usr/local/bin/ctfkit &&
  ctfkit version
```

Other platforms, deb, rpm and apk packages, a download without `gh`:
[docs/install.md](docs/install.md).

## Daily commands

```bash
ctfkit scan ./infra                    # pre_plan: .tf files before init, no credentials
ctfkit ./infra                         # the same, short form
ctfkit scan plan.json                  # post_plan: terraform show -json tfplan > plan.json
ctfkit scan plan.json -f sarif --out findings.sarif
ctfkit scan plan.json -f json --fail-on never > findings.json   # for OPA
ctfkit report                          # after terraform init (preview)
ctfkit config init                     # write a starter .ctfkit.yaml
ctfkit config validate .ctfkit.yaml    # check it
```

`ctfkit` alone prints help. All flags: [docs/commands.md](docs/commands.md).

## Pre-commit

<!-- x-release-please-start-version -->
```yaml
repos:
  - repo: https://github.com/compliancetf/ctfkit
    rev: v0.3.0-preview.4
    hooks:
      - id: ctfkit
```
<!-- x-release-please-end -->

| Hook id | Runs | Pick it for |
|---|---|---|
| `ctfkit` | `ctfkit scan --stage pre_plan <staged files>` | a repository of deployable roots |
| `ctfkit-scan-dir` | `ctfkit scan --stage pre_plan .` | a module repository: the directory scan tells reusable modules from deployable roots |

Both run on `.tf`, `.tofu`, `.tf.json` and `.tofu.json` files and build from source; for an
installed binary, see [docs/install.md](docs/install.md#pre-commit-hook).

## CI

- [GitHub Action](adapters/github/README.md) (preview; plan scans; governed apply in three jobs from
  this repository's workflow template, which needs ctfkit-action v0.3.0, not published yet): its
  default `command: report` reads the module cache, so it needs `init` to have run. For the path with no init, plan or credentials, use `command: scan`:

  ```yaml
  - uses: compliancetf/ctfkit-action@v0.2.1
    with:
      command: scan
      stage: pre_plan
      chdir: infra
      version: v0.3.0-preview.4    # ctfkit release to install; x-release-please-version
  ```
- Spacelift (preview): stack hooks, plan policy and governed apply:
  [adapters/spacelift](adapters/spacelift/README.md).
- OPA (available): a Rego policy over `scan -f json` output: [adapters/opa](adapters/opa/README.md).
- env0 (preview): a custom flow for governed apply: [adapters/env0](adapters/env0/README.md).
- HCP Terraform and Terraform Enterprise run task (preview): `ctfkit runtask serve`, advisory
  findings and a receipt per run: [adapters/hcp](adapters/hcp/README.md).
- Any other CI: `ctfkit scan infra -f sarif --out findings.sarif`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | nothing at or above `--fail-on` (default `error`) |
| `1` | unsuppressed findings at or above `--fail-on`; a `-f spacelift` run alone returns `0`, because the plan policy reads the file's verdict |
| `2` | could not run, or refused: an unreadable or invalid plan, configuration, catalog, settings or exceptions file, or an invalid flag |

`--fail-on` is `error`, `warning`, `note` or `never`; the flag wins over `CTFKIT_FAIL_ON`, which
wins over `fail_on` in the settings file.

## Configuration

`.ctfkit.yaml` is optional. `scan` reads it from the configuration directory, `report` from the
working directory, `verify-lock` from its `DIR`, unless `--config FILE` names one. Any pull
request can edit it, so a CI run that must hold regardless passes `--config`, `--exceptions`,
`--catalog` and `--fail-on` from outside the repository.

```yaml
allowed_providers:
  - registry.terraform.io/hashicorp/aws
required_tags: [Owner, Environment]
fail_on: error
```

Every key, `allowed_endpoints` included, and the exception registry:
[docs/configuration.md](docs/configuration.md).

## Documentation

| Page | Covers |
|---|---|
| [docs/install.md](docs/install.md) | archives, packages, checksums, pre-commit with an installed binary |
| [docs/commands.md](docs/commands.md) | every command and flag, network and credentials per command, exit codes |
| [docs/analyzers.md](docs/analyzers.md) | every rule, rule packs, code that runs before plan, lock file rules |
| [docs/configuration.md](docs/configuration.md) | `.ctfkit.yaml` keys, the exception registry, the catalog |
| [docs/stages.md](docs/stages.md) | what each stage can and cannot see |
| [docs/governed-apply.md](docs/governed-apply.md) | `gate plan`, `gate sign`, `verdict verify`, `apply`, run custody, preview limits |
| [docs/evidence.md](docs/evidence.md) | `evidence ship`, runner class, receipt status, known limit |
| [docs/cff.md](docs/cff.md) | CFF, the findings format |
| [docs/rule-packs.md](docs/rule-packs.md) | rule pack format and adding a provider |
| [docs/threat-model.md](docs/threat-model.md) | threats and the planned plan-to-apply binding |

The documentation site is <https://compliance.tf/docs/ctfkit/>, with a
[Spacelift integration guide](https://compliance.tf/docs/ctfkit/spacelift/) (preview): runner
image recipe, stack hooks, plan policy, per-stack `ctfkit:enforce` label. Related:
[compliance.tf](https://compliance.tf), the module registry whose requirements ctfkit reports
against, and [antonbabenko/pre-commit-terraform](https://github.com/antonbabenko/pre-commit-terraform),
the hook framework this plugs into.

## Contributing

Bug reports and feature requests are welcome as
[issues](https://github.com/compliancetf/ctfkit/issues); report a vulnerability as described in
[SECURITY.md](SECURITY.md). Pull requests come from maintainers only. Building and testing from
source: [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0. See [LICENSE](LICENSE).

Maintained by Anton Babenko - [@antonbabenko](https://github.com/antonbabenko).
