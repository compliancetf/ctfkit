# Stages

A stage is the point in a Terraform or OpenTofu workflow at which an analyzer
runs. The set is frozen in `pkg/ctfkit/analyzer.go`; adapters, `ctf.stage` and
adapter manifests use the exact strings. Input shapes per stage are in
`pkg/ctfkit/doc.go`.

The analyzers never evaluate a configuration (`internal/loader/loader.go`).
`scan`, `report` and `verify-lock` never run terraform or tofu, open no
network connection and need no credentials. `gate plan`, `gate sign`,
`verdict verify` and `apply` run terraform themselves;
[commands.md](commands.md#network-and-credentials) lists what each command runs
and reaches. What an analyzer can know depends on
what Terraform has already produced by that stage.

## Timeline

```
 edit .tf
     |
     +-------> pre_plan        ctfkit scan <dir>
     |
 terraform init
     |
     +-------> post_init       ctfkit report
     |
 terraform plan -out=tfplan
 terraform show -json tfplan > plan.json
     |
     +-------> post_plan       ctfkit scan --plan plan.json
     |
     +-------> pre_apply       (reserved: same plan.json, right before apply)
     |
 terraform apply tfplan
     |
     `-------> post_apply      (reserved: reads state)
```

In CI a PR job usually covers `pre_plan` through `post_plan`; `pre_apply`
matters only where the platform runs apply as a separate, later step.

## Stages at a glance

| Stage | Input | Entry point | Analyzers |
|---|---|---|---|
| `pre_plan` | `.tf`, `.tf.json`, `.tofu` and `.tofu.json` files, lock file (every `pre_plan` analyzer reads all four) | `scan` (default for a directory or file list), `ctfkit PATH...` | `ctf.origin.*`, `ctf.policy.floating_ref*`, `ctf.policy.disabled_control*`, `ctf.coverage.module_source*`, `ctf.exec.provisioner`, `ctf.exec.external_data`, `ctf.exec.module_uninspected`, `ctf.lock.*` (when `wrapped_providers` is set) |
| `post_init` | config + `.terraform/modules`: manifests and every installed module's `.tf`, `.tf.json`, `.tofu` and `.tofu.json` files | `report` | `ctf.coverage.*` (manifest, posture, delegation, obligation, attestation, tests), `ctf.exec.*` (provisioners and `external` data sources at any depth, endpoints of modules a module calls, local modules outside the root) |
| `post_plan` | plan JSON (`terraform show -json`) | `scan --plan` | `ctf.risk.sensitive_change_*`, `ctf.policy.tagging*`, `ctf.coverage.module_source*`, `ctf.origin.provider*` |
| `pre_apply` | plan JSON, same shape as `post_plan` | none yet | none; reserved for platforms that split plan and apply |
| `post_apply` | state | none; `scan --stage post_apply` exits 2 | none; reserved |

## pre_plan

Use for: fast feedback in an editor, pre-commit or a PR before any credentials
exist. Checks things people write as literals: provider and module sources,
version constraints, pinning, control opt-outs, and the provisioners and
`external` data sources in the files scan reads, `../` local modules beside
the directory included (`ctf.exec.provisioner`, `ctf.exec.external_data`),
which works for any configuration, with or without a compliance.tf module.

Limits:
- HCL is parsed, not evaluated. Only literal values resolve
  (`Expr.Value(nil)`); `var.*`, `local.*`, functions, `count`, `for_each` and
  module outputs do not.
- No resource contents: nothing about encryption, exposure or tags can be
  decided here.
- Module sources are known, module contents are not (no `init` yet).

## post_init

Use for: coverage questions that need downloaded modules, such as which module
versions are in use and what they attest, without a plan. Also the last point
at which code a module brings can be stopped before it runs: `plan` reads
`external` data sources and `apply` runs provisioners, and both can come from a
module several levels down. The `ctf.exec.*` rules read every installed module
here, before either step, and check the source of every module a module calls
(the root's own calls are `ctf.coverage.module_source`'s at `pre_plan`). A
`./` or `../` local module is read even when it lies outside the configuration
directory; one whose directory cannot be read stops the run (exit 2).
`ctf.exec.module_uninspected` is a warning at both stages: at `pre_plan` for a
`../` directory that is not there before `init` or, in an archive built
without a call graph (not a file list), a local call to a directory it does
not carry, and at `post_init` for a module block `modules.json` holds no
record for.

Limits:
- Still no evaluated values and no provider calls.
- Not a `scan` stage: `scan --stage post_init` exits 2 and points to `report`.

## post_plan

Use for: everything about what will change. Terraform has already resolved
variables, locals, functions, `count` / `for_each`, nested modules and provider
defaults (for example `default_tags` merged into `tags_all`), so any valid
configuration works here.

Limits:
- Values marked unknown until apply (`after_unknown`) are never guessed. A rule
  that depends on one stays silent; `ctf.policy.tagging_unresolved` reports
  unknown tags explicitly.
- Needs a plan, so it needs credentials, `init` and a successful `plan`.
- Resource rules are tied to provider resource types and attribute names
  (moving them into versioned rule packs is planned).

## pre_apply and post_apply

Part of the contract so adapters and findings can name them. No analyzer runs
at either today. `pre_apply` would reuse `post_plan` inputs on platforms that
run apply as a separate step; `post_apply` would read state for drift and
applied values. [threat-model.md](threat-model.md) describes the planned design
for binding the analyzed plan to the applied one.

## Choosing a stage

- No credentials or before `init`: `pre_plan`.
- Module coverage and attestation: `post_init` via `report`.
- Security-relevant changes, tags, anything about resource values: `post_plan`.
