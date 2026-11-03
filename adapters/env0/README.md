# env0 adapter

ctfkit by compliance.tf runs a governed apply on env0 as one custom flow file, `env0.yml`, with two
steps around env0's own plan and apply. It covers Terraform and OpenTofu templates: each hook is on
env0's Terraform step and on the matching OpenTofu step. There is no env0-specific code in ctfkit.

Status: preview. The flow has run only against stub binaries; it has not yet run on a live env0
account. The points marked [verify] below are what a live run has to confirm.

## Precondition: `verdict_required`

Use this adapter only with an org profile that sets `verdict_required`. env0 still runs its own
plan and apply after the hooks (see [What env0 still runs](#what-env0-still-runs)), a merge can
delete the hooks from `env0.yml`, and a destroy runs outside them. In each case only
`verdict_required` makes the provider refuse a mutating change that carries no verdict. Without
it, the flow governs the candidate it applies and nothing else.

| File | Goes where | Does what |
|---|---|---|
| `env0.yml` | the template folder, as `env0.yml` | Creates the candidate in the plan step, signs and applies it in the apply step |
| `flow_test.go` | Nothing; it is the offline check | Runs the hooks as written against stub `ctfkit`, `tofu` and `terraform` binaries, and fails when a Terraform hook has no matching OpenTofu hook |

## The two steps

| env0 step (Terraform / OpenTofu) | Hook | Runs | Leaves |
|---|---|---|---|
| `terraformPlan` / `opentofuPlan` | `before` | `ctfkit gate plan --out .ctfkit-artifacts` | the candidate artifact set: `planfile`, `schema.json`, `ctfkit-run.key`, `findings.sarif`, `candidate.json` |
| `terraformApply` / `opentofuApply` | `before` | `ctfkit gate sign --candidate .ctfkit-artifacts`, then `ctfkit apply --artifacts .ctfkit-artifacts` | nothing: the set is consumed |

The artifact set is created in the plan step and must reach the apply step unchanged, across the
approval [verify]. ctfkit does not trust that it did: `gate sign` and `apply` refuse a set with a
changed, missing or extra file, because each file must match its digest in `candidate.json`. When
no set is there at all, the apply step stops with exit 2 before ctfkit runs. A transfer may drop
file modes, and ctfkit refuses a set that is not a 0700 directory of 0600 files, so the apply step
first restores those modes on the regular files of the set; it changes no content.

`--out` must not exist, so a `.ctfkit-artifacts` left in the folder, committed or from anywhere
else, stops the plan step instead of being reused. Pull request plans (`prPlan`) and drift
detection apply nothing, so the plan step creates no candidate for them.

ctfkit governs no destroy. A `before` hook on env0's `terraformDestroy` and `opentofuDestroy` steps
exits 2, so a destroy deployment of the template stops before env0 destroys anything [verify the
step names on a live env0 deployment]. If that hook does not fire, `verdict_required` is the only guard against a
destroy.

Each command's exit code fails its step, and env0 stops a deployment on any non-zero exit. `gate
sign` exits 1 when the verdict does not admit the plan, so `ctfkit apply` never runs; `ctfkit
apply` exits 0 only when the run is enforced. Exit codes are listed in `ctfkit gate sign --help`
and `ctfkit apply --help`.

## Variables

Set these on the environment or project, as an admin:

| Variable | Passed as | Example |
|---|---|---|
| `CTFKIT_ORG` | `--org` | `bobthecorp` |
| `CTFKIT_ENVIRONMENT` | `--environment` | `prod` |
| `CTFKIT_PROFILE` | `--profile` | path of the signed org profile |
| `CTFKIT_FLOOR` | `--floor` | path of the signed floor statement |
| `CTFKIT_BUNDLE_DIR` | `--bundle-dir` | directory holding one directory per signed bundle |
| `CTFKIT_SIGNER` | `--signer` of `gate sign` only | `awskms:KEY_ARN` |

`--workspace` is env0's `ENV0_WORKSPACE_NAME`. A variable that is not set or is empty stops the
step before ctfkit runs. `--tf-bin` is found the same way in the plan and the apply step, so `gate
sign` and `apply` run the binary whose digest `candidate.json` records. On the OpenTofu steps it is
`tofu`, and the step exits 2 when `tofu` is not on `PATH`; it never falls back to `terraform`. On
the Terraform steps it is `tofu` when it is on `PATH` and `terraform` otherwise, and the step exits
2 when neither is there. On a runner that has both, a Terraform template therefore runs ctfkit with
`tofu`; edit both lines of the Terraform steps for such a runner.

`env0.yml` lives in the repository with the template, so a merge that edits or deletes it changes
or removes the hooks, and env0 then deploys without them. Review changes to `env0.yml` like any
other change to the deployment path. The flow cannot protect itself; `verdict_required` is the
guard that still holds when the hooks are gone.

The step names come from env0's custom flow reference: `terraformPlan`, `terraformApply` and
`terraformDestroy` for a Terraform template, `opentofuPlan`, `opentofuApply` and `opentofuDestroy`
for an OpenTofu template [verify both on a live env0 deployment]. The OpenTofu hooks run the same
text as the Terraform hooks except for the binary probe above.

## What env0 still runs

env0 documents no way to replace or skip a built-in step; a custom flow only adds hooks before and
after them. Both of env0's own steps therefore still run:

- **env0's plan** runs after `ctfkit gate plan`. It is what reviewers see before they approve, and
  it is a second plan, not the candidate: the two are made one after the other from the same state.
- **env0's apply** runs after the hook has applied the signed set, on env0's own saved plan
  [verify]. Whenever `ctfkit apply` changed anything, that saved plan is stale and terraform
  refuses it, so the deployment shows failed although the signed set was applied. When the
  candidate changed nothing, the saved plan is not stale and env0 applies it. That plan can hold
  changes the candidate did not: a data source that reads differently on each plan, an `http` or
  `external` data source, or state that moved between the two plans. Those changes carry no
  verdict. Under `verdict_required` the provider refuses every mutating change of env0's apply;
  without it they are applied ungoverned.

ctfkit does not compare env0's plan with the candidate. env0 documents no path to its saved plan
for a custom flow step, so a hook that fails when env0's `resource_changes` differ from the
candidate's would depend on an undocumented file name. That check is not built.

The signer credentials reach the apply step only if the deployment can read them; give the plan
step's role no use of the verdict key where env0 lets you separate the two.

## Checking the flow offline

```sh
go test ./adapters/env0/
```

runs the plan and apply hooks of `env0.yml` as written, once under the Terraform step names and
once under the OpenTofu ones, under `sh` and, when present, `bash`, with stub binaries on `PATH`. The stub `ctfkit` logs its arguments and behaves
like ctfkit where the flow depends on it: `gate plan` refuses an existing `--out`, `gate sign`
refuses wider modes, `apply` refuses a set with no verdict. The cases: a full deployment with
`tofu` and with only `terraform`, `prPlan` and `driftDetection`, a set left in the folder, an unset
variable, an empty variable or deployment type, no `tofu` or `terraform` on `PATH`, an unset and
an empty `CTFKIT_SIGNER` in the apply step, a set that did not reach apply, a set that is a
symlink, a verdict that does not admit the plan, a failing apply and both destroy hooks. On the OpenTofu
steps, a runner with only `terraform` stops the plan step. A separate test fails when a hook on a
Terraform step has no hook on the matching OpenTofu step, or when the two differ beyond the binary
probe.

## What the output does not claim

The flow passes ctfkit's exit codes through and adds no verdict of its own. A deployment that
skips this flow, or a template without it, has no verdict: without `verdict_required` the provider
checks single resources only and no graph control, and under `verdict_required` its mutating
applies fail closed.
