# Spacelift adapter

ctfkit by compliance.tf runs on Spacelift as three small pieces: hooks, JSON files and a plan
policy. There is no WASM module, no custom policy engine and no Spacelift-specific code in ctfkit.


| File | Goes where | Does what |
|---|---|---|
| `config.yml` | `.spacelift/config.yml` in a **module repository** | Runs the report hook in every module test case |
| `config.stack.yml` | a **consuming stack's settings**, not a file in the repository | Runs the report and scan hooks in every stack run |
| `policy.rego` | A Spacelift **Plan policy**, attached to the stacks that run the hooks | Renders the hooks' results |
| `workflow.yml` | a **governed-apply stack's** custom workflow, mounted from a context | Makes `ctfkit gate plan` the plan command and `ctfkit apply` the apply command |
| `config.gate.yml` | the same stack's settings, next to `config.stack.yml` | Runs `ctfkit gate sign` in `before_apply` |
| `task-approval.rego` | a Spacelift **Approval policy**, attached to every `ctfkit:gate` stack (sample) | Rejects tasks on that stack |
| `test/*.json` | Nothing; they are offline checks | Policy inputs for `opa eval` |

## Two hooks, two metadata keys

A stack run carries both commands, at different points and over different inputs:

| Hook | Command | Writes | Policy reads |
|---|---|---|---|
| `after_init` | `ctfkit report` over the module cache | `ctfkit.custom.spacelift.json` | `input.third_party_metadata.custom.ctfkit` |
| `after_plan` | `ctfkit scan` over the plan JSON | `ctfkit-scan.custom.spacelift.json` | `input.third_party_metadata.custom["ctfkit-scan"]` |

Separate file names are the whole reason there are two keys: one name for both would mean whichever
hook ran last silently replaced the other one's result.

Each hook first removes the file it writes (`after_plan` also removes `plan.json`), in `config.yml`
as in `config.stack.yml`, so the policy never reads a file this run did not write. The `after_plan`
script takes the first regular file among `spacelift.plan`, `*.plan` and `*.tfplan`, runs
`show -json` on it with `tofu` when that is on `PATH` and `terraform` otherwise, and exits 1 if
that fails. With no plan file it logs one stderr line and exits 0, so the policy reports the
`ctfkit-scan` key missing. `ctfkit scan` is its last command, so a tool error still fails the hook.

### The verdict decides, not the counts

ctfkit computes a `verdict` for each file when it writes it: `fail` when any unsuppressed
error-level finding exists. The verdict does not depend on `--fail-on`, so no hook threshold can
make a failing run look clean. The policy reads that field and renders it. It never counts findings
and never re-derives a verdict of its own.

That is what makes the two files safe to read together. `module_source` and `origin.provider` run at
both stages, so one underlying problem lands under the same rule id in both files; because nothing
is counted, nothing is double counted. Each message quotes that file's own `summary` totals for the
reader, and the totals of the two files are never added together.

| Condition | Shadow mode | Enforced |
|---|---|---|
| Either file's `verdict` is anything but `pass` | `warn`, quoting the verdict and that file's totals | `deny`, same message |
| A file has no `verdict` at all | `warn`, as `verdict absent` | `deny` |
| A key is absent | `warn` | `deny` |
| A file carries an unknown `schema` | not flagged | `deny` |

`pass` is the only value that passes. A verdict this policy does not recognize, and a file with no
verdict, both fail closed, because a file it cannot read as a pass is not a pass. If the totals are
missing too, the message says `totals unavailable` rather than dropping the finding.

### Neither hook can fail the run, except on a tool error

Both stack hooks render a format list of exactly `spacelift`, which by contract exits 0 on findings.
Neither can turn a run red however its threshold is set. Exit 2, a tool error, still fails the hook,
and nothing in the recipe suppresses that: there is no `|| true` anywhere, because a hook that
silently swallowed its own failure would leave the policy reading a stale file from an earlier run.

The shadow-to-enforcement flip therefore lives in the policy, and not in a hook, where each
repository would hold its own copy of the threshold. The policy enforces on a stack when either of
two things holds: the `enforce` flag, which governs every stack at once, or the stack label
`ctfkit:enforce`, which a platform admin sets on one stack at a time. See
[The enforcement flip](#the-enforcement-flip).

### Who owns the hooks

| | Lives in | Changed by |
|---|---|---|
| Module-registry test hooks (`config.yml`) | the module repository's `.spacelift/config.yml` | whoever can merge to that repository |
| Stack hooks (`config.stack.yml`) | the stack's settings, via the Spacelift UI, API or terraform provider | a platform admin |

The split is deliberate. A module repository's test hooks gate that repository's own releases, so
they are advisory to it and belong beside its code. A consuming stack's hooks produce the evidence
the plan policy reads, so they must not sit in a file that the same pull request could delete. Put
them in stack settings and nobody can remove the hook in the change that introduces the finding.

`config.stack.yml` is therefore a reference for what to configure, not a file to commit.

### Five flags, all from the image

Both hooks pin every flag that decides an outcome, and the three file paths point into the runner
image rather than at the repository being analyzed:

| Flag | Stack value | Why it is pinned |
|---|---|---|
| `--fail-on` | `error`, from day one | A repository `.ctfkit.yaml` cannot lower the threshold, and a pinned threshold is what makes the file's `verdict` mean something |
| `--format` | `spacelift` | Exactly this list is what makes findings exit 0 |
| `--config` | `/opt/ctfkit/ctfkit.yaml` | Settings are a platform decision |
| `--exceptions` | `/opt/ctfkit/exceptions.yaml` | A repository cannot grant itself an exception |
| `--catalog` | `embedded` | Pins the catalog compiled into the binary, so a repository cannot swap in a different one and no catalog file has to be shipped with the image |

The two paths are placeholders for files baked into the image. `embedded` is not a path: it is the
literal that pins the release catalog compiled into the binary and makes ctfkit ignore any catalog
on the runner. Committing a `.ctfkit.yaml`, a `.ctf-exceptions.yaml` or a
`.ctf-control-requirements.yaml` into a stack repository has no effect, because ctfkit is never left
to discover one.

### Imported test results

`--tests-json` imports the output of `tofu test -json` or `terraform test -json` into the report, so
the receipt and the markdown section record what the tests showed. It is not pinned and not on by
default: `ctfkit report` never runs tofu or terraform, so the file has to exist before the hook runs, written
by whatever step runs the tests. Both configuration files carry the form as a commented line.

The module-registry hook writes its projections with `--out-dir .ctfkit`; ctfkit creates the
directory, so no separate step is needed.

Both stack hooks carry `--fail-on error` from day one. That does not make them enforcing: a format
list of exactly `spacelift` exits 0 on findings whatever the threshold is, so shadow mode comes from
`enforce := false` in the policy and the absence of the `ctfkit:enforce` stack label. The threshold is pinned so that a repository cannot lower it for
the exit code, not to make the verdict meaningful: the verdict is independent of `--fail-on` and
reports `fail` whenever an unsuppressed error-level finding exists, whatever the threshold says.

The module-registry hook in `config.yml` pins the same five with two differences: it renders
`receipt,spacelift`, so its exit code is a real gate, and it therefore starts at `--fail-on never`
and moves to `--fail-on error` at the flip.

## Shadow mode first

`policy.rego` ships with `enforce := false`, no stack carries the `ctfkit:enforce` label until an
admin adds it, the module-registry hook ships with `--fail-on never`, and neither stack hook can fail a run on findings at all. In that state the policy only warns: a run
can fail on its own merits, or on a ctfkit tool error, but never because ctfkit found something.
This is deliberate. Nothing starts enforcing on migration day.

## The enforcement flip

The policy enforces on a stack when `enforce` is true **or** the stack carries the label
`ctfkit:enforce`. There are therefore two ways to flip consuming stacks:

- **Per stack**: add the label `ctfkit:enforce` to one stack in its settings. That stack denies
  while `enforce` stays false for every other stack. The policy reads
  `input.spacelift.stack.labels` and compares each label in lower case, so `CTFKIT:Enforce`
  enforces too. Any other label starting with `ctfkit:`, in any case, other than `ctfkit:gate`
  (see [Governed apply](#governed-apply)), such as `ctfkit:enforce-later`, `ctfkit:gate2` or a
  typo, enforces nothing and is denied, in shadow mode too, as
  `unrecognized ctfkit label <label>; the known labels are ctfkit:enforce and ctfkit:gate`. A stack
  with no label stays in shadow mode, and removing the label rolls a stack back. Labels live in
  stack settings, so a stack cannot add or remove its own label by committing a file.
- **Every stack**: set `enforce := true` in `policy.rego`. Once it is true a label adds nothing, and
  removing a label no longer rolls a stack back.

Either way `warn` keeps firing, so an enforced stack with a failing verdict shows the same message
as a warning and as a denial. The customer walkthrough, including a Terraform provider example that
sets the label, is in the [Spacelift guide](https://compliance.tf/docs/ctfkit/spacelift/).

Flip one module repository at a time. Two edits, in this order:

1. Enforce the consuming stacks, by label or by flag as above. Their policies stop only warning and
   start denying.
2. In the **module repository's** `config.yml` only, change the report hook's `--fail-on never` to
   `--fail-on error`. From then on an error-level finding exits 1, the test case fails, and
   Spacelift creates no module version, so the report becomes the release gate. Stack hooks are not
   touched and never change: step 1 already flipped the stacks.

Enforce a stack when all of these hold:

- It has had several shadow runs, and you have reviewed their warnings.
- Every run carries both metadata keys, `ctfkit` and `ctfkit-scan`.
- No run reports an unexpected `manifest_missing` finding.

For a module repository, switch `--fail-on` once its default-branch test runs show no error-level
finding and no tool error.

Once enforcing, the policy fails closed under **either** key. A `verdict: fail` under `ctfkit` or
under `ctfkit-scan`, metadata absent under either key, and metadata carrying a schema this policy
does not know, all deny. A run where one hook silently did not execute cannot pass as a clean run.

## Checking the policy offline

`policy.rego` is written in Rego v1 and carries `import rego.v1`, so it loads on OPA 1.x with no flag
and on OPA 0.59 or later evaluating in v0 mode. OPA 0.59 added `import rego.v1`, and an older OPA
rejects the file. `opa check --v0-v1 policy.rego` confirms both modes.
`go test ./adapters/spacelift/` runs that check and evaluates the policy against every committed
`ctfkit report` Spacelift fixture. It skips when `opa` is not on `PATH`; CI installs the OPA
version pinned in `mise.toml`, so there it always runs.

Shadow mode: `warn` fires on a failing verdict and on a missing key, `deny` stays empty.

```sh
cd adapters/spacelift
for f in clean manifest-missing scan-verdict-fail verdict-absent verdict-unknown \
         scan-key-missing no-metadata unknown-schema; do
  opa eval --format pretty --data policy.rego --input "test/$f.json" 'data.spacelift.warn'
  opa eval --format pretty --data policy.rego --input "test/$f.json" 'data.spacelift.deny'
done
```

Enforced mode: the flip is a one-line edit, so check it against a flipped copy rather than keeping a
second policy in the tree.

```sh
sed 's/^enforce := false/enforce := true/' policy.rego > /tmp/policy-enforced.rego
opa eval --format pretty --data /tmp/policy-enforced.rego \
  --input test/manifest-missing.json 'data.spacelift.deny'
```

Per-stack label: no copy needed, and no label fixture is committed. `policy_test.go` injects the
labels in Go. By hand, add the label to `scan-verdict-fail.json` with `jq` and evaluate the shipped
policy, `enforce := false` and all:

```sh
jq '. + {"spacelift":{"stack":{"labels":["ctfkit:enforce"]}}}' test/scan-verdict-fail.json \
  > /tmp/enforce-label.json
opa eval --format pretty --data policy.rego --input /tmp/enforce-label.json 'data.spacelift.deny'
```

It prints the `ctfkit-scan: verdict fail (2 error, 0 warning)` message. With `ctfkit:enforce-later`
in place of `ctfkit:enforce`, `deny` holds `unrecognized ctfkit label ctfkit:enforce-later; the
known labels are ctfkit:enforce and ctfkit:gate`: an unknown `ctfkit:` label is denied even in
shadow mode, so a mistyped label cannot leave a stack ungoverned unnoticed.

| Input | Shape | Expected |
|---|---|---|
| `clean.json` | both keys present, both `verdict: pass` | nothing under either rule |
| `manifest-missing.json` | both keys `verdict: fail` | one message per key quoting its own totals, warned then denied |
| `scan-verdict-fail.json` | `ctfkit` passes, `ctfkit-scan` fails | only the `ctfkit-scan` message: either file is enough |
| `verdict-absent.json` | `ctfkit-scan` has no `verdict` field | `verdict absent`, warned then denied |
| `verdict-unknown.json` | `ctfkit-scan` has `verdict: error` and no `summary` | `verdict error (totals unavailable)`, warned then denied |
| `scan-key-missing.json` | `ctfkit` clean, `ctfkit-scan` absent | the `ctfkit-scan` key named, warned then denied |
| `no-metadata.json` | neither key present | both keys named, warned then denied |
| `unknown-schema.json` | both keys present and passing, `ctfkit-scan` carries `ctfkit.spacelift/9` | no warning; denied once enforcing, because an unreadable file is not a clean file |
`manifest-missing.json` keeps `ctf.coverage.module_source` in both halves, with different counts. It
is not counted any more, but it is the realistic shape of a rule that runs at both stages, and it
keeps the fixture honest if the policy ever goes back to counting.

## Governed apply

A stack gets graph verdicts only when `ctfkit gate plan` makes its plan and `ctfkit apply`
applies that same artifact set, unregenerated. On Spacelift that takes three pieces, all owned by a
platform admin, and one precondition.

Precondition: the org profile of a `ctfkit:gate` stack sets `verdict_required`. The `ctfkit-gate`
metadata the plan policy requires is a marker, not evidence: any command that runs during
planning can write it, including a committed `.spacelift/workflow.yml` or code terraform runs at
plan time. Only `verdict_required` makes the provider refuse an apply that carries no verdict,
whatever the policy saw. Still to confirm on a live Spacelift
account: which workflow file wins when a mounted and a committed one both exist.

| Piece | Where | Does what |
|---|---|---|
| `workflow.yml` | the stack's workflow tool set to **Custom**, the file mounted at `/mnt/workspace/source/.spacelift/workflow.yml` from a context | `plan` runs `ctfkit gate plan --out .ctfkit-artifacts`, copies the candidate's planfile to the plan file Spacelift shows and stores, then writes `ctfkit-gate.custom.spacelift.json`; `apply` runs `ctfkit apply --artifacts .ctfkit-artifacts` |
| `config.gate.yml` | stack settings, `before_apply` | restores the set's 0700/0600 modes and runs `ctfkit gate sign --candidate .ctfkit-artifacts` |
| the label `ctfkit:gate` | stack settings | makes `policy.rego` require the `ctfkit-gate` metadata on every run of the stack |

A committed `.spacelift/workflow.yml` would put the plan and apply commands in the hands of anyone
who can open a pull request, so mount it instead [verify which file wins when both exist]. The
`config.stack.yml` hooks keep running next to these: `after_plan` finds the plan file the workflow
wrote and scans it as before.

What each piece refuses:

| Situation | Refused by | Exit |
|---|---|---|
| A targeted or refresh-off plan (`.Targets`, `.Refresh`) | the workflow's `plan` | 2 |
| `.ctfkit-artifacts` already in the workspace | `ctfkit gate plan` (`--out` must not exist) | 2 |
| `ctfkit gate plan` fails | the workflow's `plan`; the stale `ctfkit-gate` file is removed first, so none is left | its exit code |
| The plan file Spacelift holds at apply is not byte for byte the candidate's planfile | the workflow's `apply`, before `ctfkit apply` runs | 2 |
| The set did not reach apply, or is a symlink | the `before_apply` hook, and the workflow's `apply` | 2 |
| `tofu` is not on `PATH`, or `tofu workspace show` fails or prints nothing | the workflow's `plan` and `apply`, and the `before_apply` hook, before ctfkit runs | 2 |
| The verdict does not admit the plan | `ctfkit gate sign`, which fails the hook | 1 |
| A changed, missing or extra file in the set | `ctfkit gate sign` and `ctfkit apply` | 2 |
| A destroy | the workflow's `destroy`: there is no governed destroy yet | 2 |

The plan file check is what makes a regenerated plan fail: the plan the policy evaluated and the
reviewers saw must be the candidate, and `ctfkit apply` then applies its own sealed copy of the
signed set, never Spacelift's file.

`--workspace` is the workspace Spacelift selected (`tofu workspace show`). The other inputs come
from the stack environment: `CTFKIT_ORG`, `CTFKIT_ENVIRONMENT`, `CTFKIT_PROFILE`, `CTFKIT_FLOOR`,
`CTFKIT_BUNDLE_DIR` and `CTFKIT_SIGNER`; a variable that is not set stops the command. The workflow
runs `tofu`; replace it with `terraform` throughout on a Terraform stack. Keep the signer
credentials out of the planning phase where you can [verify how to scope them to apply].

Not yet confirmed on a live Spacelift account [verify]: that the workspace, with `.ctfkit-artifacts`
and its modes, is kept from planning to apply; that Spacelift runs workflow commands through a
shell; and that metadata written by the `plan` command reaches the plan policy.

### What the policy requires

| Stack | `ctfkit-gate` metadata | Result |
|---|---|---|
| labelled `ctfkit:gate`, in any case | present, schema `ctfkit.spacelift-gate/1` | allowed |
| labelled `ctfkit:gate`, in any case | absent | `deny`, in shadow mode too |
| any | present, schema absent or unknown | `deny` |
| no `ctfkit:gate` label | absent | allowed: no verdict, so the provider checks each resource on its own and no graph control decides (single-resource-only) |
| no `ctfkit:gate` label, `verdict_required := true` in the policy | absent | `deny` |
| any other label starting with `ctfkit:`, such as `ctfkit:gate2` | any | `deny`, in shadow mode too |

The gate rules do not wait for the enforcement flip: the label is the admin's statement that the
stack applies only through `ctfkit apply`, and without it they deny nothing. Set
`verdict_required := true` in `policy.rego` when the org profile sets `verdict_required`; the
provider refuses a mutating apply without a verdict either way, and the policy then refuses the
run at plan, before anyone approves it.

Any other label starting with `ctfkit:` is denied on every stack, in shadow mode too (see
[The enforcement flip](#the-enforcement-flip)); `ctfkit:gate2` does not make a gate stack.

The metadata file only says that the plan command ran, and anything that runs during planning can
write it. It is not evidence of a verdict: the verdict is checked by `ctfkit apply`, against the
signed org profile, and `verdict_required` is what refuses an apply without one.

### Tasks

A Spacelift task runs an arbitrary command in the stack's workspace with the stack's
credentials, outside the custom workflow, so it can change infrastructure without `gate plan`,
`gate sign` or `ctfkit apply`. Attach `task-approval.rego` as an Approval policy to every
`ctfkit:gate` stack: it rejects any run of type `TASK` on a stack with that label, in any case, and
approves every other run, leaving the decision to any other approval policy attached. Spacelift
replaced task policies with approval policies [verify on a live account that a task is rejected].

### Checking the governed apply offline

`go test ./adapters/spacelift/` also runs the workflow and the `before_apply` hook as written, with
stub `ctfkit` and `tofu` binaries, rendering the commands with Go's `text/template` (cases: plan,
sign and apply; a targeted replan; refresh off; a failing gate plan with a stale metadata file; a
regenerated plan file at apply; a set that did not reach apply; a set that is a symlink at apply;
an empty workspace and a failing `tofu workspace show`; a verdict that does not admit the plan;
destroy). It evaluates the policy against these inputs, with the shipped policy and with a copy
that sets `verdict_required := true`, with the labels as committed and with case variants,
`ctfkit:gate2` and `ctfkit:enforce` added:

| Input | Shape | Expected |
|---|---|---|
| `gate-clean.json` | `ctfkit:gate` label, both report keys passing, `ctfkit-gate` present | nothing, with or without `verdict_required` |
| `gate-missing.json` | `ctfkit:gate` label, no `ctfkit-gate` | denied: the stack's plan command must be `ctfkit gate plan` |
| `gate-unknown-schema.json` | `ctfkit-gate` in `ctfkit.spacelift-gate/9` | denied |
| `gate-schema-absent.json` | `ctfkit-gate` with no `schema` | denied, as schema `absent` |
| `gate-not-gate-stack.json` | no `ctfkit:gate` label, no `ctfkit-gate` | nothing; denied once `verdict_required` is set |

## Running the live cases

The recipe has to pass both kinds of module-test run before the flip:

- **Proposed run**: open a pull request against the module repository. Spacelift starts a proposed
  test run; confirm the hook ran, that `ctfkit.custom.spacelift.json` is in the run's working
  directory listing, and that the log shows the receipt summary.
- **Tracked run**: merge to the default branch. Spacelift starts a tracked test run and, on success,
  creates a module version. Confirm the same two things, then check that a stack consuming the new
  version shows the ctfkit warning in its plan policy evaluation.

The stack case is checked the same way with `config.stack.yml`: attach `policy.rego` as a plan
policy, trigger a run, and read the policy evaluation on the plan. Confirm that both
`ctfkit.custom.spacelift.json` and `ctfkit-scan.custom.spacelift.json` are present and that neither
overwrote the other.

## Runner image

Both config files name `<your-registry>/ctfkit-runner:<tag>`. compliance.tf publishes no Spacelift
runner image: build one on a Spacelift runner base image with a pinned, checksum-checked ctfkit
release (v0.3.0 or later) on `PATH`, push it somewhere your Spacelift workers can pull from, and
replace the placeholder. The recipe is in the [Spacelift guide](https://compliance.tf/docs/ctfkit/spacelift/).
It builds on `public.ecr.aws/spacelift/runner-terraform`, which is Alpine, runs as user
`spacelift` (uid 1983) and has `curl` but neither `jq` nor `gh`.

Releases of `compliancetf/ctfkit` download without a token, and the runner needs none at run
time: the binary is already in the image.

The recipe checks the archive against `checksums.txt`, which comes from the same release as the
archive, so it shows the download is intact, not who published it. To pin the archive you
reviewed as well, pass its digest from that `checksums.txt` as a build argument and check it next
to the checksums line of the download step; an empty argument skips the check:

```dockerfile
ARG CTFKIT_SHA256=""
# in the download RUN, after the checksums.txt check:
    if [ -n "$CTFKIT_SHA256" ]; then \
      echo "$(echo "$CTFKIT_SHA256" | tr 'A-F' 'a-f')  $tarball" | sha256sum -c -; fi; \
```

The digest is lower-cased first, as the GitHub Action does, so a digest copied in upper case still
matches. It is per archive, so an image built for both amd64 and arm64 needs one per architecture.
A release that carries a GitHub build provenance attestation can also be checked on the build host
before the image is built, with `gh attestation verify <archive> --repo compliancetf/ctfkit
--signer-workflow compliancetf/ctfkit/.github/workflows/release.yml --source-ref
refs/tags/v<version>`. Every release published here carries one; see
[Authenticating the download](../github/README.md#authenticating-the-download).

The container image built from the `Dockerfile` at the root of this repository cannot be the runner
image. It is distroless with no shell, and Spacelift runs hooks through a shell.

The image needs the settings and exception files at the two `/opt/ctfkit/` paths. It needs no
catalog: `--catalog embedded` uses the one compiled into the binary, so the catalog is pinned by the
binary version and cannot drift from it.

## What the output does not claim

The policy renders findings; it does not turn them into an attestation. It does not read the
optional `watermark` field.
