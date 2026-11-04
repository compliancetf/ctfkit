# Governed apply (preview)

ctfkit by compliance.tf can own the plan and apply steps of a Terraform or OpenTofu run, so
that only a plan whose verdict admits it gets applied, at most once. Four commands make up the
flow, all preview since v0.3.0:

| Command | Does | Network and credentials |
|---|---|---|
| `ctfkit gate plan` | runs terraform plan and writes a candidate artifact set | runs terraform `version`, `init`, `providers schema`, `plan` and `show`; terraform may use the network and your cloud credentials |
| `ctfkit gate sign` | decides the candidate and writes `verdict.json`, signed with the key `--signer` names (your AWS KMS key) | calls AWS KMS through `--signer` (network, AWS credentials); runs terraform `version`, `init` and `show -json` on a sealed copy of the planfile, no plan or apply |
| `ctfkit verdict verify` | runs every check of `apply` on an artifact set and applies nothing | runs terraform `version`, `init` and `show -json` on the sealed planfile, as `apply` does; leaves the artifact set as it is |
| `ctfkit apply` | applies the sealed plan of a checked artifact set | runs terraform `version`, `init`, `show -json` and `apply` on the sealed plan (network, cloud credentials) |

terraform `init` configures the backend, so with a remote backend every command above that runs
terraform uses the network and your backend credentials.

Of the four commands, only `gate sign` signs anything: the verdict, with your KMS key. After the
apply, `evidence ship` signs its run manifest with its `--signer` key ([evidence.md](evidence.md)).
Findings, SARIF, JSON and receipts are not signed. compliance.tf does not sign, attest or verify
anything for you. Receipt signing is planned.

## The flow

Every command takes the same signed inputs and run identity. Spelled out once:

```bash
ctfkit gate plan --out .ctfkit-artifacts \
  --dir infra --workspace default --environment prod --tf-bin /usr/bin/terraform \
  --org bobthecorp --profile profile.dsse.json --floor floor.dsse.json --bundle-dir bundles/

ctfkit gate sign --candidate .ctfkit-artifacts --signer awskms:KEY_ARN \
  --dir infra --workspace default --environment prod --tf-bin /usr/bin/terraform \
  --org bobthecorp --profile profile.dsse.json --floor floor.dsse.json --bundle-dir bundles/

# optional: every check apply makes, nothing applied
ctfkit verdict verify --artifacts .ctfkit-artifacts \
  --dir infra --workspace default --environment prod --tf-bin /usr/bin/terraform \
  --org bobthecorp --profile profile.dsse.json --floor floor.dsse.json --bundle-dir bundles/

ctfkit apply --artifacts .ctfkit-artifacts \
  --dir infra --workspace default --environment prod --tf-bin /usr/bin/terraform \
  --org bobthecorp --profile profile.dsse.json --floor floor.dsse.json --bundle-dir bundles/
```

After `apply`, `ctfkit evidence ship` uploads the provider's evidence chains and writes the run
receipt: [evidence.md](evidence.md).

Where it runs:

- GitHub Actions, three jobs with the artifact set moved between them as a workflow artifact:
  [Governed apply across three jobs](../adapters/github/README.md#governed-apply-across-three-jobs).
- Spacelift: `gate plan` as the stack's plan command, `gate sign` in `before_apply`, `apply` as
  its apply command, and a plan policy that requires the gate metadata:
  [Spacelift governed apply](../adapters/spacelift/README.md#governed-apply).
- env0 custom flow: `gate plan` in env0's plan step, `gate sign` and `apply` in its apply step,
  for Terraform and OpenTofu templates: [adapters/env0](../adapters/env0/README.md). It has run
  only against stubs, not yet on a live env0 account.

## gate plan

`ctfkit gate plan` verifies the signed bundles, org profile and floor statement, runs `version`,
`init`, `providers schema -json`, `plan` and `show -json` with a cleared environment, and writes
`planfile`, `schema.json`, `ctfkit-run.key`, `findings.sarif` and `candidate.json` (0600) to a
new `--out` directory (0700).

It reads no plan JSON from the caller and passes no terraform flag through. These exit 2 before
terraform starts:

- `-target`, `-exclude`, `-replace`, `-refresh=false`, `-refresh-only`, `-destroy`,
  `-lock=false`, `-state`, `-state-out`, `-plugin-dir` and a set `TF_CLI_ARGS*`;
- a `--dir` without `.terraform.lock.hcl`;
- any finding of the [lock file rules](analyzers.md#lock-file-rules) on the `--dir` root, for
  `aws` and any type `wrapped_providers` adds (it cannot drop `aws`), except
  `ctf.lock.upstream_present` on the `registry.terraform.io/hashicorp/aws` or
  `registry.opentofu.org/hashicorp/aws` entry, whose version the verdict binds.

The provider schema comes from the same terraform binary, data directory and locked providers
that produce the plan; gate plan takes no schema from the caller and stores the output as
`schema.json`.

Every terraform call in gate plan, gate sign, verdict verify, and apply uses a fresh copy of
`--tf-bin` from a ctfkit-owned directory. The copy comes from the bytes whose sha256 gate plan
recorded. So a binary swapped in between calls never runs. After the first `init`, the provider
packages it installed get copied into that owned directory. There they're checked against the `h1:`
hashes in the dependency lock file. Every later call installs providers only from those copies. If
the lock file lists no `h1:` hash for a package on the runner's platform, the call exits 2. Record
one with `terraform providers lock -platform=<os>_<arch>`.

The child environment holds only `PATH`, `TF_IN_AUTOMATION`, `TF_WORKSPACE` and ctfkit-owned
`HOME`, `TMPDIR`, `TF_DATA_DIR` and CLI configuration: `~/.terraformrc`,
`TF_REATTACH_PROVIDERS`, `TF_LOG*`, `LD_*`, `DYLD_*` and the CA variables never reach terraform.

`candidate.json` (`format` `compliancetf.candidate/v1`) lists the instance keys of every managed
change under the run's `ctfkit-run.key` and binds the digest of `schema.json` as
`schema_digest`. A change the instance key format cannot key (no schema entry for its type, no
prior id for an update or delete, and the other cases of the format) exits 2 and names each such
resource; no candidate is written.

Exit codes: 0 when the candidate is written (provider warnings included), 1 when
`terraform plan` fails, 2 when it could not run or refused, with no candidate written.

### Reaping orphaned sets

Run `ctfkit gate plan --reap-dir DIR`. The first thing it does is check every artifact set
directly under DIR. A set gets checked here if it was planned with the same org and profile:

- an apply that died after it started is finished as [apply](#run-custody) would finish it, at
  any age;
- a set never applied, older than the profile's `verdict.max_ttl`, with a free owner lock and no
  live owner gets a refused `result.json`, the tombstone, and its key renamed then unlinked.

The reaper never deletes a tombstone, never records a passing outcome and never changes gate
plan's exit code; it prints what it did as warnings.

## gate sign

`ctfkit gate sign --candidate DIR` takes only a candidate that gate plan wrote and the runner kept
unchanged: a 0700 directory holding exactly the files `candidate.json` lists, each 0600 and
matching its digest, and no `verdict.json` yet.

It verifies the signed inputs again (`--profile`, `--floor`, `--bundle-dir`) and refuses a
candidate planned under another profile, bundle set, content digest or floor epoch, a workspace
or environment the profile does not allow, and a `--tf-bin` other than the one gate plan ran. It
shows the planfile again with terraform (`version`, `init`, `show -json` on a sealed copy),
recomputes the instance keys with `ctfkit-run.key` and `schema.json` and refuses any difference
from `candidate.json`. A governed plan with a `registry.terraform.io/hashicorp/aws` or
`registry.opentofu.org/hashicorp/aws` resource exits 1 before anything is signed, and no
`verdict.json` is written.

Then it decides each graph control of the bundles for every managed change, and deletion guards
on the full plan, and writes `verdict.json` (0600) next to the candidate. `--format sarif`
prints the graph decisions as SARIF; without it, gate sign prints one line per graph finding
that is not a pass.

Exit codes: 0 when the shared decision state machine admits the plan and no graph finding
reaches `--fail-on` (`error`, `warning` or `note`; default `error`); 1 when the state machine
does not admit the plan or a graph finding reaches `--fail-on`; 2 when it could not run or
refused, with no `verdict.json` left. Apart from the upstream `hashicorp/aws` case above, an exit
1 still signs and writes the verdict. `apply` refuses a plan the state machine does not admit; `--fail-on` changes only gate sign's exit code,
never what the verdict admits.

### The signer

`--signer awskms:KEY_ARN` signs with an AWS KMS key of spec `ECC_NIST_P256`
(`ECDSA_SHA_256`), using the default AWS credential chain and the key's region; ctfkit assumes no
role itself. The key's id (sha256 of the public key KMS returns) must be a verdict key of the
signed org profile and not revoked, or gate sign exits 2 before KMS is asked to sign.

### Limits of gate sign

- `--break-glass` is refused.
- Same-plan creation is recorded `not_evaluable`, not `pending`.
- Exceptions and resource-local decisions are not listed yet, because they need a selector
  evaluator, so a resource-local failure blocks at apply.
- The provider always loads its embedded CIS bundle. The `--bundle-dir` must hold the
  `cis-aws` bundle from the provider release. It keeps the `manifest.dsse.json` and
  `controls.json` files. They are in `--bundle-dir/cis-aws/`. gate sign rejects a bundle set
  without it.
- The dependency lock file in `--dir` must pin both `compliancetf/aws` and `hashicorp/aws`: the
  verdict binds both versions.

## apply

`ctfkit apply --artifacts DIR` takes the same flags as gate sign, without `--signer`, and
requires the exact artifact set gate plan wrote plus `verdict.json`: no missing, extra or changed
file and no `ctfkit-run.tombstone`. Before terraform apply runs, it:

1. verifies the verdict signature against the signed org profile, its binding to
   `candidate.json` and the signed inputs, and that `ctfkit-run.key` belongs to it;
2. runs the shared decision state machine over the verdict and refuses when any decision
   blocks, a companion deletion and either half of a replace included;
3. rechecks the expiry of every listed exception and break-glass receipt against Evidence API
   time under `floor_mode: online` (unavailable: refused) or the floor statement's `issued_at`
   under `floor_mode: airgap`, never the local clock;
4. runs the same lock file check as gate plan on `--dir`;
5. runs terraform `version`, `init` and `show -json` on a sealed copy of the planfile and refuses
   a verdict that does not list exactly the plan's managed changes, deposed objects included.

Only then it runs `terraform apply -input=false` on the sealed copy, with `COMPLIANCETF_VERDICT`
(a 0600 copy of the verdict), `COMPLIANCETF_VERDICT_KEY_FILE` and, with
`--baseline-key-file PATH` (the org baseline key from the runner secret store, a 0600 file of the
runner user), `COMPLIANCETF_BASELINE_KEY_FILE` in that child's environment only; the copies live
in `ctfkit-run.staged/` of the set.

Once the set is read, every exit writes `result.json`, then `ctfkit-run.tombstone`, then unlinks
`ctfkit-run.key`, each fsynced with the directory before the next, so a set applies at most once.
SIGINT and SIGTERM end the run the same way: terraform gets SIGINT (its process group is killed
two minutes later) and the outcome is failed once terraform apply started.

Exit codes: 0 when terraform apply succeeded and nothing is pending; 1 when terraform apply
failed, a decision is pending (the post-apply linkage check is planned) or a break-glass receipt
was used; 2 when it could not run or refused, with nothing applied, and also when writing
`result.json`, writing the tombstone or removing `ctfkit-run.key` fails, which can happen after
terraform apply has run. `result.json` records the outcome.

### Run custody

- When apply runs, it takes the set's owner lock. That lock is `ctfkit-run.lock`; it records the
  pid, the process start time, and the boot id. If a set's lock is already held, a second apply
  exits 2.
- A file or directory narrowed in transport (0400, 0500) is restored to 0600 and 0700; a wider
  mode, a foreign owner or a symlink exits 2.
- `apply-start.json` is written and fsynced before terraform apply starts.
- When an earlier apply on the set died (its owner identity no longer exists: pid absent, or
  another start time or boot id), the next apply finishes it and exits 2 without running
  terraform apply again: a crash after `apply-start.json` records outcome failed, then the tombstone; a crash after
  `result.json` keeps that result and tombstones the set.

## verdict verify

`ctfkit verdict verify --artifacts DIR` runs the same checks as apply, applies nothing and leaves
the set as it is. Exit 0 when `ctfkit apply` would run terraform apply, 2 when it could not run
or refused.

## Limits of this preview

- Release builds have no Evidence API client, so `floor_mode: online` always refuses at apply.
- Exceptions, baselines and receipts are not verified yet, so a provisional decision blocks.
- The post-apply state binding and linkage check are planned. `result.json` records the result,
  and `ctfkit evidence ship --artifacts` turns it and the provider's chains into the run receipt.
- The airgap time is the floor statement of the run, not yet a high-water mark kept across runs.
- The owner lock and owner identity need Linux or macOS. Elsewhere no owner counts as gone, so
  nothing is recovered or reaped.
