# Threat model: plan-to-apply binding

Status: **planned** design. Apart from the findings digest, nothing on this page has code
behind it yet. Receipt signing and the other open work are listed in
[Work items](#work-items). An interactive view of the chain and threats is in
[threat-model.html](threat-model.html) (open the file locally; GitHub shows HTML as source).

This page answers two questions for ctfkit by compliance.tf:

1. Can a pipeline show that the plan ctfkit analyzed and a reviewer approved is the plan
   Terraform or OpenTofu applied?
2. What stays open before anyone can say the infrastructure and its compliance.tf modules are
   compliant?

The design came out of a five-round multi-model security review on 2026-09-28. It ended
unresolved on implementation details. No voice disputed the direction. The details raised in
the last round are folded in below.

## Short answer

Embedding a random nonce in the plan adds almost nothing. `sha256(tfplan)` is already unique
per plan. Terraform also refuses a saved plan whose state has moved on. What links approval to
apply is:

1. A signed statement `S` whose subject is `sha256(tfplan)`.
2. An independent check in the apply job. It decrypts that exact plan file, derives
   `plan.json` again, scans it again and compares the result with `S`.
3. One principal that can apply, and nothing else holds apply rights.
4. A single-use ledger keyed on the digest of `S`.

A nonce written to state as a root `output` would link state to a plan. It needs a change to
the customer's configuration and the ledger already stops replay, so it is optional and not
in the first phase.

The claim this supports is "applied as analyzed". It never supports "compliant".

## What Terraform guarantees, and what it does not

Verify each item on the pinned Terraform and OpenTofu versions before relying on it.

| Behaviour | Covers | Does not cover |
|---|---|---|
| `apply tfplan` uses the configuration snapshot stored in the plan file | root and module source as planned | provider plugin code, `TF_*` environment, CLI configuration (`dev_overrides`, `provider_installation`), backend credentials, anything executed at apply |
| Saved plan refused when state changed | state lineage and serial | cloud drift, a different target account |
| `.terraform.lock.hcl` checksums | provider packages at `init` | modules (no module hashes), apply time, `dev_overrides` |

The plan file itself does not pin provider code. Provider integrity rests on the lock hashes
checked at `init` against an allowlist.

## Binding design

The adapter runs every `terraform`, `tofu`, `cosign` and cloud call. ctfkit stays offline and
key-free. It computes findings and digests only.

### Workflows and identities

- **Feedback workflow** (`pull_request`): plan and scan for PR comments only. It never
  produces `S` and shares no artifacts with the apply path. Fork PRs get no cloud role.
  Internal PRs use a sandbox read role with no production state access.
- **Apply workflow**: runs on push to a protected branch, or `workflow_dispatch` from that
  branch (checked with `github.ref`). No input affects plan or apply. One concurrency group
  per environment, never cancelled in progress.
- **Plan role**: read-only, least privilege.
- **Apply role**: the only principal with write rights. Its trust policy requires the
  environment OIDC `sub`, the reusable apply workflow's `job_workflow_ref` pinned by SHA, and
  a fixed audience.
- Runners hold no static cloud credentials. The adapter clears `AWS_*`, `GOOGLE_*`, `ARM_*`
  and `VAULT_*` statics and uses OIDC only.
- Rulesets on the protected branch, workflows and the policy source: pull request required,
  code-owner review required, no bypass actors, no force push.

### Policy outside the scanned repository

Today `.ctfkit.yaml`, `.ctf-exceptions.yaml` and `CTFKIT_FAIL_ON` sit in or next to the
repository being scanned, so a change can relax its own check. The effective policy comes
from a code-owner-reviewed source outside that repository, pinned by commit. Its digest goes
into `S`, and the verifier enforces it:

- ctfkit settings, exceptions, fail-on, and the list of permitted `?disable=` controls;
- allowed ctfkit versions and catalog digests, and allowed Terraform and OpenTofu binary digests;
- provider allowlist: source, version and lock hashes;
- per environment: backend and workspace, account, apply role, provider target identities,
  and allowed reviewer accounts;
- signing trust root and maximum statement age.

### Chain

1. **Plan job.**
   - Clear `TF_*` and `TF_CLI_*` and set only the adapter's CLI configuration.
   - Check module sources before `init` (pre_plan), and check backend, workspace and lock
     entries against policy.
   - After `init`, reject provisioners, `external` data sources and module endpoints that
     are not allowed, including those in downloaded modules (post_init). This runs before
     `plan`, so the code never runs.
   - Plan, `show -json`, then scan.
   - Encrypt both artifacts with KMS: the plan role can only encrypt and the apply role can
     only decrypt. Keep them 7 days or less.
   - Findings and digests go to the job summary.
2. **Sign job** (the receipt-signing pattern).
   - Recomputes what it can itself: commit, tree, lock file, policy digest and ciphertext
     digests.
   - Records the plan job's digests as plan-job claims, together with the run id, run
     attempt and actor.
   - Signs `S`.
3. **Approval.**
   - Reviewers approve the apply environment after reading the plan and sign summaries on the
     run page.
   - The apply job reads the run's approval history from the GitHub API and requires an
     approved reviewer from the policy list.
   - The reviewer must not be the run actor, the dispatch actor, the PR author or the merger.
     These are GitHub account ids; git author strings do not count.
   - `S.run_attempt` must equal the current attempt, so a re-run of only the apply job with
     an old `S` fails.
4. **Apply job.** Each step fails closed, in this order:
   - Verify the signature on `S` and its timestamp age.
   - Check the policy allowlists.
   - Check the caller identity, the lock file and the CLI configuration against `S`.
   - Run `init`.
   - Decrypt the plan file to a private read-only path and check its digest.
   - Compare the plan's configuration snapshot with the commit tree.
   - Run `show -json` and `ctfkit scan` again and compare the canonical findings digest and
     the change set with `S`.
   - Check the backend and provider identities against policy, and read the live state
     lineage and serial.
   - Write the ledger `claimed` entry.
   - Apply that exact file.
   - Always write a terminal ledger state with the exit code.
5. **Ledger** (DynamoDB).
   - The key is the digest of `S`. Transitions go forward only and terminal states never
     change. No pipeline role can delete.
   - A conditional put of `claimed` comes strictly before apply. A job that loses the race
     stops without applying.
   - Exit 0 with an unchanged serial means `noop` for an empty change set and `unknown`
     otherwise.
   - The ledger is exported continuously to object-locked storage for the evidence period.
6. **Reconcile.** A separate scheduled workflow moves `claimed` rows older than the apply
   timeout plus a margin to `unknown`. An `unknown` row closes only when a fresh plan shows
   no changes.
7. **Post-apply record.** A separate job signs what it observes itself: the ledger row, the
   state lineage and serial, and the digest of `S`.
8. **Break-glass.** Direct human credentials, `-target`, `-replace`, or proceeding during an
   outage go only through a labeled path. That path is always reported as "not applied as
   analyzed".

## Threats, ranked

| Rank | Id | Threat | Mitigation |
|---|---|---|---|
| Critical | A1 | ctfkit scans `plan.json` while Terraform applies the binary plan file, and nothing binds them | same-job scan, then re-derive and re-scan at apply |
| Critical | A2 | another apply path: bare `apply` (re-plans), another workflow, human credentials | exclusive apply role, rulesets, protected-branch trigger |
| Critical | C1 | policy in the scanned repository relaxes its own check (`.ctfkit.yaml`, exceptions, `CTFKIT_FAIL_ON`, `?disable=`, `continue-on-error`) | out-of-repo policy enforced by the verifier |
| Critical | A3 | code at apply time: provisioners, `external` programs, `TF_*` environment, `dev_overrides` | rejected at post_init and in the plan configuration, environment allowlist, provider allowlist |
| Critical | S1 | plan artifacts hold secrets in plaintext | KMS split encrypt/decrypt, short retention, digests in logs |
| Critical | A5 | a change redirects state through backend or workspace settings | per-environment policy, live serial check |
| High | B1 | module manifests are self-asserted: a forked module can claim a control is enforced | `attestations.complianceTf` stays empty and nothing says "verified" until compliance.tf signs module digests and manifests |
| High | A4 | artifact swap, `workflow_run` poisoning, cache poisoning, persistent runners | ephemeral runners, no caches, digest checks at apply |
| High | D1 | a signature proves the workflow, not a person | approval history, reviewer allowlist, account-based separation of duties |
| High | A6 | the plan is not tied to the commit it claims | configuration snapshot compared with the commit tree |
| High | - | PR code reads data at plan time through data sources | least-privilege plan and feedback roles, no cloud role for forks |
| Residual | - | `after_unknown`, ephemeral and write-only values; non-literal provider identity; drift; state tampering; resources outside Terraform; process controls | named in the claim |
| Residual | - | a party who can rewrite the files on the CI runner rewrites a whole provider evidence chain and recomputes its hash links; `ctfkit evidence ship` detects an edit to part of a chain, not a full rewrite | known limit; closing it needs chain heads signed by the provider or the signed acknowledgement of the Evidence API, plus signed receipts (planned); release builds have no Evidence API client yet, so `--api` always spools |

## The claim evidence can support

> Plan `sha256:<X>`, whose configuration matches commit `<C>` on `<branch>`, analyzed by
> ctfkit `<version>` with catalog `<digest>` under policy `<digest>` with findings `<F>`
> (derived again at apply), approved by `<reviewer>` (not the actor, PR author or merger) in
> run `<R>` attempt `<A>`, was applied once by the apply role to
> `<account>/<backend>/<workspace>`; state `<lineage>` moved from serial `<n>` to `<m>`.
> Not covered: `after_unknown`, ephemeral and write-only values, non-literal provider
> identity, provider behaviour at apply, drift after apply, module manifest authenticity,
> data read at plan time by PR code.

The words "compliant", "signed" or "verified" do not appear in ctfkit output until the
matching work ships.

## Open items

- The layout of the plan zip (`tfconfig/`) is internal to Terraform and OpenTofu. The commit
  binding must pin it per version and fail closed on anything unknown.
- Confirm the GitHub approval-history response schema (reviewer, environment, state) on the
  pinned API version.
- Confirm which `plan.json` markers exist on the pinned versions (deferred changes,
  provisioners in `configuration`). `-target`, `-replace` and `-refresh=false` are not read
  from `plan.json`; the adapter builds the command line itself.

## Work items

| Work | Status |
|---|---|
| detached signing of receipts (existing design) | planned |
| post_init analyzer: provisioners, `external` data sources, transitive module endpoints | planned |
| effective policy from outside the scanned repository | planned |
| canonical (JCS) findings digest: `findingsDigest` in the scan `json` output ([CFF](cff.md#json-projection-and-findings-digest)) | available |
| commit binding: plan configuration snapshot against the commit tree | planned |
| adapter apply binding: re-derive, re-scan, single-use ledger | planned |
| compliance.tf signed module digest and manifest, checked at post_init | planned |

The first phase doesn't cover a few things. A nonce output in state is out of scope. So are the
Spacelift and HCP Terraform adapters, and drift analyzers. The `scan`, `report`, and `verify-lock`
commands never run `terraform` or `tofu`. But `gate plan`, `gate sign`, `verdict verify`, and
`apply` do run them. That detail is in [governed-apply.md](governed-apply.md).
