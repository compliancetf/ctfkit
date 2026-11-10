# GitHub Actions adapter

ctfkit by compliance.tf runs in GitHub Actions as a composite action. The action installs one
pinned release of the binary, verifies it against the release checksums, runs one ctfkit command
over what your workflow already produced, uploads the findings to the Security tab and writes the
markdown report to the job summary.

For `report` and `scan` the action does not run `init`, `plan`, `test`, `tag`,
`commit` or `release`. Your workflow owns those, and the action reads what they produced. `plan`,
`sign` and `apply` run ctfkit's gate commands, which run terraform themselves; see
[Governed apply across three jobs](#governed-apply-across-three-jobs).

## Commands

| `command` | Reads | Runs | After your workflow has run |
|---|---|---|---|
| `report` (default) | the module cache, via `path` | `ctfkit report` | `init` |
| `scan` | plan JSON, via `plan` | `ctfkit scan` | `init`, `plan`, `show -json` |
| `scan` with `stage: pre_plan` | configuration in `chdir` | `ctfkit scan --stage pre_plan` | checkout only |
| `plan` | configuration in `chdir`, signed inputs | `ctfkit gate plan --out <artifacts>` | checkout, terraform or tofu installed |
| `sign` | the candidate in `artifacts` | `ctfkit gate sign --candidate <artifacts>` | `plan` in an earlier job, the artifact downloaded |
| `apply` | the signed set in `artifacts` | `ctfkit apply --artifacts <artifacts>` | `sign` in an earlier job, the artifact downloaded |

`plan` is required when `command: scan`, unless `stage: pre_plan`, which reads configuration only
and refuses a `plan`; the action fails with a clear message either way. `path` and `format` apply to
`report` only. `scan` always renders SARIF, because feeding the Security tab is the reason to run it
here, plus ctfkit's text output for the job summary. `stage` is `auto` (the default), `pre_plan` or
`post_plan` for `scan`, passed as `--stage`; for `report` it is `post_init`.

## Usage

The action lives in the public `compliancetf/ctfkit-action` repository, and it downloads the
binary from the releases of the public `compliancetf/ctfkit` repository with the default job
token; to install from a private copy, see
[Installing from a private copy](#installing-from-a-private-copy).

Examples on this page use `compliancetf/ctfkit-action@v0`, which follows the newest v0 release of
the action, and leave out `version`, so the action installs the newest ctfkit release. For a
reproducible pipeline, pin both: the action to a release commit SHA (Dependabot can bump it) and
`version` to the ctfkit release you reviewed, such as `version: v1.2.3`. `sha256` needs a pinned
`version`.

```yaml
permissions:
  contents: read
  security-events: write   # required for the Security tab upload

steps:
  - uses: actions/checkout@v7

  # report: coverage from the module cache
  - run: tofu init -input=false
    working-directory: examples/complete
  - uses: compliancetf/ctfkit-action@v0
    with:
      path: examples/complete

  # scan: findings from the plan
  - run: |
      tofu plan -input=false -out=tfplan
      tofu show -json tfplan > plan.json
    working-directory: examples/complete
  - uses: compliancetf/ctfkit-action@v0
    with:
      command: scan
      plan: examples/complete/plan.json

  # pre_plan scan: configuration only, no init, no plan, no credentials
  - uses: compliancetf/ctfkit-action@v0
    with:
      command: scan
      stage: pre_plan
      chdir: examples/complete
```

`workflow-template.yml` in this directory is the fuller module-author pattern: a matrix over roots
and examples, an init step that holds the registry token, a test run, then both commands.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `command` | `report` | `report`, `scan`, `plan`, `sign` or `apply` |
| `path` | `.` | Module root or example directory, passed as `--path`. `report` only |
| `tests-json` | none | Output of `tofu test -json` or `terraform test -json` for the same root, written by an earlier step, passed as `--tests-json`. `report` never runs tofu or terraform itself. `report` only |
| `plan` | none | Plan JSON from `show -json`. Required for `scan` unless `stage: pre_plan`, which refuses it; ignored for `report` |
| `chdir` | none | Terraform configuration directory, passed as `--chdir`: the one the plan was made from, or the one a `pre_plan` scan reads (`.` when empty); see [Scanning one root of several](#scanning-one-root-of-several). `scan`; for `plan`, `sign` and `apply` it is passed as `--dir` |
| `version` | `latest` | ctfkit release to install: `latest`, the newest stable release when the job runs, or a release version with or without the leading `v`, such as `v1.2.3`; anything else is refused. The `ctfkit-version` output names the release installed |
| `sha256` | none | SHA-256 of the release archive for the runner's OS and architecture. The download must match it; see [Authenticating the download](#authenticating-the-download) |
| `verify-attestation` | `false` | `true` checks the archive with `gh attestation verify` against the build provenance attestation of the release workflow for the requested tag, and fails the step when it does not verify |
| `repository` | `compliancetf/ctfkit` | Repository whose release holds the archive and `checksums.txt`. It is the repository `.goreleaser.yml` publishes to |
| `github-token` | `${{ github.token }}` | Token for the release download only; the default reads public releases. See [Installing from a private copy](#installing-from-a-private-copy) |
| `fail-on` | `error` | Lowest level that fails the step: `error`, `warning`, `note`, `never`. `sign` takes `error`, `warning` or `note` |
| `config` | bundled | ctfkit settings file |
| `exceptions` | bundled | Exception registry |
| `catalog` | `embedded` | Control catalog: `embedded` pins the one in the binary, `pull` downloads the full catalog (paid plan, token in `TF_TOKEN_registry_compliance_tf`), or a path; see [Nothing is read from the checkout](#nothing-is-read-from-the-checkout) |
| `sarif` | `true` | Upload the findings to the Security tab. Set `'false'` on a private repository without code scanning |
| `pr-comment` | `false` | Keep one comment with the job summary on the pull request; see [Pull request comment](#pull-request-comment) |
| `comment-token` | `${{ github.token }}` | Token for the pull request comment only, never used for the download |
| `format` | `receipt,sarif,markdown` | Comma-separated report formats. `report` only; `spacelift` is refused |
| `artifacts` | none | Artifact set directory. `plan` creates it; `sign` and `apply` read it. Required for those three |
| `workspace`, `environment`, `tf-bin`, `org`, `profile`, `floor`, `bundle-dir` | none | Passed as the gate flags of the same names (`--tf-bin` an absolute path). `plan`, `sign` and `apply` |
| `signer` | none | Verdict signer URI, such as `awskms:KEY_ARN`. `sign` only |
| `verify-lock` | `false` | `true` runs `ctfkit verify-lock` on `path` (`report`) or `chdir` (every other command) before the command and fails the step on any finding; wrapped types come from `config` (`wrapped_providers`, default `aws`) |
| `stage` | empty | `scan`: `auto` when empty, `pre_plan` or `post_plan`; `post_init`, the old default, is read as `auto` with a warning. `report`: `post_init` when empty; `post_apply` is planned and is refused |

## Governed apply across three jobs

`verdict-workflow-template.yml` in this directory is a copyable workflow with three jobs:

| Job | Action `command` | Hands on |
|---|---|---|
| `plan` | `plan`: `ctfkit gate plan` writes `planfile`, `schema.json`, `ctfkit-run.key`, `findings.sarif` and `candidate.json` | the candidate, uploaded as one artifact |
| `sign` | `sign`: `ctfkit gate sign --signer awskms:KEY_ARN` adds `verdict.json` | the signed set, uploaded as one artifact |
| `apply` | `apply`: `ctfkit apply` checks the set and applies its sealed planfile | nothing: the set is consumed |

The set moves with `actions/upload-artifact` and `actions/download-artifact`. ctfkit does not trust
the transfer: `gate sign` and `apply` refuse a set with a changed, missing or extra file, because
each file must match its digest in `candidate.json` and the verdict signature binds the plan. The
transfer drops file modes, and ctfkit refuses a set that is not a 0700 directory of 0600 files, so
for `sign` and `apply` the action first restores those modes on the regular files of `artifacts`;
it changes no content and leaves anything else for ctfkit to refuse.

What the template sets up:

- No stored cloud keys. Each job assumes its own AWS role with GitHub OIDC
  (`aws-actions/configure-aws-credentials`); the `awskms` signer reads the default credential
  chain, so the sign role only needs `kms:Sign` on the verdict key, plus state read for `init`.
- Least privilege. The workflow grants nothing; each job gets `contents: read` and
  `id-token: write`. The apply job runs in the `production` environment, so required reviewers
  can hold it and the apply role's trust policy can name that environment.
- The same terraform binary in every job, installed without a wrapper: ctfkit records its SHA-256
  at `plan` and refuses another one.
- Artifacts named after the run attempt and kept for one day. Re-running only a failed job finds
  no artifact for the new attempt and fails, so a retry plans again rather than reusing an old set.
- One run per branch at a time (`concurrency`), and third-party actions pinned by commit SHA.

`profile`, `floor` and `bundle-dir` point at signed files; commit them, or write them from secrets
in an earlier step. The template reads the org id and role ARNs from repository variables.

## Installing from a private copy

The install step downloads the release with `gh release download`, authenticated by
`github-token`. ctfkit releases are published to the public `compliancetf/ctfkit` repository, and
the default job token reads them, so a workflow needs no extra secret. To install from a private
copy of ctfkit instead, name it in `repository` and pass a token that can read it, such as a
fine-grained personal access token with Contents: read on that repository. Store it as a secret
and pass it as `github-token`:

```yaml
      - uses: compliancetf/ctfkit-action@v0
        with:
          command: scan
          plan: plan.json
          repository: <owner>/<your-ctfkit-copy>
          github-token: ${{ secrets.CTFKIT_COPY_TOKEN }}
```

The token is used for the release download only; the pull request comment uses `comment-token`.
The archive is verified against the release checksums file either way. `gh` is preinstalled on
GitHub-hosted runners; a self-hosted runner needs it on `PATH`.

### Authenticating the download

`checksums.txt` comes from the same release, with the same token, as the archive. It shows the
download is intact, not who published it. Two optional inputs check the archive against something
the release cannot change:

- `sha256`: the digest of the archive you reviewed, copied from its line in that release's
  `checksums.txt`, such as `ctfkit_<version>_Linux_x86_64.tar.gz` on `ubuntu-latest`, with `version` pinned to that release. A
  different archive fails the step. A matrix over runner architectures needs one digest per archive.
- `verify-attestation: true`: runs `gh attestation verify <archive> --repo <repository>
  --signer-workflow <repository>/.github/workflows/release.yml --source-ref refs/tags/v<version>`
  and fails the step unless the archive has a GitHub build provenance attestation made by that
  repository's release workflow for the requested tag. It needs a gh with both flags. Every
  release published here carries one for every file in `checksums.txt`; a release from a copy
  without the release workflow has none and fails this check, so it stays off by default.

```yaml
      - uses: compliancetf/ctfkit-action@v0
        with:
          command: scan
          plan: plan.json
          version: v1.2.3   # the release you reviewed
          sha256: <digest of ctfkit_1.2.3_Linux_x86_64.tar.gz from its checksums.txt>
```

A workflow inside `compliancetf/ctfkit` itself, such as its own self-test, needs no extra token:
the default job token has `contents: read` on the repository it runs in, unless a `permissions:`
block omits it, in which case the download gets a 404. Such a workflow uses the action from the
checkout and names its own repository:

```yaml
    permissions:
      contents: read
    steps:
      - uses: ./adapters/github
        with:
          command: scan
          plan: plan.json
          repository: ${{ github.repository }}
```

## Scanning one root of several

Without `chdir`, `scan` reads Terraform configuration from the working directory, which in a job is
the whole checkout, walked recursively. In a repository with several roots, set `chdir` to the root
the plan was made from:

```yaml
      - uses: ./adapters/github
        with:
          command: scan
          plan: infra/plan.json
          chdir: infra
```

`plan` stays relative to the checkout. ctfkit writes each finding's file relative to `chdir`, so the
`sarif` output says `main.tf`. The copy uploaded to the Security tab has the `chdir` prefix put back
(`infra/main.tf`), because code scanning resolves a file against the repository root. That copy
needs `jq`, which GitHub-hosted runners have. `chdir` is a path relative to the checkout, or an
absolute path inside the workspace such as `${{ github.workspace }}/infra`, which is made relative
before the prefix is put back. An absolute path outside the workspace, or a `chdir` that does not
exist, fails the step before ctfkit is downloaded.

A `pre_plan` scan needs no plan at all. It reads the configuration in `chdir`, or the whole checkout
when `chdir` is empty, and the same prefix rule applies to the uploaded copy:

```yaml
      - uses: ./adapters/github
        with:
          command: scan
          stage: pre_plan
          chdir: infra
```

## Pull request comment

With `pr-comment: 'true'`, the action keeps one comment on the pull request carrying the markdown it
wrote to the job summary: ctfkit's markdown section for `report`, and ctfkit's text findings for
`scan`. Every run updates that comment in place instead of adding another.

```yaml
on: pull_request

permissions:
  contents: read
  pull-requests: write     # required for the comment

jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        root: [infra/network, infra/storage]
    steps:
      - uses: actions/checkout@v7
      - uses: compliancetf/ctfkit-action@v0
        with:
          command: scan
          stage: pre_plan
          chdir: ${{ matrix.root }}
          sarif: 'false'   # a private repository without code scanning
          pr-comment: 'true'
```

The comment body starts with a hidden marker, `<!-- ctfkit:report:<path>:<hash> -->` for `report`
or `<!-- ctfkit:scan:<chdir>:<hash> -->` for `scan`, with `.` when the input is empty, for example
`<!-- ctfkit:scan:infra/network:1f0c9a2b -->`. The directory is made relative to the workspace and
reduced to letters, digits and `._/@+-`, anything else becoming `_`, so it cannot end the HTML
comment. `<hash>` is the first 8 hex digits of the SHA-256 of the relative directory before that
reduction, so `a b` and `a_b` keep separate comments. A matrix over several roots therefore keeps
one comment per root. Two steps with the same command and directory, for example the same root
under two Terraform versions, share one comment and the later run wins.

The action lists the pull request's comments and updates the first one that starts with the marker
and was written by the comment token's own account; otherwise it creates one. That account is the
login `GET /user` returns for the token, or, when that call fails as it does for the job token,
`github-actions[bot]` with the Bot account type. Anyone can post a comment that starts with the
marker, and the action never edits one it did not write. A GitHub App installation token also fails
`GET /user` and comments as its own bot, so with one the action creates a new comment on every run.

The comment uses `comment-token`, default `${{ github.token }}`. It is separate from
`github-token`, which only downloads the release and often holds a read-only token for a private
ctfkit repository. The job needs `pull-requests: write`.

GitHub refuses a comment over 65536 characters. A body over 60000 is cut at the last blank line,
or at the last line break when that would drop more than half. A `<pre>` block or a code fence the
cut left open is closed, and a note links to the run, whose job summary has the full report.

A comment that cannot be listed, created or updated is a `::warning::`, never a failed step: the
ctfkit exit code alone decides the job. The usual cause is a token without `pull-requests: write`.
On a `pull_request` from a fork the job token is read-only, so every such run ends with that
warning and no comment.

`pull_request_target` has a write token and the repository's secrets, and it runs the workflow of
the base branch. Under it, never check out the pull request's head, and never run `tofu` or
`terraform` with secrets available: configuration from a fork can run code during `init` and
`plan`. The comment is only as trustworthy as what the job analyzed.

On any event other than `pull_request` and `pull_request_target` the step skips with a notice. A
`pr-comment` value other than `true` or `false` fails the install step, since that is a typo in the
workflow. The comment step runs after the job summary and before the exit code is re-applied, so a
run with findings still comments.

The `pr-comment` output says what happened: `created`, `updated`, `skipped` or `failed`, and empty
when `pr-comment` is off.

Values a pull request can choose, such as module keys, module sources and the finding messages
that quote them, cannot add markdown, HTML or a mention to the comment or the job summary. The
`report` markdown escapes them where they are rendered: `&`, `<` and `>` as HTML entities, a
backtick as `&#96;`, `|` as `\|` and `@` as `&#64;`. The `scan` text findings are HTML escaped,
`@` included, inside `<pre>`. While ctfkit runs, workflow commands are turned off with a random
`::stop-commands::` token, so a line of its log output cannot set an output or write an annotation.

## Nothing is read from the checkout

`fail-on`, `config`, `exceptions` and `catalog` are passed to ctfkit on every run, so it is never
left to discover one of those files in the repository it is analyzing. A repository cannot lower the
threshold the workflow asked for, widen its endpoint allowlist, grant itself an exception or swap in
a different catalog by committing a file.

`config` and `exceptions` default to the copies in `defaults/` in this directory. Both are safe as
they stand: the settings file leaves every key at the ctfkit default, and the exception registry is
empty, so nothing is suppressed.

`catalog` defaults to the literal `embedded`, which pins the release catalog compiled into the
binary you pinned with `version`. Nothing to ship and nothing to keep current; the compliance.tf
module source that closes each gap always resolves, and control ids and clauses resolve for the
CIS AWS Benchmark v6.0 controls the embedded catalog holds. A path overrides it, and a catalog file
**replaces** the embedded one wholesale rather than adding to it; point this at the full catalog
file to get every control and framework ([configuration](../../docs/configuration.md#catalog)).

`catalog: pull` downloads the full catalog with `ctfkit catalog pull` before `scan` or `report`.
It needs a paid plan and the registry token in `TF_TOKEN_registry_compliance_tf` on the step; ctfkit
sends that token to `registry.compliance.tf` only. The file goes to a directory of its own under
`RUNNER_TEMP`, outside the output directory the summary, upload and comment steps read, and is
deleted when the step ends. A failed pull fails the step with exit code `2` and ctfkit does not run.
`scan` and `report` stay offline; only the pull uses the network.

```yaml
- uses: compliancetf/ctfkit-action@v0
  env:
    TF_TOKEN_registry_compliance_tf: ${{ secrets.COMPLIANCETF_REGISTRY_TOKEN }}
  with:
    catalog: pull
```

The action fails in the install step, before the binary is downloaded, if `config` or `exceptions`
names a file that is not there. `embedded` and `pull` are literals rather than paths, so they are not checked
that way.

## SARIF is what this action produces

`scan` always runs with `--format sarif,text`, the text being only for the job summary, and
`report` refuses a `format` that contains
`spacelift`. The Spacelift projection is written by the hooks in `../spacelift`, into the run
working directory where a plan policy can read it; there is nothing for it to do in a GitHub run.

## Step order

The ctfkit exit code is captured, not applied immediately. The SARIF upload, the job summary and the
pull request comment then run in always-run steps, and the captured code is re-applied last. A run with findings therefore
still populates the Security tab before the job goes red.

The upload step is also conditional on the SARIF file being on disk. Because the output directory
is created empty for this invocation, a file found there was written by this run of ctfkit: a
`findings.sarif` committed to the repository is never uploaded, and a stale one from an earlier step
cannot be either: the first thing every invocation does is reset the exit code, file paths and
comment key it hands to the later steps, so one that fails before ctfkit runs publishes nothing from
an earlier invocation in the same job. Exit 2 is a tool error and often means nothing was written, so the step is skipped
rather than failing a second time on a missing artifact.

Input validation and the policy-file check happen in the install step, before the binary is
downloaded, so a misconfigured workflow fails early and cheaply.

## Outputs

| Output | Meaning |
|---|---|
| `receipt` | Path to the evidence receipt. Empty for `command: scan` |
| `sarif` | Path to the CFF/SARIF findings file |
| `markdown` | Path to the markdown written to the job summary: the report section for `report`, the escaped text findings for `scan` |
| `exit-code` | `0` ok, `1` findings at or above `fail-on`, `2` environment error |
| `pr-comment` | `created`, `updated`, `skipped` or `failed`; empty when `pr-comment` is off |

Files land in a fresh directory this invocation creates under `$RUNNER_TEMP`, never in the
checkout: `receipt.json`, `report.md` and `findings.sarif`, plus `findings.txt` for `scan`, whose
`report.md` is the escaped text findings. Two steps in the same job get separate
directories, so a `report` step and a `scan` step never read each other's output. The action fails the step on exit `1` and `2`, so read
`exit-code` from a step that sets `continue-on-error: true`.

## What the action does not claim

The receipt records which controls
the compliance.tf served modules in the configuration enforce at module build time, as read from the
manifests written at `init`. It is not a live-state assertion and not an attestation by
compliance.tf.

## Where this file lives

The action source is kept here, next to the binary it installs, and the in-repository self-test
uses it from this directory. Customers use the copy published in the public
`compliancetf/ctfkit-action` repository, which holds only the action. Maintainers copy `action.yml`
and `defaults/` there with
`scripts/sync-action-repo.sh`; that repository has its own short README.
