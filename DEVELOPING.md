# Developing ctfkit

ctfkit by compliance.tf is an Apache-2.0 analyzer runtime for Terraform and OpenTofu. It turns
configuration, plans and module manifests into consistent SARIF findings and an evidence receipt,
and hands its results to the policy workflow the user already has. `scan`, `report` and
`verify-lock` run inside CI offline: no network connection, no credentials, no terraform. The
preview commands do not: `gate plan`, `gate sign`, `verdict verify` and `apply` run terraform,
`gate sign` and `evidence ship` call AWS KMS, `evidence ship` uploads to S3, and `runtask serve`
serves HCP Terraform requests and downloads plans. When a compliance.tf module would have
prevented a finding, it names the exact module source.

User-facing behaviour: [README.md](README.md) and the `docs/` pages it indexes
([commands](docs/commands.md), [analyzers](docs/analyzers.md),
[configuration](docs/configuration.md)). Keep this file current in the same pull request as the
change it describes.

## Rules

- Everything committed here is public. No private repository names, issue-tracker ids, local
  paths, customer names or internal planning notes; `make hygiene` must pass. Machine-local notes
  go in an ignored local file (`CLAUDE.local.md`, `AGENTS.local.md`), never in the tree.
- Run `make hooks` once per clone and never bypass the hooks.
- Changes land by pull request from maintainers only; users open issues
  ([CONTRIBUTING.md](CONTRIBUTING.md)), security reports follow [SECURITY.md](SECURITY.md).
- Docs that describe a change ship in the same pull request. A behaviour change with no README,
  help-text or reference update is not done.
- Label every capability available, preview or planned. Do not describe planned work as
  available.

### Public-facing text

Anything a user can read (README, help text, error strings, release notes, command output):

- ctfkit is not a policy engine and not a scanner. It produces findings; OPA and tfpolicy consume
  them, and it runs alongside Sentinel. Never use "policy engine" or "gate" as the headline noun.
- Signing: `gate sign` writes `verdict.json` signed with the key named by `--signer` (your AWS KMS
  key), and `evidence ship` signs the run manifest with its `--signer` key. Findings, SARIF, JSON
  and receipts are not signed; never claim they are signed, attested or independently verified.
  compliance.tf does not sign, attest or verify anything for you. Receipt signing is planned.
- Write "compliance.tf" and "terraform-aws-modules" in full. Never a bare three-letter
  abbreviation for compliance.tf: it reads as Capture The Flag to a security audience. The binary
  name `ctfkit` is the one allowed short form, and the first mention in any document is
  "ctfkit by compliance.tf".
- Do not compare rule counts with other scanners. Frame by job: they find misconfigured
  resources, ctfkit says what the estate requires and which module closes each gap.
- Never name a customer or a user organization.

## Setup

Go 1.25 (`go.mod`); tool versions are pinned in `mise.toml` (`mise install`).

```bash
make hooks                                   # prek install: pre-commit and pre-push hooks
make build                                   # go build -o ctfkit ./cmd/ctfkit
go test -race ./...
./ctfkit scan --stage pre_plan testdata/pass/                        # exit 0
./ctfkit scan testdata/fixtures/plan/01-raw-s3-no-ctf/input/plan.json # exit 1
```

## Make targets

`make check` runs every gate; run it before opening a pull request. CI runs the same gates on
every pull request and push to master.

| Target | What it runs | Notes |
|---|---|---|
| `build` | `go build ./cmd/ctfkit` | the binary the integration tests exec |
| `test` | `go test -v ./...` | also run `go test -race ./...` before done |
| `lint` | `golangci-lint run` | falls back to `go vet ./...` with a notice when golangci-lint is absent; a local binary whose version differs from the pin in `mise.toml` is advisory only |
| `conformance` | `go test ./testdata/...` | the fixture conformance suite |
| `schemacheck` | `go run ./cmd/schemacheck ...` | checks fixtures against `schema/` |
| `hygiene` | `scripts/check-no-private-content.sh` and its self-test | see [Hygiene](#hygiene) |
| `vulncheck` | `govulncheck ./...` | known vulnerabilities in reachable code |
| `hooks` | `prek install` | once per clone |

Behaviour still worth checking by hand:

```bash
./ctfkit scan --stage pre_plan testdata/pass/ && ! ./ctfkit scan --stage pre_plan testdata/fail/non_ctf_module.tf
goreleaser check && goreleaser build --snapshot --clean   # before touching release config
```

## Repository layout

| Change | Edit | Do not edit |
|---|---|---|
| Validation rule | `internal/validator/*`, a fixture in `testdata/`, `validator_test.go` | `internal/parser/*` unless a new HCL construct is needed |
| Provider fact or sensitive-change rule | `internal/rulepack/rules/<provider>/v<major>/*.yaml` ([docs/rule-packs.md](docs/rule-packs.md)) | resource types or attribute names as Go literals in `internal/analyzer` (a test fails on them) |
| CLI flag or subcommand | `internal/cli/*`; return errors, never `os.Exit` outside `main` | new top-level packages |
| Config key | `internal/config/loader.go` + a `.ctfkit.yaml` example the loader reads | - |
| Output format | `internal/output/*` + register it in `getFormatter` | do not add a format without a consumer |
| GitHub Action | `adapters/github/*`, then copy `action.yml` and `defaults/` to `compliancetf/ctfkit-action` with `scripts/sync-action-repo.sh <checkout>` | the copies in `compliancetf/ctfkit-action` directly; its README is its own |
| Tool versions | `go.mod`, `mise.toml` and `.github/workflows/*` together | any one of the three alone |
| Report fixture inputs or `PIN.json` | a re-record with `scripts/record-report-fixtures.sh` (maintainers only, needs a registry token; see `testdata/fixtures/README.md` "Pinning and re-recording") | hand edits under `testdata/fixtures/report/*/input` or to `PIN.json` |
| Instance-key apply recordings (`pkg/verdict/testdata/instancekey/<type>/{apply,envelope}/`, `SOURCE.json`) | a re-record with `scripts/record-instancekey-apply.sh <provider-checkout> <type>...` (a clean terraform-provider-aws checkout with the `record` build tag; fake upstream only), then add the type to `goldenSides` in `pkg/verdict/instancekey/golden_sides_test.go` | hand edits of the recorded files or `SOURCE.json` |

- Fixtures live only in `testdata/`. There is no `tests/` directory.
- `pkg/ctfkit` is the public analyzer SDK contract, and nothing else goes under `pkg/` except the
  verdict packages already there. Everything else is `internal/`.

## Conventions

- Exit codes are a contract: `0` all checks passed, `1` policy violations found, `2`
  configuration or runtime error. They are set in `cmd/ctfkit/main.go`.
- Settings discovery (`internal/cli/report.go`, `loadSettings`): `--config` if given, then
  `.ctfkit.yaml` in the discovery root (scan: the configuration directory, report: the working
  directory), then built-in defaults.
- Output formats of scan: `sarif`, `json`, `text`, `pretty` (default), `junit`, `spacelift`,
  selected with `--format`.
- Cross-compilation has one source of truth, `.goreleaser.yml`. `make build-all` delegates to it;
  do not add a second GOOS/GOARCH matrix.

### Go

- `go.mod` is the source of truth for dependencies; `go.sum` is committed. `go mod tidy` leaves
  no diff. No `replace` pointing at a local path. A new runtime dependency needs a one-line
  justification; reach for the standard library first.
- The `go` directive in `go.mod` equals `go-version` in every workflow.
- Standard library `testing` only: table-driven tests and `t.Run` subtests. No assertion
  framework, no viper or testify.
- `-race` locally and in CI. Never skip a test to make a gate pass.
- `os.Exit` belongs in `main` only; a command's `RunE` returns an error.
- A test that execs the built binary appends `.exe` on Windows. CI runs Linux only; the release
  job cross-compiles Windows and macOS.
- One pinned golangci-lint version, identical in `mise.toml` and CI; `.golangci.yml` is on the v2
  schema.

### Fixture provenance

Every committed fixture comes from the `bobthecorp` test organization or from a public framework
host. Never a real organization, in any environment, and never a resource name, account id or
module path taken from one. Parity runs against outside trees use fixtures kept under
`testdata/local/`, which is gitignored; they are never committed and never quoted in a commit
message, pull request or test name.

## Commits and pull requests

- Conventional commits for every commit and pull request title: `type(scope)!: description`, with
  type one of `feat`, `fix`, `perf`, `deps`, `revert`, `docs`, `style`, `refactor`, `test`,
  `build`, `ci`, `chore`. The `PR title` workflow fails any other title.
- Pull requests are squash-merged with the title as the commit subject, so the title is what the
  changelog shows. `feat` and `fix` drive the version; `feat!` or a `BREAKING CHANGE:` footer
  marks a breaking change.

## Protected paths

`.github/protected-paths` lists the paths (verdict, graph, signing, evidence, CI and release
config, crypto entries in `go.mod` / `go.sum`, their goldens) whose pull requests need the owner's
approval of the head commit. The `protected-paths` workflow classifies each pull request with
`scripts/protected-paths.sh` from the default branch, without checking out pull request code, and
sets the `owner-approval` commit status; a pull request that is not the owner's own stays pending,
labelled `needs-owner`, with auto-merge disabled. A new protected package gets its rule (and a
self-test case) before its first file lands.

`workflow_pins_test.go` fails on an action not pinned to a commit SHA with a `# vX.Y.Z` note, a
checkout that persists credentials, a floating tool version, a workflow without a top-level
`permissions` block, or a trigger missing from its allowlist.

## Hygiene

`scripts/check-no-private-content.sh` scans tracked and untracked files. It fails on local agent
and issue-tracker state (`.beads/`, `.claude/`, `.codex/`, `.cursor/`, `.agents/`), home-directory
paths other than placeholders (`/home/user`, `/Users/dev`, ...), issue-tracker ids, and any term
of a private pattern list that maintainers keep outside this repository: set
`COMPLIANCETF_PRIVATE_PATTERNS_FILE`, or copy the list to `.git/info/private-patterns`. Without
the list that rule is skipped. The pre-commit hook and CI run it.

## Releasing

Releases are cut by [release-please](https://github.com/googleapis/release-please) from the
conventional commits on master; goreleaser builds them.

1. Every push to master runs `release-please.yml`, which keeps one release pull request open. It
   bumps `.release-please-manifest.json`, the pinned versions in `README.md` and `docs/install.md`
   (between `x-release-please` markers) and adds a `CHANGELOG.md` entry. `feat`, `fix`, `perf`,
   `deps` and `revert` commits are listed; the other types are hidden and open no release.
2. Versioning is `prerelease` with the `preview` label (`release-please-config.json`): each
   release adds one to the preview number. To ship `0.3.0`, set `"prerelease": false`. A
   `Release-As: X.Y.Z` commit footer forces a version.
3. The job token opens the release pull request, so Test and the PR title check do not run on it.
   Check the Test run of the master commit it was cut from, then merge it.
4. On the merge, release-please creates the `vX.Y.Z` tag and the GitHub release with the changelog
   as notes, then dispatches `release.yml` on that tag.
5. `release.yml` runs goreleaser on the tag: archives, `checksums.txt`, an SPDX SBOM per archive,
   deb, rpm and apk packages and ghcr.io images, uploaded to the existing release with the install
   notes appended. The `attest` job writes one build provenance attestation covering every file in
   `checksums.txt`.
6. A maintainer can also push a `v*` tag by hand; `release.yml` then creates the release itself,
   with goreleaser's changelog.

To verify a download:

```bash
sha256sum --ignore-missing -c checksums.txt
gh attestation verify <archive> --repo compliancetf/ctfkit \
  --signer-workflow compliancetf/ctfkit/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
```

The action self-test in `test.yml` installs a pinned published release
(`CTFKIT_SELFTEST_VERSION` and its SHA-256); bump both when a release changes what the self-test
reports.
