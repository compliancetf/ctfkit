# Analyzers

ctfkit by compliance.tf puts its analyzers inside the binary itself. When you run
`ctfkit scan`, it uses control ids and replacement module sources from the catalog baked
into that binary. So no catalog file, settings file, network, or credentials are needed. The
command `ctfkit report` runs `post_init` rules after `init`. [stages.md](stages.md)
tells you what each stage can and cannot see.

## Rules

| Rule | Stage | Finds |
|---|---|---|
| `ctf.coverage.module_source` | pre_plan, post_plan | module sources outside compliance.tf endpoints, and raw resources a compliance.tf module covers; names the replacement module |
| `ctf.policy.disabled_control` | pre_plan | `?disable=<control_id>` on a compliance.tf module source |
| `ctf.policy.floating_ref` | pre_plan | module sources not pinned to an immutable reference |
| `ctf.origin.provider` | pre_plan, post_plan | providers outside `allowed_providers`, resource types outside `allowed_resources` |
| `ctf.origin.provider_unpinned` | pre_plan | `required_providers` entries with no upper-bounded version in a deployable root ([Provider constraints in reusable modules](#provider-constraints-in-reusable-modules)) |
| `ctf.lock.*` | pre_plan | only when `wrapped_providers` is set: the [lock file rules](#lock-file-rules) |
| `ctf.policy.tagging` | post_plan | planned resources missing the tags `tags` or `required_tags` ask for |
| `ctf.risk.sensitive_change_*` | post_plan | changes that open public access, grant wildcard IAM, remove audit logging, turn off encryption at rest, or delete, replace or unprotect a stateful resource |
| `ctf.exec.provisioner` | pre_plan, post_init | a provisioner in a `resource` or `removed` block, in any file `scan` reads ([Code that runs before plan](#code-that-runs-before-plan)) |
| `ctf.exec.external_data` | pre_plan, post_init | a `data "external"` block, in any file `scan` reads |
| `ctf.exec.module_endpoint` | post_init | a module called from inside another module whose source `allowed_endpoints` does not admit |
| `ctf.exec.module_uninspected` | pre_plan, post_init | a module call whose files were not inspected, such as a `../` local module directory a directory scan calls that does not exist yet (warning) |

`report` also runs the `ctf.coverage.*` rules on module manifests, posture, delegation,
obligations, attestations and tests; [stages.md](stages.md#post_init) lists them.

Example findings:

```hcl
# finding: a raw resource a compliance.tf module covers
resource "aws_s3_bucket" "logs" {
  bucket = "bobthecorp-logs"
}

# finding: the module source switches a control off
module "s3_bucket" {
  source = "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws?disable=s3_bucket_versioning_enabled"
}
```

## Rule packs

Rule packs embedded in the binary tell the sensitive-change rules what to check. They are
versioned, one per provider major version. They also say which attributes hold a resource's
tags. `hashicorp/aws` v6 is available; a `hashicorp/google` v8 proof pack is also available. If a
plan changes resources for a provider that has no pack, `scan` prints one stderr line with that
provider's name and leaves those resources unchecked. Providers that manage no infrastructure,
like `hashicorp/random`, are not named. If the lock file pins a provider major with no pack,
`scan` writes one stderr line saying which pack it used instead. stdout does not change.
[rule-packs.md](rule-packs.md) explains the format and how to add a provider.

On `hashicorp/google` resources, `ctf.policy.tagging` judges labels: `labels`, the provider's
`default_labels` and `effective_labels` take the place of `tags`, so a google resource with no
`tags` attribute can get tagging findings. GCP label keys must be lower case, so a tag rule such
as `Owner` can never be met by a google resource; limit such a rule to other resource types
with `resource_types`, or add a lower-case rule for labels.

## Provider constraints in reusable modules

A reusable module only states the lowest provider version it supports. For instance,
`version = ">= 6.0"`. It leaves the upper bound to the root that calls it. When `scan` reads a
directory, `ctf.origin.provider_unpinned` reports only the deployable roots inside it. It
classifies them from the configuration alone. The first rule that matches decides:

1. a directory with a `backend` or `cloud` block is a root;
2. a directory that a directory with a `backend`, `cloud` or `provider` block calls through a
   `./` or `../` module source is a module, the scanned directory included;
3. the scanned directory is a root;
4. a directory with a `provider` block is a root;
5. any other directory is a module.

A file list (`ctfkit scan main.tf versions.tf`) reports every entry. The `ctfkit` pre-commit
hook passes the staged file names, so it runs in file-list mode and this classification does not
apply to it; the `ctfkit-scan-dir` hook scans the repository as a directory and does
([Pre-commit hook](install.md#pre-commit-hook)). Known misses, each with its remedy:

- If a directory is deployable and has no `backend`, `cloud`, or `provider` block, and nothing
  calls it, it counts as a module. Scan that directory by itself.
- When another root in the same scan calls a deployable directory, that directory counts as a
  module. You have two options: scan it by itself, or if its callers are beneath it, provide its
  files as a list.
- A module's unbounded constraint still applies to a root that declares no constraint of its own
  for that provider. Bound the provider in every deployable root.

In a code-scanning workflow, run one scan per deployable root.

## Code that runs before plan

The `ctf.exec` rules report code that would run on the machine that plans or applies the
configuration, before `plan` runs any of it. They run at two stages:

- `ctfkit scan --stage pre_plan` on a directory checks provisioners and `external` data sources
  in every file it reads: the root, the local modules under it, and the `./` or `../` local
  modules it calls outside it, such as `../shared`, and theirs in turn. Any configuration gets
  them, with or without a compliance.tf module. A file list is read as given.
- `ctfkit report` runs after `init` and also reads the files of every module `init`
  installed, at any depth, including remote modules, the modules they call, and `../` local
  modules beside the root.

| Rule | Stage | Level | Fires when |
|---|---|---|---|
| `ctf.exec.provisioner` | pre_plan, post_init | error | a `resource` or `removed` block declares a provisioner: `local-exec`, `remote-exec`, `file` or any other |
| `ctf.exec.external_data` | pre_plan, post_init | error | a `data "external"` block, or a block of another data source type the built-in rule pack lists as running a local program, at top level or scoped to a `check` block (reported as `check.<name>.data.external.<name>`) |
| `ctf.exec.module_endpoint` | post_init | error | a module called from inside another module comes from a source `allowed_endpoints` does not admit; only a `./` or `../` path or a registry address on an allowed endpoint is admitted ([allowed_endpoints](configuration.md#allowed_endpoints)) |
| `ctf.exec.module_uninspected` | pre_plan, post_init | warning | a module call whose files were not inspected: in `scan`, a `../` local module directory that does not exist yet; in an SDK-built archive with no call graph, a `./` or `../` call whose directory it does not carry; in `report`, a module block `.terraform/modules/modules.json` holds no record for |

`report` lists `ctf.exec.*` findings for code inside nested remote modules as well as for the
root. `ctf.exec.module_endpoint` does not check a module the root calls directly: `scan` checks
that source with `ctf.coverage.module_source`, so the two rules never report the same source. A
configuration that calls public registry modules from the root gets no
`ctf.exec.module_endpoint` finding for those calls.

All four suffixes are read, override files and both copies of a `.tf` / `.tofu` pair included,
so a block either Terraform or OpenTofu would run is reported. A finding names the block's file,
lines and address; it never quotes a command or a program. Every finding of `scan` or `report`
that quotes a module source, these rules, `ctf.coverage.*` and `ctf.policy.floating_ref*`
included, quotes it without its userinfo or query, which can carry a token or an SSH key, and
so do the Markdown section and the receipt where they list a module's source.

### What the rules read

The read boundary, called the configuration directory below, is the directory under analysis
with its symlinks resolved: the directory argument of `scan` (or `--chdir`), and the `--path`
root of `report` (default: the working directory). It does not depend on the working directory
either command uses to discover `.ctfkit.yaml`: running `report --path ../infra` from a
repository root reads `../infra` and the modules it names, judged against `../infra`, while the
settings come from the repository root.

The `ctf.exec` rules read these directories and nothing else:

- every directory below the configuration directory that the configuration walk reads, plus the
  configuration directory itself;
- the directory of every explicit `./` or `../` local source, followed through the local sources
  of the modules it reaches;
- in `report`, the directory of every module `.terraform/modules/modules.json` lists, under the
  checks below.

`report` trusts `modules.json` as `init` wrote it, in the same job and on the same checkout,
before `report` runs. It checks where each recorded directory lies, not who wrote the file: a
`modules.json` edited or carried over from another checkout can name a different directory
inside the configuration directory, or leave a module out, and `report` reads what it says.

### Where a module directory may be

What happens when a module directory lies outside the boundary, or cannot be read:

- A `./` or `../` local source is read wherever it leads, inside the configuration directory or
  beside it, its `compliancetf-manifest.json` included, and so is a directory the configuration
  walk skips, such as `./.terraform.d/hook`. The source is explicit in the configuration and
  Terraform runs what it names, so a provisioner in `../shared` is an error like one in the
  root. `init` records such a module with its `Dir` relative to the root (`../shared`).
- When a child module has a source, that source gets joined to the parent's resolved directory.
  It works the same way `init` does. For example, if `../alias` is a symlink to `../libs/pkg`,
  and the module calls `../hook`, then the system reads `../libs/hook`. It never reads a
  `../hook` that sits beside the root. Directories are tracked by their resolved path. If a
  module calls itself through a cycle of local sources, that's an exit 2 error.
- Any module directory, or a file in one, that resolves outside the configuration directory
  for any other reason has exit code 2. That includes a symlink leading out, unless it lands
  on the directory of an explicit `../` source. It also includes a remote module recorded
  outside the root. Paths are compared by component after their symlinks are resolved. For a
  root `repo` beside `repo-evil`:

  | How `repo-evil` is reached | Result |
  |---|---|
  | an explicit `source = "../repo-evil"` | read, like any `../` source |
  | a `./x` symlink that resolves to it | exit 2 |
  | a remote module recorded there | exit 2 |
  | a path whose text starts with `repo` | never inside `repo`: paths compare by component |
  | a file symlink in a module directory that resolves into it | exit 2 |

  A file symlink in a module directory is read when it resolves inside the configuration
  directory or inside that module's own directory. One that resolves anywhere else is exit 2,
  never skipped: Terraform would read and run it.

- A local module directory that exists but cannot be listed, or that does not resolve, is exit 2
  in `report`: `init` installed it, so Terraform reads it, and ctfkit was not shown its files.
  `scan` exits 2 on one that exists and cannot be listed too.
- `scan` runs before `init`, so a `../` directory that is not there yet is reported as
  `ctf.exec.module_uninspected` rather than refused. The finding is a warning, so it changes the
  exit code only under `--fail-on warning` (or `note`): a scan whose only finding is this one
  exits 0 under the default `--fail-on error`.
- A file list is read as given, and a `./` or `../` call to a directory it does not name is
  outside the files you chose, so it is not a finding. An archive built through the SDK without
  a call graph (no `LocalCalls`) and not marked `Partial` reports such a call as
  `ctf.exec.module_uninspected` at the address `module.<name>.<unresolved>`.
- `report` reads a module only where `.terraform/modules/modules.json` records it. A module
  block, in the root or in an installed module, that has no record there is
  `ctf.exec.module_uninspected` at `module.<name>.<unresolved>`, local or remote, and its
  directory is not read in its place. No exception covers an address that holds `<unresolved>`.
- `report` does not take `modules.json` at its word for anything outside the configuration
  directory. The root module record must name the configuration directory itself, and a record
  whose `./` or `../` source leads out of it is read only when a module block of its caller
  declares that call with that source. A `modules.json` that breaks either rule is exit 2.
- If you pass a symlink to `report --path` or to `scan`, the tool reads it from where the link
  actually points.
- If a module directory is a symlink and it stays inside the configuration directory, it gets
  read just like any other directory.
- A module `init` installed for a `terraform test` run block is test scaffolding and is not
  read: its key has the exact shape `test.<test file directories>.<file name>.<run name>`, with no
  record for any of its prefixes from two segments up. Any other `test.` key is read, including a
  root module call that happens to be named `test`, its children, and any shape `init` does not
  write for a run block.
- Every diagnostic that names a module directory or source prints it without userinfo or query,
  and prints `<unparsed module source>` for one it cannot read as an address. The location of
  every finding of `scan` and `report`, of every rule, is redacted the same way, path component
  by component, since a module directory, inside the configuration directory or beside it, is
  named after its source: modules at `../user:token@shared` and `./modules/user:token@shared` are
  located at `../shared/main.tf` and `modules/shared/main.tf`. Each component is percent-decoded
  until it stops changing; one that still holds an `@`, a `?`, a `/`, a `\` or a control
  character, written or encoded (`%40`, `%2540`, `%3F`, `%2F`, `%5C`, `%09`), or a malformed
  escape becomes `<unparsed module source>`. A space is not a reason: `stacks/my module/main.tf`
  keeps its path. A file that cannot be read is named the same way, never through the operating
  system's error, which carries the absolute path.
- In `scan` and in `report`, a `ctf.exec` finding in a module carries the module's address, as
  Terraform gives it: `module.<name>.check.<check>.data.external.<name>` for a data source scoped
  to a check block in that module. `scan` takes the address from the local module calls it read,
  each followed to the directory it resolves to, so `../alias`, a symlink to `../libs/pkg`, gives
  the files in `../libs/pkg` the address `module.<call name>`. A directory reached by more than
  one call is reported once per call, under each full address, sorted: `module.a.<...>` and
  `module.b.module.c.<...>` for a directory that `module.a` and the `module.c` inside `module.b`
  both call. A call whose module block and override file name different sources leads to both
  directories. An exception matches one address, so one written for the root's
  `check.health.data.external.probe` does not cover a module's. A local module directory no
  followed call reaches, or one reached only through a cycle, is never addressed as the root: it
  takes `module.<name>.<unresolved>.` for a call that could not be followed, and no exception
  covers an address holding `<unresolved>`.
- A configuration file that does not parse is exit 2 in `report`. `scan` skips it, as its other
  rules do.

The `report` checks run only where `report` runs, so a configuration with no compliance.tf
module manifest at all exits 2 before them; `scan` still applies the pre_plan rules to it.

## Lock file rules

`ctfkit verify-lock` checks the `.terraform.lock.hcl` of every deployable root for the
wrapped provider types: `--provider` (repeatable: `aws`, `azurerm`, `google`), else
`wrapped_providers` in `.ctfkit.yaml`, else `aws`. `scan --stage pre_plan` runs the same rules on
a directory when the settings file sets `wrapped_providers`. Flags and exit codes are in
[commands.md](commands.md#ctfkit-verify-lock).

| Rule | Level | Fires when |
|---|---|---|
| `ctf.lock.missing` | error | a root has no lock file |
| `ctf.lock.upstream_present` | error | the lock has `registry.terraform.io/hashicorp/<t>` or `registry.opentofu.org/hashicorp/<t>` for a wrapped `<t>` |
| `ctf.lock.wrapper_missing` | error | the lock has no `registry.compliance.tf/compliancetf/<t>` entry for a wrapped `<t>` the root uses (a lock entry or a `required_providers` entry of the root names that type) |
| `ctf.lock.wrapper_unhashed` | error | that entry records no `zh:` hash |
| `ctf.lock.source_mismatch` | error | a `required_providers` entry, in a root or a module, names `hashicorp/<t>` for a wrapped `<t>`, or names no source, or a resource or provider block of `<t>` has no entry at all |
| `ctf.lock.unwrapped` | warning | the lock has `hashicorp/google-beta` while `google` is wrapped |

If you serve the wrapper under `hashicorp/aws` from a network mirror,
`ctf.lock.upstream_present` fails. That's intentional. The lock still points at the upstream
address. A planned check will verify the wrapper entry equals the pinned wrapper release.
Before terraform starts, `ctfkit gate plan` runs these rules on the `--dir` root
([governed-apply.md](governed-apply.md#gate-plan)).
