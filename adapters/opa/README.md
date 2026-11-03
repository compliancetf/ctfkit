# OPA example

ctfkit by compliance.tf produces findings; OPA decides what to do with them. `policy.rego` is a
short Rego v1 policy over the output of `ctfkit scan --format json`: it denies every error-level
finding that no accepted exception suppresses. Nothing in ctfkit needs to change to use it, and the
policy is yours to edit: raise the bar to warnings, allow a rule, or add your own conditions next
to it.

Status: **available**. Needs OPA 1.0 or later, or `--v1-compatible` on an older OPA that has the
flag: the policy uses the v1 keywords without `import rego.v1`.

| File | What it is |
|---|---|
| `policy.rego` | The policy, package `ctfkit`, rule `deny` |
| `test/error.json` | `ctfkit scan` output with one unsuppressed error finding (a raw `aws_s3_bucket`) |
| `test/clean.json` | `ctfkit scan` output with no findings |
| `test/suppressed.json` | The same error finding under an accepted exception |
| `policy_test.go` | Runs `opa check` and `opa eval` on the files above; skips when `opa` is not on `PATH` |

The three JSON files were recorded with `ctfkit scan plan.json --format json` on the
`01-raw-s3-no-ctf`, `02-ctf-module-intact` and `06-sentinel-exception` plan fixtures under
`testdata/fixtures/plan/`, each run from its `input/` directory. A re-run reproduces them except
for `ctf.exception.ttlSeconds` in `suppressed.json`, which counts down to the exception's expiry
from the day of the run.

## Run it

```sh
terraform plan -out=tfplan && terraform show -json tfplan > plan.json
ctfkit scan plan.json --format json --fail-on never > findings.json
opa eval --format pretty --data adapters/opa/policy.rego --input findings.json 'data.ctfkit.deny'
```

`--fail-on never` keeps ctfkit's exit code at `0` when it finds something, so the decision is OPA's
alone. On `test/error.json` the result is:

```
[
  "ctf.coverage.module_source at aws_s3_bucket.logs: Raw aws_s3_bucket where the compliance.tf module soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws exists"
]
```

On `test/clean.json` and `test/suppressed.json` it is `[]`.

To fail a CI step on any denial, ask for the members of the set and let `--fail-defined` set the
exit code (`1` when at least one message exists, `0` otherwise):

```sh
opa eval --fail-defined --format pretty --data adapters/opa/policy.rego --input findings.json 'data.ctfkit.deny[_]'
```

Conftest reads the same policy:

```sh
conftest test --policy adapters/opa/policy.rego --namespace ctfkit findings.json
```

## What the policy reads

`ctfkit scan --format json` writes `catalogVersion` and `findings`, plus `watermark` when
`--watermark` sets a banner line. Each finding is a
SARIF result: `ruleId`, `level` (`error`, `warning` or `note`), `message.text`, `locations` and,
when an exception covers it, `suppressions`. The policy uses only those fields; the `properties`
bag (control ids, frameworks, the compliance.tf module that closes the gap) is there for richer
rules. The policy does not read `watermark`.

## Check it

```sh
opa check --v1-compatible adapters/opa/policy.rego
go test ./adapters/opa/
```
