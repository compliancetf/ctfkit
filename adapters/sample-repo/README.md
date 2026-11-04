# Sample repository

One Terraform configuration, one finding, three places it shows up: the terminal, the GitHub
Security tab and a Spacelift plan policy. Every output below was produced by ctfkit by compliance.tf
from the `plan.json` committed here, and `sample_test.go` reproduces all three on every `go test`.

Status: preview, alongside the two adapters it exercises.

## What you need

- the `ctfkit` binary
- `plan.json`

Nothing else. The scan itself needs no credentials, no network, no settings file and no
`tofu init`; only installing the binary downloads anything, as the GitHub Action does. Control ids and the
replacement module source come from the catalog compiled into the binary.

## What is in the configuration

`main.tf` holds two things:

- `module "logs"`, the S3 bucket module served from `bobthecorp.compliance.tf`, with the inputs
  that build requires. Nothing is reported for it.
- `resource "aws_s3_bucket" "raw"`, declared directly in the root. A compliance.tf module covers
  this resource type, so ctfkit reports it and names the module source to use instead. This is the
  finding.

The bucket names, the KMS key and the role ARN are `bobthecorp` placeholders and account
`111111111111`. The configuration is for planning, not for applying.

## Screen one: the terminal

```sh
ctfkit scan plan.json --format pretty
```

```
ERROR      ctf.coverage.module_source
  aws_s3_bucket.raw (main.tf:69)
  Raw aws_s3_bucket where the compliance.tf module soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws exists
  fix: use soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws ~> 5.0

1 finding(s): 1 error, 0 warning, 0 note, 0 suppressed
stage post_plan, catalog 2026.9.3 (embedded)
ctfkit: configuration directory /path/to/sample-repo (the working directory; name another with --chdir)
ctfkit: 1 finding(s) at or above error
```

Exit code 1: the finding is at error level and `--fail-on` defaults to `error`. The last two lines
are on stderr: the first names the configuration directory scan read, because none was named.

## Screen two: the GitHub Security tab

```sh
ctfkit scan plan.json --format sarif --out findings.sarif
```

The file validates against `schema/cff-1.schema.json`. Its one result, with the 12 framework
entries under `ctf.frameworks` cut for length:

```json
{
  "ruleId": "ctf.coverage.module_source",
  "level": "error",
  "kind": "fail",
  "message": {
    "text": "Raw aws_s3_bucket where the compliance.tf module soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws exists"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": { "uri": "main.tf" },
        "region": { "startLine": 69, "endLine": 71 }
      },
      "logicalLocations": [ { "fullyQualifiedName": "aws_s3_bucket.raw", "kind": "resource" } ]
    }
  ],
  "partialFingerprints": {
    "ctfkitFindingHash/v1": "9e1995ab80e155592243a5be43596692f5f0cb9ae4fcfff31ceffadf6c4afaed"
  },
  "properties": {
    "ctf.schema": "1.0",
    "ctf.stage": "post_plan",
    "ctf.controlIds": [ "s3_bucket_object_lock_enabled" ],
    "ctf.frameworks": [ "..." ],
    "ctf.preventive": true,
    "ctf.remediation": {
      "moduleSource": "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws",
      "version": "~> 5.0"
    }
  }
}
```

The run carries `"ctf.catalogVersion": {"version": "2026.9.3", "origin": "embedded"}` in its
properties.

`.github/workflows/ctfkit.yml` runs the same scan through the action with `command: scan` and
`plan: plan.json`. The action uploads the file with category `ctfkit`, so the finding opens as a
code scanning alert under Security for rule `ctf.coverage.module_source`, attached to `main.tf`.
The location names the file, the lines of the `aws_s3_bucket "raw"` block and the resource
address, so the alert points at the block. `partialFingerprints` keys the alert on the rule, the
file and the address rather than the line, so the alert survives the block moving. The job is red, because the action passes the exit code through
after the upload. Uploading needs `permissions: security-events: write`, which the workflow sets.

## Screen three: the Spacelift plan policy

```sh
ctfkit scan --plan plan.json --format spacelift
```

This writes `ctfkit-scan.custom.spacelift.json` into the working directory and exits 0: a format
list of exactly `spacelift` never fails the hook, the plan policy decides.

```json
{
  "schema": "ctfkit.spacelift/1",
  "stage": "post_plan",
  "verdict": "fail",
  "summary": {
    "error": 1,
    "warning": 0,
    "note": 0
  },
  "findings": [
    {
      "ruleId": "ctf.coverage.module_source",
      "level": "error",
      "message": "Raw aws_s3_bucket where the compliance.tf module soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws exists"
    }
  ]
}
```

Spacelift hands that file to the plan policy as `input.third_party_metadata.custom["ctfkit-scan"]`.
The same evaluation offline, with `adapters/spacelift/policy.rego` as committed (shadow mode):

```sh
echo "{\"third_party_metadata\":{\"custom\":{\"ctfkit-scan\":$(cat ctfkit-scan.custom.spacelift.json)}}}" > input.json
opa eval --format pretty --data ../spacelift/policy.rego --input input.json 'data.spacelift.warn'
opa eval --format pretty --data ../spacelift/policy.rego --input input.json 'data.spacelift.deny'
```

```
[
  "ctfkit metadata is missing from this run under key ctfkit",
  "ctfkit-scan: verdict fail (1 error, 0 warning)"
]
[]
```

After the enforcement flip (`enforce := true`), the same messages move to `deny` and Spacelift
refuses to apply:

```sh
sed 's/^enforce := false/enforce := true/' ../spacelift/policy.rego > policy-enforced.rego
opa eval --format pretty --data policy-enforced.rego --input input.json 'data.spacelift.deny'
```

```
[
  "ctfkit metadata is missing from this run under key ctfkit",
  "ctfkit-scan: verdict fail (1 error, 0 warning)"
]
```

The first message is there because this offline run has only the `scan` file. On a stack the
`after_init` hook writes the second key, `ctfkit`, with `ctfkit report`, which needs the module
cache from `tofu init`. The policy reads the `verdict` each file carries, so a rule that fires at
both stages is never counted twice.

`.spacelift/config.yml` carries both hooks, with the same flags as `../spacelift/config.stack.yml`.
Every flag that decides an outcome (`--fail-on`, `--format`, `--config`, `--exceptions`,
`--catalog`) reads from the runner image, never from this repository. It is committed here so the
sample reads in one place; on a real stack these hooks belong in the stack's settings, where a pull
request cannot remove them. `../spacelift/README.md` explains the split.

The `after_plan` hook still carries a `<plan-file>` placeholder: how Spacelift names the plan file
in the run working directory is not yet confirmed against a live run. The Spacelift half of this
page is the policy evaluated offline, not a watched Spacelift run.

## The same finding, three renderings

Rule id `ctf.coverage.module_source`, level `error` and the message text are identical in all three
outputs; the terminal and the SARIF also name `aws_s3_bucket.raw` in `main.tf`. `sample_test.go` asserts exactly that: it builds
`cmd/ctfkit`, runs the three commands above with an empty `HOME` and no CI or cloud variables,
validates the SARIF against the schema, and runs `opa eval` in both modes. When `opa` is not
installed it checks the metadata file and skips the policy evaluation, and says so.

```sh
go test ./adapters/sample-repo/
```

## How plan.json was recorded

Live, with OpenTofu 1.12.6 and hashicorp/aws 6.65.0, the same way as the fixture pack in
`testdata/fixtures/`:

```sh
tofu init -backend=false          # fetches the served module from bobthecorp.compliance.tf
tofu plan -out=tfplan
tofu show -json tfplan > plan.json
```

A `providers_override.tf` beside `main.tf`, not committed, set `access_key = "mock_access_key"`,
`secret_key = "mock_secret_key"`, the four `skip_*` checks, and an STS endpoint on `127.0.0.1` served
by a local stub, because the served module reads `aws_caller_identity`. That is why the provider
configuration inside `plan.json` shows the mock keys. `HTTPS_PROXY` and `HTTP_PROXY` pointed at a
closed local port, so any request to AWS would have failed the recording; none did. One
normalization: `timestamp` is frozen to `2026-09-20T00:00:00Z`.

## Where the action comes from

The workflow names `compliancetf/ctfkit-action@v0` and no `version`, so it runs the newest action
and ctfkit releases; pin both for a reproducible run, as the
[GitHub adapter](../github/README.md#usage) describes. The action lives in the public `compliancetf/ctfkit-action` repository and downloads the binary from
the releases of the public `compliancetf/ctfkit` repository with the default job token.
Inside `compliancetf/ctfkit` itself, the same step runs with `uses: ./adapters/github` from a
workflow at the repository root.
