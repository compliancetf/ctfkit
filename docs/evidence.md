# Evidence shipping (preview)

ctfkit by compliance.tf sends the evidence. The compliance.tf provider records that evidence
during a run. You use `ctfkit evidence ship` to do this. The command has been in preview since
v0.3.0-preview.1. It checks the provider's evidence chains, uploads them with a run manifest to
S3 Object Lock, and then writes the provider-run receipt.

Network and credentials: it uploads to S3 and calls AWS KMS through `--signer`, both with the
default AWS credential chain. It runs no terraform.

## Usage

```bash
ctfkit evidence ship --chains /var/lib/ctfkit/evidence/<run id> --artifacts .ctfkit-artifacts \
  --workspace default --signer awskms:KEY_ARN --receipt receipt.json \
  --sink s3://bobthecorp-evidence/ctfkit \
  --org bobthecorp --profile profile.dsse.json --floor floor.dsse.json --bundle-dir bundles/
```

| Flag | Meaning |
|---|---|
| `--chains DIR` | the provider's evidence directory of one run (`<evidence_dir>/<run_id>/`) |
| `--workspace`, `--org`, `--profile`, `--floor`, `--bundle-dir` | the run's workspace and the signed inputs, as for [governed apply](governed-apply.md) |
| `--signer` | `awskms:KEY_ARN`, a verdict key of the profile |
| `--receipt FILE` | where the receipt goes; must not exist |
| `--sink s3://bucket/prefix` | repeatable; each must be an `s3_object_lock` entry of the profile's `evidence.sinks` |
| `--api` | post the manifest to the Evidence API |
| `--artifacts DIR` | the artifact set `ctfkit apply` consumed for this run (runner class `ci`) |

## What it does

1. Verifies the signed bundles, org profile and floor statement.
2. It checks the hash links for every chain in `--chains`. Segments are stitched together. A line
   that got cut by a crash is left out.
3. Writes a run manifest: per chain its sequence range, final hash and the ranges it is missing.
   The manifest is signed with the `--signer` key (your AWS KMS key) and bound to that profile
   verdict key for the Evidence API.
4. For each `--sink`, it writes the chains and the manifest once. Object Lock is COMPLIANCE, and
   retention matches that sink's `min_retention_days`. If you pass `--api`, the manifest goes to
   the Evidence API.
5. If an upload or post fails, it goes into `.ctfkit/spool/` in the working directory. The next
   run starts by retrying it.
6. Writes the receipt (`ctf.evidence.receipt/1`, kind `provider-run`) to `--receipt` and fsyncs it
   with its directory before the command exits.

The receipt is not signed, and its `attestations` lists are empty. compliance.tf does not sign,
attest or verify anything for you. Receipt signing is planned.

In release builds, there is no Evidence API client yet. Because of that, `--api` always spools.

## Tampered chains

Chains whose hash links do not check, or, with an authenticated `--artifacts` set (runner class
`ci`), whose records are not bound to its verdict, are not uploaded anywhere. Under `ci`:

- every record must carry the verdict's run id;
- every eval record at stage `apply_pre` (the records the provider binds while a verdict is
  loaded) must name the verdict in `digests.verdict`, so a null or missing digest there counts as
  tampering;
- no record may name another verdict.

A `local` run has no verdict to bind, so only the hash links are checked. In either case the
receipt records status `failed`, the reason in `statement.reason` and the alert
`evidence_tampered` (`ALERT` on stderr), and the command exits 1.

The receipt's run id is the authenticated verdict's when there is one, else the chains' run. For
chains that fail verification without a verdict it is the `--chains` directory name when that is
a plain id (`[A-Za-z0-9_-]`, up to 128 characters), else `unknown`.

## Runner class

The runner class comes from the command, never the environment. It is `ci` only when
`--artifacts` is an artifact set `ctfkit apply` consumed:

- its `verdict.json` checks against the profile's verdict keys (kid not revoked) and names this
  org and workspace;
- `result.json` and the tombstone name that verdict's run (`result.json` also its plan) and agree
  on the outcome;
- `ctfkit-run.key` is gone.

Any other set, or none, is `local`, and stderr says why. Under `ci`, chains that are not of the
authenticated verdict's run count as tampered (above).

## Receipt status

The receipt status is the first that holds:

| Status | When |
|---|---|
| `failed` | the apply failed or was refused, a local run under `verdict_required`, chains whose hash links do not check, or the Evidence API flagged the run's nonce as reused |
| `overridden` | the apply used a break-glass receipt, or a chain record carries `break_glass_id` |
| `evidence-degraded` | a sink of the profile failed, was not named or none was shipped to; a chain is unterminated, has a break or a missing segment |
| `single-resource-only` | a local run under a profile without `verdict_required` |
| `enforced` | none of the above |

Every status that holds appears in `statement.conditions`. A run that has a break-glass
record and degraded evidence raises an alert. That alert is `ALERT` on stderr and
`break_glass_evidence_degraded` in `statement.alerts`. `recovery_required` is in the
schema. This release does not record `errored.tfstate`, so it never writes it.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | the status is `enforced` |
| `1` | any other status, a `failed` evidence run and tampered chains included |
| `2` | could not run, or refused: a bad flag, unreadable or refused signed inputs, an unreadable `--chains` directory, a `--sink` outside the profile, an existing `--receipt`. A refusal writes no receipt; a failure while writing the receipt also exits 2 and can leave a partial or complete `--receipt` file |

## Known limit

The hash links detect an edit to part of a chain. A party who can rewrite the files on the CI
runner can rewrite a whole chain and recompute its hash links, and `evidence ship` does not detect
that. Closing this needs chain heads signed by the provider or the signed acknowledgement of the
Evidence API, plus signed receipts (planned).
