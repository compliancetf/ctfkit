# HCP Terraform and Terraform Enterprise run task

ctfkit by compliance.tf serves an HCP Terraform or Terraform Enterprise (TFE) run task with
`ctfkit runtask serve`. The run task is advisory: it reports findings and writes a receipt for
every run, and it never produces a verdict.

Status: preview.

## What a run gets

HCP and TFE run `terraform plan` themselves, so no `ctfkit gate plan` candidate exists for these
runs and no gate verdict can be signed for them. What the run task does instead:

| Step | What happens |
|---|---|
| Request | HCP posts the run task request; ctfkit answers within the request and does the work after |
| Plan JSON | downloaded from `plan_json_api_url` with the run's access token |
| Findings | the `post_plan` analyzers of `ctfkit scan` run over the plan JSON |
| Receipt | `<task result id>.receipt.json` in `--receipt-dir`, kind `provider-run`, runner class `hcp-advisory` |
| Task result | `PATCH task_result_callback_url` with the status, a summary and one outcome per finding (up to 50) |

Receipt status and task result:

| Case | Receipt status | Task result |
|---|---|---|
| Profile without `verdict_required` | `single-resource-only` | `failed` for an unsuppressed error-level finding under `mandatory` enforcement, `passed` otherwise |
| Profile with `verdict_required`, a non-speculative run that changes resources | `failed` | `failed`: route applies through CI with `ctfkit apply`, or leave `verdict_required` off |
| Profile with `verdict_required`, a speculative or no-change run | `single-resource-only` | as the first row |
| The run cannot be evaluated: profile refused, plan JSON not downloaded or not a plan, analyzer error, `--timeout` reached | `failed` | `failed`, with a message and receipt `reason` that start "the check did not run" |

Infrastructure errors fail closed: when the download, the plan or the analyzers fail, ctfkit
reports the run failed, because a pass the check never earned would read as evidence that it did. The message and the receipt
`reason` say the check did not run, so the result is not mistaken for a failure on findings. They
name one fixed category (profile refused, plan download failed, plan JSON not readable, analyzer
error, analyzer panic, run timed out) with at most an HTTP status or the byte limit; error text
and panic values never leave the server, since they can carry URLs, tokens or plan content.
Under `advisory` enforcement HCP shows it as a warning; under `mandatory` it blocks the run until
the cause is fixed and the run is retried.

`single-resource-only` means the provider's resource-local controls are the only ones in force
for that apply: graph controls need a gate verdict, which these runs never carry. The provider,
not the run task, is where controls are enforced at apply.

## Run it

```bash
ctfkit runtask serve \
  --listen 0.0.0.0:8443 --tls-cert /etc/ctfkit/tls.crt --tls-key /etc/ctfkit/tls.key \
  --hmac-key-file /etc/ctfkit/runtask.key \
  --receipt-dir /var/lib/ctfkit/receipts \
  --org bobthecorp --profile profile.dsse.json --floor floor.dsse.json --bundle-dir bundles/
```

Then create the run task in HCP Terraform (organization settings, Run tasks) with the endpoint
URL and the same HMAC key, and attach it to a workspace at the **post-plan** stage (pre-apply
works too). Pre-plan and post-apply stages have no plan JSON and are answered 422.

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | Address to listen on. Plain HTTP only on a loopback address |
| `--tls-cert`, `--tls-key` | none | TLS pair; required for any non-loopback `--listen` |
| `--hmac-key-file` | required | Absolute path of a 0600 file of this user holding the run task HMAC key (16 bytes or more; one trailing newline is ignored) |
| `--hostname` | `app.terraform.io` | Host every payload URL must be on; your TFE hostname for TFE |
| `--archive-host` | `archivist.terraform.io` for HCP Terraform, none otherwise | Host a plan JSON download may be redirected to; repeatable |
| `--receipt-dir` | required | Existing directory the receipts are written to |
| `--org`, `--profile`, `--floor`, `--bundle-dir` | required | Signed inputs, as for `gate plan`; read and verified again for every run, so a renewed floor statement needs no restart |
| `--max-plan-bytes` | 64 MiB | Largest plan JSON read. A parsed plan takes several times its size in memory, so size the host for `--max-concurrent` times that |
| `--replay-window` | `1h` | How old a run's `run_created_at` may be. It counts from run creation, so it must cover the longest queue and plan time (and, at pre-apply, the wait for confirmation) of the attached workspaces, or their runs answer 401 |
| `--timeout` | `5m` | Limit for one run, download to callback; keep it below the 10 minute progress limit of HCP |
| `--max-concurrent` | 4 | Runs in flight; a request beyond it answers 503 and HCP retries it |

The command reads `.ctfkit.yaml` from the working directory (or `--config`) for analyzer
settings. SIGINT or SIGTERM stops accepting and waits for runs in flight. Exit 0 after a signal,
2 on a refused flag, key file, signed input or listen address.

## Receipts

ctfkit never deletes a receipt. A receipt is also what refuses a second run of its task result
after a restart, so prune only receipts whose run is older than `--replay-window`: by then the
window check refuses the request anyway. A receipt pruned sooner lets its task result run again
after the next restart. Keep the copies your evidence retention needs elsewhere before pruning.

## Threat handling

| Threat | Handling |
|---|---|
| Forged request | `X-TFC-Task-Signature` must be the HMAC-SHA512 of the body under the configured key, compared in constant time; anything else answers 401 before the body is parsed. A run task saved without an HMAC key sends an empty signature and is refused |
| Replayed request | `run_created_at` (inside the signed body) must be within `--replay-window` and at most 5 minutes ahead, else 401. A task result id already accepted, or one with a receipt in `--receipt-dir` (so also after a restart), is HCP retrying a request whose answer it did not see: it answers 200, starts no new run and sends no second callback, and the log line says duplicate |
| Server-side request forgery | `plan_json_api_url` and `task_result_callback_url` must be https URLs on `--hostname` with the run task API path, no userinfo, query or fragment, else 422 and no outbound call. A plan JSON redirect may go only to https on `--hostname` or an `--archive-host`, at most 3 hops; the callback follows no redirect |
| Token leak | the access token is sent to `--hostname` only and dropped on a redirect to any other host. The token, the HMAC key and signed download URLs are never logged; error lines keep a URL's host only |
| Oversized or slow input | at most 64 request bodies read at once, none without a signature header of the right length; request body up to 1 MiB; plan JSON up to `--max-plan-bytes`; header, read, write and idle timeouts on the server; dial, TLS handshake and response header timeouts on outbound calls; `--timeout` per run; `--max-concurrent` runs at once |
| Path traversal through ids | run and task result ids must match `[A-Za-z0-9_-]{1,128}`, and the receipt is written through an `os.Root` of `--receipt-dir`, exclusively, 0600, then synced with its directory |

## Limits and residual risks of this preview

- The configuration version archive is not downloaded, so `pre_plan` analyzers do not run and
  findings are anchored to plan addresses only.
- Crash window: the set of accepted task results is held in memory, and the receipt is written
  only when a run ends. A run in flight when the process crashes leaves no receipt, so HCP's
  retry of it within `--replay-window` starts a second run and a second callback.
- Open connections are not capped; put the endpoint behind a proxy that limits them when it
  faces the internet.
- There is no per-workspace override of the enforcement level; HCP's own enforcement level of
  the task decides whether a `failed` result blocks the run.
- The receipt is not signed. Signing is planned.
