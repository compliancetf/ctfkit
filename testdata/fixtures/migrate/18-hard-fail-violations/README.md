# 18-hard-fail-violations

Status: `input/`, `preflight.show.json` (the show -json of the preflight plan), `expected/migrate-plan.json` (`units[]`, `edits[]`, `blocked[]`), `expected/files/` and `expected/exit-code` filled by PM-T05. The floor check verifies the signed inputs case `pkg/verdict/testdata/inputs/valid` (mode floor `hard_fail`, graph control `s3_bucket_public_access_block_present`); `aws_s3_bucket.logs` has no public access block. Checked by `internal/migrate` TestBlockersFixtures (`blocked[]`, exit code), TestRewriteFixtures and TestDiscoverUnitsFixtures.

Covers: A `hard_fail` floor unit with pre-existing violations: `blocked[]` kind `floor_violations`, exit 1.

Filled by: PM-T05 (`blocked[]`).

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
