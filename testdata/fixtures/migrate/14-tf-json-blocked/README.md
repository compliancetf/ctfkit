# 14-tf-json-blocked

Status: `input/`, `expected/migrate-plan.json` (`units[]`, `edits[]`, `blocked[]`) and `expected/exit-code` filled by PM-T05. Checked by `internal/migrate` TestBlockersFixtures (`blocked[]`, exit code), TestRewriteFixtures (no edits: the JSON-declared `aws` is not implied again) and TestDiscoverUnitsFixtures.

Covers: `*.tf.json` holding `required_providers`: `blocked[]` kind `json_config`, exit 1.

Filled by: PM-T05 (`blocked[]`).

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
