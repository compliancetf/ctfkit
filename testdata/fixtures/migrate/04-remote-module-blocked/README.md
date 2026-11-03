# 04-remote-module-blocked

Status: `input/`, `expected/migrate-plan.json` (`units[]`, `edits[]`, `blocked[]`), `expected/files/` and `expected/exit-code` filled by PM-T05. Checked by `internal/migrate` TestBlockersFixtures (`blocked[]`, exit code), TestRewriteFixtures and TestDiscoverUnitsFixtures. The `--vendor-modules` expected tree arrives with PM-T06.

Covers: A remote module (git source) that requires `hashicorp/aws`: listed in `blocked[]` (kind `remote_module`), exit 1; with `--vendor-modules` the vendored tree.

Filled by: PM-T05 (`blocked[]`), PM-T06 (`--vendor-modules` expected tree).

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
