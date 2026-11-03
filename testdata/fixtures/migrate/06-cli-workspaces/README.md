# 06-cli-workspaces

Status: `input/` and `expected/migrate-plan.json` `units[]` filled by PM-T03. Only `units[]` is checked today (`internal/migrate` TestDiscoverUnitsFixtures); providers, platforms and edits are placeholders.

Covers: A CLI root with several workspaces: each listed in the unit's `workspaces[]`.

Filled by: PM-T03 (`units[]`).

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
