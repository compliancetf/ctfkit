# 03-local-modules

Status: `input/`, `expected/migrate-plan.json` (`units[]` by PM-T03, `edits[]` by PM-T04) and `expected/files/` (PM-T04) filled. Checked by `internal/migrate` TestDiscoverUnitsFixtures (`units[]`) and TestRewriteFixtures (`edits[]`, `expected/files/`); providers and platforms are placeholders until PM-T09.

Covers: Local modules (`./`, `../` sources) with their own `required_providers`: rewritten in place, version constraints kept.

Filled by: PM-T03 (`units[]`), PM-T04 (`expected/files/`).

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
