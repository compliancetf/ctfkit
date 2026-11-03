# 05-implied-provider

Status: `input/`, `expected/migrate-plan.json` (`units[]`, `edits[]`) and `expected/files/` filled by PM-T04. Checked by `internal/migrate` TestDiscoverUnitsFixtures (`units[]`) and TestRewriteFixtures (`edits[]`, `expected/files/`); providers and platforms are placeholders until PM-T09.

Covers: `aws_*` resources with no `required_providers` entry: the entry is added to `versions.tf`, created when absent (`sha256_before` null): the root has none, the local module has one without `required_providers`.

Filled by: PM-T04 (`expected/files/`).

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
