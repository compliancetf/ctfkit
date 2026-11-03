# 02-aliases-and-configuration-aliases

Status: `input/`, `expected/migrate-plan.json` (`units[]`, `edits[]`) and `expected/files/` filled by PM-T04. Checked by `internal/migrate` TestDiscoverUnitsFixtures (`units[]`) and TestRewriteFixtures (`edits[]`, `expected/files/`); providers and platforms are placeholders until PM-T09.

Covers: Provider aliases and `configuration_aliases = [aws.west]`: `configuration_aliases` and `version` are kept and only `source` changes (`version` from the constraint table only where absent); `provider "aws" { alias = ... }` blocks stay as they are. Also another local name (`awsprod`, single-line object without `version`) and a `versions_override.tf` with `required_providers`.

Filled by: PM-T04 (`expected/files/`).

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
