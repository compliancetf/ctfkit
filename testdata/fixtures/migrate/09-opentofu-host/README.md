# 09-opentofu-host

Status: `input/`, `expected/migrate-plan.json` (`units[]`, `edits[]`) and `expected/files/` filled by PM-T04. Checked by `internal/migrate` TestDiscoverUnitsFixtures (`units[]`) and TestRewriteFixtures (`edits[]`, `expected/files/`); providers and platforms are placeholders until PM-T09.

Covers: `registry.opentofu.org/hashicorp/aws` (OpenTofu host form) rewritten like the Terraform host form; the local module's legacy string entry (`aws = ">= 5.0"`) expanded to the object form.

Filled by: PM-T04 (`expected/files/`).

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
