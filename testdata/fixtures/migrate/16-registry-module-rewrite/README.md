# 16-registry-module-rewrite

Status: skeleton. `input/` and `expected/` arrive with the task that fills the case.

Covers: A call to a registry.compliance.tf-served module rewritten to the `compliancetf/<t>` variant.

Filled by: PM-T26 (`expected/files/`).

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
