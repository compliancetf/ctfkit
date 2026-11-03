# 07-terragrunt-generate

Status: skeleton. `input/` and `expected/` arrive with the task that fills the case.

Covers: Terragrunt `generate` blocks holding `required_providers`: the inner HCL is rewritten.

Filled by: PM-T19.

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
