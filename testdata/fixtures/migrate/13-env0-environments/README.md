# 13-env0-environments

Status: skeleton. `input/` and `expected/` arrive with the task that fills the case.

Covers: env0 environments, including one whose apply re-plans.

Filled by: PM-T21 (against the env0 fake).

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
