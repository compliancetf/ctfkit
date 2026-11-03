# 12-spacelift-stacks

Status: skeleton. `input/` and `expected/` arrive with the task that fills the case.

Covers: Spacelift stacks, including one whose apply re-plans (reported as a runner-settings difference).

Filled by: PM-T20 (against the Spacelift fake).

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
