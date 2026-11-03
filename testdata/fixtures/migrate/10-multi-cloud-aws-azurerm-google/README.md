# 10-multi-cloud-aws-azurerm-google

Status: skeleton. `input/` and `expected/` arrive with the task that fills the case.

Covers: A mixed estate with aws, azurerm and google providers.

Filled by: PM-T23.

Layout once filled: `input/` is the configuration `ctfkit migrate plan` reads;
`expected/migrate-plan.json` (schema `ctfkit.migrate-plan/1`) and `expected/files/`
are what it must produce. Every name, workspace, org and stack uses `bobthecorp`.
`make schemacheck` validates `expected/migrate-plan.json`; an empty placeholder fails it,
so do not commit one.
