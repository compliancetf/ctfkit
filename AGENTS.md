# AGENTS.md

Coding agents write most of the code in this repository. Before changing anything, read
`DEVELOPING.md` in full: it holds the rules, the layout, every make target and script, the test
gates and the release flow. Keep it current in the same pull request as your change.

@DEVELOPING.md

The short version:

- Everything committed here is public. No private repository names, issue-tracker ids, local
  paths, customer names or internal planning notes; `make hygiene` must pass. Machine-local notes
  go in an ignored local file (`CLAUDE.local.md`, `AGENTS.local.md`), never in the tree.
- Run `make hooks` once per clone; never bypass the hooks. Before opening a pull request,
  `make check` and `go test -race ./...` must pass.
- Changes land by pull request from maintainers only; users open issues.
- Task tracking, research notes and other private context live in a private companion repository
  of the maintainers, not here. If it is available in your session, follow its `AGENTS.md`. Never
  copy its content, names or ids into this repository, and keep no issue-tracker state here.
- ctfkit produces findings; it is not a policy engine or a scanner. Findings, SARIF, JSON and
  receipts are not signed. Label capabilities available, preview or planned.
- Exit codes are a contract: `0` passed, `1` policy violations, `2` configuration or runtime
  error.
