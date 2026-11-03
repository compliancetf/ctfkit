# Contributing to ctfkit

Issues are welcome for ctfkit by compliance.tf: bug reports, feature requests and questions
about how a rule or command behaves. Pull requests come from maintainers only. Report a
vulnerability privately, as described in [SECURITY.md](SECURITY.md), not in an issue.

## Opening an issue

Open one at <https://github.com/compliancetf/ctfkit/issues>. A report we can act on includes:

- the output of `ctfkit version`;
- the command you ran and the stage (`pre_plan`, `post_plan` or after `init`);
- what you expected and what happened, with the relevant output.

Strip secrets, account ids, resource names and anything else from your estate before you paste
it. A small configuration that shows the problem helps more than a real one.

## Building from source

ctfkit builds with Go 1.25 (see `go.mod`). From a checkout:

```bash
make build                 # go build -o ctfkit ./cmd/ctfkit
go test -race ./...
make check                 # build, tests, lint, conformance and schema checks
```

`make lint` uses golangci-lint v2 at the version pinned in `mise.toml`; another version is
advisory only. Some adapter tests run `opa` when it is on `PATH`.

Every commit and pull request title follows [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope)!: description`, for example `fix(cli): name the missing flags`. `feat:`, `fix:` and
`feat!:` decide the next version. [DEVELOPING.md](DEVELOPING.md) describes the repository
layout, the gates and the release flow.
