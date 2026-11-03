// Package conformance is the adapter conformance harness of the SDK and
// adapter contracts: every adapter runs the
// canonical fixtures of the stages it runs, turns its native output back into
// SARIF with its own helper, and must match the recorded expected/findings.sarif
// after run context is normalized. An adapter that fails the round trip is not
// a ctfkit adapter.
//
// The package is internal while the adapters live in this repository. It is
// written to be importable as compliancetf/ctfkit/conformance once an adapter
// moves to a repository of its own: nothing here depends on the CLI package,
// and adapters exec a ctfkit binary rather than calling it in process.
//
// What it provides:
//
//   - Fixtures loads the plan and report fixture packs and joins them with the
//     case table (argv, pinned catalog, known deviations).
//   - Adapter is the contract an adapter implements for the harness; CLI,
//     GitHubAction and Spacelift implement it the way the real adapters marshal.
//   - Check runs one adapter over one fixture and returns the fields that
//     differ. The Spacelift summary file carries only its own fields, so it is
//     compared on those (rule ids, levels, per-level counts, verdict,
//     watermark) instead of a full SARIF round trip.
//   - CheckPure runs analyzers under the race detector with every input hashed
//     before and after Analyze. It covers only the code paths the fixtures
//     exercise: an analyzer that mutates its input on a branch no fixture
//     reaches passes this check, and the race detector reports only when the
//     test binary is built with -race.
package conformance
