package loader

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Event types of a `tofu test -json` / `terraform test -json` stream that this
// import reads. Every other type is skipped rather than fatal, because the
// runner adds types between releases and an unknown one is not a broken
// document.
const (
	eventTestRun      = "test_run"
	eventTestSummary  = "test_summary"
	eventTestAbstract = "test_abstract"
)

// testEvent is the decode shape of one line of the stream. Only the envelope
// type and the two payloads this import reads are named; everything else the
// runner writes on the line is ignored.
type testEvent struct {
	Type    string            `json:"type"`
	Run     *testRunEvent     `json:"test_run"`
	Summary *testSummaryEvent `json:"test_summary"`
}

// testRunEvent is the payload of a test_run line: one run block result.
type testRunEvent struct {
	Run    string `json:"run"`
	Status string `json:"status"`
	// Module is the module call key the run block exercises. The runner is
	// not required to write it, so it is empty on most streams.
	Module string `json:"module"`
}

// testSummaryEvent is the payload of a test_summary line: the runner's own
// count by status, which is what the receipt records.
type testSummaryEvent struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Errored int `json:"errored"`
	Skipped int `json:"skipped"`
}

// maxTestLineBytes is the longest single stream line this import accepts. A
// tofu diagnostic line carries the failing expression, its snippet and the
// values either side of the comparison, so lines of tens of kilobytes are
// ordinary; a megabyte is not, and bufio's own default of 64 KiB is too low.
const maxTestLineBytes = 1 << 20

// ImportTests reads a `tofu test -json` or `terraform test -json` document
// into a TestRun.
//
// ctfkit never runs tofu or terraform, so the file is whatever the caller
// produced and named with --tests-json. That path is the operator's, resolved
// against the process working directory rather than under a --path root, so
// there is no root to contain it against and the read is a plain guarded one.
//
// The digest is taken over the exact bytes read, before any parse, for the
// same reason a manifest's is: an auditor re-hashes the file on disk and gets
// the number the receipt carries.
//
// A malformed stream is an environment error. That covers a line that is not
// a JSON object, which is what a killed runner's truncated last line looks
// like, and a document that carries no test event at all. Diagnostics name the
// file and the reason and never echo its text, because that text is written by
// the repository under analysis.
func ImportTests(path string) (*ctfkit.TestRun, error) {
	// #nosec G304 -- operator-chosen path: the value of --tests-json, which
	// deliberately resolves outside any --path root
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrInput, path, err)
	}

	sum := sha256.Sum256(content)
	run := &ctfkit.TestRun{File: path, SHA256: hex.EncodeToString(sum[:])}

	var summary *testSummaryEvent
	recognized := false

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), maxTestLineBytes)

	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}

		var event testEvent
		if decodeErr := json.Unmarshal([]byte(text), &event); decodeErr != nil {
			// The decoder's message quotes the input it choked on, and that
			// input is the customer's test output, so only the line number
			// survives into the diagnostic.
			return nil, fmt.Errorf("%w: %s is not a valid test -json stream: line %d is not a JSON object",
				ErrInput, path, line)
		}

		switch event.Type {
		case eventTestRun:
			if event.Run == nil {
				return nil, fmt.Errorf("%w: %s is not a valid test -json stream: line %d carries no test_run payload",
					ErrInput, path, line)
			}
			recognized = true
			run.Cases = append(run.Cases, ctfkit.TestCase{
				Name:      event.Run.Run,
				Status:    event.Run.Status,
				ModuleKey: event.Run.Module,
			})
		case eventTestSummary:
			if event.Summary == nil {
				return nil, fmt.Errorf("%w: %s is not a valid test -json stream: line %d carries no test_summary payload",
					ErrInput, path, line)
			}
			recognized = true
			summary = event.Summary
		case eventTestAbstract:
			// The abstract only announces which run blocks exist. It is
			// counted as a recognized event so that a document that ran no
			// block is still a valid stream rather than an error.
			recognized = true
		}
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrInput, path, scanErr)
	}

	if !recognized {
		return nil, fmt.Errorf("%w: %s carries no test -json events", ErrInput, path)
	}

	// Runs is the number of run blocks that reported a result, which is what
	// the "3 run(s)" line of the report counts. The four status counts come
	// from the runner's own summary when it wrote one, because that is the
	// producer's count of its own run; a stream that ends before the summary
	// is counted from the cases that did arrive.
	run.Runs = len(run.Cases)
	if summary != nil {
		run.Passed = summary.Passed
		run.Failed = summary.Failed
		run.Errored = summary.Errored
		run.Skipped = summary.Skipped

		return run, nil
	}

	// A status this build does not classify leaves all four counters alone
	// and is still counted in Runs, so the four need not sum to Runs. That is
	// the honest reading: the runner reported a result this build cannot put
	// in a bucket, and inventing a bucket for it would misstate the run.
	for _, testCase := range run.Cases {
		switch testCase.Status {
		case "pass":
			run.Passed++
		case "fail":
			run.Failed++
		case "error":
			run.Errored++
		case "skip":
			run.Skipped++
		}
	}

	return run, nil
}

// RunFlags are the run context values an operator set explicitly on the
// command line. An empty field means the flag was not passed, so detection
// fills it; a set field always wins.
type RunFlags struct {
	RunID     string
	Commit    string
	Platform  string
	Workspace string
	Actor     string
}

// Platform names DetectRunMetadata reports. They are the receipt's vocabulary,
// not the platform's own naming.
const (
	platformGitHubActions = "github-actions"
	platformSpacelift     = "spacelift"
	platformGitLab        = "gitlab"
	platformLocal         = "local"
)

// DetectRunMetadata fills RunMetadata from the CI environment, with explicit
// flags overriding every detected value.
//
// env is the environment lookup, injected so a test does not mutate the
// process environment, and now is the run clock, injected for the same reason
// RunMetadata.Now exists: a run over recorded input produces the same output
// on any day. Now is stored in UTC, which everything reading the contract may
// assume.
//
// A platform is recognized by its run identifier being set, because that is
// the one variable each of them always writes. Nothing here reads a
// credential, and every value it does read is one the customer's own CI
// already knows.
func DetectRunMetadata(env func(string) string, now time.Time, flags RunFlags) ctfkit.RunMetadata {
	metadata := ctfkit.RunMetadata{Platform: platformLocal, Now: now.UTC()}

	switch {
	case env("GITHUB_RUN_ID") != "":
		metadata.Platform = platformGitHubActions
		metadata.RunID = env("GITHUB_RUN_ID")
		metadata.Commit = env("GITHUB_SHA")
		metadata.Workspace = env("GITHUB_REPOSITORY")
		metadata.Actor = env("GITHUB_ACTOR")
	case env("TF_VAR_spacelift_run_id") != "":
		metadata.Platform = platformSpacelift
		metadata.RunID = env("TF_VAR_spacelift_run_id")
		metadata.Commit = env("TF_VAR_spacelift_commit_sha")
		metadata.Workspace = env("TF_VAR_spacelift_stack_id")
		metadata.Actor = env("TF_VAR_spacelift_run_trigger")
	case env("CI_PIPELINE_ID") != "":
		metadata.Platform = platformGitLab
		metadata.RunID = env("CI_PIPELINE_ID")
		metadata.Commit = env("CI_COMMIT_SHA")
		metadata.Workspace = env("CI_PROJECT_PATH")
		metadata.Actor = env("GITLAB_USER_LOGIN")
	}

	// A flag is the operator's statement about the run, so it overrides what
	// the environment said, field by field: passing --commit alone leaves the
	// detected run id and platform in place.
	if flags.RunID != "" {
		metadata.RunID = flags.RunID
	}
	if flags.Commit != "" {
		metadata.Commit = flags.Commit
	}
	if flags.Platform != "" {
		metadata.Platform = flags.Platform
	}
	if flags.Workspace != "" {
		metadata.Workspace = flags.Workspace
	}
	if flags.Actor != "" {
		metadata.Actor = flags.Actor
	}

	return metadata
}
