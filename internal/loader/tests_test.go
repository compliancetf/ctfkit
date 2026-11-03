package loader_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// testsFileName is the name the report fixtures give the imported test
// document. The test names it itself so a rename in the fixture pack has to
// be defended here too.
const testsFileName = "tests.json"

// receiptTests is the inputs.tests block of an expected receipt. It is the
// oracle for the five counts and the digest: the loader has to agree with the
// file a renderer will be measured against.
type receiptTests struct {
	SHA256  string `json:"sha256"`
	Runs    int    `json:"runs"`
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	Errored int    `json:"errored"`
	Skipped int    `json:"skipped"`
}

// expectedReceipt is the part of an expected receipt this file reads.
type expectedReceipt struct {
	Statement struct {
		Inputs struct {
			Tests *receiptTests `json:"tests"`
		} `json:"inputs"`
	} `json:"statement"`
}

// readExpectedTests returns the inputs.tests block of the named fixture's
// expected receipt, failing the test when the fixture carries none.
func readExpectedTests(t *testing.T, fixture string) receiptTests {
	t.Helper()

	path := filepath.Join("..", "..", "testdata", "fixtures", "report", fixture, "expected", "receipt.json")
	content, err := os.ReadFile(path) // #nosec G304 -- test-owned fixture path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	var receipt expectedReceipt
	if err := json.Unmarshal(content, &receipt); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	if receipt.Statement.Inputs.Tests == nil {
		t.Fatalf("%s carries no inputs.tests block", path)
	}

	return *receipt.Statement.Inputs.Tests
}

func TestImportTests(t *testing.T) {
	const fixture = "example-multi-instance"

	path := filepath.Join("..", "..", "testdata", "fixtures", "report", fixture, "input", testsFileName)
	want := readExpectedTests(t, fixture)

	run, err := loader.ImportTests(path)
	if err != nil {
		t.Fatalf("ImportTests(%s): %v", path, err)
	}

	if run.File != path {
		t.Errorf("File = %q, want %q", run.File, path)
	}
	if run.SHA256 != want.SHA256 {
		t.Errorf("SHA256 = %q, want %q", run.SHA256, want.SHA256)
	}
	if run.Runs != want.Runs {
		t.Errorf("Runs = %d, want %d", run.Runs, want.Runs)
	}
	if run.Passed != want.Passed {
		t.Errorf("Passed = %d, want %d", run.Passed, want.Passed)
	}
	if run.Failed != want.Failed {
		t.Errorf("Failed = %d, want %d", run.Failed, want.Failed)
	}
	if run.Errored != want.Errored {
		t.Errorf("Errored = %d, want %d", run.Errored, want.Errored)
	}
	if run.Skipped != want.Skipped {
		t.Errorf("Skipped = %d, want %d", run.Skipped, want.Skipped)
	}

	// The digest is over the exact bytes on disk, as with every other input
	// digest, so it is recomputed here rather than trusted from the receipt
	// alone.
	content, err := os.ReadFile(path) // #nosec G304 -- test-owned fixture path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	sum := sha256.Sum256(content)
	if got := hex.EncodeToString(sum[:]); got != run.SHA256 {
		t.Errorf("SHA256 = %q, want the digest of the file on disk %q", run.SHA256, got)
	}
}

func TestImportTestsReadsEveryCase(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "fixtures", "report", "example-multi-instance", "input", testsFileName)

	run, err := loader.ImportTests(path)
	if err != nil {
		t.Fatalf("ImportTests(%s): %v", path, err)
	}

	want := []ctfkit.TestCase{
		{Name: "archive_bucket_is_planned", Status: "pass"},
		{Name: "data_bucket_is_planned", Status: "pass"},
		{Name: "artifacts_bucket_has_expected_region", Status: "fail"},
	}

	if len(run.Cases) != len(want) {
		t.Fatalf("Cases has %d entries, want %d", len(run.Cases), len(want))
	}
	for i, wantCase := range want {
		got := run.Cases[i]
		if got.Name != wantCase.Name || got.Status != wantCase.Status {
			t.Errorf("Cases[%d] = %+v, want %+v", i, got, wantCase)
		}
	}
}

func TestImportTestsTruncatedLineIsAnInputError(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "fixtures", "report", "example-multi-instance", "input", testsFileName)
	content, err := os.ReadFile(path) // #nosec G304 -- test-owned fixture path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	// A run cut off mid-line is the shape a killed runner leaves behind: the
	// last line is a JSON object that stops in the middle.
	truncated := content[:len(content)-40]

	dir := t.TempDir()
	broken := filepath.Join(dir, testsFileName)
	if writeErr := os.WriteFile(broken, truncated, 0o600); writeErr != nil {
		t.Fatalf("writing %s: %v", broken, writeErr)
	}

	if _, err := loader.ImportTests(broken); !errors.Is(err, loader.ErrInput) {
		t.Fatalf("ImportTests over a truncated stream returned %v, want ErrInput", err)
	}
}

func TestImportTestsNonJSONFileIsAnInputError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testsFileName)
	if err := os.WriteFile(path, []byte("Error: no test files found\n"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	if _, err := loader.ImportTests(path); !errors.Is(err, loader.ErrInput) {
		t.Fatalf("ImportTests over a non-JSON file returned %v, want ErrInput", err)
	}
}

func TestImportTestsEmptyStreamIsAnInputError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testsFileName)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	if _, err := loader.ImportTests(path); !errors.Is(err, loader.ErrInput) {
		t.Fatalf("ImportTests over an empty stream returned %v, want ErrInput", err)
	}
}

func TestImportTestsMissingFileIsAnInputError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")

	if _, err := loader.ImportTests(path); !errors.Is(err, loader.ErrInput) {
		t.Fatalf("ImportTests over a missing file returned %v, want ErrInput", err)
	}
}

func TestImportTestsDiagnosticNeverEchoesRepositoryText(t *testing.T) {
	const secret = "s3://customer-private-bucket/very-secret-name"

	dir := t.TempDir()
	path := filepath.Join(dir, testsFileName)
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	_, err := loader.ImportTests(path)
	if err == nil {
		t.Fatal("ImportTests over a non-JSON file returned no error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("diagnostic echoes the file's text: %v", err)
	}
}

func TestDetectRunMetadata(t *testing.T) {
	now := time.Date(2026, 9, 20, 18, 31, 55, 0, time.FixedZone("CEST", 2*60*60))

	cases := []struct {
		name  string
		env   map[string]string
		flags loader.RunFlags
		want  ctfkit.RunMetadata
	}{
		{
			name: "github actions",
			env: map[string]string{
				"GITHUB_RUN_ID":     "17209977000",
				"GITHUB_SHA":        "1e4b692ae5e0a8470000000000000000000000ab",
				"GITHUB_ACTOR":      "bobthecorp-ci",
				"GITHUB_REPOSITORY": "bobthecorp/platform",
			},
			want: ctfkit.RunMetadata{
				RunID:     "17209977000",
				Platform:  "github-actions",
				Workspace: "bobthecorp/platform",
				Commit:    "1e4b692ae5e0a8470000000000000000000000ab",
				Actor:     "bobthecorp-ci",
			},
		},
		{
			name: "spacelift",
			env: map[string]string{
				"TF_VAR_spacelift_run_id":      "01K5RUN",
				"TF_VAR_spacelift_commit_sha":  "2f5c703bf6f1b9580000000000000000000000cd",
				"TF_VAR_spacelift_stack_id":    "bobthecorp-platform-prod",
				"TF_VAR_spacelift_run_trigger": "git-push",
			},
			want: ctfkit.RunMetadata{
				RunID:     "01K5RUN",
				Platform:  "spacelift",
				Workspace: "bobthecorp-platform-prod",
				Commit:    "2f5c703bf6f1b9580000000000000000000000cd",
				Actor:     "git-push",
			},
		},
		{
			name: "gitlab",
			env: map[string]string{
				"CI_PIPELINE_ID":    "993421",
				"CI_COMMIT_SHA":     "3a6d814cg7g2caa90000000000000000000000ef",
				"CI_PROJECT_PATH":   "bobthecorp/platform",
				"GITLAB_USER_LOGIN": "bobthecorp-ci",
			},
			want: ctfkit.RunMetadata{
				RunID:     "993421",
				Platform:  "gitlab",
				Workspace: "bobthecorp/platform",
				Commit:    "3a6d814cg7g2caa90000000000000000000000ef",
				Actor:     "bobthecorp-ci",
			},
		},
		{
			name: "no platform env is a local run",
			env:  map[string]string{},
			want: ctfkit.RunMetadata{Platform: "local"},
		},
		{
			name: "flags win over detection",
			env: map[string]string{
				"GITHUB_RUN_ID":     "17209977000",
				"GITHUB_SHA":        "1e4b692ae5e0a8470000000000000000000000ab",
				"GITHUB_ACTOR":      "bobthecorp-ci",
				"GITHUB_REPOSITORY": "bobthecorp/platform",
			},
			flags: loader.RunFlags{
				RunID:     "operator-run",
				Commit:    "0000000000000000000000000000000000000000",
				Platform:  "local",
				Workspace: "operator-workspace",
				Actor:     "operator",
			},
			want: ctfkit.RunMetadata{
				RunID:     "operator-run",
				Platform:  "local",
				Workspace: "operator-workspace",
				Commit:    "0000000000000000000000000000000000000000",
				Actor:     "operator",
			},
		},
		{
			name: "a flag fills only the field it names",
			env: map[string]string{
				"GITHUB_RUN_ID":     "17209977000",
				"GITHUB_SHA":        "1e4b692ae5e0a8470000000000000000000000ab",
				"GITHUB_ACTOR":      "bobthecorp-ci",
				"GITHUB_REPOSITORY": "bobthecorp/platform",
			},
			flags: loader.RunFlags{Commit: "0000000000000000000000000000000000000000"},
			want: ctfkit.RunMetadata{
				RunID:     "17209977000",
				Platform:  "github-actions",
				Workspace: "bobthecorp/platform",
				Commit:    "0000000000000000000000000000000000000000",
				Actor:     "bobthecorp-ci",
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			env := func(key string) string { return testCase.env[key] }

			got := loader.DetectRunMetadata(env, now, testCase.flags)

			want := testCase.want
			want.Now = now.UTC()

			if got.RunID != want.RunID {
				t.Errorf("RunID = %q, want %q", got.RunID, want.RunID)
			}
			if got.Platform != want.Platform {
				t.Errorf("Platform = %q, want %q", got.Platform, want.Platform)
			}
			if got.Workspace != want.Workspace {
				t.Errorf("Workspace = %q, want %q", got.Workspace, want.Workspace)
			}
			if got.Commit != want.Commit {
				t.Errorf("Commit = %q, want %q", got.Commit, want.Commit)
			}
			if got.Actor != want.Actor {
				t.Errorf("Actor = %q, want %q", got.Actor, want.Actor)
			}
			if !got.Now.Equal(want.Now) {
				t.Errorf("Now = %v, want %v", got.Now, want.Now)
			}
			if got.Now.Location() != time.UTC {
				t.Errorf("Now is in %v, want UTC", got.Now.Location())
			}
		})
	}
}

func TestImportTestsCountsFromCasesWhenTheSummaryIsMissing(t *testing.T) {
	// A runner killed after the last run block but before its summary leaves
	// a stream of complete lines with no test_summary. The counts then come
	// from the run blocks that did arrive.
	const stream = `{"type":"test_abstract","test_abstract":{"tests/a.tftest.hcl":["one","two","three","four"]}}
{"type":"test_run","test_run":{"run":"one","status":"pass"}}
{"type":"test_run","test_run":{"run":"two","status":"fail"}}
{"type":"test_run","test_run":{"run":"three","status":"error"}}
{"type":"test_run","test_run":{"run":"four","status":"skip"}}
`

	path := filepath.Join(t.TempDir(), testsFileName)
	if err := os.WriteFile(path, []byte(stream), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	run, err := loader.ImportTests(path)
	if err != nil {
		t.Fatalf("ImportTests(%s): %v", path, err)
	}

	if run.Runs != 4 || run.Passed != 1 || run.Failed != 1 || run.Errored != 1 || run.Skipped != 1 {
		t.Errorf("counts = runs %d, passed %d, failed %d, errored %d, skipped %d; want 4/1/1/1/1",
			run.Runs, run.Passed, run.Failed, run.Errored, run.Skipped)
	}
}

func TestImportTestsCountsAnUnclassifiedStatusInRunsOnly(t *testing.T) {
	// A status outside the four this build knows is still a run, so it counts
	// in Runs and in no status counter. The four are not required to sum to
	// Runs, because inventing a bucket for an unknown status would misstate
	// the run.
	const stream = `{"type":"test_run","test_run":{"run":"one","status":"pass"}}
{"type":"test_run","test_run":{"run":"two","status":"pending"}}
`

	path := filepath.Join(t.TempDir(), testsFileName)
	if err := os.WriteFile(path, []byte(stream), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	run, err := loader.ImportTests(path)
	if err != nil {
		t.Fatalf("ImportTests(%s): %v", path, err)
	}

	if run.Runs != 2 {
		t.Errorf("Runs = %d, want 2", run.Runs)
	}
	if run.Passed != 1 || run.Failed != 0 || run.Errored != 0 || run.Skipped != 0 {
		t.Errorf("counts = passed %d, failed %d, errored %d, skipped %d; want 1/0/0/0",
			run.Passed, run.Failed, run.Errored, run.Skipped)
	}
}

func TestImportTestsSkipsAnUnknownEventType(t *testing.T) {
	// The runner adds event types between releases, so one this build does
	// not know is skipped rather than fatal.
	const stream = `{"type":"version","tofu":"1.12.6"}
{"type":"a_type_from_a_later_release","payload":{"whatever":true}}
{"type":"test_run","test_run":{"run":"one","status":"pass"}}
{"type":"test_summary","test_summary":{"passed":1,"failed":0,"errored":0,"skipped":0}}
`

	path := filepath.Join(t.TempDir(), testsFileName)
	if err := os.WriteFile(path, []byte(stream), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	run, err := loader.ImportTests(path)
	if err != nil {
		t.Fatalf("ImportTests(%s): %v", path, err)
	}
	if run.Runs != 1 || run.Passed != 1 {
		t.Errorf("counts = runs %d, passed %d; want 1/1", run.Runs, run.Passed)
	}
}

func TestImportTestsReadsAModuleKeyWhenTheStreamCarriesOne(t *testing.T) {
	const stream = `{"type":"test_run","test_run":{"run":"one","status":"pass","module":"archive"}}
{"type":"test_summary","test_summary":{"passed":1,"failed":0,"errored":0,"skipped":0}}
`

	path := filepath.Join(t.TempDir(), testsFileName)
	if err := os.WriteFile(path, []byte(stream), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	run, err := loader.ImportTests(path)
	if err != nil {
		t.Fatalf("ImportTests(%s): %v", path, err)
	}
	if len(run.Cases) != 1 {
		t.Fatalf("Cases has %d entries, want 1", len(run.Cases))
	}
	if run.Cases[0].ModuleKey != "archive" {
		t.Errorf("ModuleKey = %q, want %q", run.Cases[0].ModuleKey, "archive")
	}
}

func TestImportTestsEventWithoutItsPayloadIsAnInputError(t *testing.T) {
	cases := []struct {
		name   string
		stream string
	}{
		{name: "test_run", stream: `{"type":"test_run"}` + "\n"},
		{name: "test_summary", stream: `{"type":"test_summary"}` + "\n"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), testsFileName)
			if err := os.WriteFile(path, []byte(testCase.stream), 0o600); err != nil {
				t.Fatalf("writing %s: %v", path, err)
			}

			if _, err := loader.ImportTests(path); !errors.Is(err, loader.ErrInput) {
				t.Fatalf("ImportTests over a %s line with no payload returned %v, want ErrInput", testCase.name, err)
			}
		})
	}
}

func TestImportTestsOversizedLineIsAnInputError(t *testing.T) {
	// A single line past the scanner's ceiling is a stream this build refuses
	// to read rather than one it silently truncates.
	line := `{"type":"test_run","test_run":{"run":"` + strings.Repeat("x", 2<<20) + `","status":"pass"}}` + "\n"

	path := filepath.Join(t.TempDir(), testsFileName)
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	if _, err := loader.ImportTests(path); !errors.Is(err, loader.ErrInput) {
		t.Fatalf("ImportTests over an oversized line returned %v, want ErrInput", err)
	}
}
