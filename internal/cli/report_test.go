package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixtureClock is the run time every recorded projection was rendered at. It
// is frozen so the bytes are the same on any day.
const fixtureClock = "2026-09-20T00:00:00Z"

// fixtureContext is the run context the fixture pack README pins. A
// regeneration passes the same flags or the bytes differ.
var fixtureContext = []string{
	"--run-id", "ctfkit-fixture-run",
	"--commit", "0000000000000000000000000000000000000000",
	"--platform", "local",
	// The catalog the recorded manifests join against: the release catalog
	// compiled into the binary. The recorded projections carry its control
	// names and clause text, so a run against any other catalog renders
	// different bytes. Naming it explicitly keeps the run reproducible on a
	// developer laptop that has a home catalog file.
	"--catalog", fixtureCatalog,
}

// fixtureCatalog is the catalog the recorded manifests join against: the
// embedded release catalog, the same one the coverage analyzer's own tests
// use, so the two cannot drift apart.
const fixtureCatalog = "embedded"

// fixtureVersion is the generator version the recorded receipts name.
const fixtureVersion = "1.0.0"

// repoRoot is where a fixture path such as testdata/fixtures/report/... is
// resolved from. The recorded receipts carry that relative path as the subject
// root, so the command has to be run from here to reproduce their bytes.
const repoRoot = "../.."

// runReport runs one `ctfkit report` invocation in process and returns what it
// wrote to stdout and the exit code the process would have taken.
func runReport(t *testing.T, args ...string) (string, int) {
	t.Helper()

	clock, err := time.Parse(time.RFC3339, fixtureClock)
	if err != nil {
		t.Fatalf("parse the fixture clock: %v", err)
	}

	cli := New(fixtureVersion)
	cli.now = func() time.Time { return clock }

	out := new(bytes.Buffer)
	cli.rootCmd.SetOut(out)
	cli.rootCmd.SetErr(out)
	cli.rootCmd.SetArgs(append([]string{"report"}, args...))

	runErr := cli.Execute()

	return out.String(), ExitCode(runErr)
}

// runReportErr is runReport when the test is about the diagnostic rather than
// the output.
func runReportErr(t *testing.T, args ...string) (int, error) {
	t.Helper()

	clock, err := time.Parse(time.RFC3339, fixtureClock)
	if err != nil {
		t.Fatalf("parse the fixture clock: %v", err)
	}

	cli := New(fixtureVersion)
	cli.now = func() time.Time { return clock }
	cli.rootCmd.SetOut(new(bytes.Buffer))
	cli.rootCmd.SetErr(new(bytes.Buffer))
	cli.rootCmd.SetArgs(append([]string{"report"}, args...))

	runErr := cli.Execute()

	return ExitCode(runErr), runErr
}

// fixturePath is the input tree of one recorded case, as the recorded
// projections name it.
func fixturePath(name string) string {
	return "testdata/fixtures/report/" + name + "/input"
}

// TestReportExitCodes is the table of the exit contract: 0 on a clean run, 1 on
// findings at or above the threshold, 2 on an environment error, and the one
// deliberate exception where a spacelift-only format list returns 0 on findings
// because the plan policy is the gate.
func TestReportExitCodes(t *testing.T) {
	t.Chdir(repoRoot)

	// The spacelift-only row writes ctfkit.custom.spacelift.json into the
	// working directory, which is the repository root here, so it is removed
	// rather than left behind as an untracked file.
	t.Cleanup(func() { _ = os.Remove("ctfkit.custom.spacelift.json") })

	tests := []struct {
		name string
		args []string
		want int
	}{
		{
			name: "a clean served leaf exits 0",
			args: []string{"--path", fixturePath("served-leaf")},
			want: ExitOK,
		},
		{
			name: "an error-level finding exits 1",
			args: []string{"--path", fixturePath("missing-manifest")},
			want: ExitFindings,
		},
		{
			name: "--fail-on never keeps the same findings and exits 0",
			args: []string{"--path", fixturePath("missing-manifest"), "--fail-on", "never"},
			want: ExitOK,
		},
		{
			name: "a spacelift-only format list exits 0 on findings",
			args: []string{"--path", fixturePath("missing-manifest"), "--format", "spacelift"},
			want: ExitOK,
		},
		{
			name: "an unsupported manifest schema major exits 2",
			args: []string{"--path", fixturePath("schema-4-stub")},
			want: ExitEnvironment,
		},
		{
			name: "a directory with no modules.json exits 2",
			args: []string{"--path", "testdata/pass"},
			want: ExitEnvironment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, code := runReport(t, append(tt.args, fixtureContext...)...)
			if code != tt.want {
				t.Errorf("exit code = %d, want %d", code, tt.want)
			}
		})
	}
}

// TestReportRecordedExitCodes checks every recorded case against the exit code
// committed beside it, so a case added to the pack is covered without a new
// table row here.
func TestReportRecordedExitCodes(t *testing.T) {
	t.Chdir(goldenRoot(t))

	cases, err := os.ReadDir("testdata/fixtures/report")
	if err != nil {
		t.Fatalf("read the fixture pack: %v", err)
	}

	for _, entry := range cases {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			args := append([]string{"--path", fixturePath(entry.Name())}, fixtureContext...)
			// The recorded exit code of the multi-instance case assumes the
			// imported test results, which is where its error-level finding
			// comes from.
			if testsJSON := filepath.Join(fixturePath(entry.Name()), "tests.json"); exists(testsJSON) {
				args = append(args, "--tests-json", testsJSON)
			}
			// Markdown goes to a scratch file rather than stdout so a failing
			// case does not print a whole report into the test log.
			args = append(args, "--out", filepath.Join(t.TempDir(), "report.md"))

			_, code := runReport(t, args...)
			if rerecording() {
				writeExpected(t, entry.Name(), "exit-code", []byte(fmt.Sprintf("%d\n", code)))
			}
			if want := readExpectedExitCode(t, entry.Name()); code != want {
				t.Errorf("exit code = %d, want %d", code, want)
			}
		})
	}
}

// TestReportEnvironmentDiagnostic asserts the one recorded stderr line: the
// program name, a colon, and the reason, with no internal sentinel text and
// nothing the operator cannot act on.
func TestReportEnvironmentDiagnostic(t *testing.T) {
	t.Chdir(goldenRoot(t))

	code, runErr := runReportErr(t, append([]string{"--path", fixturePath("schema-4-stub")}, fixtureContext...)...)
	if code != ExitEnvironment {
		t.Fatalf("exit code = %d, want %d", code, ExitEnvironment)
	}
	// What main prints for an exit-2 run: the program name, a colon, the
	// reason and a newline.
	if rerecording() {
		writeExpected(t, "schema-4-stub", "stderr.txt", []byte("ctfkit: "+runErr.Error()+"\n"))
	}

	recorded, err := os.ReadFile("testdata/fixtures/report/schema-4-stub/expected/stderr.txt")
	if err != nil {
		t.Fatalf("read the recorded diagnostic: %v", err)
	}
	want := strings.TrimSuffix(strings.TrimPrefix(string(recorded), "ctfkit: "), "\n")
	if runErr.Error() != want {
		t.Errorf("diagnostic =\n%q\nwant\n%q", runErr.Error(), want)
	}

	var exit *ExitError
	if !asExitError(runErr, &exit) {
		t.Fatalf("diagnostic is not an ExitError: %T", runErr)
	}
	if exit.Category != categoryInput {
		t.Errorf("category = %q, want %q", exit.Category, categoryInput)
	}
}

// TestReportProjections is the byte-parity gate: every recorded case renders
// the committed report.md and receipt.json. The Markdown comparison strips the
// Generated-by line, which is the one line the Python parity harness strips
// too; the receipt is compared whole, because those bytes are what a signature
// will one day cover.
func TestReportProjections(t *testing.T) {
	t.Chdir(goldenRoot(t))

	for _, name := range recordedCases(t) {
		if !rerecording() && !exists(filepath.Join("testdata/fixtures/report", name, "expected", "report.md")) {
			continue // schema-4-stub stops before it renders anything
		}

		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{
				"--path", fixturePath(name),
				"--format", "markdown,receipt",
				"--out-dir", dir,
			}, fixtureContext...)
			if testsJSON := filepath.Join(fixturePath(name), "tests.json"); exists(testsJSON) {
				args = append(args, "--tests-json", testsJSON)
			}

			if _, code := runReport(t, args...); code == ExitEnvironment {
				if rerecording() {
					return // an exit-2 case renders no projection
				}
				t.Fatalf("report exited 2")
			}
			if rerecording() {
				writeExpected(t, name, "report.md", readFile(t, filepath.Join(dir, "report.md")))
				writeExpected(t, name, "receipt.json", readFile(t, filepath.Join(dir, "receipt.json")))
			}

			assertSameBytes(t, "report.md",
				stripGeneratedBy(readFile(t, filepath.Join("testdata/fixtures/report", name, "expected", "report.md"))),
				stripGeneratedBy(readFile(t, filepath.Join(dir, "report.md"))))
			assertSameBytes(t, "receipt.json",
				readFile(t, filepath.Join("testdata/fixtures/report", name, "expected", "receipt.json")),
				readFile(t, filepath.Join(dir, "receipt.json")))
		})
	}
}

// TestReportSpaceliftLandsInTheWorkingDirectory asserts the destination rule
// the Spacelift adapter depends on: the metadata file is written beside the run
// and never under --out-dir, because that is where Spacelift discovers a custom
// metadata input.
func TestReportSpaceliftLandsInTheWorkingDirectory(t *testing.T) {
	root := absFixture(t, "missing-manifest")
	recorded := absExpected(t, "missing-manifest", "ctfkit.custom.spacelift.json")

	work := t.TempDir()
	elsewhere := t.TempDir()
	t.Chdir(work)

	// Every path is absolute here: the run happens in a scratch working
	// directory, which is the whole point of the case.
	args := []string{
		"--path", root,
		"--format", "markdown,spacelift",
		"--out-dir", elsewhere,
		"--run-id", "ctfkit-fixture-run",
		"--commit", "0000000000000000000000000000000000000000",
		"--platform", "local",
		"--catalog", fixtureCatalog,
	}

	if _, code := runReport(t, args...); code != ExitFindings {
		t.Fatalf("exit code = %d, want %d", code, ExitFindings)
	}

	if exists(filepath.Join(elsewhere, "ctfkit.custom.spacelift.json")) {
		t.Error("the Spacelift file was written under --out-dir, where Spacelift never looks for it")
	}

	assertSameBytes(t, "ctfkit.custom.spacelift.json",
		readFile(t, recorded),
		readFile(t, filepath.Join(work, "ctfkit.custom.spacelift.json")))
}

// TestReportFailOnPrecedence walks the chain: the flag beats the environment
// variable, the environment variable beats the default, and a widened
// threshold turns warnings into an exit 1 without changing what was found.
func TestReportFailOnPrecedence(t *testing.T) {
	t.Chdir(repoRoot)

	tests := []struct {
		name string
		args []string
		env  string
		want int
	}{
		{
			name: "the default threshold ignores warnings",
			args: []string{"--path", fixturePath("delegated-without-sibling")},
			want: ExitOK,
		},
		{
			name: "CTFKIT_FAIL_ON widens the threshold to warnings",
			args: []string{"--path", fixturePath("delegated-without-sibling")},
			env:  "warning",
			want: ExitFindings,
		},
		{
			name: "the flag beats the environment variable",
			args: []string{"--path", fixturePath("delegated-without-sibling"), "--fail-on", "error"},
			env:  "warning",
			want: ExitOK,
		},
		{
			name: "never disables exit 1 even at note level",
			args: []string{"--path", fixturePath("blueprint-wrapper"), "--fail-on", "never"},
			env:  "note",
			want: ExitOK,
		},
		{
			name: "an unknown threshold is an environment error",
			args: []string{"--path", fixturePath("served-leaf"), "--fail-on", "critical"},
			want: ExitEnvironment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv(failOnEnv, tt.env)
			}
			args := append(tt.args, fixtureContext...) //nolint:gocritic // a fresh slice per row is the point
			args = append(args, "--out", filepath.Join(t.TempDir(), "report.md"))

			if _, code := runReport(t, args...); code != tt.want {
				t.Errorf("exit code = %d, want %d", code, tt.want)
			}
		})
	}
}

// TestReportWatermarkBanner asserts that --watermark renders its banner text
// exactly once.
func TestReportWatermarkBanner(t *testing.T) {
	t.Chdir(repoRoot)

	args := append([]string{
		"--path", fixturePath("served-leaf"),
		"--watermark", "internal draft, do not circulate",
	}, fixtureContext...)

	out, code := runReport(t, args...)
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d", code, ExitOK)
	}

	if n := strings.Count(out, "internal draft, do not circulate"); n != 1 {
		t.Errorf("the banner text appears %d times in the rendered section, want 1", n)
	}
}

// TestReportReadmeInjection asserts that the section replaces the marked region
// and leaves every byte outside it alone, and that a start marker with no end
// marker is an environment error rather than a guess about where the region
// the operator meant ends.
func TestReportReadmeInjection(t *testing.T) {
	t.Chdir(repoRoot)

	t.Run("the marked region is replaced and the prose is kept", func(t *testing.T) {
		readme := filepath.Join(t.TempDir(), "README.md")
		body := "# Bucket module\n\nProse above.\n\n" +
			"<!-- CTFKIT_REPORT_START -->\nstale\n<!-- CTFKIT_REPORT_END -->\n\nProse below.\n"
		if err := os.WriteFile(readme, []byte(body), 0o600); err != nil {
			t.Fatalf("write the README: %v", err)
		}

		args := append([]string{"--path", fixturePath("served-leaf"), "--readme", readme}, fixtureContext...)
		if _, code := runReport(t, args...); code != ExitOK {
			t.Fatalf("exit code = %d, want %d", code, ExitOK)
		}

		merged := string(readFile(t, readme))
		if !strings.HasPrefix(merged, "# Bucket module\n\nProse above.\n\n") {
			t.Error("the prose above the markers was not kept")
		}
		if !strings.HasSuffix(merged, "\n\nProse below.\n") {
			t.Error("the prose below the markers was not kept")
		}
		if strings.Contains(merged, "stale") {
			t.Error("the old section survived the injection")
		}
		if !strings.Contains(merged, "## Compliance coverage") {
			t.Error("the new section was not injected")
		}
	})

	t.Run("--readme is a destination and does not swallow --out-dir", func(t *testing.T) {
		dir := t.TempDir()
		readme := filepath.Join(dir, "README.md")
		body := "<!-- CTFKIT_REPORT_START -->\nstale\n<!-- CTFKIT_REPORT_END -->\n"
		if err := os.WriteFile(readme, []byte(body), 0o644); err != nil { //nolint:gosec // a README's usual mode is the point
			t.Fatalf("write the README: %v", err)
		}

		out := t.TempDir()
		args := append([]string{
			"--path", fixturePath("served-leaf"),
			"--format", "markdown,receipt",
			"--out-dir", out,
			"--readme", readme,
		}, fixtureContext...)
		if _, code := runReport(t, args...); code != ExitOK {
			t.Fatalf("exit code = %d, want %d", code, ExitOK)
		}

		for _, name := range []string{"report.md", "receipt.json"} {
			if !exists(filepath.Join(out, name)) {
				t.Errorf("%s was not written to --out-dir", name)
			}
		}
		if !strings.Contains(string(readFile(t, readme)), "## Compliance coverage") {
			t.Error("the README was not injected")
		}

		// The README belongs to whoever wrote it, mode included.
		info, err := os.Stat(readme)
		if err != nil {
			t.Fatalf("stat the README: %v", err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Errorf("README mode = %o, want 644: the injection rewrote the file's own permissions", info.Mode().Perm())
		}
	})

	t.Run("a start marker with no end marker exits 2", func(t *testing.T) {
		readme := filepath.Join(t.TempDir(), "README.md")
		if err := os.WriteFile(readme, []byte("<!-- CTFKIT_REPORT_START -->\nno end\n"), 0o600); err != nil {
			t.Fatalf("write the README: %v", err)
		}

		args := append([]string{"--path", fixturePath("served-leaf"), "--readme", readme}, fixtureContext...)
		if _, code := runReport(t, args...); code != ExitEnvironment {
			t.Errorf("exit code = %d, want %d", code, ExitEnvironment)
		}
	})

	t.Run("custom markers are honored", func(t *testing.T) {
		readme := filepath.Join(t.TempDir(), "README.md")
		body := "before\n<!-- COMPLIANCE_REPORT_START -->\nstale\n<!-- COMPLIANCE_REPORT_END -->\nafter\n"
		if err := os.WriteFile(readme, []byte(body), 0o600); err != nil {
			t.Fatalf("write the README: %v", err)
		}

		args := append([]string{
			"--path", fixturePath("served-leaf"),
			"--readme", readme,
			"--markers", "<!-- COMPLIANCE_REPORT_START -->,<!-- COMPLIANCE_REPORT_END -->",
		}, fixtureContext...)
		if _, code := runReport(t, args...); code != ExitOK {
			t.Fatalf("exit code = %d, want %d", code, ExitOK)
		}

		merged := string(readFile(t, readme))
		if !strings.Contains(merged, "## Compliance coverage") || strings.Contains(merged, "stale") {
			t.Error("the custom marker pair did not delimit the replaced region")
		}
	})
}

// TestReportFlagMisuse covers the combinations that have no defined output.
// Each is exit 2: a run whose document has nowhere to go has not judged the
// configuration, and saying so beats writing one of two requested documents.
func TestReportFlagMisuse(t *testing.T) {
	t.Chdir(repoRoot)

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "an unknown format",
			args: []string{"--format", "pdf"},
		},
		{
			name: "a repeated format",
			args: []string{"--format", "markdown,markdown"},
		},
		{
			name: "--out and --out-dir together",
			args: []string{"--out", "a.md", "--out-dir", "."},
		},
		{
			name: "--out with several formats",
			args: []string{"--format", "markdown,receipt", "--out", "a.md"},
		},
		{
			name: "--out with the fixed-name Spacelift file",
			args: []string{"--format", "spacelift", "--out", "a.json"},
		},
		{
			name: "several formats and no --out-dir",
			args: []string{"--format", "markdown,receipt"},
		},
		{
			name: "--markers without a pair",
			args: []string{"--markers", "START,"},
		},
		{
			name: "--out-dir with nothing but the fixed-name Spacelift file",
			args: []string{"--format", "spacelift", "--out-dir", "."},
		},
		{
			name: "--readme with no markdown in the format list",
			args: []string{"--format", "receipt", "--out", "r.json", "--readme", "README.md"},
		},
		{
			name: "--markers with no markdown in the format list",
			args: []string{"--format", "receipt", "--out", "r.json", "--markers", "A,B"},
		},
		{
			name: "two roots in one run",
			args: []string{"--path", fixturePath("served-leaf"), "--path", fixturePath("blueprint-wrapper")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"--path", fixturePath("served-leaf")}, tt.args...)
			if _, code := runReport(t, args...); code != ExitEnvironment {
				t.Errorf("exit code = %d, want %d", code, ExitEnvironment)
			}
		})
	}
}

// --- helpers ---

func recordedCases(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir("testdata/fixtures/report")
	if err != nil {
		t.Fatalf("read the fixture pack: %v", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("the fixture pack is empty, so nothing was compared")
	}

	return names
}

func readExpectedExitCode(t *testing.T, name string) int {
	t.Helper()

	raw := strings.TrimSpace(string(readFile(t, filepath.Join("testdata/fixtures/report", name, "expected", "exit-code"))))
	switch raw {
	case "0":
		return ExitOK
	case "1":
		return ExitFindings
	case "2":
		return ExitEnvironment
	default:
		t.Fatalf("%s records an exit code outside the contract: %q", name, raw)
		return -1
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	body, err := os.ReadFile(path) //nolint:gosec // a test path under testdata or t.TempDir
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return body
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// absPath resolves a repository-relative path while the test runs somewhere
// else.
func absPath(t *testing.T, rel string) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatalf("resolve %s: %v", rel, err)
	}

	return path
}

func absFixture(t *testing.T, name string) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join(repoRoot, fixturePath(name)))
	if err != nil {
		t.Fatalf("resolve the fixture path: %v", err)
	}

	return path
}

func absExpected(t *testing.T, name, file string) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join(repoRoot, "testdata/fixtures/report", name, "expected", file))
	if err != nil {
		t.Fatalf("resolve the recorded path: %v", err)
	}

	return path
}

// stripGeneratedBy removes the one line two generators of the same report
// cannot agree on, which is the comparison the Python parity harness makes.
func stripGeneratedBy(body []byte) []byte {
	lines := strings.Split(string(body), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, "Generated by ctfkit report ") {
			continue
		}
		kept = append(kept, line)
	}

	return []byte(strings.Join(kept, "\n"))
}

func assertSameBytes(t *testing.T, name string, want, got []byte) {
	t.Helper()

	if bytes.Equal(want, got) {
		return
	}

	t.Errorf("%s does not match the recorded bytes\n--- recorded ---\n%s\n--- rendered ---\n%s", name, want, got)
}

// asExitError is errors.As without the import ceremony at every call site.
func asExitError(err error, target **ExitError) bool {
	exit, ok := err.(*ExitError) //nolint:errorlint // the command layer returns the value, never a wrapper
	if ok {
		*target = exit
	}

	return ok
}

// TestReportNoManifestsAtAll asserts the environment error the specification
// separates from a per-instance manifest_missing finding: a root where not one
// instance carries a manifest has no served build to report on, and an empty
// coverage document with a pass verdict reads exactly like a configuration
// whose modules enforce nothing.
func TestReportNoManifestsAtAll(t *testing.T) {
	root := t.TempDir()
	modules := filepath.Join(root, ".terraform", "modules")
	// The local module's directory exists, as init leaves it: a directory
	// that does not resolve is its own environment error.
	for _, dir := range []string{modules, filepath.Join(root, "modules", "local")} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("build the tree: %v", err)
		}
	}
	body := `{"Modules":[{"Key":"","Source":"","Dir":"."},` +
		`{"Key":"local","Source":"./modules/local","Dir":"modules/local"}]}`
	if err := os.WriteFile(filepath.Join(modules, "modules.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write modules.json: %v", err)
	}

	t.Chdir(t.TempDir())

	code, err := runReportErr(t,
		"--path", root,
		"--catalog", fixtureCatalog,
		"--run-id", "ctfkit-fixture-run",
		"--commit", "0000000000000000000000000000000000000000",
		"--platform", "local",
		"--out", filepath.Join(t.TempDir(), "report.md"),
	)
	if code != ExitEnvironment {
		t.Fatalf("exit code = %d, want %d", code, ExitEnvironment)
	}
	if !strings.Contains(err.Error(), "compliancetf-manifest.json") {
		t.Errorf("diagnostic does not name what is missing: %q", err.Error())
	}
}

// TestReportToleratesAControlTheCatalogLacks runs report over a served
// manifest that delegates a control id the embedded catalog does not hold, as
// a manifest served after this release can. The run completes with the
// recorded case's exit code and writes every projection, rather than exiting
// 2; the unknown id is named in the delegation finding.
func TestReportToleratesAControlTheCatalogLacks(t *testing.T) {
	const (
		delegated = `"control_id": "s3_bucket_event_notifications_enabled"`
		unknown   = "s3_control_from_a_newer_catalog"
	)

	root := filepath.Join(t.TempDir(), "input")
	if err := os.CopyFS(root, os.DirFS(absFixture(t, "delegated-without-sibling"))); err != nil {
		t.Fatalf("copy the fixture: %v", err)
	}
	manifest := filepath.Join(root, ".terraform", "modules", "s3_bucket", "compliancetf-manifest.json")
	body := readFile(t, manifest)
	if !bytes.Contains(body, []byte(delegated)) {
		t.Fatalf("the fixture manifest no longer delegates %s", delegated)
	}
	body = bytes.Replace(body, []byte(delegated), []byte(`"control_id": "`+unknown+`"`), 1)
	if err := os.WriteFile(manifest, body, 0o600); err != nil {
		t.Fatalf("write the manifest: %v", err)
	}

	outDir := t.TempDir()
	t.Chdir(t.TempDir())
	code, err := runReportErr(t, append([]string{"--path", root, "--out-dir", outDir, "--format", "markdown,receipt,sarif"}, fixtureContext...)...)
	if code != ExitOK {
		t.Fatalf("exit code = %d (%v), want %d as the recorded case", code, err, ExitOK)
	}

	for _, name := range []string{"report.md", "receipt.json", "findings.sarif"} {
		if !exists(filepath.Join(outDir, name)) {
			t.Errorf("%s was not written", name)
		}
	}
	if sarif := readFile(t, filepath.Join(outDir, "findings.sarif")); !bytes.Contains(sarif, []byte("Control "+unknown+" ")) {
		t.Errorf("findings.sarif does not name %s in a delegation finding", unknown)
	}
}

// TestReportPolicyFileDiagnostics asserts that an unreadable policy file stops
// the run rather than falling back silently, and that each one reports its own
// diagnostic category so a caller can tell which file to go and fix.
func TestReportPolicyFileDiagnostics(t *testing.T) {
	t.Chdir(repoRoot)

	missing := filepath.Join(t.TempDir(), "not-there.yaml")

	tests := []struct {
		name     string
		flag     string
		category string
	}{
		{name: "an unreadable settings file", flag: "--config", category: categorySettings},
		{name: "an unreadable exception registry", flag: "--exceptions", category: categoryExceptions},
		{name: "an unreadable catalog", flag: "--catalog", category: categoryCatalog},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"--path", fixturePath("served-leaf"), tt.flag, missing}
			// The catalog row replaces the pinned catalog rather than adding
			// a second one.
			if tt.flag != "--catalog" {
				args = append(args, "--catalog", fixtureCatalog)
			}

			code, err := runReportErr(t, args...)
			if code != ExitEnvironment {
				t.Fatalf("exit code = %d, want %d", code, ExitEnvironment)
			}

			var exit *ExitError
			if !asExitError(err, &exit) {
				t.Fatalf("diagnostic is not an ExitError: %T", err)
			}
			if exit.Category != tt.category {
				t.Errorf("category = %q, want %q", exit.Category, tt.category)
			}
		})
	}
}

// TestReportSettingsDiscovery asserts the two halves of the discovery rule: the
// settings file is read from the process working directory, and never from a
// --path root. --path is repeatable, so several roots cannot each carry one
// policy, and a policy file inside the configuration under analysis would let
// the change author lower the gate.
func TestReportSettingsDiscovery(t *testing.T) {
	// delegated-without-sibling carries two warnings and no error, so it exits
	// 0 at the default threshold and 1 at a threshold of warning. That makes
	// the exit code a direct read-out of which settings file was in force.
	source := absFixture(t, "delegated-without-sibling")

	settings := []byte("fail_on: warning\n")

	t.Run("a settings file in the working directory is read", func(t *testing.T) {
		work := t.TempDir()
		if err := os.WriteFile(filepath.Join(work, ".ctfkit.yaml"), settings, 0o600); err != nil {
			t.Fatalf("write the settings file: %v", err)
		}
		t.Chdir(work)

		if _, code := runReport(t, "--path", source, "--catalog", fixtureCatalog,
			"--out", filepath.Join(t.TempDir(), "report.md")); code != ExitFindings {
			t.Errorf("exit code = %d, want %d: the working directory's fail_on was not applied", code, ExitFindings)
		}
	})

	t.Run("a settings file under the --path root is not read", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "root")
		if err := os.CopyFS(root, os.DirFS(source)); err != nil {
			t.Fatalf("copy the fixture tree: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, ".ctfkit.yaml"), settings, 0o600); err != nil {
			t.Fatalf("write the settings file: %v", err)
		}
		t.Chdir(t.TempDir())

		if _, code := runReport(t, "--path", root, "--catalog", fixtureCatalog,
			"--out", filepath.Join(t.TempDir(), "report.md")); code != ExitOK {
			t.Errorf("exit code = %d, want %d: a settings file inside the analyzed root lowered the gate", code, ExitOK)
		}
	})
}

// The release catalog is what a run gets when the operator names no file, so a
// recorded tree has to report against it and not only against the catalog the
// other tests pin. The embedded catalog once held 16 hand-written controls
// and could resolve 2 of the 12 control ids these manifests name.
//
// It passes --catalog embedded rather than omitting the flag: without it the
// loader would prefer a catalog file in the developer's home directory, and
// this test is about the catalog compiled into the binary.
func TestReportRunsOnTheEmbeddedCatalog(t *testing.T) {
	t.Chdir(repoRoot)

	args := []string{
		"--path", fixturePath("served-leaf"),
		"--run-id", "ctfkit-fixture-run",
		"--commit", "0000000000000000000000000000000000000000",
		"--platform", "local",
		"--catalog", "embedded",
	}

	out, code := runReport(t, args...)
	if code != 0 {
		t.Fatalf("report on the embedded catalog exited %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "Verdict: pass") {
		t.Errorf("report on the embedded catalog did not reach a pass verdict:\n%s", out)
	}
}

// Every control id the recorded manifests name has to render with the name the
// embedded catalog gives it, which is what proves the join happened rather
// than the id merely passing through.
func TestReportOnTheEmbeddedCatalogNamesItsControls(t *testing.T) {
	t.Chdir(repoRoot)

	out, code := runReport(t,
		"--path", fixturePath("served-leaf"),
		"--run-id", "ctfkit-fixture-run",
		"--commit", "0000000000000000000000000000000000000000",
		"--platform", "local",
		"--catalog", "embedded",
	)
	if code != 0 {
		t.Fatalf("report exited %d, want 0\n%s", code, out)
	}
	if want := "s3_bucket_event_notifications_enabled"; !strings.Contains(out, want) {
		t.Errorf("report does not mention %s:\n%s", want, out)
	}
}
