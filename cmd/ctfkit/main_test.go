package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	os.Exit(runWithFreshBinary(m))
}

// runWithFreshBinary builds the binary under test from this tree into a new
// temporary directory, once per package run, and runs the tests against it.
//
// It always builds. It used to reuse ./ctfkit at the repository root whenever
// one existed, so an old build - from another branch, or from before a
// subcommand was added - answered for the current source and the suite failed
// with errors such as "unknown command report" that nothing in the tree
// produced. A temporary directory is somewhere no other build writes.
//
// It is a separate function so the directory is removed by a defer: os.Exit
// in TestMain would skip one.
func runWithFreshBinary(m *testing.M) int {
	dir, err := os.MkdirTemp("", "ctfkit-bin-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create a directory for the test binary: %v\n", err)
		return 2
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// `go build -o ctfkit` produces ctfkit.exe on Windows, so without the
	// suffix every exec here fails with "executable file not found in %PATH%"
	// and the whole suite reports as broken.
	name := "ctfkit"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binaryPath = filepath.Join(dir, name)

	//nolint:gosec // fixed argv, no user input
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/ctfkit")
	cmd.Dir = filepath.Join("..", "..")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build the binary under test: %v\n%s", err, stderr.String())
		return 2
	}

	return m.Run()
}

func TestVersionCommand(t *testing.T) {
	//nolint:gosec // subprocess with test binary path
	cmd := exec.Command(binaryPath, "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	for _, want := range []string{"ctfkit version", "commit:", "built:", "go:", "platform:"} {
		if !strings.Contains(outputStr, want) {
			t.Errorf("version output lacks %q: %s", want, outputStr)
		}
	}
}

// TestVersionLdflags builds with the -X flags .goreleaser.yml passes: main
// must declare commit and date, or the linker drops them without a word.
func TestVersionLdflags(t *testing.T) {
	bin := filepath.Join(t.TempDir(), filepath.Base(binaryPath))
	//nolint:gosec // fixed argv, no user input
	build := exec.Command("go", "build", "-o", bin,
		"-ldflags", "-X main.version=9.9.9 -X main.commit=abc123 -X main.date=2026-10-27T14:02:11Z", "./cmd/ctfkit")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	//nolint:gosec // subprocess with the test-built binary
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	for _, want := range []string{"ctfkit version 9.9.9\n", "  commit:   abc123\n", "  built:    2026-10-27T14:02:11Z\n"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("version lacks %q:\n%s", want, out)
		}
	}
}

func TestHelpCommand(t *testing.T) {
	//nolint:gosec // subprocess with test binary path
	cmd := exec.Command(binaryPath, "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("help command failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "Usage:") {
		t.Errorf("help output missing usage: %s", outputStr)
	}
	if !strings.Contains(outputStr, "scan") {
		t.Errorf("help output missing the scan command: %s", outputStr)
	}
}

func TestScanPassingFile(t *testing.T) {
	testFile := filepath.Join("..", "..", "testdata", "pass", "valid_ctf_module.tf")

	//nolint:gosec // subprocess with test binary path
	cmd := exec.Command(binaryPath, "scan", "--stage", "pre_plan", testFile)
	output, err := cmd.CombinedOutput()

	// Should succeed
	if err != nil {
		t.Errorf("scan should pass but failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "All checks passed") {
		t.Errorf("expected success message, got: %s", outputStr)
	}
}

// scan --stage pre_plan is what the published pre-commit hook runs on the
// staged files: a file that calls no compliance.tf module is exit 1.
func TestScanFailingFile(t *testing.T) {
	testFile := filepath.Join("..", "..", "testdata", "fail", "non_ctf_module.tf")

	//nolint:gosec // subprocess with test binary path
	cmd := exec.Command(binaryPath, "scan", "--stage", "pre_plan", testFile)
	output, err := cmd.CombinedOutput()

	// Should fail
	if err == nil {
		t.Error("scan should fail but succeeded")
	}

	if outputStr := string(output); !strings.Contains(outputStr, "ctf.coverage.module_source") {
		t.Errorf("expected rule ctf.coverage.module_source in output, got: %s", outputStr)
	}
}

func TestScanControlDisable(t *testing.T) {
	testFile := filepath.Join("..", "..", "testdata", "fixtures", "plan", "03-ctf-module-disabled-control", "input", "main.tf")

	//nolint:gosec // subprocess with test binary path
	cmd := exec.Command(binaryPath, "scan", "--stage", "pre_plan", testFile)
	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Errorf("scan should fail but succeeded. Output: %s", output)
	}
	if outputStr := string(output); !strings.Contains(outputStr, "ctf.policy.disabled_control") {
		t.Errorf("expected ctf.policy.disabled_control in output, got: %s", outputStr)
	}
}

func TestJSONOutput(t *testing.T) {
	testFile := filepath.Join("..", "..", "testdata", "fail", "non_ctf_module.tf")

	//nolint:gosec // subprocess with test binary path
	cmd := exec.Command(binaryPath, "scan", "--stage", "pre_plan", "--format", "json", testFile)
	output, err := cmd.Output()

	// Should fail but produce JSON
	if err == nil {
		t.Error("scan should fail")
	}

	var doc struct {
		Watermark string           `json:"watermark"`
		Findings  []map[string]any `json:"findings"`
	}
	if jsonErr := json.Unmarshal(output, &doc); jsonErr != nil {
		t.Fatalf("output is not the json object: %v\n%s", jsonErr, output)
	}
	if doc.Watermark != "" || len(doc.Findings) == 0 || doc.Findings[0]["ruleId"] == nil {
		t.Errorf("json = %s", output)
	}
}

func TestConfigInit(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".ctfkit.yaml")

	//nolint:gosec // subprocess with test binary path
	cmd := exec.Command(binaryPath, "config", "init")
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("config init failed: %v\nOutput: %s", err, output)
	}

	// Check config file was created
	if _, statErr := os.Stat(configFile); os.IsNotExist(statErr) {
		t.Errorf("config file was not created at %s", configFile)
	}

	// Check content
	//nolint:gosec // reading test config file
	content, err := os.ReadFile(configFile) //nolint:gosec // Reading test config file
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "allowed_endpoints") {
		t.Error("config missing allowed_endpoints")
	}
	if !strings.Contains(contentStr, "soc2.compliance.tf") {
		t.Error("config missing default endpoints")
	}
}

func TestConfigValidate(t *testing.T) {
	// Use existing config file
	configFile := filepath.Join("..", "..", ".ctfkit.yaml")

	//nolint:gosec // subprocess with test binary path
	cmd := exec.Command(binaryPath, "config", "validate", configFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("config validate failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "valid") {
		t.Errorf("expected validation success message, got: %s", outputStr)
	}
}

func TestScanDirectory(t *testing.T) {
	testDir := filepath.Join("..", "..", "testdata", "pass")

	//nolint:gosec // subprocess with test binary path
	cmd := exec.Command(binaryPath, "scan", "--stage", "pre_plan", testDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("directory validation failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "All checks passed") {
		t.Errorf("expected success message, got: %s", outputStr)
	}
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantExit int
	}{
		{
			name:     "passing file returns 0",
			file:     "testdata/pass/valid_ctf_module.tf",
			wantExit: 0,
		},
		{
			name:     "failing file returns 1",
			file:     "testdata/fail/non_ctf_module.tf",
			wantExit: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testFile := filepath.Join("..", "..", tt.file)
			//nolint:gosec // subprocess with test binary path
			cmd := exec.Command(binaryPath, "scan", "--stage", "pre_plan", testFile)
			err := cmd.Run()

			exitCode := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				}
			}

			if exitCode != tt.wantExit {
				t.Errorf("expected exit code %d, got %d", tt.wantExit, exitCode)
			}
		})
	}
}

// reportFixtureContext is the run context every recorded projection was
// rendered with, plus the catalog the recorded manifests join against: the
// source file of the embedded release catalog, which carries every control id
// these manifests name.
var reportFixtureContext = []string{
	"--run-id", "ctfkit-fixture-run",
	"--commit", "0000000000000000000000000000000000000000",
	"--platform", "local",
	"--catalog", "internal/catalog/data/catalog.yaml",
}

// TestReportExitContractThroughTheBinary runs the real binary, because the
// exit code and the stderr bytes are the contract every adapter gates on and
// neither is proven by calling the command in process: only main maps an error
// onto os.Exit, and only main writes the diagnostic line.
func TestReportExitContractThroughTheBinary(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve the repository root: %v", err)
	}

	tests := []struct {
		name     string
		args     []string
		wantExit int
	}{
		{
			name:     "a clean served leaf exits 0",
			args:     []string{"--path", "testdata/fixtures/report/served-leaf/input"},
			wantExit: 0,
		},
		{
			name:     "an error-level finding exits 1",
			args:     []string{"--path", "testdata/fixtures/report/missing-manifest/input"},
			wantExit: 1,
		},
		{
			name:     "an unsupported manifest schema major exits 2",
			args:     []string{"--path", "testdata/fixtures/report/schema-4-stub/input"},
			wantExit: 2,
		},
		{
			name:     "an unreadable root exits 2 rather than 1",
			args:     []string{"--path", "testdata/pass"},
			wantExit: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"report"}, tt.args...)
			args = append(args, reportFixtureContext...)
			args = append(args, "--out", filepath.Join(t.TempDir(), "report.md"))

			//nolint:gosec // subprocess with the test binary path and fixed argv
			cmd := exec.Command(binaryPath, args...)
			cmd.Dir = repo
			err := cmd.Run()

			exitCode := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else if err != nil {
				t.Fatalf("run the binary: %v", err)
			}

			if exitCode != tt.wantExit {
				t.Errorf("exit code = %d, want %d", exitCode, tt.wantExit)
			}
		})
	}
}

// TestReportDiagnosticBytes compares what the process writes to stderr against
// the bytes recorded beside the fixture, which is the wire format an operator
// and a log scraper both read.
func TestReportDiagnosticBytes(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve the repository root: %v", err)
	}

	recorded, err := os.ReadFile(filepath.Join(repo,
		"testdata", "fixtures", "report", "schema-4-stub", "expected", "stderr.txt"))
	if err != nil {
		t.Fatalf("read the recorded diagnostic: %v", err)
	}

	args := append([]string{"report", "--path", "testdata/fixtures/report/schema-4-stub/input"},
		reportFixtureContext...)

	//nolint:gosec // subprocess with the test binary path and fixed argv
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = repo
	stderr := new(bytes.Buffer)
	cmd.Stderr = stderr
	_ = cmd.Run()

	if stderr.String() != string(recorded) {
		t.Errorf("stderr =\n%q\nwant\n%q", stderr.String(), string(recorded))
	}
}
