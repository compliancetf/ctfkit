package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runCLIEnv makes the test binary run the CLI instead of the test suite, so
// the black-box tests exercise a real process: its exit code, its stderr line
// and its environment, HOME included.
const runCLIEnv = "CTFKIT_TEST_RUN_CLI"

func TestMain(m *testing.M) {
	if os.Getenv(runCLIEnv) != "1" {
		// Each evidence ship test runs from its own temp working directory,
		// which keeps its spool apart from every other test's and the user's.
		spoolDir = filepath.Join(".ctfkit", "spool")
		os.Exit(m.Run())
	}

	// Mirrors cmd/ctfkit/main.go, so the exit codes and the diagnostic line
	// asserted here are the ones the shipped binary produces.
	err := New("test").Execute()
	if code := ExitCode(err); code != ExitOK {
		if msg := err.Error(); msg != "" {
			fmt.Fprintf(os.Stderr, "ctfkit: %s\n", msg)
		}
		os.Exit(code)
	}
	os.Exit(0)
}

// blackBox is one subprocess run of the CLI.
type blackBox struct {
	stdout, stderr string
	code           int
}

// runBlackBox runs the CLI in a subprocess from dir with env added to the
// inherited environment.
func runBlackBox(t *testing.T, dir string, env []string, args ...string) blackBox {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locate the test binary: %v", err)
	}
	cmd := exec.Command(exe, args...) // #nosec G204 -- re-execs this test binary with test-owned arguments
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), runCLIEnv+"=1"), env...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	out := blackBox{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &exitErr):
		out.code = exitErr.ExitCode()
	default:
		t.Fatalf("running the CLI %v: %v", args, runErr)
	}
	return out
}

// TestScanAcceptance is the scan acceptance list, each row a real process.
func TestScanAcceptance(t *testing.T) {
	fixture01 := fixtureInput(t, "01-raw-s3-no-ctf")
	plan01 := filepath.Join(fixture01, "plan.json")
	// An empty HOME: no ~/.ctf catalog file and no settings file anywhere
	// the run could find one. The launch promise is findings from the
	// embedded catalog alone.
	cleanHome := []string{"HOME=" + t.TempDir(), "CTFKIT_FAIL_ON="}

	truncated := filepath.Join(t.TempDir(), "plan.json")
	full := readFile(t, plan01)
	if err := os.WriteFile(truncated, full[:len(full)/2], 0o600); err != nil {
		t.Fatalf("write the truncated plan: %v", err)
	}

	t.Run("credential-free fixture 01 exits 1 with a finding", func(t *testing.T) {
		got := runBlackBox(t, t.TempDir(), cleanHome, "scan", plan01)
		if got.code != ExitFindings {
			t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", got.code, got.stdout, got.stderr)
		}
		if !strings.Contains(got.stdout, "ctf.coverage.module_source") {
			t.Errorf("no module_source finding printed:\n%s", got.stdout)
		}
	})

	t.Run("fail-on never exits 0", func(t *testing.T) {
		got := runBlackBox(t, t.TempDir(), cleanHome, "scan", plan01, "--fail-on", "never")
		if got.code != ExitOK {
			t.Errorf("exit = %d, want 0\nstderr: %s", got.code, got.stderr)
		}
	})

	t.Run("stage post_init exits 2", func(t *testing.T) {
		got := runBlackBox(t, t.TempDir(), cleanHome, "scan", "--stage", "post_init", plan01)
		if got.code != ExitEnvironment {
			t.Errorf("exit = %d, want 2\nstderr: %s", got.code, got.stderr)
		}
		if !strings.Contains(got.stderr, "ctfkit report") {
			t.Errorf("diagnostic does not point at report: %s", got.stderr)
		}
	})

	t.Run("truncated plan exits 2", func(t *testing.T) {
		got := runBlackBox(t, t.TempDir(), cleanHome, "scan", truncated)
		if got.code != ExitEnvironment {
			t.Errorf("exit = %d, want 2\nstderr: %s", got.code, got.stderr)
		}
		if got.stdout != "" {
			t.Errorf("an exit-2 run wrote output: %s", got.stdout)
		}
	})

	t.Run("pre_plan passes testdata/pass", func(t *testing.T) {
		got := runBlackBox(t, absPath(t, "."), cleanHome, "scan", "--stage", "pre_plan", "testdata/pass/")
		if got.code != ExitOK {
			t.Errorf("exit = %d, want 0\nstdout: %s\nstderr: %s", got.code, got.stdout, got.stderr)
		}
	})

	// The hidden validate alias is gone; the name is now a missing path.
	t.Run("validate is no command", func(t *testing.T) {
		got := runBlackBox(t, absPath(t, "."), cleanHome, "validate", "testdata/pass/")
		if got.code != ExitEnvironment || !strings.Contains(got.stderr, `no file or directory "validate"`) {
			t.Errorf("exit = %d, want 2 naming the missing path\nstderr: %s", got.code, got.stderr)
		}
	})
}

// TestScanAllowedResources is the resource allowlist the legacy validator
// enforced, carried into ctf.origin.provider_resource_type.
func TestScanAllowedResources(t *testing.T) {
	dir, err := filepath.Abs("testdata/allowed-resources")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		config string
		exit   int
	}{
		{"only-s3.ctfkit.yaml", ExitFindings},
		{"both.ctfkit.yaml", ExitOK},
	} {
		t.Run(tc.config, func(t *testing.T) {
			got := runScanIn(t, dir, "scan", "--stage", "pre_plan", "--config", tc.config, "--format", "json", "main.tf")
			if got.code != tc.exit {
				t.Errorf("exit = %d, want %d (%v)\n%s", got.code, tc.exit, got.err, got.stdout)
			}
			fired := strings.Contains(got.stdout, `"ruleId": "ctf.origin.provider_resource_type"`)
			if fired != (tc.exit == ExitFindings) {
				t.Errorf("provider_resource_type fired = %t:\n%s", fired, got.stdout)
			}
		})
	}
}
