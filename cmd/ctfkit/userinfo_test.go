package main

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The in-process tests in internal/cli assert on the error main prints. This
// runs the built binary and reads its real stderr, so the one line main writes
// is checked end to end: a credential in a flag value must not reach a CI log.
func TestBinaryStderrCarriesNoUserinfo(t *testing.T) {
	const secret = "canary-s3cret"
	url := "https://user:" + secret + "@example.invalid/c.yaml"

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	served := filepath.Join(root, "testdata", "fixtures", "report", "served-leaf", "input")
	plan := filepath.Join(root, "testdata", "fixtures", "plan", "01-raw-s3-no-ctf", "input", "plan.json")

	for name, args := range map[string][]string{
		"report": {"report", "--path", served, "--catalog", url},
		"scan":   {"scan", plan, "--catalog", url},
	} {
		t.Run(name, func(t *testing.T) {
			//nolint:gosec // subprocess with the test binary and fixed arguments
			cmd := exec.Command(binaryPath, args...)
			cmd.Dir = t.TempDir()
			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 {
				t.Fatalf("exit = %v, want 2\nstderr: %s", err, stderr.String())
			}
			if strings.Contains(stderr.String(), secret) {
				t.Errorf("stderr carries the credential:\n%s", stderr.String())
			}
			if !strings.Contains(stderr.String(), "example.invalid") {
				t.Errorf("stderr no longer names the value at all; the host should remain:\n%s", stderr.String())
			}
		})
	}
}
