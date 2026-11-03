package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSettingsErrorDiagnostic pins the exit-2 diagnostic of a settings file
// that does not load, byte for byte and the same on every command that reads
// one. The wire format is the report spec's: one
// line, "ctfkit: <reason>", with no category word; the settings category
// travels on the error value (see internal/cli).
func TestSettingsErrorDiagnostic(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "bad.ctfkit.yaml")
	if err := os.WriteFile(settings, []byte("fail_on: bogus\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const reason = "fail_on is not one of error, warning, note, never; set one of them or remove the key"
	root := filepath.Join("..", "..")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "scan",
			args: []string{"scan", "--stage", "pre_plan", "--config", settings, filepath.Join(root, "testdata", "pass")},
			want: "ctfkit: settings file " + settings + ": " + reason + "\n",
		},
		{
			name: "report",
			args: []string{"report", "--path", filepath.Join(root, "testdata", "fixtures", "report", "served-leaf", "input"), "--config", settings},
			want: "ctfkit: settings file " + settings + ": " + reason + "\n",
		},
		{
			name: "config validate",
			args: []string{"config", "validate", settings},
			want: "ctfkit: settings file " + settings + ": " + reason + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//nolint:gosec // subprocess with the test binary and test-owned paths
			cmd := exec.Command(binaryPath, tt.args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()

			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 {
				t.Fatalf("exit = %v, want exit status 2\nstderr: %s", err, stderr.String())
			}
			if got := stderr.String(); got != tt.want {
				t.Errorf("stderr = %q\nwant     %q", got, tt.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want nothing on an exit-2 run", stdout.String())
			}
		})
	}
}
