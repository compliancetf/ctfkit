package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const configDirNote = "ctfkit: configuration directory "

// TestScanNamesTheConfigDirOnlyWhenNoneWasNamed is a regression test: a scan
// that falls back to the working directory says so on one
// stderr line, and a scan that names its configuration prints nothing. stdout
// is the same either way, so no projection changes.
func TestScanNamesTheConfigDirOnlyWhenNoneWasNamed(t *testing.T) {
	input := fixtureInput(t, "02-ctf-module-intact")
	plan := filepath.Join(input, "plan.json")

	tests := []struct {
		name     string
		args     []string
		wantNote bool
	}{
		{"plan only", []string{"scan", plan}, true},
		{"--chdir", []string{"scan", plan, "--chdir", input}, false},
		{"directory argument", []string{"scan", "--stage", "pre_plan", input}, false},
		{"file list", []string{"scan", "--stage", "pre_plan", filepath.Join(input, "main.tf")}, false},
	}

	stdout := map[string]string{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append(append(tt.args, "--format", "json"), scanRunContext...)
			res := runScanIn(t, input, args...)
			if res.code != 0 {
				t.Fatalf("exit %d, want 0\n%s", res.code, res.stderr)
			}
			stdout[tt.name] = res.stdout

			var notes []string
			for _, line := range strings.Split(res.stderr, "\n") {
				if strings.HasPrefix(line, configDirNote) {
					notes = append(notes, line)
				}
			}
			switch {
			case !tt.wantNote && len(notes) != 0:
				t.Errorf("stderr names a configuration directory the operator named: %q", notes)
			case tt.wantNote && len(notes) != 1:
				t.Errorf("stderr carries %d configuration directory lines, want 1:\n%s", len(notes), res.stderr)
			case tt.wantNote && !strings.Contains(notes[0], filepath.Join("02-ctf-module-intact", "input")+" "):
				t.Errorf("note %q does not name the working directory %s", notes[0], input)
			}
		})
	}

	if stdout["plan only"] != stdout["--chdir"] {
		t.Errorf("stdout differs between the plan-only and --chdir runs:\n%s\n%s", stdout["plan only"], stdout["--chdir"])
	}
}

// TestScanConfigDirNoteStaysOffAnErrorRun keeps the exit-2 contract of one
// stderr line: a plan-only run that fails prints its error and no notice.
func TestScanConfigDirNoteStaysOffAnErrorRun(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(plan, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	res := runScanIn(t, dir, append([]string{"scan", plan, "--format", "json"}, scanRunContext...)...)
	if res.code != ExitEnvironment {
		t.Fatalf("exit %d, want %d\n%s", res.code, ExitEnvironment, res.stderr)
	}
	if strings.Contains(res.stderr, configDirNote) {
		t.Errorf("an exit-2 run printed the configuration directory notice:\n%s", res.stderr)
	}
}
