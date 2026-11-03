package spacelift

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Stubs for the after_plan hook. tofu and terraform print a JSON line naming
// the plan file they were shown, and fail on a file named *bad*. ctfkit checks
// that plan.json is there, writes the scan metadata and exits $STUB_CTFKIT_EXIT.
const (
	stubShow = "#!/bin/sh\n" +
		"[ \"$1 $2\" = 'show -json' ] || exit 9\n" +
		"[ -f \"$3\" ] || { echo \"no file $3\" >&2; exit 1; }\n" +
		"case \"$3\" in *bad*) echo 'corrupt plan' >&2; exit 1;; esac\n" +
		"printf '{\"shown\":\"%s\",\"by\":\"%s\"}\\n' \"$3\" \"$(basename \"$0\")\"\n"
	stubCtfkit = "#!/bin/sh\n" +
		"[ -s plan.json ] || { echo 'plan.json missing' >&2; exit 2; }\n" +
		"echo '{\"schema\":\"ctfkit.spacelift/1\"}' > ctfkit-scan.custom.spacelift.json\n" +
		"exit \"${STUB_CTFKIT_EXIT:-0}\"\n"
)

// TestAfterPlanHook runs the after_plan hook text of config.stack.yml as
// written, under sh -e and bash -e -o pipefail, with stub tofu, terraform and
// ctfkit on PATH. The hooks are POSIX sh, as on a Spacelift worker.
func TestAfterPlanHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Spacelift hook scripts are POSIX sh")
	}
	hook := afterPlanHook(t)
	shells := [][]string{{"sh", "-e", "-c"}}
	if _, err := exec.LookPath("bash"); err == nil {
		shells = append(shells, []string{"bash", "-e", "-o", "pipefail", "-c"})
	}
	for _, tc := range []struct {
		name       string
		files      []string // plan files to create; a trailing / makes a directory
		stale      bool     // leave a stale plan.json and scan metadata behind
		ctfkitExit string
		noTofu     bool // only terraform on PATH
		wantExit   int
		wantShown  string // plan file shown, empty when the scan is skipped
		wantBy     string
	}{
		{name: "spacelift.plan", files: []string{"spacelift.plan", "other.tfplan"}, wantShown: "spacelift.plan", wantBy: "tofu"},
		{name: "only tfplan", files: []string{"x.tfplan"}, wantShown: "x.tfplan", wantBy: "tofu"},
		{name: "no plan", stale: true, wantExit: 0},
		{name: "directory named x.plan", files: []string{"x.plan/", "y.tfplan"}, wantShown: "y.tfplan", wantBy: "tofu"},
		{name: "name with spaces", files: []string{"my plan.tfplan"}, wantShown: "my plan.tfplan", wantBy: "tofu"},
		{name: "failing show", files: []string{"bad.plan"}, stale: true, wantExit: 1},
		{name: "ctfkit tool error", files: []string{"x.plan"}, ctfkitExit: "2", wantExit: 2, wantShown: "x.plan", wantBy: "tofu"},
		{name: "terraform fallback", files: []string{"x.plan"}, noTofu: true, wantShown: "x.plan", wantBy: "terraform"},
	} {
		for _, shell := range shells {
			t.Run(tc.name+"/"+shell[0], func(t *testing.T) {
				bin := t.TempDir()
				writeStub(t, bin, "ctfkit", stubCtfkit)
				writeStub(t, bin, "terraform", stubShow)
				if !tc.noTofu {
					writeStub(t, bin, "tofu", stubShow)
				}
				work := t.TempDir()
				for _, f := range tc.files {
					if strings.HasSuffix(f, "/") {
						mkdir(t, filepath.Join(work, f))
						continue
					}
					writeFile(t, filepath.Join(work, f), "saved plan")
				}
				if tc.stale {
					writeFile(t, filepath.Join(work, "plan.json"), "stale")
					writeFile(t, filepath.Join(work, "ctfkit-scan.custom.spacelift.json"), "stale")
				}

				cmd := exec.Command(shell[0], append(shell[1:], hook)...) // #nosec G204 -- the committed hook text
				cmd.Dir = work
				// Only the stubs and the base system: a real tofu elsewhere on PATH
				// would win over the terraform fallback.
				cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "STUB_CTFKIT_EXIT=" + tc.ctfkitExit}
				var stderr strings.Builder
				cmd.Stderr = &stderr
				err := cmd.Run()
				code := 0
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					code = exitErr.ExitCode()
				} else if err != nil {
					t.Fatal(err)
				}
				if code != tc.wantExit {
					t.Fatalf("exit %d, want %d\nstderr: %s", code, tc.wantExit, stderr.String())
				}

				plan, planErr := os.ReadFile(filepath.Join(work, "plan.json")) // #nosec G304 -- test temp dir
				_, metaErr := os.Stat(filepath.Join(work, "ctfkit-scan.custom.spacelift.json"))
				if tc.wantShown == "" {
					if planErr == nil && string(plan) == "stale" {
						t.Error("the stale plan.json was not removed")
					}
					if tc.wantExit == 0 {
						if metaErr == nil {
							t.Error("the stale ctfkit-scan metadata was not removed")
						}
						if !strings.Contains(stderr.String(), "no plan file") {
							t.Errorf("stderr %q does not report the missing plan file", stderr.String())
						}
					}
					return
				}
				want := `{"shown":"` + tc.wantShown + `","by":"` + tc.wantBy + `"}` + "\n"
				if planErr != nil || string(plan) != want {
					t.Errorf("plan.json %q (%v), want %q", plan, planErr, want)
				}
				if metaErr != nil {
					t.Errorf("no ctfkit-scan metadata written: %v", metaErr)
				}
			})
		}
	}
}

func afterPlanHook(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("config.stack.yml")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		AfterPlan []string `yaml:"after_plan"`
	}
	if err = yaml.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.AfterPlan) != 1 {
		t.Fatalf("after_plan has %d hooks, want the one plan probe", len(file.AfterPlan))
	}
	return file.AfterPlan[0]
}

func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil { //nolint:gosec // an executable stub in the test's temp directory
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
}
