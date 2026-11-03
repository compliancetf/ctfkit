// Package env0 holds the offline check of env0.yml: its hooks run as written
// against stub ctfkit, tofu and terraform binaries, under env0's Terraform and
// OpenTofu step names.
package env0

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// stubCtfkit logs its argv to $STUB_LOG and plays the part of ctfkit that the
// flow relies on: gate plan refuses an existing --out and creates a 0700 set,
// gate sign refuses a set whose modes are wider than 0700 and 0600 and exits
// $STUB_SIGN_EXIT, apply refuses a set with no verdict and exits
// $STUB_APPLY_EXIT.
const stubCtfkit = `#!/bin/sh
echo "$*" >> "$STUB_LOG"
val() { f=$1; shift; while [ $# -gt 1 ]; do [ "$1" = "$f" ] && { echo "$2"; return; }; shift; done; }
case "$1 $2" in
"gate plan")
  out=$(val --out "$@")
  [ ! -e "$out" ] || { echo "--out $out must not exist" >&2; exit 2; }
  mkdir -m 0700 "$out" && (umask 077 && echo plan > "$out/planfile" && echo '{}' > "$out/candidate.json")
  ;;
"gate sign")
  c=$(val --candidate "$@")
  [ "$(ls -ld "$c" | cut -c1-10)" = drwx------ ] || { echo "$c is not 0700" >&2; exit 2; }
  ! ls -l "$c" | grep -v '^total' | grep -qv '^-rw-------' || { echo "a file in $c is not 0600" >&2; exit 2; }
  (umask 077 && echo '{}' > "$c/verdict.json")
  exit "${STUB_SIGN_EXIT:-0}"
  ;;
"apply --artifacts")
  [ -f "$(val --artifacts "$@")/verdict.json" ] || { echo "no verdict" >&2; exit 2; }
  exit "${STUB_APPLY_EXIT:-0}"
  ;;
*) exit 9 ;;
esac
`

const artifacts = ".ctfkit-artifacts"

// TestFlow runs the plan and apply hooks of env0.yml in one template folder,
// the way env0 would around its own plan and apply, for a Terraform and an
// OpenTofu template.
func TestFlow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("env0 custom flow steps are POSIX sh")
	}
	flavors := flowSteps(t)
	shells := []string{"sh"}
	if _, err := exec.LookPath("bash"); err == nil {
		shells = append(shells, "bash")
	}
	for _, tc := range []struct {
		name           string
		deployType     string
		skipPlan       bool   // apply step only: the plan step's folder did not reach apply
		before         string // "set" leaves an artifact set in the folder, "symlink" a symlink to one
		noTofu         bool
		noTF           bool   // neither tofu nor terraform on PATH
		unset          string // variable left out of the env
		empty          string // variable set to the empty string
		signExit       string
		applyExit      string
		wantPlanExit   int  // -1: any non-zero exit
		wantApplyExit  int  // checked when the apply step runs; -1: any non-zero exit
		runApply       bool // run the apply step after a plan step that exited 0
		wantCalls      []string
		wantNoArtifact bool
	}{
		{name: "deploy", deployType: "deploy", runApply: true, wantCalls: []string{"plan", "sign", "apply"}},
		{name: "terraform only", deployType: "deploy", noTofu: true, runApply: true, wantCalls: []string{"plan", "sign", "apply"}},
		{name: "pr plan", deployType: "prPlan", wantNoArtifact: true},
		{name: "drift detection", deployType: "driftDetection", wantNoArtifact: true},
		{name: "set left in the folder", deployType: "deploy", before: "set", wantPlanExit: 2, wantCalls: []string{"plan"}},
		{name: "variable unset", deployType: "deploy", unset: "CTFKIT_ORG", wantPlanExit: -1, wantNoArtifact: true},
		{name: "variable empty", deployType: "deploy", empty: "CTFKIT_ORG", wantPlanExit: -1, wantNoArtifact: true},
		{name: "deployment type empty", deployType: "", wantPlanExit: -1, wantNoArtifact: true},
		{name: "no terraform binary", deployType: "deploy", noTF: true, wantPlanExit: 2, wantNoArtifact: true},
		{name: "signer unset", deployType: "deploy", unset: "CTFKIT_SIGNER", runApply: true, wantApplyExit: -1, wantCalls: []string{"plan"}},
		{name: "signer empty", deployType: "deploy", empty: "CTFKIT_SIGNER", runApply: true, wantApplyExit: -1, wantCalls: []string{"plan"}},
		{name: "set did not reach apply", deployType: "deploy", skipPlan: true, runApply: true, wantApplyExit: 2},
		{name: "set is a symlink", deployType: "deploy", skipPlan: true, before: "symlink", runApply: true, wantApplyExit: 2},
		{name: "verdict refuses the plan", deployType: "deploy", signExit: "1", runApply: true, wantApplyExit: 1, wantCalls: []string{"plan", "sign"}},
		{name: "terraform apply fails", deployType: "deploy", applyExit: "1", runApply: true, wantApplyExit: 1, wantCalls: []string{"plan", "sign", "apply"}},
	} {
		for _, fl := range flavors {
			for _, shell := range shells {
				tc := tc
				if fl.tofuOnly && tc.noTofu {
					// An OpenTofu template never falls back to terraform.
					tc.wantPlanExit, tc.wantCalls, tc.wantNoArtifact = 2, nil, true
				}
				plan, apply := fl.plan, fl.apply
				t.Run(fl.name+"/"+tc.name+"/"+shell, func(t *testing.T) {
					bin := t.TempDir()
					writeStub(t, bin, "ctfkit", stubCtfkit)
					tf := filepath.Join(bin, "terraform")
					if !tc.noTF {
						writeStub(t, bin, "terraform", "#!/bin/sh\nexit 0\n")
					}
					if !tc.noTofu && !tc.noTF {
						writeStub(t, bin, "tofu", "#!/bin/sh\nexit 0\n")
						tf = filepath.Join(bin, "tofu")
					}
					work := t.TempDir()
					log := filepath.Join(t.TempDir(), "calls")
					switch tc.before {
					case "set":
						mkdir(t, filepath.Join(work, artifacts))
					case "symlink":
						real := filepath.Join(t.TempDir(), "set")
						mkdir(t, real)
						if err := os.Symlink(real, filepath.Join(work, artifacts)); err != nil {
							t.Fatal(err)
						}
					}
					env := []string{
						"PATH=" + bin + ":/usr/bin:/bin", "STUB_LOG=" + log,
						"STUB_SIGN_EXIT=" + tc.signExit, "STUB_APPLY_EXIT=" + tc.applyExit,
						"ENV0_DEPLOYMENT_TYPE=" + tc.deployType, "ENV0_WORKSPACE_NAME=ws1",
					}
					for _, kv := range []string{
						"CTFKIT_ORG=bobthecorp", "CTFKIT_ENVIRONMENT=prod",
						"CTFKIT_PROFILE=/opt/ctfkit/profile.dsse.json", "CTFKIT_FLOOR=/opt/ctfkit/floor.dsse.json",
						"CTFKIT_BUNDLE_DIR=/opt/ctfkit/bundles", "CTFKIT_SIGNER=awskms:arn:aws:kms:eu-west-1:111111111111:key/test",
					} {
						name, _, _ := strings.Cut(kv, "=")
						switch name {
						case tc.unset:
						case tc.empty:
							env = append(env, name+"=")
						default:
							env = append(env, kv)
						}
					}

					if !tc.skipPlan {
						code, stderr := runStep(t, shell, plan, work, env)
						if tc.wantPlanExit == -1 && code == 0 || tc.wantPlanExit != -1 && code != tc.wantPlanExit {
							t.Fatalf("plan step exit %d, want %d\nstderr: %s", code, tc.wantPlanExit, stderr)
						}
						if tc.before == "set" {
							if entries, err := os.ReadDir(filepath.Join(work, artifacts)); err != nil || len(entries) != 0 {
								t.Errorf("the set left in the folder was changed (%v, %d entries)", err, len(entries))
							}
						}
						if code != 0 {
							tc.runApply = false
						}
					}
					if tc.runApply {
						if !tc.skipPlan {
							loosenModes(t, filepath.Join(work, artifacts))
						}
						if code, stderr := runStep(t, shell, apply, work, env); tc.wantApplyExit == -1 && code == 0 || tc.wantApplyExit != -1 && code != tc.wantApplyExit {
							t.Fatalf("apply step exit %d, want %d\nstderr: %s", code, tc.wantApplyExit, stderr)
						}
					}

					if _, err := os.Lstat(filepath.Join(work, artifacts)); tc.wantNoArtifact && err == nil {
						t.Error("an artifact set was created")
					}
					common := " --tf-bin " + tf + " --workspace ws1 --environment prod --org bobthecorp" +
						" --profile /opt/ctfkit/profile.dsse.json --floor /opt/ctfkit/floor.dsse.json --bundle-dir /opt/ctfkit/bundles"
					want := map[string]string{
						"plan":  "gate plan --out " + artifacts + common,
						"sign":  "gate sign --candidate " + artifacts + " --signer awskms:arn:aws:kms:eu-west-1:111111111111:key/test --fail-on error" + common,
						"apply": "apply --artifacts " + artifacts + common,
					}
					var wantLog []string
					for _, c := range tc.wantCalls {
						wantLog = append(wantLog, want[c])
					}
					if got := readLog(t, log); !slices.Equal(got, wantLog) {
						t.Errorf("ctfkit calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantLog, "\n"))
					}
				})
			}
		}
	}
}

// TestDestroyGuard runs the destroy hooks: a destroy deployment of a Terraform
// or an OpenTofu template stops with exit 2 before env0 destroys anything, and
// ctfkit is never called.
func TestDestroyGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("env0 custom flow steps are POSIX sh")
	}
	for _, fl := range flowSteps(t) {
		t.Run(fl.name, func(t *testing.T) {
			bin := t.TempDir()
			log := filepath.Join(t.TempDir(), "calls")
			writeStub(t, bin, "ctfkit", stubCtfkit)
			env := []string{"PATH=" + bin + ":/usr/bin:/bin", "STUB_LOG=" + log, "ENV0_DEPLOYMENT_TYPE=destroy"}
			if code, stderr := runStep(t, "sh", fl.destroy, t.TempDir(), env); code != 2 {
				t.Fatalf("destroy step exit %d, want 2\nstderr: %s", code, stderr)
			}
			if got := readLog(t, log); got != nil {
				t.Errorf("ctfkit was called: %v", got)
			}
		})
	}
}

// TestOpenTofuMirrorsTerraform fails when a hook on an env0 Terraform step has
// no matching hook on the OpenTofu step of the same name, or the other way
// round. The OpenTofu hook must run the same text except that it takes only
// tofu as --tf-bin, never terraform.
func TestOpenTofuMirrorsTerraform(t *testing.T) {
	file := readFlow(t)
	for phase, steps := range map[string]map[string]hooks{"deploy": file.Deploy.Steps, "destroy": file.Destroy.Steps} {
		for name, tf := range steps {
			rest, isTF := strings.CutPrefix(name, "terraform")
			if !isTF {
				if otRest, isOT := strings.CutPrefix(name, "opentofu"); !isOT {
					t.Errorf("%s step %s is neither a Terraform nor an OpenTofu step", phase, name)
				} else if _, ok := steps["terraform"+otRest]; !ok {
					t.Errorf("%s step %s has no Terraform counterpart terraform%s", phase, name, otRest)
				}
				continue
			}
			ot, ok := steps["opentofu"+rest]
			if !ok {
				t.Errorf("%s step %s has no OpenTofu counterpart opentofu%s", phase, name, rest)
				continue
			}
			for kind, pair := range map[string][2][]step{"before": {tf.Before, ot.Before}, "after": {tf.After, ot.After}} {
				if len(pair[0]) != len(pair[1]) {
					t.Errorf("%s %s: %d %s hooks, opentofu%s has %d", phase, name, len(pair[0]), kind, rest, len(pair[1]))
					continue
				}
				for i := range pair[0] {
					t.Run(fmt.Sprintf("%s/%s/%s/%d", phase, rest, kind, i), func(t *testing.T) {
						tfHook, otHook := pair[0][i], pair[1][i]
						if tfHook.Name != otHook.Name {
							t.Errorf("hook name %q, OpenTofu %q", tfHook.Name, otHook.Name)
						}
						if strings.Contains(otHook.Run, "terraform") {
							t.Errorf("the OpenTofu hook mentions terraform:\n%s", otHook.Run)
						}
						if got := tofuOnly.Replace(otHook.Run); got != tfHook.Run {
							t.Errorf("the OpenTofu hook differs from the Terraform hook beyond the binary probe:\n%s\nwant:\n%s", got, tfHook.Run)
						}
					})
				}
			}
		}
	}
}

// tofuOnly turns the OpenTofu hooks' binary probe back into the Terraform
// hooks' one, the only difference the two may have.
var tofuOnly = strings.NewReplacer(
	`tf="$(command -v tofu || :)"`, `tf="$(command -v tofu || command -v terraform || :)"`,
	`"ctfkit: tofu is not on PATH"`, `"ctfkit: neither tofu nor terraform is on PATH"`,
)

type step struct{ Name, Run string }

type hooks struct{ Before, After []step }

type flow struct {
	Version int
	Deploy  struct{ Steps map[string]hooks }
	Destroy struct{ Steps map[string]hooks }
}

func readFlow(t *testing.T) flow {
	t.Helper()
	raw, err := os.ReadFile("env0.yml")
	if err != nil {
		t.Fatal(err)
	}
	var file flow
	if err = yaml.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Version != 2 {
		t.Fatalf("version %d, want 2", file.Version)
	}
	return file
}

// flavor is the run text of the one before hook on each step env0 runs for a
// Terraform or an OpenTofu template.
type flavor struct {
	name                 string
	plan, apply, destroy string
	tofuOnly             bool // --tf-bin is tofu, never terraform
}

func flowSteps(t *testing.T) []flavor {
	t.Helper()
	file := readFlow(t)
	steps, d := file.Deploy.Steps, file.Destroy.Steps
	if len(steps) != 4 || len(d) != 2 {
		t.Fatalf("want plan and apply steps for terraform and opentofu, and their destroy steps, got %+v and %+v", steps, d)
	}
	var out []flavor
	for _, p := range []string{"terraform", "opentofu"} {
		plan, apply, destroy := steps[p+"Plan"], steps[p+"Apply"], d[p+"Destroy"]
		for name, h := range map[string]hooks{p + "Plan": plan, p + "Apply": apply, p + "Destroy": destroy} {
			if len(h.Before) != 1 || len(h.After) != 0 {
				t.Fatalf("want exactly one before hook on %s, got %+v", name, h)
			}
		}
		out = append(out, flavor{
			name: p, plan: plan.Before[0].Run, apply: apply.Before[0].Run, destroy: destroy.Before[0].Run,
			tofuOnly: p == "opentofu",
		})
	}
	return out
}

// runStep runs a step the way env0 does with shell sh or bash: the run text as
// one script, in the template folder.
func runStep(t *testing.T, shell, script, dir string, env []string) (int, string) {
	t.Helper()
	cmd := exec.Command(shell, "-c", script) // #nosec G204 -- the committed step text
	cmd.Dir = dir
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), stderr.String()
	case err != nil:
		t.Fatal(err)
	}
	return 0, stderr.String()
}

// loosenModes widens the set as a transfer that drops file modes would, so
// the apply step has to restore them before ctfkit reads the set.
func loosenModes(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err = os.Chmod(filepath.Join(dir, e.Name()), 0o644); err != nil { //nolint:gosec // simulates a transfer that widened modes
			t.Fatal(err)
		}
	}
	if err = os.Chmod(dir, 0o755); err != nil { //nolint:gosec // simulates a transfer that widened modes
		t.Fatal(err)
	}
}

func readLog(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil { //nolint:gosec // an executable stub in the test's temp directory
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
}
