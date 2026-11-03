package spacelift

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
)

// stubGateCtfkit logs its argv to $STUB_LOG and plays the part of ctfkit the
// gate workflow relies on: gate plan creates a 0700 set holding a planfile
// (or exits $STUB_PLAN_EXIT), gate sign refuses modes wider than 0700 and
// 0600 and exits $STUB_SIGN_EXIT, apply refuses a set with no verdict.
const stubGateCtfkit = `#!/bin/sh
echo "$*" >> "$STUB_LOG"
val() { f=$1; shift; while [ $# -gt 1 ]; do [ "$1" = "$f" ] && { echo "$2"; return; }; shift; done; }
case "$1 $2" in
"gate plan")
  [ -z "${STUB_PLAN_EXIT:-}" ] || exit "$STUB_PLAN_EXIT"
  out=$(val --out "$@")
  [ ! -e "$out" ] || { echo "--out $out must not exist" >&2; exit 2; }
  mkdir -m 0700 "$out" && (umask 077 && echo candidate > "$out/planfile" && echo '{}' > "$out/candidate.json")
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
  ;;
*) exit 9 ;;
esac
`

// stubGateTofu answers the two calls the workflow makes besides init. With
// $STUB_NO_WS set, workspace show prints nothing and exits $STUB_NO_WS.
const stubGateTofu = `#!/bin/sh
case "$1 $2" in
"workspace show") [ -z "${STUB_NO_WS:-}" ] || exit "$STUB_NO_WS"; echo ws1 ;;
"show -json") [ -f "$3" ] && echo '{}' ;;
*) exit 0 ;;
esac
`

const (
	planFileName = "spacelift.plan"
	gateSet      = ".ctfkit-artifacts"
	gateMetadata = "ctfkit-gate.custom.spacelift.json"
)

// workflowData is a stand-in for what Spacelift passes to the workflow
// templates, not Spacelift's own type. render executes templates on this
// struct, so a template field the struct lacks fails at render: a field the
// workflow uses that this stand-in does not model fails the test (fail
// closed) instead of rendering empty.
type workflowData struct {
	Lock, Refresh               bool
	PlanFileName, WorkspaceName string
	Targets                     []string
}

// TestGateWorkflow runs the commands of workflow.yml and the before_apply hook
// of config.gate.yml in the order Spacelift runs them for a tracked run: plan,
// showPlan, before_apply, apply. Templates are rendered with text/template,
// the package Spacelift's templates are written for.
func TestGateWorkflow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Spacelift workflow commands are POSIX sh")
	}
	workflow := gateWorkflow(t)
	hook := beforeApplyHook(t)
	shells := []string{"sh"}
	if _, err := exec.LookPath("bash"); err == nil {
		shells = append(shells, "bash")
	}
	for _, tc := range []struct {
		name      string
		targets   []string
		noRefresh bool
		stale     bool   // a ctfkit-gate metadata file is already in the workspace
		planExit  string // gate plan exit code
		between   string // "regenerate" replaces the plan file, "lose" removes the set, "symlink" makes the signed set a symlink before apply
		noWS      string // STUB_NO_WS: workspace show prints nothing and exits with this code
		signExit  string
		wantPlan  int
		wantHook  int
		wantApply int
		wantCalls []string
	}{
		{name: "plan, sign, apply", wantCalls: []string{"plan", "sign", "apply"}},
		{name: "targeted replan", targets: []string{"aws_s3_bucket.logs"}, wantPlan: 2},
		{name: "refresh off", noRefresh: true, wantPlan: 2},
		{name: "failing gate plan, stale metadata", stale: true, planExit: "1", wantPlan: 1, wantCalls: []string{"plan"}},
		{name: "regenerated plan at apply", between: "regenerate", wantApply: 2, wantCalls: []string{"plan", "sign"}},
		{name: "set did not reach apply", between: "lose", wantHook: 2, wantApply: 2, wantCalls: []string{"plan"}},
		{name: "set is a symlink at apply", between: "symlink", wantApply: 2, wantCalls: []string{"plan", "sign"}},
		{name: "empty workspace", noWS: "0", wantPlan: 2},
		{name: "workspace show fails", noWS: "1", wantPlan: 2},
		{name: "verdict refuses the plan", signExit: "1", wantHook: 1, wantCalls: []string{"plan", "sign"}},
	} {
		for _, shell := range shells {
			t.Run(tc.name+"/"+shell, func(t *testing.T) {
				bin := t.TempDir()
				writeStub(t, bin, "ctfkit", stubGateCtfkit)
				writeStub(t, bin, "tofu", stubGateTofu)
				work := t.TempDir()
				log := filepath.Join(t.TempDir(), "calls")
				if tc.stale {
					writeFile(t, filepath.Join(work, gateMetadata), `{"schema":"ctfkit.spacelift-gate/1"}`)
				}
				env := append(gateEnv(bin, log), "STUB_PLAN_EXIT="+tc.planExit, "STUB_SIGN_EXIT="+tc.signExit, "STUB_NO_WS="+tc.noWS)
				data := workflowData{Lock: true, Refresh: !tc.noRefresh, PlanFileName: planFileName, WorkspaceName: "ws1", Targets: tc.targets}
				run := func(script string) (int, string) { return runSh(t, shell, render(t, script, data), work, env) }

				code, stderr := run(workflow["plan"])
				_, metaErr := os.Stat(filepath.Join(work, gateMetadata))
				if code != tc.wantPlan {
					t.Fatalf("plan exit %d, want %d\nstderr: %s", code, tc.wantPlan, stderr)
				}
				if code == 0 {
					plan, err := os.ReadFile(filepath.Join(work, planFileName)) // #nosec G304 -- test temp dir
					if err != nil || string(plan) != "candidate\n" {
						t.Errorf("%s holds %q (%v), want the candidate's planfile", planFileName, plan, err)
					}
					meta, err := os.ReadFile(filepath.Join(work, gateMetadata)) // #nosec G304 -- test temp dir
					if err != nil || string(meta) != `{"schema":"ctfkit.spacelift-gate/1"}`+"\n" {
						t.Errorf("gate metadata %q (%v)", meta, err)
					}
					if code, stderr = run(workflow["showPlan"]); code != 0 {
						t.Errorf("showPlan exit %d: %s", code, stderr)
					}
					switch tc.between {
					case "regenerate":
						writeFile(t, filepath.Join(work, planFileName), "regenerated")
					case "lose":
						if err = os.RemoveAll(filepath.Join(work, gateSet)); err != nil {
							t.Fatal(err)
						}
					default:
						loosen(t, filepath.Join(work, gateSet))
					}
					if code, stderr = runSh(t, shell, hook, work, env); code != tc.wantHook {
						t.Fatalf("before_apply exit %d, want %d\nstderr: %s", code, tc.wantHook, stderr)
					}
					if tc.between == "symlink" {
						moved := filepath.Join(t.TempDir(), "set")
						if err = os.Rename(filepath.Join(work, gateSet), moved); err != nil {
							t.Fatal(err)
						}
						if err = os.Symlink(moved, filepath.Join(work, gateSet)); err != nil {
							t.Fatal(err)
						}
					}
					if code == 0 || tc.between == "lose" {
						if code, stderr = run(workflow["apply"]); code != tc.wantApply {
							t.Fatalf("apply exit %d, want %d\nstderr: %s", code, tc.wantApply, stderr)
						}
					}
				} else if metaErr == nil {
					t.Error("a failed plan left ctfkit-gate metadata in the workspace")
				}

				common := " --tf-bin " + filepath.Join(bin, "tofu") + " --workspace ws1 --environment prod --org bobthecorp" +
					" --profile /opt/ctfkit/profile.dsse.json --floor /opt/ctfkit/floor.dsse.json --bundle-dir /opt/ctfkit/bundles"
				want := map[string]string{
					"plan":  "gate plan --out " + gateSet + common,
					"sign":  "gate sign --candidate " + gateSet + " --signer awskms:arn:aws:kms:eu-west-1:111111111111:key/test --fail-on error" + common,
					"apply": "apply --artifacts " + gateSet + common,
				}
				var wantLog []string
				for _, c := range tc.wantCalls {
					wantLog = append(wantLog, want[c])
				}
				if got := callLog(t, log); !slices.Equal(got, wantLog) {
					t.Errorf("ctfkit calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantLog, "\n"))
				}
			})
		}
	}
}

// TestGateWorkflowRefusesDestroy: there is no governed destroy, so the
// workflow's destroy fails rather than destroying outside ctfkit.
func TestGateWorkflowRefusesDestroy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Spacelift workflow commands are POSIX sh")
	}
	bin := t.TempDir()
	writeStub(t, bin, "ctfkit", stubGateCtfkit)
	writeStub(t, bin, "tofu", stubGateTofu)
	log := filepath.Join(t.TempDir(), "calls")
	script := render(t, gateWorkflow(t)["destroy"], workflowData{})
	if code, _ := runSh(t, "sh", script, t.TempDir(), gateEnv(bin, log)); code != 2 {
		t.Errorf("destroy exit %d, want 2", code)
	}
	if got := callLog(t, log); got != nil {
		t.Errorf("destroy called ctfkit: %q", got)
	}
}

// gateWorkflow reads workflow.yml and checks it has every command Spacelift
// requires of a custom workflow, each one a template that parses.
func gateWorkflow(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf map[string]string
	if err = yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	keys := []string{"init", "workspaceSelect", "workspaceNew", "plan", "showState", "showPlan", "getOutputs", "apply", "destroy"}
	for _, k := range keys {
		if strings.TrimSpace(wf[k]) == "" {
			t.Errorf("workflow.yml has no %s command", k)
		}
		if _, err = template.New(k).Parse(wf[k]); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	if len(wf) != len(keys) {
		t.Errorf("workflow.yml has %d keys, want exactly %v", len(wf), keys)
	}
	return wf
}

func beforeApplyHook(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("config.gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Version     string
		BeforeApply []string `yaml:"before_apply"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err = dec.Decode(&file); err != nil {
		t.Fatalf("config.gate.yml holds only version and before_apply: %v", err)
	}
	if len(file.BeforeApply) != 1 {
		t.Fatalf("before_apply has %d hooks, want the one gate sign hook", len(file.BeforeApply))
	}
	return file.BeforeApply[0]
}

func gateEnv(bin, log string) []string {
	return []string{
		"PATH=" + bin + ":/usr/bin:/bin", "STUB_LOG=" + log,
		"CTFKIT_ORG=bobthecorp", "CTFKIT_ENVIRONMENT=prod",
		"CTFKIT_PROFILE=/opt/ctfkit/profile.dsse.json", "CTFKIT_FLOOR=/opt/ctfkit/floor.dsse.json",
		"CTFKIT_BUNDLE_DIR=/opt/ctfkit/bundles", "CTFKIT_SIGNER=awskms:arn:aws:kms:eu-west-1:111111111111:key/test",
	}
}

func render(t *testing.T, text string, data workflowData) string {
	t.Helper()
	tmpl, err := template.New("cmd").Option("missingkey=error").Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err = tmpl.Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func runSh(t *testing.T, shell, script, dir string, env []string) (int, string) {
	t.Helper()
	cmd := exec.Command(shell, "-c", script) // #nosec G204 -- the committed command text
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

// loosen widens the set's modes as a transfer that drops them would.
func loosen(t *testing.T, dir string) {
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

func callLog(t *testing.T, path string) []string {
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
