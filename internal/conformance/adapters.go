package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// CLI is the command line adapter: the built binary with the fixture's argv
// and --format sarif. Its native output is SARIF, so ToSARIF is the identity.
type CLI struct {
	// Bin is the ctfkit binary under test.
	Bin string
}

// Name implements Adapter.
func (CLI) Name() string { return "cli" }

// Stages implements Adapter: the CLI runs every stage.
func (CLI) Stages() []ctfkit.Stage {
	return []ctfkit.Stage{ctfkit.PrePlan, ctfkit.PostInit, ctfkit.PostPlan}
}

// ToSARIF implements Adapter.
func (CLI) ToSARIF(native []byte) ([]byte, error) { return native, nil }

// Run implements Adapter. A plan case runs its argv from the input directory,
// with the run context and the case's pinned catalog as flags.
// A report case runs the README regeneration command from the repository root.
func (c CLI) Run(t testing.TB, f Fixture) ([]byte, error) {
	env := append(baseEnv(t, c.Bin), "CTFKIT_FAIL_ON=")
	flags := []string{"--format", "sarif", "--run-id", FixtureRunID, "--commit", FixtureCommit, "--platform", "local"}
	if f.CatalogPath != "" {
		flags = append(flags, "--catalog", f.CatalogPath)
	}

	dir, argv := f.Input, f.Argv
	if f.Family == FamilyReport {
		rel, err := relInput(f)
		if err != nil {
			return nil, err
		}
		dir, argv = f.Root, []string{"report", "--path", rel}
		if f.TestsJSON != "" {
			argv = append(argv, "--tests-json", filepath.Join(rel, "tests.json"))
		}
	}

	p, err := run(dir, env, c.Bin, append(append([]string{}, argv...), flags...)...)
	if err != nil {
		return nil, err
	}
	if p.code != f.Exit {
		return nil, fmt.Errorf("exit %d, want %d\nstderr: %s", p.code, f.Exit, p.stderr)
	}
	if f.Exit == 2 {
		if f.Stderr != nil && !bytes.Equal(p.stderr, f.Stderr) {
			return nil, fmt.Errorf("stderr %q, recorded %q", p.stderr, f.Stderr)
		}
		return nil, nil
	}
	return p.stdout, nil
}

// GitHubAction runs the Run ctfkit step of adapters/github/action.yml exactly
// as the composite action composes it: the step's own shell script, its env
// mapping resolved from the action's inputs, and the runner variables a
// GitHub-hosted job sets. The install step is replaced by putting the binary
// under test on PATH, which is what that step does with a released one.
type GitHubAction struct {
	Bin string
	// Dir is adapters/github, the action path.
	Dir string
}

// Name implements Adapter.
func (GitHubAction) Name() string { return "github-action" }

// Stages implements Adapter: command report at post_init, command scan with
// a plan at post_plan.
func (GitHubAction) Stages() []ctfkit.Stage { return []ctfkit.Stage{ctfkit.PostInit, ctfkit.PostPlan} }

// ToSARIF implements Adapter: the action's native output is the SARIF file it
// uploads.
func (GitHubAction) ToSARIF(native []byte) ([]byte, error) { return native, nil }

type actionFile struct {
	Inputs map[string]struct {
		Default string `yaml:"default"`
	} `yaml:"inputs"`
	Runs struct {
		Steps []struct {
			ID  string            `yaml:"id"`
			Env map[string]string `yaml:"env"`
			Run string            `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"runs"`
}

var expression = regexp.MustCompile(`^\$\{\{\s*(inputs\.([a-z-]+)|github\.action_path)\s*\}\}$`)

// Run implements Adapter.
func (a GitHubAction) Run(t testing.TB, f Fixture) ([]byte, error) {
	var action actionFile
	raw, err := os.ReadFile(filepath.Join(a.Dir, "action.yml")) //nolint:gosec // the adapter directory the caller names
	if err != nil {
		return nil, err
	}
	if err = yaml.Unmarshal(raw, &action); err != nil {
		return nil, fmt.Errorf("action.yml: %w", err)
	}

	inputs := map[string]string{}
	for name, in := range action.Inputs {
		inputs[name] = in.Default
	}
	inputs["catalog"] = orDefault(f.CatalogPath, inputs["catalog"])
	inputs["config"] = f.ConfigPath
	inputs["exceptions"] = f.ExceptionsPath
	dir := f.Input
	if f.Family == FamilyReport {
		inputs["command"] = "report"
		if inputs["path"], err = relInput(f); err != nil {
			return nil, err
		}
		// The action's tests-json input, set when the case records imported
		// test results, as the CLI adapter passes --tests-json.
		if f.TestsJSON != "" {
			inputs["tests-json"] = f.TestsJSON
		}
		dir = f.Root
	} else {
		inputs["command"] = "scan"
		inputs["plan"] = filepath.Join(f.Input, "plan.json")
	}

	for _, step := range action.Runs.Steps {
		if step.ID == "report" {
			return a.runStep(t, dir, step.Env, step.Run, inputs, f)
		}
	}
	return nil, fmt.Errorf("action.yml has no step with id report")
}

func (a GitHubAction) runStep(t testing.TB, dir string, stepEnv map[string]string, script string,
	inputs map[string]string, f Fixture) ([]byte, error) {
	tmp := t.TempDir()
	output, envFile := filepath.Join(tmp, "output"), filepath.Join(tmp, "env")
	env := append(baseEnv(t, a.Bin),
		"RUNNER_TEMP="+tmp, "GITHUB_RUN_ID="+FixtureRunID, "GITHUB_RUN_ATTEMPT=1", "GITHUB_SHA="+FixtureCommit,
		"GITHUB_OUTPUT="+output, "GITHUB_ENV="+envFile)
	for key, value := range stepEnv {
		m := expression.FindStringSubmatch(value)
		switch {
		case m == nil:
			return nil, fmt.Errorf("step env %s=%q is not an input or the action path", key, value)
		case m[1] == "github.action_path":
			env = append(env, key+"="+a.Dir)
		default:
			env = append(env, key+"="+inputs[m[2]])
		}
	}

	// shell: bash on a GitHub runner is `bash --noprofile --norc -eo pipefail {0}`.
	scriptFile := filepath.Join(tmp, "step.sh")
	if err := os.WriteFile(scriptFile, []byte(script), 0o600); err != nil {
		return nil, err
	}
	p, err := run(dir, env, "bash", "--noprofile", "--norc", "-eo", "pipefail", scriptFile)
	if err != nil {
		return nil, err
	}

	outputs, err := readOutputs(output)
	if err != nil {
		return nil, err
	}
	if outputs["exit-code"] != fmt.Sprint(f.Exit) {
		return nil, fmt.Errorf("output exit-code=%q, want %d (step exit %d)\nstderr: %s",
			outputs["exit-code"], f.Exit, p.code, p.stderr)
	}
	if f.Exit == 2 {
		return nil, nil
	}
	if outputs["sarif"] == "" {
		return nil, fmt.Errorf("the step wrote no sarif output\nstderr: %s", p.stderr)
	}
	return os.ReadFile(outputs["sarif"]) //nolint:gosec // written by the step into the harness temp directory
}

// readOutputs parses the name=value lines a step appends to GITHUB_OUTPUT.
func readOutputs(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the harness's own temp file
	if err != nil {
		return nil, fmt.Errorf("GITHUB_OUTPUT: %w", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if name, value, ok := strings.Cut(line, "="); ok {
			out[name] = value
		}
	}
	return out, nil
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// Spacelift runs the ctfkit hooks of an adapters/spacelift configuration file
// in a copy of the fixture input, as the project root of a run, and reads the
// metadata file the hook leaves there. Hooks that never call ctfkit are
// skipped. A hook that is a script around ctfkit (the after_plan plan probe)
// runs whole, with the fixture's plan.json as the saved plan and a stub tofu
// that prints it back. The runner image's policy files are replaced by the
// case's.
type Spacelift struct {
	Bin string
	// File is config.stack.yml (after_init report, after_plan scan) or
	// config.yml (module test after_init).
	File string
}

// Name implements Adapter.
func (s Spacelift) Name() string { return "spacelift/" + filepath.Base(s.File) }

// Stages implements Adapter.
func (s Spacelift) Stages() []ctfkit.Stage {
	hooks, err := s.hooks()
	if err != nil {
		return nil
	}
	var stages []ctfkit.Stage
	for stage, cmds := range hooks {
		if len(cmds) > 0 {
			stages = append(stages, stage)
		}
	}
	return stages
}

// FieldsOnly implements FieldsOnly.
func (Spacelift) FieldsOnly() bool { return true }

func (s Spacelift) hooks() (map[ctfkit.Stage][]string, error) {
	var file struct {
		AfterInit    []string `yaml:"after_init"`
		AfterPlan    []string `yaml:"after_plan"`
		TestDefaults struct {
			AfterInit []string `yaml:"after_init"`
		} `yaml:"test_defaults"`
	}
	raw, err := os.ReadFile(s.File) //nolint:gosec // the adapter configuration the caller names
	if err != nil {
		return nil, err
	}
	if err = yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("%s: %w", s.File, err)
	}
	return map[ctfkit.Stage][]string{
		ctfkit.PostInit: append(file.AfterInit, file.TestDefaults.AfterInit...),
		ctfkit.PostPlan: file.AfterPlan,
	}, nil
}

// Run implements Adapter.
func (s Spacelift) Run(t testing.TB, f Fixture) ([]byte, error) {
	hooks, err := s.hooks()
	if err != nil {
		return nil, err
	}
	work := t.TempDir()
	if err = os.CopyFS(work, os.DirFS(f.Input)); err != nil {
		return nil, err
	}
	config := orDefault(f.ConfigPath, writeTemp(t, "ctfkit.yaml", "{}\n"))
	exceptions := orDefault(f.ExceptionsPath, writeTemp(t, "exceptions.yaml", "exceptions: []\n"))
	env := append(baseEnv(t, s.Bin), "TF_VAR_spacelift_run_id="+FixtureRunID, "TF_VAR_spacelift_commit_sha="+FixtureCommit)

	// A script that finds the saved plan and runs tofu show itself (the
	// after_plan plan probe) runs as written, against the fixture plan and a
	// stub tofu, set up once for the stage. The hooks are POSIX sh, as on a
	// Spacelift worker, so that path does not run on Windows.
	for _, hook := range hooks[f.Stage] {
		if invokesCtfkit.MatchString(hook) && !strings.HasPrefix(hook, "ctfkit ") {
			if runtime.GOOS == "windows" {
				t.Skip("Spacelift hook scripts are POSIX sh")
			}
			if env, err = stubTofu(t, work, env); err != nil {
				return nil, err
			}
			break
		}
	}

	ran := false
	for _, hook := range hooks[f.Stage] {
		if !invokesCtfkit.MatchString(hook) {
			continue
		}
		hook = strings.NewReplacer(
			"/opt/ctfkit/ctfkit.yaml", quote(config),
			"/opt/ctfkit/exceptions.yaml", quote(exceptions),
		).Replace(hook)
		if f.CatalogPath != "" {
			hook = strings.Replace(hook, "--catalog embedded", "--catalog "+quote(f.CatalogPath), 1)
		}
		p, runErr := run(work, env, "sh", "-c", hook)
		if runErr != nil {
			return nil, runErr
		}
		// Every hook exits 0 on findings (a spacelift-only format list, or
		// --fail-on never); exit 2 is a tool error and fails the hook.
		want := 0
		if f.Exit == 2 {
			want = 2
		}
		if p.code != want {
			return nil, fmt.Errorf("hook %q exited %d, want %d\nstderr: %s", hook, p.code, want, p.stderr)
		}
		ran = true
	}
	if !ran {
		return nil, fmt.Errorf("%s has no ctfkit hook for stage %s", s.File, f.Stage)
	}
	if f.Exit == 2 {
		return nil, nil
	}
	name := "ctfkit.custom.spacelift.json"
	if f.Stage == ctfkit.PostPlan {
		name = "ctfkit-scan.custom.spacelift.json"
	}
	return os.ReadFile(filepath.Join(work, name)) //nolint:gosec // the harness's own temp directory
}

// ToSARIF implements Adapter. The summary file carries rule ids, levels,
// messages, per-level counts, the verdict and the watermark; that is all the
// projection can hold. Counts and verdict are kept as run properties, so the
// comparison reads what the file said rather than recomputing it.
func (Spacelift) ToSARIF(native []byte) ([]byte, error) {
	var doc struct {
		Verdict   string         `json:"verdict"`
		Watermark string         `json:"watermark"`
		Summary   map[string]int `json:"summary"`
		Findings  []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message string `json:"message"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(native, &doc); err != nil {
		return nil, fmt.Errorf("parse the summary file: %w", err)
	}
	results := make([]map[string]any, 0, len(doc.Findings))
	for _, f := range doc.Findings {
		results = append(results, map[string]any{
			"ruleId": f.RuleID, "level": f.Level, "message": map[string]string{"text": f.Message},
		})
	}
	return json.MarshalIndent(map[string]any{
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"properties": map[string]any{
				propWatermark: doc.Watermark, propVerdict: doc.Verdict, propSummary: doc.Summary,
			},
			"results": results,
		}},
	}, "", "  ")
}

func writeTemp(t testing.TB, name, body string) string {
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// invokesCtfkit matches a hook that runs the ctfkit binary as a command, at
// the start of the hook or after a shell separator, rather than one that only
// mentions it.
var invokesCtfkit = regexp.MustCompile(`(^|[\s;&|(])ctfkit (scan|report)\b`)

// stubTofu moves the fixture's plan.json to spacelift.plan, the saved plan a
// Spacelift after_plan hook looks for, and returns env with a tofu on PATH
// whose `show -json FILE` prints FILE back. With no plan.json, or a
// spacelift.plan already in place, it leaves the directory and env as they are.
func stubTofu(t testing.TB, work string, env []string) ([]string, error) {
	plan, saved := filepath.Join(work, "plan.json"), filepath.Join(work, "spacelift.plan")
	if _, err := os.Stat(plan); err != nil {
		return env, nil //nolint:nilerr // no fixture plan: nothing to stub
	}
	if _, err := os.Stat(saved); err == nil {
		return env, nil
	}
	if err := os.Rename(plan, saved); err != nil {
		return nil, fmt.Errorf("stub tofu: %w", err)
	}
	bin := t.TempDir()
	stub := "#!/bin/sh\n[ \"$1 $2\" = 'show -json' ] && exec cat \"$3\"\necho \"stub tofu: $*\" >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "tofu"), []byte(stub), 0o700); err != nil { //nolint:gosec // an executable stub in the harness's temp directory
		return nil, fmt.Errorf("stub tofu: %w", err)
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if path, ok := strings.CutPrefix(kv, "PATH="); ok {
			kv = "PATH=" + bin + string(os.PathListSeparator) + path
		}
		out = append(out, kv)
	}
	return out, nil
}

// quote single-quotes a path for sh.
func quote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}
