package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/config"
)

func TestCLI_Version(t *testing.T) {
	cli := New("test-version")
	cli.rootCmd.SetArgs([]string{"version"})

	// Capture output
	out := new(bytes.Buffer)
	cli.rootCmd.SetOut(out)

	err := cli.Execute()
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "test-version") {
		t.Errorf("Version output missing version string: %s", output)
	}
}

// TestVersionStamp: the commit and date the release build stamps are what
// version prints, as text, as JSON and through --version, which prints the
// same text.
func TestVersionStamp(t *testing.T) {
	run := func(args ...string) string {
		t.Helper()
		c := New("1.2.3")
		c.SetBuild("4d992d7c0ffee", "2026-10-27T14:02:11Z")
		out := new(bytes.Buffer)
		c.rootCmd.SetOut(out)
		c.rootCmd.SetArgs(args)
		if err := c.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return out.String()
	}

	text := run("version")
	for _, want := range []string{
		"ctfkit version 1.2.3\n",
		"\n  commit:   4d992d7c0ffee\n",
		"\n  built:    2026-10-27T14:02:11Z\n",
		"\n  go:       go",
		"\n  platform: ",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("version lacks %q:\n%s", want, text)
		}
	}
	if flag := run("--version"); flag != text {
		t.Errorf("--version differs from version:\n%s\n---\n%s", flag, text)
	}

	var doc map[string]string
	if err := json.Unmarshal([]byte(run("version", "-f", "json")), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "1.2.3" || doc["commit"] != "4d992d7c0ffee" || doc["date"] != "2026-10-27T14:02:11Z" ||
		doc["go_version"] == "" || doc["os"] == "" || doc["arch"] == "" {
		t.Errorf("version -f json = %v", doc)
	}
}

// TestVersionUnstamped: a build without release stamps names no empty
// commit or date.
func TestVersionUnstamped(t *testing.T) {
	commit, date := New("dev").build()
	if commit == "" || date != unknownBuild {
		t.Errorf("build() = %q, %q; want a commit and %q", commit, date, unknownBuild)
	}
}

// TestRootDispatch is the grammar of the bare command: no path prints the
// help and exits 0, a path runs scan --stage pre_plan, and a missing path that
// is a typo of a command name exits 2 naming the command.
func TestRootDispatch(t *testing.T) {
	pass := absPath(t, "testdata/pass")
	for _, tc := range []struct {
		name   string
		args   []string
		code   int
		stdout string
		err    string // the diagnostic, or its prefix when it ends in "*"
	}{
		{"bare prints the help", []string{}, ExitOK, "Check configurations and plans:", ""},
		{"flags only print the help", []string{"-f", "json"}, ExitOK, "Check configurations and plans:", ""},
		{"--help", []string{"--help"}, ExitOK, "Check configurations and plans:", ""},
		{"a path scans", []string{pass}, ExitOK, "All checks passed", ""},
		{"a typo of scan", []string{"scna"}, ExitEnvironment, "", `no file or directory "scna"; did you mean "ctfkit scan"?`},
		{"a typo of config", []string{"conifg"}, ExitEnvironment, "", `no file or directory "conifg"; did you mean "ctfkit config"?`},
		{"a short prefix of gate", []string{"gat"}, ExitEnvironment, "", `no file or directory "gat"; did you mean "ctfkit gate"?`},
		{"a long prefix is no typo", []string{"ver"}, ExitEnvironment, "", "cannot read ver: *"},
		{"a missing path far from every command", []string{"nothing-here"}, ExitEnvironment, "", "cannot read nothing-here: *"},
		{"the removed validate alias", []string{"validate"}, ExitEnvironment, "", `no file or directory "validate"; did you mean "ctfkit scan"?`},
		{"-- makes scan a path", []string{"--", "scan"}, ExitEnvironment, "", `no file or directory "scan"; did you mean "ctfkit scan"?`},
		{"a second -f", []string{pass, "-f", "json", "-f", "sarif"}, ExitEnvironment, "", "--format is given more than once; give it once"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runScanIn(t, t.TempDir(), tc.args...)
			if got.code != tc.code {
				t.Fatalf("exit = %d, want %d (%v)\nstdout: %s", got.code, tc.code, got.err, got.stdout)
			}
			if !strings.Contains(got.stdout, tc.stdout) {
				t.Errorf("stdout does not contain %q:\n%s", tc.stdout, got.stdout)
			}
			msg := ""
			if got.err != nil {
				msg = got.err.Error()
			}
			if prefix, ok := strings.CutSuffix(tc.err, "*"); ok {
				if !strings.HasPrefix(msg, prefix) {
					t.Errorf("error = %q, want prefix %q", msg, prefix)
				}
			} else if msg != tc.err {
				t.Errorf("error = %q, want %q", msg, tc.err)
			}
		})
	}
}

// TestRootDoubleDashScansADirNamedScan: after --, a directory named scan is a
// path, not the command.
func TestRootDoubleDashScansADirNamedScan(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "scan"), 0o750); err != nil {
		t.Fatal(err)
	}
	body := readFile(t, absPath(t, "testdata/pass/valid_ctf_module.tf"))
	if err := os.WriteFile(filepath.Join(dir, "scan", "main.tf"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	got := runScanIn(t, dir, "--", "scan")
	if got.code != ExitOK || !strings.Contains(got.stdout, "All checks passed") {
		t.Errorf("ctfkit -- scan: exit %d (%v)\n%s", got.code, got.err, got.stdout)
	}
}

// TestRootPathIsScanPrePlan: "ctfkit PATH -f json" is "ctfkit scan --stage
// pre_plan PATH -f json", byte for byte.
func TestRootPathIsScanPrePlan(t *testing.T) {
	fail := absPath(t, "testdata/fail")
	// No run context flags: the bare command has none, so both sides detect
	// the same context from the same environment and clock.
	short := runScanIn(t, t.TempDir(), fail, "-f", "json")
	long := runScanIn(t, t.TempDir(), "scan", "--stage", "pre_plan", fail, "-f", "json")
	if short.code != ExitFindings || short.code != long.code {
		t.Fatalf("exit = %d and %d, want 1 for both (%v, %v)", short.code, long.code, short.err, long.err)
	}
	if short.stdout != long.stdout || short.stderr != long.stderr {
		t.Errorf("ctfkit PATH differs from scan --stage pre_plan PATH:\n%s\n---\n%s", short.stdout, long.stdout)
	}
}

// TestRootHelp pins the shape of the root help: both usage lines, then the
// groups in order with their commands in order.
func TestRootHelp(t *testing.T) {
	got := runScanIn(t, t.TempDir(), "--help")
	if got.code != ExitOK {
		t.Fatalf("exit = %d (%v)", got.code, got.err)
	}
	rest := got.stdout
	for _, want := range []string{
		"ctfkit by compliance.tf checks",
		"Usage:\n  ctfkit COMMAND [flags]\n  ctfkit PATH... [flags]\n",
		"Examples:\n  ctfkit scan ./infra",
		"Check configurations and plans:\n  scan ", "\n  report ", "\n  verify-lock ",
		"Governed apply (preview):\n  gate ", "\n  verdict ", "\n  apply ", "\n  evidence ",
		"Run tasks (preview):\n  runtask ",
		"Settings and help:\n  config ", "\n  version ", "\n  completion ", "\n  help ",
		"-f, --format LIST",
	} {
		i := strings.Index(rest, want)
		if i < 0 {
			t.Fatalf("root help lacks %q after the previous part:\n%s", want, got.stdout)
		}
		rest = rest[i+len(want):]
	}
	if strings.Contains(got.stdout, "validate") {
		t.Errorf("root help still names the validate alias:\n%s", got.stdout)
	}
}

// TestHelpText holds every command's help to the rules for public text: a
// preview command says so in its Short, the text is plain ASCII, no help calls
// ctfkit a policy engine, and the commands that run terraform are not called
// offline.
func TestHelpText(t *testing.T) {
	preview := map[string]bool{
		"report": true, "verify-lock": true, "gate": true, "gate plan": true, "gate sign": true,
		"verdict": true, "verdict verify": true, "apply": true, "evidence": true, "evidence ship": true,
		"runtask": true, "runtask serve": true,
	}
	runsTerraform := map[string]bool{"gate plan": true, "gate sign": true, "verdict verify": true, "apply": true}

	var walk func(cmd *cobra.Command)
	walk = func(cmd *cobra.Command) {
		path := strings.TrimPrefix(cmd.CommandPath(), "ctfkit ")
		text := cmd.Short + "\n" + cmd.Long + "\n" + cmd.Example + "\n" + cmd.Flags().FlagUsages()
		if preview[path] != strings.HasSuffix(cmd.Short, " (preview)") {
			t.Errorf("%s: Short %q, want the (preview) label exactly when the command is preview", path, cmd.Short)
		}
		for i, r := range text {
			if r > 0x7f {
				t.Errorf("%s: non-ASCII %q at %d", path, r, i)
				break
			}
		}
		lower := strings.ToLower(text)
		if strings.Contains(lower, "policy engine") {
			t.Errorf("%s: help calls ctfkit a policy engine", path)
		}
		if runsTerraform[path] && (strings.Contains(lower, "offline") || strings.Contains(lower, "no network")) {
			t.Errorf("%s runs terraform, and its help says it works offline:\n%s", path, text)
		}
		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}
	walk(New("test").rootCmd)
}

// TestFormatFlagIsPerCommand: --format and -f exist only on the commands that
// render a format, so a command that ignores it no longer accepts it.
func TestFormatFlagIsPerCommand(t *testing.T) {
	root := New("test").rootCmd
	for path, want := range map[string]bool{
		"scan": true, "report": true, "verify-lock": true, "gate sign": true,
		"version": true, "config validate": true,
		"gate plan": false, "verdict verify": false, "apply": false, "evidence ship": false,
		"runtask serve": false, "config init": false, "completion bash": false,
	} {
		cmd, _, err := root.Find(strings.Fields(path))
		if err != nil || cmd.CommandPath() != "ctfkit "+path {
			t.Fatalf("find %q: %v, %v", path, cmd.CommandPath(), err)
		}
		cmd.InheritedFlags() // merges the persistent flags into Flags
		if got := cmd.Flags().Lookup("format") != nil && cmd.Flags().ShorthandLookup("f") != nil; got != want {
			t.Errorf("%s: --format/-f registered = %t, want %t", path, got, want)
		}
	}

	got := runScanIn(t, t.TempDir(), "gate", "plan", "-f", "json")
	if got.code != ExitEnvironment || got.err == nil || got.err.Error() != `unknown flag -f for "ctfkit gate plan"; see "ctfkit gate plan --help"` {
		t.Errorf("gate plan -f json: exit %d, err %v; want exit 2 for the unknown flag", got.code, got.err)
	}
}

// TestFormatOneOf: the single-document commands refuse a format outside
// their list, and a list.
func TestFormatOneOf(t *testing.T) {
	for _, args := range [][]string{
		{"version", "-f", "sarif"},
		{"version", "-f", "text,json"},
		{"config", "validate", "-f", "sarif", "x.yaml"},
	} {
		got := runScanIn(t, t.TempDir(), args...)
		if got.code != ExitEnvironment || got.stdout != "" {
			t.Errorf("%v: exit %d, stdout %q (%v); want exit 2 and no output", args, got.code, got.stdout, got.err)
		}
	}
}

// config validate classifies a settings file that does not load the way scan
// and report do: an exit-2 error in the settings category. The message bytes
// are pinned by cmd/ctfkit's TestSettingsErrorDiagnostic.
func TestCLI_ConfigValidateInvalidIsSettingsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctfkit.yaml")
	if err := os.WriteFile(path, []byte("fail_on: bogus\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cli := New("test")
	cli.rootCmd.SetArgs([]string{"config", "validate", path})
	cli.rootCmd.SetOut(new(bytes.Buffer))
	cli.rootCmd.SetErr(new(bytes.Buffer))

	err := cli.Execute()
	var exit *ExitError
	if !asExitError(err, &exit) || exit.Code != ExitEnvironment || exit.Category != categorySettings {
		t.Fatalf("error = %#v, want an exit-2 error in category %q", err, categorySettings)
	}
	if want := "settings file " + path + ": fail_on is not one of error, warning, note, never; set one of them or remove the key"; exit.Message != want {
		t.Errorf("message = %q, want %q", exit.Message, want)
	}
}

func TestCLI_ConfigValidateJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctfkit.yaml")
	body := "allowed_endpoints:\n  - \"soc2.compliance.tf\"\nfail_on_control_disable: true\nfail_fast: true\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cli := New("test")
	cli.rootCmd.SetArgs([]string{"--format", "json", "config", "validate", path})
	out := new(bytes.Buffer)
	cli.rootCmd.SetOut(out)

	if err := cli.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	raw := out.Bytes()
	if len(raw) == 0 {
		t.Fatal("config validate --format json wrote nothing")
	}

	var got config.Config
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, raw)
	}
	if len(got.AllowedEndpoints) != 1 || got.AllowedEndpoints[0] != "soc2.compliance.tf" {
		t.Errorf("allowed_endpoints = %v, want [soc2.compliance.tf]", got.AllowedEndpoints)
	}
	if !got.FailOnControlDisable || !got.FailFast {
		t.Errorf("flags lost in round trip: %+v", got)
	}

	// Marshaling the struct, not a map, is what keeps key order stable across runs.
	if second := renderConfigJSON(t, path); second != string(raw) {
		t.Errorf("output is not byte-stable across runs:\n%s\n%s", raw, second)
	}
}

// TestConfigInitChangesNoFinding: a module from a compliance.tf host of the
// operator's own gets the same findings with no settings file and with the
// file config init writes, since that file leaves allowed_endpoints unset.
func TestConfigInitChangesNoFinding(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no ~/.ctf catalog file
	t.Setenv("CTFKIT_FAIL_ON", "")
	dir := t.TempDir()
	main := "module \"bucket\" {\n  source  = \"bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws\"\n  version = \"5.0.0\"\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(main), 0o600); err != nil {
		t.Fatal(err)
	}
	scan := []string{"scan", "--stage", "pre_plan", "-f", "json", "--fail-on", "never", "."}

	before := runScanIn(t, dir, scan...)
	if got := runScanIn(t, dir, "config", "init"); got.code != ExitOK || got.stdout != "Wrote .ctfkit.yaml\n" {
		t.Fatalf("config init: exit %d, stdout %q (%v)", got.code, got.stdout, got.err)
	}
	after := runScanIn(t, dir, scan...)
	if before.code != ExitOK || after.code != ExitOK {
		t.Fatalf("scan: exit %d without and %d with the settings file (%v, %v)", before.code, after.code, before.err, after.err)
	}
	if before.stdout != after.stdout {
		t.Errorf("findings differ:\nwithout a settings file:\n%s\nwith the config init file:\n%s", before.stdout, after.stdout)
	}
	if strings.Contains(after.stdout, "unknown_registry") {
		t.Errorf("the bobthecorp.compliance.tf module is called an unknown registry:\n%s", after.stdout)
	}
}

// config init refuses an existing file, writing nothing, unless --force.
func TestConfigInitRefusesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ctfkit.yaml")
	if err := os.WriteFile(path, []byte("fail_on: warning\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := runScanIn(t, dir, "config", "init")
	if got.code != ExitEnvironment || got.stdout != "" || got.err == nil || !strings.Contains(got.err.Error(), "--force") {
		t.Fatalf("config init over a file: exit %d, stdout %q, err %v; want exit 2 naming --force", got.code, got.stdout, got.err)
	}
	if data := readFile(t, path); string(data) != "fail_on: warning\n" {
		t.Errorf("the refused config init changed the file:\n%s", data)
	}

	if got = runScanIn(t, dir, "config", "init", "--force"); got.code != ExitOK {
		t.Fatalf("config init --force: exit %d (%v)", got.code, got.err)
	}
	if data := readFile(t, path); strings.Contains(string(data), "fail_on: warning") {
		t.Errorf("config init --force kept the old file:\n%s", data)
	}
}

// config validate with no FILE checks .ctfkit.yaml in the working directory.
func TestConfigValidateDefaultFile(t *testing.T) {
	dir := t.TempDir()
	if got := runScanIn(t, dir, "config", "init"); got.code != ExitOK {
		t.Fatalf("config init: exit %d (%v)", got.code, got.err)
	}
	got := runScanIn(t, dir, "config", "validate")
	const want = ".ctfkit.yaml is valid\n" +
		"  allowed_endpoints: not set (any host ending in .compliance.tf)\n" +
		"  fail_on:           not set (error)\n"
	if got.code != ExitOK || got.stdout != want {
		t.Errorf("config validate: exit %d (%v)\n got %q\nwant %q", got.code, got.err, got.stdout, want)
	}
}

// config validate with no FILE reads the file --config names; FILE and a
// --config that name another file are refused.
func TestConfigValidateConfigFlag(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"ci.yaml": "fail_on: warning\n", ".ctfkit.yaml": "fail_on: note\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		args   []string
		code   int
		stdout string // prefix
	}{
		{"--config alone", []string{"--config", "ci.yaml", "config", "validate"}, ExitOK, "ci.yaml is valid\n"},
		{"FILE alone", []string{"config", "validate", "ci.yaml"}, ExitOK, "ci.yaml is valid\n"},
		{"neither", []string{"config", "validate"}, ExitOK, ".ctfkit.yaml is valid\n"},
		{"the same file twice", []string{"--config", "ci.yaml", "config", "validate", "./ci.yaml"}, ExitOK, "./ci.yaml is valid\n"},
		{"two files", []string{"--config", "ci.yaml", "config", "validate", ".ctfkit.yaml"}, ExitEnvironment, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runScanIn(t, dir, tc.args...)
			if got.code != tc.code || !strings.HasPrefix(got.stdout, tc.stdout) || (tc.stdout == "" && got.stdout != "") {
				t.Errorf("exit %d (%v), stdout %q; want exit %d, stdout %q", got.code, got.err, got.stdout, tc.code, tc.stdout)
			}
		})
	}
}

// config init writes .ctfkit.yaml only, so it refuses --config rather than
// ignore it.
func TestConfigInitRefusesConfigFlag(t *testing.T) {
	dir := t.TempDir()
	got := runScanIn(t, dir, "--config", "ci.yaml", "config", "init")
	if got.code != ExitEnvironment || got.stdout != "" {
		t.Fatalf("config init --config: exit %d (%v), stdout %q; want exit 2", got.code, got.err, got.stdout)
	}
	for _, name := range []string{"ci.yaml", ".ctfkit.yaml"} {
		if exists(filepath.Join(dir, name)) {
			t.Errorf("a refused config init wrote %s", name)
		}
	}
}

// With no allowed_endpoints key, -f json prints null, what the run uses (any
// host ending in .compliance.tf), not the list setDefaults fills in.
func TestConfigValidateJSONUnsetEndpoints(t *testing.T) {
	dir := t.TempDir()
	if got := runScanIn(t, dir, "config", "init"); got.code != ExitOK {
		t.Fatalf("config init: exit %d (%v)", got.code, got.err)
	}
	got := runScanIn(t, dir, "config", "validate", "-f", "json")
	if got.code != ExitOK || !strings.Contains(got.stdout, `"allowed_endpoints": null`) {
		t.Errorf("config validate -f json: exit %d (%v)\n%s", got.code, got.err, got.stdout)
	}
}

func renderConfigJSON(t *testing.T, path string) string {
	t.Helper()
	cli := New("test")
	cli.rootCmd.SetArgs([]string{"--format", "json", "config", "validate", path})
	out := new(bytes.Buffer)
	cli.rootCmd.SetOut(out)
	if err := cli.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	return out.String()
}
