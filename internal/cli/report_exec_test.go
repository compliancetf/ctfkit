package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// postInitFixtures is the ctf.exec fixture pack, relative to this package.
const postInitFixtures = "../../testdata/fixtures/postinit"

// postInitCases are the ctf.exec cases, each with the rules it must fire, the
// text it must not carry, and its exit code. clean fires none; code-exec fires
// the error rules at the root and inside downloaded modules, and none for the
// root's own remote call; endpoint-allowlist shows report reading
// allowed_endpoints from the settings file in the working directory, for a
// nested call only; local-outside reads a ../ module beside the root and
// reports its provisioner at error level.
var postInitCases = []struct {
	name   string
	exit   int
	rules  []string
	absent []string
}{
	{name: "clean", exit: ExitOK},
	{
		name: "code-exec", exit: ExitFindings,
		rules:  []string{"ctf.exec.provisioner", "ctf.exec.external_data", "ctf.exec.module_endpoint"},
		absent: []string{"Module module.app is installed", "ctf.exec.module_uninspected"},
	},
	{
		name: "endpoint-allowlist", exit: ExitFindings,
		rules:  []string{"ctf.exec.module_endpoint"},
		absent: []string{"Module module.s3_bucket_notification is installed", "module.s3_bucket_notification.module.audit"},
	},
	{
		// The ../shared module is explicit, so report reads it: its
		// provisioner is an error, and nothing is left uninspected.
		name: "local-outside", exit: ExitFindings,
		rules:  []string{"ctf.exec.provisioner"},
		absent: []string{"ctf.exec.module_uninspected"},
	},
}

// TestReportExecFixtures runs report over every case and compares the SARIF
// with expected/findings.sarif byte for byte. CTFKIT_RERECORD=1 writes the
// rendered document instead. Every command, program and file source in the
// inputs carries a CANARY- marker, and no output may: findings name blocks,
// never what they would run.
func TestReportExecFixtures(t *testing.T) {
	refuseSwitchesInCI(t)
	for _, tc := range postInitCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			base, err := filepath.Abs(filepath.Join(postInitFixtures, tc.name))
			if err != nil {
				t.Fatal(err)
			}
			got := runScanIn(t, filepath.Join(base, "input"), append([]string{"report", "--format", "sarif"}, fixtureContext...)...)
			if got.code != tc.exit {
				t.Fatalf("exit = %d, want %d (%v)", got.code, tc.exit, got.err)
			}
			for _, rule := range tc.rules {
				if !strings.Contains(got.stdout, `"ruleId": "`+rule+`"`) {
					t.Errorf("%s did not fire:\n%s", rule, got.stdout)
				}
			}
			for _, text := range tc.absent {
				if strings.Contains(got.stdout, text) {
					t.Errorf("the SARIF carries %q:\n%s", text, got.stdout)
				}
			}
			if tc.rules == nil && strings.Contains(got.stdout, `"ruleId": "ctf.exec.`) {
				t.Errorf("a ctf.exec rule fired on a clean configuration:\n%s", got.stdout)
			}
			if strings.Contains(got.stdout, "CANARY-") || strings.Contains(got.stdout, "ref=") {
				t.Errorf("the SARIF carries a value from the configuration:\n%s", got.stdout)
			}
			path := filepath.Join(base, "expected", "findings.sarif")
			if rerecording() {
				if err := os.WriteFile(path, []byte(got.stdout), 0o644); err != nil { //nolint:gosec // a committed fixture
					t.Fatal(err)
				}
				return
			}
			if want := string(readFile(t, path)); got.stdout != want {
				t.Errorf("SARIF differs from %s:\n%s", path, got.stdout)
			}
		})
	}
}

// The ../shared module of local-outside is read by both entry points: the
// root report and the root directory scan each report its provisioner at
// error level, and so does a scan of ../shared itself.
func TestLocalModuleOutsideTheRootIsInspected(t *testing.T) {
	refuseSwitchesInCI(t)
	base, err := filepath.Abs(filepath.Join(postInitFixtures, "local-outside"))
	if err != nil {
		t.Fatal(err)
	}
	input, shared := filepath.Join(base, "input"), filepath.Join(base, "shared")
	scan := []string{"scan", "--stage", "pre_plan", "--format", "sarif", "--catalog", "embedded", "."}
	for _, tc := range []struct {
		name, dir string
		args      []string
		uri       string
	}{
		{"report root", input, append([]string{"report", "--format", "sarif"}, fixtureContext...), "../shared/main.tf"},
		{"scan root", input, scan, "../shared/main.tf"},
		{"scan shared directory", shared, scan, "main.tf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			got := runScanIn(t, tc.dir, tc.args...)
			if got.code != ExitFindings {
				t.Fatalf("exit = %d, want %d (%v):\n%s", got.code, ExitFindings, got.err, got.stdout)
			}
			if !strings.Contains(got.stdout, `"ruleId": "ctf.exec.provisioner"`) ||
				!strings.Contains(got.stdout, `"uri": "`+tc.uri+`"`) {
				t.Errorf("no ctf.exec.provisioner at %s:\n%s", tc.uri, got.stdout)
			}
			// The external data source scoped to ../shared's check block.
			if !strings.Contains(got.stdout, `check.shared.data.external.probe"`) {
				t.Errorf("no ctf.exec.external_data for the check-scoped data source:\n%s", got.stdout)
			}
			if strings.Contains(got.stdout, "CANARY-") || strings.Contains(got.stdout, "module_uninspected") {
				t.Errorf("unexpected output:\n%s", got.stdout)
			}
		})
	}
}

// ctf.exec.module_uninspected is a warning; here it is scan's ../ module
// that is not there yet (scan runs before init): where it is the only
// finding, scan exits 0 under the default --fail-on and 1 under --fail-on
// warning. Every other directory that cannot be read fails closed: report
// exits 2 on a local module directory that cannot be listed or does not
// resolve, since init installed it and terraform reads it.
func TestModuleUninspectedExitCodes(t *testing.T) {
	refuseSwitchesInCI(t)

	// scan: a root whose only local module is a ../ directory that is not there.
	scanRoot := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(scanRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scanRoot, "main.tf"), []byte("module \"gone\" {\n  source = \"../gone\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// report: local-outside copied, with ../shared made unlistable, and a
	// second copy whose ../shared does not exist.
	locked, missing := copyLocalOutside(t), copyLocalOutside(t)
	if err := os.RemoveAll(filepath.Join(missing, "..", "shared")); err != nil {
		t.Fatal(err)
	}
	sharedDir := filepath.Join(locked, "..", "shared")
	if err := os.Chmod(sharedDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sharedDir, 0o750) }) //nolint:gosec // restores a test directory so TempDir can remove it

	scan := []string{"scan", "--stage", "pre_plan", "--format", "sarif", "--catalog", "embedded"}
	report := append([]string{"report", "--format", "sarif"}, fixtureContext...)
	for _, tc := range []struct {
		name, dir string
		args      []string
		exit      int
		errText   string // for exit 2, what the diagnostic names
		rootOnly  bool   // needs a non-root user, for whom mode 000 denies listing
	}{
		{"scan, default fail-on", scanRoot, append(append([]string{}, scan...), "."), ExitOK, "", false},
		{"scan, fail-on warning", scanRoot, append(append([]string{}, scan...), "--fail-on", "warning", "."), ExitFindings, "", false},
		{"report, directory that cannot be listed", locked, report, ExitEnvironment, "cannot be listed", true},
		{"report, directory that does not resolve", missing, report, ExitEnvironment, "does not resolve", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.rootOnly && os.Geteuid() == 0 {
				t.Skip("root lists a directory whatever its mode")
			}
			t.Setenv("HOME", t.TempDir())
			got := runScanIn(t, tc.dir, tc.args...)
			if got.code != tc.exit {
				t.Fatalf("exit = %d, want %d (%v):\n%s", got.code, tc.exit, got.err, got.stdout)
			}
			if tc.exit == ExitEnvironment {
				if !strings.Contains(got.err.Error(), tc.errText) {
					t.Errorf("error = %v, want one containing %q", got.err, tc.errText)
				}
				return
			}
			if !strings.Contains(got.stdout, `"ruleId": "ctf.exec.module_uninspected"`) ||
				strings.Count(got.stdout, `"ruleId": `) != 1 {
				t.Errorf("want ctf.exec.module_uninspected as the only finding:\n%s", got.stdout)
			}
		})
	}
}

// report --path given a symlink to the configuration reports exactly what
// it reports on the directory itself: the root's
// own provisioner included, which a walk that did not resolve the link first
// would have missed.
func TestReportFollowsASymlinkedPath(t *testing.T) {
	refuseSwitchesInCI(t)
	t.Setenv("HOME", t.TempDir())
	input, err := filepath.Abs(filepath.Join(postInitFixtures, "code-exec", "input"))
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(input, link); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}
	work := t.TempDir()
	direct := runScanIn(t, work, append([]string{"report", "--format", "sarif", "--path", input}, fixtureContext...)...)
	linked := runScanIn(t, work, append([]string{"report", "--format", "sarif", "--path", link}, fixtureContext...)...)
	if linked.code != direct.code || linked.stdout != direct.stdout {
		t.Errorf("through the link: exit %d (%v), want %d; SARIF equal: %v", linked.code, linked.err, direct.code, linked.stdout == direct.stdout)
	}
	if !strings.Contains(linked.stdout, `"fullyQualifiedName": "terraform_data.bootstrap"`) {
		t.Errorf("the root's own provisioner is missing through the link:\n%s", linked.stdout)
	}
}

// leakyDir is a module directory named the way a source with credentials
// would name it: userinfo and an sshkey query.
const leakyDir = "CANARY-user:CANARY-token@shared?sshkey=CANARY-key"

// writeTree writes files, keyed by absolute path, creating their directories.
func writeTree(t *testing.T, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// leakyLocalOutside copies local-outside with its ../shared module renamed
// to leakyDir and the references to it rewritten, and returns the input.
func leakyLocalOutside(t *testing.T) string {
	t.Helper()
	input := copyLocalOutside(t)
	if err := os.Rename(filepath.Join(input, "..", "shared"), filepath.Join(input, "..", leakyDir)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"main.tf", ".terraform/modules/modules.json"} {
		path := filepath.Join(input, filepath.FromSlash(name))
		body := strings.ReplaceAll(string(readFile(t, path)), "../shared", "../"+leakyDir)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return input
}

// noCredential fails when any of the named outputs carries a CANARY value or
// the sshkey query.
func noCredential(t *testing.T, outputs map[string]string) {
	t.Helper()
	for name, body := range outputs {
		if strings.Contains(body, "CANARY") || strings.Contains(body, "sshkey") {
			t.Errorf("%s carries a credential:\n%s", name, body)
		}
	}
}

// collect reads every file in dir, plus the Spacelift file the run wrote to
// its working directory, with the run's stdout, stderr and error.
func collect(t *testing.T, dir, cwd string, got scanResult) map[string]string {
	t.Helper()
	outputs := map[string]string{"stdout": got.stdout, "stderr": got.stderr}
	if got.err != nil {
		outputs["error"] = got.err.Error()
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		outputs[e.Name()] = string(readFile(t, filepath.Join(dir, e.Name())))
	}
	spacelift := filepath.Join(cwd, "ctfkit.custom.spacelift.json")
	if _, err := os.Stat(spacelift); err == nil {
		outputs["ctfkit.custom.spacelift.json"] = string(readFile(t, spacelift))
	}
	return outputs
}

// A finding in a module file carries the file's path as its location, and
// that path is named after the module source, so it goes through the same
// redaction as a quoted source, for a module beside the root
// and one inside it alike: modules at ../leakyDir and ./modules/leakyDir are
// located at ../shared/main.tf and modules/shared/main.tf. No output of any
// format carries a CANARY value, nor does the location of a module source or
// origin finding in a directory of that name: scan's pretty, text, json, sarif, junit and
// spacelift, report's markdown, receipt, sarif and spacelift, and stdout and
// stderr of both.
func TestModuleFileLocationsAreRedacted(t *testing.T) {
	refuseSwitchesInCI(t)
	t.Setenv("HOME", t.TempDir())

	t.Run("scan", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "repo")
		writeTree(t, map[string]string{
			filepath.Join(root, "main.tf"): "module \"outside\" {\n  source = \"../" + leakyDir + "\"\n}\n\n" +
				"module \"inside\" {\n  source = \"./modules/" + leakyDir + "\"\n}\n",
			filepath.Join(parent, leakyDir, "main.tf"):          provisionedResource("outside"),
			filepath.Join(root, "modules", leakyDir, "main.tf"): provisionedResource("inside"),
			// A second configuration under the root, not called by the first,
			// in a directory of the same name: the module source and origin
			// rules report it, as a root.
			filepath.Join(root, "stacks", leakyDir, "main.tf"): originAndSource,
		})
		out := t.TempDir()
		got := runScanIn(t, root, "scan", "--stage", "pre_plan", "--format", "pretty,text,json,sarif,junit,spacelift",
			"--out-dir", out, "--catalog", "embedded", ".")
		if got.code != ExitFindings {
			t.Fatalf("exit = %d (%v)", got.code, got.err)
		}
		outputs := collect(t, out, root, got)
		if len(outputs) < 8 {
			t.Errorf("want stdout, stderr and six formats, got %d outputs", len(outputs))
		}
		noCredential(t, outputs)
		sarif := outputs["findings.sarif"]
		for _, uri := range []string{"../shared/main.tf", "modules/shared/main.tf"} {
			if !strings.Contains(sarif, `"uri": "`+uri+`"`) {
				t.Errorf("findings.sarif does not locate a finding at %s:\n%s", uri, sarif)
			}
		}
		// The module source and origin rules fire in stacks/leakyDir; their
		// locations pass the same central redaction as every finding's.
		if !strings.Contains(sarif, `"uri": "stacks/shared/main.tf"`) {
			t.Errorf("findings.sarif does not locate a finding at stacks/shared/main.tf:\n%s", sarif)
		}
		for _, rule := range []string{"ctf.coverage.module_source", "ctf.policy.floating_ref", "ctf.policy.floating_ref_unbounded"} {
			if !strings.Contains(sarif, `"ruleId": "`+rule+`"`) {
				t.Errorf("findings.sarif has no %s:\n%s", rule, sarif)
			}
		}
	})

	t.Run("report", func(t *testing.T) {
		input := leakyLocalOutside(t)
		out := t.TempDir()
		got := runScanIn(t, input, append([]string{"report", "--format", "markdown,receipt,sarif,spacelift", "--out-dir", out}, fixtureContext...)...)
		if got.code != ExitFindings {
			t.Fatalf("exit = %d (%v)", got.code, got.err)
		}
		outputs := collect(t, out, input, got)
		noCredential(t, outputs)
		if !strings.Contains(outputs["findings.sarif"], `"uri": "../shared/main.tf"`) {
			t.Errorf("findings.sarif does not locate the finding at ../shared/main.tf:\n%s", outputs["findings.sarif"])
		}
	})
}

// A file that cannot be read in a module directory named after a source with
// credentials is exit 2, and the diagnostic names it through the redaction:
// the OS error, which carries the resolved absolute path, never reaches
// stderr. Covered for a configuration file in scan's walk,
// a configuration file and a manifest in report's module read.
func TestReadFailuresInModuleDirectoriesAreRedacted(t *testing.T) {
	refuseSwitchesInCI(t)
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
	t.Setenv("HOME", t.TempDir())
	lock := func(t *testing.T, path string) {
		t.Helper()
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) }) //nolint:gosec // restores a test file so TempDir can remove it
	}
	report := append([]string{"report", "--format", "sarif"}, fixtureContext...)

	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T) (dir string, args []string)
		named   string // what the diagnostic must name instead
	}{
		{
			name: "scan, configuration file",
			prepare: func(t *testing.T) (string, []string) {
				root := t.TempDir()
				locked := filepath.Join(root, "modules", leakyDir, "main.tf")
				writeTree(t, map[string]string{
					filepath.Join(root, "main.tf"): "module \"inside\" {\n  source = \"./modules/" + leakyDir + "\"\n}\n",
					locked:                         `locals {}`,
				})
				lock(t, locked)
				return root, []string{"scan", "--stage", "pre_plan", "--format", "sarif", "--catalog", "embedded", "."}
			},
			named: "modules/shared/main.tf",
		},
		{
			name: "report, configuration file",
			prepare: func(t *testing.T) (string, []string) {
				input := leakyLocalOutside(t)
				lock(t, filepath.Join(input, "..", leakyDir, "main.tf"))
				return input, report
			},
			named: "../shared/main.tf",
		},
		{
			name: "report, manifest",
			prepare: func(t *testing.T) (string, []string) {
				input := leakyLocalOutside(t)
				manifest := filepath.Join(input, "..", leakyDir, "compliancetf-manifest.json")
				writeTree(t, map[string]string{manifest: `{"schema_version": "3.3"}`})
				lock(t, manifest)
				return input, report
			},
			named: "../shared/compliancetf-manifest.json",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, args := tc.prepare(t)
			got := runScanIn(t, dir, args...)
			if got.code != ExitEnvironment || got.err == nil {
				t.Fatalf("exit = %d (%v), want 2", got.code, got.err)
			}
			noCredential(t, map[string]string{"stdout": got.stdout, "stderr": got.stderr, "error": got.err.Error()})
			if !strings.Contains(got.err.Error(), tc.named) || !strings.Contains(got.err.Error(), "cannot be read") {
				t.Errorf("error = %v, want one naming %s as unreadable", got.err, tc.named)
			}
		})
	}
}

// originAndSource is configuration that the module source and origin rules
// report: an upstream module compliance.tf serves, with no version
// constraint, and a module installed from a git branch.
const originAndSource = `
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
}

module "network" {
  source = "git::https://example.com/bobthecorp/network.git?ref=main"
}
`

// provisionedResource is a native-syntax resource with a local-exec
// provisioner whose command carries a CANARY value.
func provisionedResource(name string) string {
	return "resource \"terraform_data\" \"" + name + "\" {\n  provisioner \"local-exec\" {\n    command = \"echo CANARY-command\"\n  }\n}\n"
}

// copyLocalOutside copies the local-outside case (input and its ../shared
// sibling) into a fresh directory and returns the copied input.
func copyLocalOutside(t *testing.T) string {
	t.Helper()
	base, err := filepath.Abs(filepath.Join(postInitFixtures, "local-outside"))
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	for _, dir := range []string{"input", "shared"} {
		if err := os.CopyFS(filepath.Join(dst, dir), os.DirFS(filepath.Join(base, dir))); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dst, "input")
}

// The Markdown and receipt projections list each instance without a manifest
// by its source, and that source goes through ctfkit.RedactSource like every
// finding's: code-exec's app.tools source carries CANARY values
// in userinfo and query, and neither projection may.
func TestReportProjectionsRedactInstanceSources(t *testing.T) {
	refuseSwitchesInCI(t)
	t.Setenv("HOME", t.TempDir())
	input, err := filepath.Abs(filepath.Join(postInitFixtures, "code-exec", "input"))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	got := runScanIn(t, input, append([]string{"report", "--format", "markdown,receipt", "--out-dir", out}, fixtureContext...)...)
	if got.code != ExitFindings {
		t.Fatalf("exit = %d (%v)", got.code, got.err)
	}
	for _, name := range []string{"report.md", "receipt.json"} {
		body := string(readFile(t, filepath.Join(out, name)))
		if !strings.Contains(body, "git::https://example.com/bobthecorp/tools.git") {
			t.Errorf("%s does not list app.tools by its redacted source:\n%s", name, body)
		}
		if strings.Contains(body, "CANARY-") || strings.Contains(body, "sshkey") {
			t.Errorf("%s carries a value from the configuration:\n%s", name, body)
		}
	}
}

// allowed_endpoints decides ctf.exec.module_endpoint, so report reads the
// settings file even when --fail-on is given, and one that does not load is
// exit 2 rather than a silent fall back to the defaults.
func TestReportRefusesAnUnreadableSettingsFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".ctfkit.yaml"), []byte("allowed_endpoints: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := filepath.Abs(filepath.Join(postInitFixtures, "clean", "input"))
	if err != nil {
		t.Fatal(err)
	}
	got := runScanIn(t, dir, append([]string{"report", "--format", "sarif", "--fail-on", "never", "--path", input}, fixtureContext...)...)
	if got.code != ExitEnvironment || !strings.Contains(got.err.Error(), "allowed_endpoints") {
		t.Fatalf("exit = %d, err = %v; want 2 naming allowed_endpoints", got.code, got.err)
	}
}
