package cli

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/compliancetf/ctfkit/internal/render/spacelift"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// canarySecrets are the two fake secrets fixture 16 plants, per its README.
var canarySecrets = []string{
	"CANARY-50c488e396915cedcc5b650db695f0d2",
	"canary-pass-8fdf8eaa189601fd",
}

// allFormats is every scan format, spacelift included.
const allFormats = "sarif,json,text,pretty,junit,spacelift"

// TestScanOutDirNames asserts the findings.<ext> names --out-dir writes, and
// that the Spacelift file lands in the working directory and not there.
func TestScanOutDirNames(t *testing.T) {
	input := fixtureInput(t, "04-floating-ref")
	work := t.TempDir()
	outDir := filepath.Join(work, "out")
	if err := os.Mkdir(outDir, 0o700); err != nil {
		t.Fatal(err)
	}

	got := runScanIn(t, work, "scan", "--stage", "pre_plan", input, "--format", allFormats, "--out-dir", outDir)
	if got.code != ExitOK {
		t.Fatalf("exit = %d (%v)", got.code, got.err)
	}
	if got.stdout != "" {
		t.Errorf("--out-dir run wrote to stdout: %s", got.stdout)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := "findings.json findings.junit.xml findings.pretty.txt findings.sarif findings.txt"
	if strings.Join(names, " ") != want {
		t.Errorf("--out-dir holds %v, want %s", names, want)
	}
	if !exists(filepath.Join(work, spacelift.ScanFileName)) {
		t.Errorf("%s is not in the working directory", spacelift.ScanFileName)
	}
	if exists(filepath.Join(work, spacelift.FileName)) {
		t.Errorf("scan wrote report's %s", spacelift.FileName)
	}
}

// TestScanSpaceliftOnlyExitsZero is the one exception to exit 1: a format list
// of exactly spacelift returns 0 on findings, because the plan policy renders
// the denial from the file's verdict. Any other list follows the threshold.
func TestScanSpaceliftOnlyExitsZero(t *testing.T) {
	input := fixtureInput(t, "03-ctf-module-disabled-control")

	t.Run("spacelift only", func(t *testing.T) {
		work := t.TempDir()
		got := runScanIn(t, work, "scan", "--stage", "pre_plan", input, "--format", "spacelift")
		if got.code != ExitOK {
			t.Fatalf("exit = %d, want 0 (%v)", got.code, got.err)
		}
		var doc struct {
			Schema  string `json:"schema"`
			Stage   string `json:"stage"`
			Verdict string `json:"verdict"`
		}
		if err := json.Unmarshal(readFile(t, filepath.Join(work, spacelift.ScanFileName)), &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Schema != spacelift.SchemaID || doc.Stage != "pre_plan" || doc.Verdict != spacelift.VerdictFail {
			t.Errorf("spacelift file = %+v, want a fail verdict at pre_plan", doc)
		}
	})

	t.Run("spacelift and sarif", func(t *testing.T) {
		work := t.TempDir()
		got := runScanIn(t, work, "scan", "--stage", "pre_plan", input, "--format", "spacelift,sarif", "--out-dir", work)
		if got.code != ExitFindings {
			t.Errorf("exit = %d, want 1 (%v)", got.code, got.err)
		}
	})
}

// TestScanSecretCanary runs fixture 16 in every format at both stages, and a
// broken copy that exits 2, and asserts neither planted secret reaches any
// output, stderr or a diagnostic.
func TestScanSecretCanary(t *testing.T) {
	input := fixtureInput(t, "16-secret-canary")
	check := func(t *testing.T, where, body string) {
		t.Helper()
		for _, secret := range canarySecrets {
			if strings.Contains(body, secret) {
				t.Errorf("%s carries the canary %s", where, secret)
			}
		}
	}
	allowlist := absPath(t, "testdata/fixtures/plan/09-unknown-provider/input/.ctfkit.yaml")

	for _, stage := range []string{"post_plan", "pre_plan"} {
		t.Run(stage, func(t *testing.T) {
			work := t.TempDir()
			got := runScanIn(t, work, "scan", "--stage", stage, "--chdir", input,
				"--plan", filepath.Join(input, "plan.json"), "--config", allowlist,
				"--format", allFormats, "--out-dir", work, "--fail-on", "never")
			if got.code != ExitOK {
				t.Fatalf("exit = %d (%v)", got.code, got.err)
			}
			entries, err := os.ReadDir(work)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 6 {
				t.Errorf("wrote %d files, want 6", len(entries))
			}
			for _, e := range entries {
				check(t, e.Name(), string(readFile(t, filepath.Join(work, e.Name()))))
			}
			check(t, "stdout", got.stdout)
			check(t, "stderr", got.stderr)
		})
	}

	t.Run("exit 2 on a broken copy", func(t *testing.T) {
		broken := t.TempDir()
		for _, name := range []string{"main.tf", "providers.tf", "plan.json"} {
			body := readFile(t, filepath.Join(input, name))
			if name == "plan.json" {
				// Cut the document right after the first canary.
				at := strings.Index(string(body), canarySecrets[0])
				body = body[:at+len(canarySecrets[0])+3]
			}
			if err := os.WriteFile(filepath.Join(broken, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}

		for _, args := range [][]string{
			{"scan", "plan.json"},
			{"scan", "--plan", "git::https://canary-user:canary-pass-8fdf8eaa189601fd@example.invalid/plan.json"},
		} {
			got := runBlackBox(t, broken, []string{"HOME=" + t.TempDir()}, args...)
			if got.code != ExitEnvironment {
				t.Errorf("%v: exit = %d, want 2 (%s)", args, got.code, got.stderr)
			}
			check(t, "stdout", got.stdout)
			check(t, "stderr", got.stderr)
		}

		// A syntax error in a file that carries the credentialed source: the
		// diagnostic names the file and line, never the source text.
		mainTF := filepath.Join(broken, "main.tf")
		body := strings.Replace(string(readFile(t, mainTF)), "module \"naming\" {", "module \"naming\" {{", 1)
		if err := os.WriteFile(mainTF, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		got := runBlackBox(t, broken, []string{"HOME=" + t.TempDir()}, "scan", "--stage", "pre_plan", ".")
		if got.code != ExitEnvironment || !strings.Contains(got.stderr, "main.tf:") {
			t.Errorf("exit = %d, stderr %q; want 2 naming main.tf", got.code, got.stderr)
		}
		check(t, "stderr", got.stderr)
	})
}

// TestScanHCLErrorIsInput asserts a syntax error surfaces as an input error
// before any analyzer runs, never as an analyzer error or a skipped file.
func TestScanHCLErrorIsInput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource \"aws_s3_bucket\" \"a\" {\n  bucket = \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runScanIn(t, dir, "scan", "--stage", "pre_plan", ".")
	var exit *ExitError
	if !asExitError(got.err, &exit) || exit.Code != ExitEnvironment || exit.Category != categoryInput {
		t.Fatalf("err = %#v, want an input error", got.err)
	}
	if !strings.HasPrefix(exit.Message, "main.tf:") {
		t.Errorf("diagnostic %q does not name the file and line", exit.Message)
	}
	if got.stdout != "" {
		t.Errorf("wrote output before failing: %s", got.stdout)
	}
}

// TestScanInputMisuse is the exit-2 list of the scan specification for flags and
// positionals, each with its category.
func TestScanInputMisuse(t *testing.T) {
	input := fixtureInput(t, "04-floating-ref")
	other := fixtureInput(t, "09-unknown-provider")
	plan := filepath.Join(input, "plan.json")
	tf := filepath.Join(input, "main.tf")
	badSettings := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(badSettings, []byte("tags:\n  - key: A\n    pattern: \"(?<=x)\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	bogusFailOn := filepath.Join(t.TempDir(), "bogus.yaml")
	if err := os.WriteFile(bogusFailOn, []byte("fail_on: bogus\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		args     []string
		category string
	}{
		"stage post_apply":              {[]string{"--stage", "post_apply", plan}, categoryInput},
		"unknown stage":                 {[]string{"--stage", "later", input}, categoryInput},
		"post_plan without a plan":      {[]string{"--stage", "post_plan", input}, categoryInput},
		"unknown format":                {[]string{"--format", "html", input}, categoryInput},
		"out with two formats":          {[]string{"--format", "sarif,json", "--out", "x", input}, categoryInput},
		"out and out-dir":               {[]string{"--out", "x", "--out-dir", "y", input}, categoryInput},
		"out with spacelift":            {[]string{"--format", "spacelift", "--out", "x", input}, categoryInput},
		"several formats, no out-dir":   {[]string{"--format", "sarif,json", input}, categoryInput},
		"repeated flag":                 {[]string{"--fail-on", "error", "--fail-on", "never", input}, categoryInput},
		"repeated format":               {[]string{"--format", "json", "--format", "sarif", input}, ""},
		"unknown flag":                  {[]string{"--frobnicate", input}, categoryInput},
		"bad fail-on":                   {[]string{"--fail-on", "fatal", input}, categoryInput},
		"chdir and a directory":         {[]string{"--chdir", input, other}, categoryInput},
		"file list and a directory":     {[]string{tf, input}, categoryInput},
		"file list and chdir":           {[]string{"--chdir", input, tf}, categoryInput},
		"plan and a file list":          {[]string{plan, tf}, categoryInput},
		"two directories":               {[]string{input, other}, categoryInput},
		"two plans":                     {[]string{"--plan", plan, plan}, categoryInput},
		"missing path":                  {[]string{filepath.Join(input, "nope")}, categoryInput},
		"remediation host not in hosts": {[]string{"--remediation-host", "nope", input}, categoryInput},
		"catalog file missing":          {[]string{"--catalog", filepath.Join(input, "nope.yaml"), input}, categoryCatalog},
		"exceptions file missing":       {[]string{"--exceptions", filepath.Join(input, "nope.yaml"), input}, categoryExceptions},
		"invalid RE2 in settings":       {[]string{"--config", badSettings, input}, categorySettings},
		"no configuration at pre_plan":  {[]string{"--stage", "pre_plan", t.TempDir()}, categoryInput}, "repeated config": {[]string{"--config", badSettings, "--config", badSettings, input}, categoryInput}, "empty stage": {[]string{"--stage=", input}, categoryInput}, "empty fail-on": {[]string{"--fail-on=", input}, categoryInput}, "settings fail_on unknown": {[]string{"--config", bogusFailOn, "--fail-on", "never", input}, categorySettings},
	} {
		t.Run(name, func(t *testing.T) {
			got := runScanIn(t, t.TempDir(), append([]string{"scan"}, tc.args...)...)
			if got.code != ExitEnvironment {
				t.Fatalf("exit = %d, want 2 (%v)", got.code, got.err)
			}
			var exit *ExitError
			if tc.category != "" && (!asExitError(got.err, &exit) || exit.Category != tc.category) {
				t.Errorf("err = %#v, want category %s", got.err, tc.category)
			}
		})
	}
}

// TestScanFailOnPrecedence is flag, then CTFKIT_FAIL_ON, then settings
// fail_on, then error. Fixture 04 carries one warning.
func TestScanFailOnPrecedence(t *testing.T) {
	input := fixtureInput(t, "04-floating-ref")
	warnSettings := filepath.Join(t.TempDir(), "warn.yaml")
	if err := os.WriteFile(warnSettings, []byte("fail_on: warning\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		env  string
		args []string
		exit int
	}{
		"default error":         {"", nil, ExitOK},
		"settings warning":      {"", []string{"--config", warnSettings}, ExitFindings},
		"env beats settings":    {"never", []string{"--config", warnSettings}, ExitOK},
		"flag beats env":        {"never", []string{"--fail-on", "warning"}, ExitFindings},
		"flag never over error": {"", []string{"--fail-on", "never"}, ExitOK},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(failOnEnv, tc.env)
			args := append([]string{"scan", "--stage", "pre_plan", input}, tc.args...)
			if got := runScanIn(t, t.TempDir(), args...); got.code != tc.exit {
				t.Errorf("exit = %d, want %d (%v)", got.code, tc.exit, got.err)
			}
		})
	}
}

// TestScanProjections checks the shape of json and junit, and that text and
// pretty end in the --watermark banner when one is set.
func TestScanProjections(t *testing.T) {
	input := fixtureInput(t, "04-floating-ref")
	run := func(format string, extra ...string) string {
		t.Helper()
		args := append([]string{"scan", "--stage", "pre_plan", input, "--format", format}, extra...)
		got := runScanIn(t, t.TempDir(), args...)
		if got.code != ExitOK {
			t.Fatalf("%s: exit = %d (%v)", format, got.code, got.err)
		}
		return got.stdout
	}

	var doc struct {
		Watermark      string `json:"watermark"`
		CatalogVersion struct {
			Version string `json:"version"`
			Origin  string `json:"origin"`
		} `json:"catalogVersion"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(run("json")), &doc); err != nil {
		t.Fatalf("json is not an object: %v", err)
	}
	if doc.Watermark != "" || doc.CatalogVersion.Origin != "embedded" || len(doc.Findings) != 1 ||
		doc.Findings[0]["ruleId"] != "ctf.policy.floating_ref" {
		t.Errorf("json = %+v", doc)
	}
	sarifResults := parseResults(t, run("sarif"))
	if len(sarifResults) != 1 {
		t.Errorf("sarif carries %d results, json 1", len(sarifResults))
	}

	var suites struct {
		Suite struct {
			Tests      int `xml:"tests,attr"`
			Properties []struct {
				Name  string `xml:"name,attr"`
				Value string `xml:"value,attr"`
			} `xml:"properties>property"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal([]byte(run("junit")), &suites); err != nil {
		t.Fatalf("junit does not parse: %v", err)
	}
	if suites.Suite.Tests != 1 || len(suites.Suite.Properties) == 0 || suites.Suite.Properties[0].Name != "ctf.catalogVersion" {
		t.Errorf("junit = %+v", suites)
	}

	for _, format := range []string{"text", "pretty"} {
		body := run(format, "--watermark", "team \x1b[31mred\x1b[0m\nsecond")
		want := "\n\nteam redsecond\n"
		if !strings.HasSuffix(body, want) {
			t.Errorf("%s does not end in the watermark block:\n%q", format, body)
		}
	}
}

// TestScanWatermarkBanner: with no --watermark no projection carries a
// watermark field, property or line; with --watermark X every projection
// carries exactly X, once.
func TestScanWatermarkBanner(t *testing.T) {
	input := fixtureInput(t, "04-floating-ref")
	const banner = "bobthecorp platform team"
	for _, format := range []string{"json", "sarif", "junit", "text", "pretty"} {
		args := []string{"scan", "--stage", "pre_plan", input, "--format", format, "--no-color"}
		plain := runScanIn(t, t.TempDir(), args...)
		if plain.code != ExitOK {
			t.Fatalf("%s: exit = %d (%v)", format, plain.code, plain.err)
		}
		if strings.Contains(plain.stdout, "watermark") {
			t.Errorf("%s without --watermark carries a watermark:\n%s", format, plain.stdout)
		}
		if strings.HasSuffix(plain.stdout, "\n\n") {
			t.Errorf("%s without --watermark ends in an empty trailing block:\n%q", format, plain.stdout)
		}

		marked := runScanIn(t, t.TempDir(), append(args, "--watermark", banner)...)
		if marked.code != ExitOK {
			t.Fatalf("%s --watermark: exit = %d (%v)", format, marked.code, marked.err)
		}
		if n := strings.Count(marked.stdout, banner); n != 1 {
			t.Errorf("%s --watermark carries the banner %d times, want 1:\n%s", format, n, marked.stdout)
		}
	}
}

// TestScanPrePlanIgnoresPlan says so on stderr when --stage pre_plan is given
// a plan.
func TestScanPrePlanIgnoresPlan(t *testing.T) {
	input := fixtureInput(t, "04-floating-ref")
	got := runScanIn(t, input, "scan", "--stage", "pre_plan", "plan.json", "--chdir", ".")
	if got.code != ExitOK || !strings.Contains(got.stderr, "ignores the plan plan.json") {
		t.Errorf("exit = %d, stderr = %q", got.code, got.stderr)
	}
}

// TestScanNoPartialOutput: an exit-2 run leaves no projection behind, whether
// the destination is missing or an analyzer fails.
func TestScanNoPartialOutput(t *testing.T) {
	input := fixtureInput(t, "03-ctf-module-disabled-control")

	// An --out-dir that cannot be used fails before anything is written. A
	// missing directory is created, so the unusable case is a
	// path that exists as a regular file.
	t.Run("out-dir is a file", func(t *testing.T) {
		work := t.TempDir()
		notDir := filepath.Join(work, "not-a-dir")
		if err := os.WriteFile(notDir, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		got := runScanIn(t, work, "scan", "--stage", "pre_plan", input,
			"--format", "spacelift,sarif", "--out-dir", notDir)
		if got.code != ExitEnvironment || exists(filepath.Join(work, spacelift.ScanFileName)) {
			t.Errorf("exit = %d, spacelift file written = %t", got.code, exists(filepath.Join(work, spacelift.ScanFileName)))
		}
	})

	t.Run("analyzer error", func(t *testing.T) {
		saved := newScanRegistry
		t.Cleanup(func() { newScanRegistry = saved })
		newScanRegistry = func() ctfkit.Registry {
			r := ctfkit.NewRegistry()
			ctfkit.MustRegister(r, failingAnalyzer{})
			return r
		}

		work := t.TempDir()
		got := runScanIn(t, work, "scan", "--stage", "pre_plan", input, "--format", "spacelift")
		var exit *ExitError
		if !asExitError(got.err, &exit) || exit.Category != categoryAnalyzer {
			t.Fatalf("err = %#v, want an analyzer error", got.err)
		}
		if got.stdout != "" || exists(filepath.Join(work, spacelift.ScanFileName)) {
			t.Errorf("an analyzer failure wrote output")
		}
	})
}

// failingAnalyzer returns an error, the malfunction exit 2 names.
type failingAnalyzer struct{}

func (failingAnalyzer) ID() string          { return "ctf.test.failing_rule" }
func (failingAnalyzer) Stage() ctfkit.Stage { return ctfkit.PrePlan }
func (failingAnalyzer) Analyze(context.Context, ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return nil, errors.New("boom")
}

// TestScanWatermarkUserinfo: the extra banner line passes the userinfo strip
// in every format, not only in text and pretty.
func TestScanWatermarkUserinfo(t *testing.T) {
	input := fixtureInput(t, "04-floating-ref")
	work := t.TempDir()
	got := runScanIn(t, work, "scan", "--stage", "pre_plan", input, "--format", allFormats,
		"--out-dir", work, "--watermark", "https://user:hunter2@example.com/x")
	if got.code != ExitOK {
		t.Fatalf("exit = %d (%v)", got.code, got.err)
	}
	entries, _ := os.ReadDir(work)
	for _, e := range entries {
		if strings.Contains(string(readFile(t, filepath.Join(work, e.Name()))), "hunter2") {
			t.Errorf("%s carries the watermark credential", e.Name())
		}
	}
}

// TestRootScansPaths: the bare command scans the paths given at pre_plan,
// the behavior it had before scan.
func TestRootScansPaths(t *testing.T) {
	got := runScanIn(t, fixtureInput(t, "03-ctf-module-disabled-control"), "main.tf")
	if got.code != ExitFindings {
		t.Errorf("exit = %d, want 1 (%v)", got.code, got.err)
	}
}

// TestNoColorFlag: --no-color takes effect, not only NO_COLOR.
func TestNoColorFlag(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	saved := color.NoColor
	t.Cleanup(func() { color.NoColor = saved })
	fail := absPath(t, "testdata/fail")
	for _, tc := range []struct {
		flag string
		ansi bool
	}{{"--no-color=false", true}, {"--no-color", false}} {
		color.NoColor = false // a terminal
		got := runScanIn(t, t.TempDir(), "scan", "--stage", "pre_plan", fail, "-f", "pretty", tc.flag)
		if got.code != ExitFindings {
			t.Fatalf("%s: exit %d (%v)", tc.flag, got.code, got.err)
		}
		if strings.Contains(got.stdout, "\x1b[") != tc.ansi {
			t.Errorf("%s: color codes in the output = %t, want %t:\n%q", tc.flag, !tc.ansi, tc.ansi, got.stdout)
		}
	}
}

// TestVerboseDeprecated: --verbose and -v still parse, and say on stderr that
// they do nothing.
func TestVerboseDeprecated(t *testing.T) {
	for _, flag := range []string{"--verbose", "-v"} {
		got := runBlackBox(t, t.TempDir(), nil, flag, "version")
		if got.code != ExitOK || !strings.HasPrefix(got.stdout, "ctfkit version") || !strings.Contains(got.stderr, "it has no effect") {
			t.Errorf("%s version: exit %d, stdout %q, stderr %q", flag, got.code, got.stdout, got.stderr)
		}
	}
	if help := runScanIn(t, t.TempDir(), "--help"); strings.Contains(help.stdout, "verbose") {
		t.Errorf("the help still lists --verbose:\n%s", help.stdout)
	}
}

// TestGlobalBoolFlags: -v, --verbose and --no-color work bare, and refuse a
// second use.
func TestGlobalBoolFlags(t *testing.T) {
	for args, want := range map[string]int{
		"-v version":                    ExitOK,
		"--verbose version":             ExitOK,
		"--no-color version":            ExitOK,
		"--no-color=false version":      ExitOK,
		"-v -v version":                 ExitEnvironment,
		"--no-color --no-color version": ExitEnvironment,
	} {
		t.Run(args, func(t *testing.T) {
			if got := runScanIn(t, t.TempDir(), strings.Fields(args)...); got.code != want {
				t.Errorf("exit = %d, want %d (%v)", got.code, want, got.err)
			}
		})
	}
}
