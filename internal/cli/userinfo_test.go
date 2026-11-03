package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// canarySecret is the password half of every canary URL. It must never reach a
// diagnostic: CI logs keep stderr, and a flag value is where an operator puts
// a URL that carries a credential.
const canarySecret = "canary-s3cret"

func canaryURL(name string) string {
	return "https://user:" + canarySecret + "@example.invalid/" + name
}

// assertNoCanary checks the error main prints and anything the command wrote
// to its own stderr. Either reaching the terminal is the leak.
func assertNoCanary(t *testing.T, code int, err error, stderr string) {
	t.Helper()
	if code != ExitEnvironment {
		t.Fatalf("exit %d, want 2 (err %v)", code, err)
	}
	if err == nil {
		t.Fatal("no error on the exit-2 path")
	}
	if strings.Contains(err.Error(), canarySecret) {
		t.Errorf("the diagnostic carries the credential: %q", err.Error())
	}
	if strings.Contains(stderr, canarySecret) {
		t.Errorf("stderr carries the credential:\n%s", stderr)
	}
}

// Every report flag that names something to read, given a URL carrying a
// credential, fails on the exit-2 path without printing the credential.
func TestReportDiagnosticsCarryNoUserinfo(t *testing.T) {
	served, err := filepath.Abs(filepath.Join(repoRoot, fixturePath("served-leaf")))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]string{
		"--catalog":    {"--path", served, "--catalog", canaryURL("c.yaml")},
		"--exceptions": {"--path", served, "--exceptions", canaryURL("e.yaml")},
		"--tests-json": {"--path", served, "--tests-json", canaryURL("t.json")},
		"--path":       {"--path", canaryURL("p")},
		"--readme":     {"--path", served, "--readme", canaryURL("README.md")},
		"--config":     {"--path", served, "--config", canaryURL("ctfkit.yaml")},
	}
	for flag, args := range cases {
		t.Run(flag, func(t *testing.T) {
			// A temporary working directory, so a value that were ever
			// treated as a path to write could not land in the repository.
			t.Chdir(t.TempDir())
			code, err := runReportErr(t, args...)
			assertNoCanary(t, code, err, "")
		})
	}
}

// The same for scan, which shares the error path.
func TestScanDiagnosticsCarryNoUserinfo(t *testing.T) {
	input := fixtureInput(t, "01-raw-s3-no-ctf")
	plan := filepath.Join(input, "plan.json")

	cases := map[string][]string{
		"--catalog":    {"scan", plan, "--catalog", canaryURL("c.yaml")},
		"--exceptions": {"scan", plan, "--exceptions", canaryURL("e.yaml")},
		"--plan":       {"scan", "--plan", canaryURL("plan.json")},
		"--chdir":      {"scan", "--chdir", canaryURL("dir")},
		"--config":     {"scan", plan, "--config", canaryURL("ctfkit.yaml")},
		"positional":   {"scan", canaryURL("plan.json")},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			got := runScanIn(t, t.TempDir(), args...)
			assertNoCanary(t, got.code, got.err, got.stderr)
		})
	}
}
