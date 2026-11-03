package cli

import (
	"strings"
	"testing"
)

// report's single-value flags refuse a second use, as scan's do: taking the
// last value silently would run a different report than the one the command
// line reads as, which is the catch-all rule the scan specification applies. A refusal
// is an input error, exit 2. --path is repeatable by design and is not
// refused.
func TestReportRefusesARepeatedFlag(t *testing.T) {
	t.Chdir(repoRoot)

	for _, flag := range []string{
		"--tests-json", "--exceptions", "--catalog", "--format", "--out", "--out-dir",
		"--readme", "--markers", "--fail-on", "--run-id", "--commit", "--platform", "--watermark",
	} {
		t.Run(flag, func(t *testing.T) {
			code, err := runReportErr(t, flag, "a", flag, "b")

			var exit *ExitError
			if code != ExitEnvironment || !asExitError(err, &exit) || exit.Category != categoryInput {
				t.Fatalf("%s given twice: exit %d, err %v; want exit 2, category input", flag, code, err)
			}
			if !strings.Contains(err.Error(), "more than once") {
				t.Errorf("error = %q, want it to say the flag was given more than once", err)
			}
		})
	}
}

// --path is repeatable, so a second use is not refused as a repeat.
func TestReportAcceptsARepeatedPath(t *testing.T) {
	t.Chdir(repoRoot)

	_, err := runReportErr(t,
		"--path", fixturePath("served-leaf"), "--path", fixturePath("served-leaf"),
		"--catalog", "embedded", "--format", "markdown")
	if err != nil && strings.Contains(err.Error(), "more than once") {
		t.Errorf("--path given twice was refused as a repeat: %v", err)
	}
}

// A flag error echoes the value it could not accept, and a value can carry
// credentials; scan strips userinfo from the message, and so does report.
func TestReportFlagErrorStripsUserinfo(t *testing.T) {
	t.Chdir(repoRoot)

	_, err := runReportErr(t, "--catalog", "a", "--catalog", "https://user:secret@example.com/c.yaml")
	if err == nil {
		t.Fatal("a repeated --catalog was accepted")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("the flag error leaks userinfo: %q", err)
	}
}
