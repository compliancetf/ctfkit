package output

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/fatih/color"

	"github.com/compliancetf/ctfkit/internal/validator"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/ from the current formatter output")

// The JUnit timestamp attribute is wall-clock by design, so it is the one part
// of the output a golden file cannot pin. Everything around it still is.
var junitTimestamp = regexp.MustCompile(`timestamp="[^"]*"`)

func TestFormattersGolden(t *testing.T) {
	// The color package disables itself when stdout is not a terminal, which
	// makes the pretty formatter render differently under `go test` than in a
	// real shell. Forcing it on pins the escape sequences in the golden file,
	// so a change to the colors is a visible diff rather than a silent one.
	restore := color.NoColor
	color.NoColor = false
	t.Cleanup(func() { color.NoColor = restore })

	formatters := map[string]Formatter{
		"json":   NewJSONFormatter(),
		"junit":  NewJUnitFormatter(),
		"pretty": NewPrettyFormatter(),
		"sarif":  NewSARIFFormatter(),
		"text":   NewTextFormatter(),
	}

	cases := map[string][]validator.Violation{
		"violations": sampleViolations(),
		"empty":      {},
	}

	for name, formatter := range formatters {
		for caseName, violations := range cases {
			t.Run(name+"_"+caseName, func(t *testing.T) {
				got, err := formatter.Format(violations)
				if err != nil {
					t.Fatalf("Format() error = %v", err)
				}
				got = junitTimestamp.ReplaceAll(got, []byte(`timestamp="SCRUBBED"`))
				assertGolden(t, name+"_"+caseName+".golden", got)
			})
		}
	}
}

// TestJUnitSuiteOrderIsStable guards the one ordering the golden file cannot:
// the suites come from a map keyed by file, and Go randomizes map iteration
// per run, so a single formatting pass can agree with the golden by luck.
func TestJUnitSuiteOrderIsStable(t *testing.T) {
	f := NewJUnitFormatter()
	first, err := f.Format(sampleViolations())
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	first = junitTimestamp.ReplaceAll(first, []byte(`timestamp="SCRUBBED"`))

	for i := 0; i < 50; i++ {
		got, err := f.Format(sampleViolations())
		if err != nil {
			t.Fatalf("Format() error = %v", err)
		}
		got = junitTimestamp.ReplaceAll(got, []byte(`timestamp="SCRUBBED"`))
		if string(got) != string(first) {
			t.Fatalf("suite order is not stable across runs (iteration %d):\n%s\n---\n%s", i, first, got)
		}
	}
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()

	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0750); err != nil {
			t.Fatalf("create testdata: %v", err)
		}
		if err := os.WriteFile(path, got, 0600); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path) //nolint:gosec // test-controlled path under testdata/
	if err != nil {
		t.Fatalf("read golden %s (run `go test ./internal/output -update` to create it): %v", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("output does not match %s\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}
