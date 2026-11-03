package conformance_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/compliancetf/ctfkit/internal/cli"
	"github.com/compliancetf/ctfkit/internal/conformance"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// root is the repository root, relative to this package.
const root = "../.."

var bin string

func TestMain(m *testing.M) { os.Exit(buildAndRun(m)) }

// buildAndRun builds the binary under test once per package run, somewhere
// no other build writes, and removes it with a defer os.Exit would skip.
func buildAndRun(m *testing.M) int {
	dir, err := os.MkdirTemp("", "ctfkit-conformance-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if bin, err = conformance.BuildBinary(root, dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return m.Run()
}

func fixtures(t *testing.T) []conformance.Fixture {
	t.Helper()
	all, err := conformance.Fixtures(root)
	if err != nil {
		t.Fatal(err)
	}
	return all
}

func fixture(t *testing.T, name string) conformance.Fixture {
	t.Helper()
	for _, f := range fixtures(t) {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no fixture %s", name)
	return conformance.Fixture{}
}

func adapters(t *testing.T) []conformance.Adapter {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join(root, "adapters"))
	if err != nil {
		t.Fatal(err)
	}
	return []conformance.Adapter{
		conformance.CLI{Bin: bin},
		conformance.GitHubAction{Bin: bin, Dir: filepath.Join(abs, "github")},
		conformance.Spacelift{Bin: bin, File: filepath.Join(abs, "spacelift", "config.stack.yml")},
		conformance.Spacelift{Bin: bin, File: filepath.Join(abs, "spacelift", "config.yml")},
	}
}

// gaps are adapter rows this build cannot pass, keyed "adapter/case". Each
// names a string the diff must contain, so a row fails the moment the gap
// closes or changes shape, and is then removed.
var gaps = map[string]string{
	// The Spacelift hooks pass no --tests-json, so the imported test results
	// the case records never reach the report. Both configs show the
	// --tests-json form as a comment rather than running it: ctfkit never runs
	// tofu, so the file has to come from the step that runs the tests, and
	// only the operator knows where that is.
	"spacelift/config.stack.yml/example-multi-instance": noTestsJSON,
	"spacelift/config.yml/example-multi-instance":       noTestsJSON,
}

const noTestsJSON = "ctf.coverage.tests_failed"

// TestAdapterMatrix is the adapter-by-stage matrix of the scan specification
// ("Fixtures and acceptance"): every adapter over the canonical fixtures of the stages it
// runs, native output back to SARIF, empty diff (field equivalence for the
// Spacelift summary file).
func TestAdapterMatrix(t *testing.T) {
	for _, a := range adapters(t) {
		if len(a.Stages()) == 0 {
			t.Errorf("%s runs no stage; its configuration is missing or does not parse", a.Name())
		}
		for _, f := range fixtures(t) {
			if !conformance.Runs(a, f) {
				continue
			}
			t.Run(a.Name()+"/"+f.Name, func(t *testing.T) {
				diff := conformance.Check(t, a, f)
				key := a.Name() + "/" + f.Name
				if want, gap := gaps[key]; gap {
					if !strings.Contains(strings.Join(diff, "\n"), want) {
						t.Errorf("known gap %q no longer shows; remove it from gaps. diff:\n%s", want, strings.Join(diff, "\n"))
					}
					t.Logf("known gap: %s", want)
					return
				}
				if f.Deviation != "" {
					t.Logf("known deviation, dropped from the recorded side: %s", f.Deviation)
				}
				if len(diff) > 0 {
					t.Errorf("round trip differs:\n%s", strings.Join(diff, "\n"))
				}
			})
		}
	}
}

// corruptLevel is an adapter whose ToSARIF helper rewrites the first result
// level, the kind of "meaningful logic" the round trip must catch.
type corruptLevel struct{ conformance.Adapter }

func (c corruptLevel) ToSARIF(native []byte) ([]byte, error) {
	doc, err := c.Adapter.ToSARIF(native)
	result := []byte("\"level\": \"error\",\n          \"kind\"")
	return bytes.Replace(doc, result, bytes.Replace(result, []byte("error"), []byte("warning"), 1), 1), err
}

// corruptCount does the same to the Spacelift projection's error count.
type corruptCount struct{ conformance.Spacelift }

func (c corruptCount) ToSARIF(native []byte) ([]byte, error) {
	return c.Spacelift.ToSARIF(bytes.Replace(native, []byte(`"error": 2`), []byte(`"error": 1`), 1))
}

// TestHarnessHasTeeth is the acceptance proof: a deliberately broken adapter
// helper fails the round trip with a diff that names the corrupted field.
func TestHarnessHasTeeth(t *testing.T) {
	adapterDir, err := filepath.Abs(filepath.Join(root, "adapters", "spacelift", "config.stack.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		adapter conformance.Adapter
		fixture string
		field   string
	}{
		{corruptLevel{conformance.CLI{Bin: bin}}, "01-raw-s3-no-ctf", "runs[0].results[0].level"},
		{corruptCount{conformance.Spacelift{Bin: bin, File: adapterDir}}, "11-sensitive-public-exposure", "summary.error"},
	} {
		t.Run(tc.adapter.Name()+"/"+tc.fixture, func(t *testing.T) {
			diff := conformance.Check(t, tc.adapter, fixture(t, tc.fixture))
			t.Logf("diff:\n%s", strings.Join(diff, "\n"))
			if len(diff) == 0 || !strings.HasPrefix(diff[0], tc.field+":") {
				t.Errorf("diff does not name %s:\n%s", tc.field, strings.Join(diff, "\n"))
			}
		})
	}
}

// TestPostApplyStaysWithTheHarness: fixture 10 is exempt from the scan round
// trip; `scan --stage post_apply` exiting 2 is its test.
func TestPostApplyStaysWithTheHarness(t *testing.T) {
	native, err := conformance.CLI{Bin: bin}.Run(t, fixture(t, "10-post-apply-state"))
	if err != nil || native != nil {
		t.Errorf("post_apply scan: output %q, error %v; want exit 2 and no output", native, err)
	}
}

// TestAnalyzersArePure runs the registered analyzer set of each stage on
// every fixture under the race detector (go test -race) with the input hashed
// before and after Analyze. It covers the paths these fixtures exercise and
// no others.
func TestAnalyzersArePure(t *testing.T) {
	for _, f := range fixtures(t) {
		if f.Exit == 2 {
			continue // the loaders refuse these inputs; no analyzer runs
		}
		t.Run(f.Name, func(t *testing.T) {
			in, err := conformance.Input(f)
			if err != nil {
				t.Fatalf("build the input: %v", err)
			}
			registry := cli.ScanAnalyzers()
			if f.Stage == ctfkit.PostInit {
				registry = cli.ReportAnalyzers()
			}
			analyzers := registry.ByStage(f.Stage)
			if len(analyzers) == 0 {
				t.Fatalf("no analyzer registered at %s", f.Stage)
			}
			conformance.CheckPure(t, analyzers, in)
		})
	}
}

// mutator is an analyzer that writes to its input, once.
type mutator struct{ once *sync.Once }

func (mutator) ID() string          { return "ctf.test.mutator" }
func (mutator) Stage() ctfkit.Stage { return ctfkit.PostPlan }
func (m mutator) Analyze(_ context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	m.once.Do(func() { in.PlanJSON.FormatVersion = "mutated" })
	return nil, nil
}

// recorder captures what CheckPure reports instead of failing the test.
type recorder struct {
	testing.TB
	errors []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

// TestCheckPureCatchesMutation is the positive control: without it a clean
// TestAnalyzersArePure proves nothing about the check itself.
func TestCheckPureCatchesMutation(t *testing.T) {
	in, err := conformance.Input(fixture(t, "01-raw-s3-no-ctf"))
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{TB: t}
	conformance.CheckPure(r, []ctfkit.Analyzer{mutator{once: new(sync.Once)}}, in)
	if len(r.errors) != 1 || !strings.Contains(r.errors[0], "mutated its AnalyzerInput") {
		t.Errorf("CheckPure did not report the mutation: %q", r.errors)
	}
}
